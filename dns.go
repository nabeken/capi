package capi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/hlog"
	"gopkg.in/square/go-jose.v2"
)

// GetDNSSigningKey returns a public key used for signing the S3 endpoint JWT.
func GetDNSSigningKey(sm *secretsmanager.SecretsManager, secretName string) (*jose.JSONWebKey, error) {
	resp, err := sm.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"),
	})
	if err != nil {
		return nil, fmt.Errorf("getting secret: %w", err)
	}

	jwkstr := aws.StringValue(resp.SecretString)

	// https://github.com/square/go-jose/blob/v2.4.1/jose-util/utils.go#L27
	jwk := &jose.JSONWebKey{}
	if err := jwk.UnmarshalJSON([]byte(jwkstr)); err != nil {
		return nil, fmt.Errorf("unable to unmarshal JWK: %s", err)
	}

	if !jwk.Valid() {
		return nil, errors.New("invalid JWK key")
	}
	if jwk.IsPublic() {
		return nil, errors.New("the JWK must be a private key")
	}

	return jwk, nil
}

// S3EndpointJWT represents S3 endpoint information in JWT.
// It is installed in TXT resource record for host.
type S3EndpointJWT struct {
	S3Bucket string `json:"s3b"`
	Host     string `json:"hst"`

	// To sign a request, we need to have this separately
	Region string `json:"reg"`
}

func (t S3EndpointJWT) Valid() bool {
	return t.S3Bucket != "" && t.Host != "" && t.Region != ""
}

func (t S3EndpointJWT) URL() *url.URL {
	if !t.Valid() {
		return nil
	}
	ep, _ := url.Parse(fmt.Sprintf("https://%s.s3-%s.amazonaws.com", t.S3Bucket, t.Region))
	return ep
}

// DNSS3EndpointResolver resolves host to S3 endpoint in the TXT resource record of host.
type DNSS3EndpointResolver struct {
	Cache *cache.Cache
	JWK   *jose.JSONWebKey
}

// ServeHTTP resolves host in the Host header and set S3 endpoint in the context for the proxy handler.
// If it cannot find the endpoint, it will return 404.
func (r *DNSS3EndpointResolver) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	host := req.Host
	if strings.Contains(host, ":") {
		host_, _, err := net.SplitHostPort(req.Host)
		if err != nil {
			hlog.FromRequest(req).Info().Err(err).Msg("failed to get hostname in the header")
			http.NotFound(rw, req)
			return
		}
		host = host_
	}

	s3Endpoint, err := r.ResolveS3EndpointWithCache(host)
	if err != nil {
		hlog.FromRequest(req).Info().Err(err).Msg("failed to resolve S3 endpoint")
		http.NotFound(rw, req)
		return
	}

	req = req.WithContext(context.WithValue(req.Context(), ctxS3EndpointJWT, s3Endpoint))
	next(rw, req)
}

func (r *DNSS3EndpointResolver) ResolveS3EndpointWithCache(host string) (S3EndpointJWT, error) {
	if v, found := r.Cache.Get(host); found {
		return v.(S3EndpointJWT), nil
	}

	s3Endpoint, err := r.ResolveS3Endpoint(host)
	if err != nil {
		return S3EndpointJWT{}, err
	}

	r.Cache.Set(host, s3Endpoint, cache.DefaultExpiration)
	return s3Endpoint, nil
}

func (r *DNSS3EndpointResolver) ResolveS3Endpoint(host string) (S3EndpointJWT, error) {
	rrs, err := net.LookupTXT(host)
	if err != nil {
		return S3EndpointJWT{}, fmt.Errorf("resolving TXT resource record: %w", err)
	}

	const prefix = "capi="
	for _, rr := range rrs {
		if strings.HasPrefix(rr, prefix) {
			s3Endpoint, err := r.verifyJWT(host, rr[len(prefix):])
			if err != nil {
				return S3EndpointJWT{}, fmt.Errorf("failed to verify JWT: %w", err)
			}

			return s3Endpoint, nil
		}
	}

	return S3EndpointJWT{}, errors.New("no TXT resource record found for capi")
}

func (r *DNSS3EndpointResolver) verifyJWT(host, token string) (S3EndpointJWT, error) {
	jwsobj, err := jose.ParseSigned(token)
	if err != nil {
		return S3EndpointJWT{}, fmt.Errorf("parsing JWT: %w", err)
	}

	// Use the public key to verify
	signed, err := jwsobj.Verify(r.JWK.Public())
	if err != nil {
		return S3EndpointJWT{}, fmt.Errorf("verifying the signature: %w", err)
	}

	ret := S3EndpointJWT{}
	if err := json.Unmarshal(signed, &ret); err != nil {
		return S3EndpointJWT{}, fmt.Errorf("decoding: %w", err)
	}

	if !ret.Valid() {
		return S3EndpointJWT{}, errors.New("all fields are required")
	}

	return ret, nil
}
