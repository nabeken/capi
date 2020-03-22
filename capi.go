package capi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	v4signer "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/nabeken/go-jwkset"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/urfave/negroni"
	"gopkg.in/square/go-jose.v2"
)

type Signer struct {
	Signer *v4signer.Signer
}

func (s *Signer) Sign(req *http.Request, signRegion string, signTime time.Time) error {
	// Only GET and HEAD supported
	_, err := s.Signer.Sign(req, nil, "s3", signRegion, signTime)
	return err
}

const (
	indexDocument  = "index.html"
	policyDocument = "capiaccess.txt"
)

// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html
type ALBOIDCClaimSet struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Exp   int64  `json:"exp"`
}

var jwtExpSkew = time.Minute

func FromALBOIDCClaimSetContext(ctx context.Context) ALBOIDCClaimSet {
	v, _ := ctx.Value(ctxClaimSet).(ALBOIDCClaimSet)
	return v
}

func FromS3EndpointJWT(ctx context.Context) S3EndpointJWT {
	v, _ := ctx.Value(ctxS3EndpointJWT).(S3EndpointJWT)
	return v
}

type capiHTTPContext int

const (
	ctxClaimSet capiHTTPContext = iota
	ctxS3EndpointJWT
)

type Authorizer struct {
	Signer *Signer
	Cache  *cache.Cache
}

func (a *Authorizer) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	s3Endpoint := FromS3EndpointJWT(req.Context())
	log := hlog.FromRequest(req).With().Str("s3_endpoint", s3Endpoint.URL().String()).Logger()
	policy, err := a.lookupPolicy(s3Endpoint)
	if err != nil {
		log.Info().Err(err).Msg("failed to lookup policy")
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claim := FromALBOIDCClaimSetContext(req.Context())
	for _, pol := range policy {
		if Authorize(claim.Email, pol) {
			next(rw, req)
			return
		}
	}

	http.Error(rw, "Unauthorized", http.StatusUnauthorized)
}

func (a *Authorizer) lookupPolicy(s3Endpoint S3EndpointJWT) ([]string, error) {
	if policy, found := a.Cache.Get(s3Endpoint.URL().String()); found {
		return policy.([]string), nil
	}

	policy, err := a.fetchPolicy(s3Endpoint)
	if err != nil {
		return nil, fmt.Errorf("fetching policy: %w", err)
	}

	a.Cache.Set(s3Endpoint.URL().String(), policy, cache.DefaultExpiration)
	return policy, nil
}

func (a *Authorizer) fetchPolicy(s3Endpoint S3EndpointJWT) ([]string, error) {
	policyURL, err := s3Endpoint.URL().Parse("/" + policyDocument)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, policyURL.String(), nil)
	if err != nil {
		return nil, err
	}

	if err := a.Signer.Sign(req, s3Endpoint.Region, time.Now()); err != nil {
		panic(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reading policy: %s", resp.Status)
	}

	lines, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading policy: %w", err)
	}

	return strings.Split(string(lines), "\n"), nil
}

type Authenticator struct {
	JWKFetcher jwkset.Fetcher
}

func (a *Authenticator) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	claim, err := a.verifyJWT(req.Header.Get("x-amzn-oidc-data"))
	if err != nil {
		hlog.FromRequest(req).Info().Err(err).Msg("unable to verify JWT")
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	req = req.WithContext(context.WithValue(req.Context(), ctxClaimSet, claim))
	next(rw, req)
}

func (a *Authenticator) LogWithSub(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	log := zerolog.Ctx(req.Context())
	claim := FromALBOIDCClaimSetContext(req.Context())
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("sub", claim.Sub)
	})
	next(rw, req)
}

func (a *Authenticator) verifyJWT(data string) (ALBOIDCClaimSet, error) {
	// ALB contains trailing `==` in the signature payload...
	data = strings.TrimSuffix(data, "==")
	jwsobj, err := jose.ParseSigned(data)
	if err != nil {
		return ALBOIDCClaimSet{}, fmt.Errorf("parsing JWT: %w", err)
	}

	sig := jwsobj.Signatures[0]

	jwkobj, err := a.JWKFetcher.FetchJWKs(sig.Header.KeyID)
	if err != nil {
		return ALBOIDCClaimSet{}, fmt.Errorf("loading JWK: %w", err)
	}

	var verifiedPayload []byte
	var verified bool
	var verifyErr error
	for _, k := range jwkobj.Keys {
		payload, err := jwsobj.Verify(k)
		if err == nil {
			verifiedPayload = payload
			verified = true
			break
		}

		verifyErr = err
	}

	if !verified {
		return ALBOIDCClaimSet{}, fmt.Errorf("verifying: %w", verifyErr)
	}

	claim := ALBOIDCClaimSet{}
	if err := json.Unmarshal(verifiedPayload, &claim); err != nil {
		return ALBOIDCClaimSet{}, fmt.Errorf("decoding: %w", err)
	}

	if !verifyExp(time.Now(), jwtExpSkew, claim.Exp) {
		return ALBOIDCClaimSet{}, errors.New("exp expired")
	}

	return claim, nil
}

func verifyExp(now time.Time, skew time.Duration, exp int64) bool {
	expT := time.Unix(exp, 0)
	skewT := expT.Add(skew)
	return now.Before(skewT)
}

func NewProxy(signer *Signer) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			s3Endpoint := FromS3EndpointJWT(req.Context())

			s3url := s3Endpoint.URL()
			req.Host = s3url.Host
			req.URL.Scheme = s3url.Scheme
			req.URL.Host = s3url.Host

			// when we proxy to S3, we have to exclude the following headers
			// since after the signer signs it, the proxy handler alters it.

			req.Header.Del("x-forwarded-for")
			req.Header.Del("x-forwarded-port")
			req.Header.Del("x-forwarded-proto")
			req.Header.Del("connection")

			// simulate index document
			if strings.HasSuffix(req.URL.Path, "/") {
				req.URL.Path = req.URL.Path + indexDocument
			}

			if err := signer.Sign(req, s3Endpoint.Region, time.Now()); err != nil {
				panic(err)
			}
		},
	}
}

func DebugHandler(dir func(*http.Request)) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		dir(req)

		claim := FromALBOIDCClaimSetContext(req.Context())

		rw.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(rw, "%#v\n", req)
		fmt.Fprintf(rw, "%#v\n", req.URL)
		fmt.Fprintf(rw, "%#v\n", claim)
	}
}

type Logger struct {
	L zerolog.Logger
}

func (l *Logger) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	start := time.Now()

	rl := l.L.With().
		Str("hostname", req.Host).
		Str("method", req.Method).
		Str("path", req.URL.Path).Logger()

	req = req.WithContext(rl.WithContext(req.Context()))

	next(rw, req)

	res := rw.(negroni.ResponseWriter)

	rl.Info().
		Int("status", res.Status()).
		Dur("duration", time.Since(start)).
		Msg("completed.")
}
