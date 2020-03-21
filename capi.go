package capi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	v4signer "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/nabeken/go-jwkset"
	"gopkg.in/square/go-jose.v2"
)

type Signer struct {
	Region string
	Signer *v4signer.Signer
}

func (s *Signer) Sign(req *http.Request, signTime time.Time) error {
	// Only GET and HEAD supported
	_, err := s.Signer.Sign(req, nil, "s3", s.Region, signTime)
	return err
}

const indexDocument = "index.html"

// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html
type ALBOIDCClaimSet struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Exp   int64  `json:"exp"`
}

func FromALBOIDCClaimSetContext(ctx context.Context) ALBOIDCClaimSet {
	v, _ := ctx.Value(ctxClaimSet).(ALBOIDCClaimSet)
	return v
}

type capiHTTPContext int

const (
	ctxClaimSet capiHTTPContext = 1
)

type Authenticator struct {
	JWKFetcher jwkset.Fetcher
}

func (a *Authenticator) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	claim, err := a.verifyJWT(req.Header.Get("x-amzn-oidc-data"))
	if err != nil {
		log.Printf("unable to verify: %s", err)
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	req = req.WithContext(context.WithValue(req.Context(), ctxClaimSet, claim))
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

	return claim, nil
}

func Director(signer *Signer, s3Endpoint *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		req.Host = s3Endpoint.Host
		req.URL.Scheme = s3Endpoint.Scheme
		req.URL.Host = s3Endpoint.Host

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

		if err := signer.Sign(req, time.Now()); err != nil {
			panic(err)
		}
	}
}

func NewProxy(signer *Signer, s3Endpoint *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: Director(signer, s3Endpoint),
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
