package capi

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	v4signer "github.com/aws/aws-sdk-go/aws/signer/v4"
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
		fmt.Fprintf(rw, "%#v\n", req)
		fmt.Fprintf(rw, "%#v\n", req.URL)
	}
}
