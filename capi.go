package capi

import (
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

func NewProxy(signer *Signer, s3Endpoint *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.Host = s3Endpoint.Host
			req.URL.Scheme = s3Endpoint.Scheme
			req.URL.Host = s3Endpoint.Host

			// simulate index document
			if strings.HasSuffix(req.URL.Path, "/") {
				req.URL.Path = req.URL.Path + indexDocument
			}

			if err := signer.Sign(req, time.Now()); err != nil {
				panic(err)
			}
		},
	}
}
