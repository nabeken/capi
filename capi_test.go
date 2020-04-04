package capi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
)

type psMockClient struct {
	Arg   string
	Param string
	Err   error
}

func (c *psMockClient) GetParameter(key string) (string, error) {
	c.Arg = key
	return c.Param, c.Err
}

func TestS3EndpointResolver(t *testing.T) {

	cache := cache.New(time.Minute, time.Minute)
	mockClient := &psMockClient{
		Param: `{"bucket":"test","region":"test"}`,
	}

	r := &S3EndpointResolver{
		Cache:    cache,
		PSClient: mockClient,
	}

	t.Run("host with port", func(t *testing.T) {
		assert := assert.New(t)

		r.resolveEndpoint("example.com:8080")
		assert.Equal("/capi/hosts/example.com_8080", mockClient.Arg)
	})

	t.Run("success", func(t *testing.T) {
		assert := assert.New(t)

		expected := S3Endpoint{
			Bucket: "test",
			Region: "test",
		}

		actual, err := r.resolveEndpoint("example.com")
		assert.NoError(err)
		assert.Equal(expected, actual)

		_, ok := cache.Get("__capi/error/example.com")
		assert.False(ok)
	})

	t.Run("error", func(t *testing.T) {
		assert := assert.New(t)

		mockClient.Err = errors.New("not found")

		actual, err := r.resolveEndpoint("example.com")
		assert.EqualError(errors.Unwrap(err), mockClient.Err.Error())
		assert.Equal(S3Endpoint{}, actual)

		cachedIErr, cached := cache.Get("__capi/error/example.com")
		assert.True(cached)

		cachedErr, ok := cachedIErr.(error)
		assert.True(ok)
		assert.EqualError(cachedErr, mockClient.Err.Error())
	})

	t.Run("cached error", func(t *testing.T) {
		assert := assert.New(t)

		_, err := r.resolveEndpoint("example.com")
		assert.Contains(err.Error(), "(cached)")
	})

	// clear the cache and mock
	mockClient.Err = nil
	cache.Flush()

	t.Run("success ServeHTTP", func(t *testing.T) {
		assert := assert.New(t)

		var actualS3ep S3Endpoint
		handler := func(rw http.ResponseWriter, req *http.Request) {
			actualS3ep = S3EndpointFromContext(req.Context())
			io.WriteString(rw, "it worked.")
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		r.ServeHTTP(rw, req, handler)

		assert.Equal("it worked.", rw.Body.String())
		assert.Equal(http.StatusOK, rw.Code)
		assert.Equal("/capi/hosts/example.com", mockClient.Arg)
		assert.Equal(S3Endpoint{Bucket: "test", Region: "test"}, actualS3ep)
	})

	t.Run("404 ServeHTTP", func(t *testing.T) {
		assert := assert.New(t)

		mockClient.Err = errors.New("not found")

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://example.com:8080/", nil)
		r.ServeHTTP(rw, req, func(_ http.ResponseWriter, _ *http.Request) {
			panic("should not be invoked")
		})

		assert.Equal(http.StatusNotFound, rw.Code)
		assert.Equal("/capi/hosts/example.com_8080", mockClient.Arg)
	})
}

type mockSigner struct {
	Err error
}

func (s *mockSigner) Sign(_ *http.Request, _ string, _ time.Time) error {
	return nil
}

type mockDoer struct {
	url *url.URL
}

func (d *mockDoer) Do(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = d.url.Scheme
	req.URL.Host = d.url.Host
	return http.DefaultClient.Do(req)
}

func TestAuthorizer(t *testing.T) {
	handler := func(rw http.ResponseWriter, req *http.Request) {
		switch req.Host {
		case "test.s3-success.amazonaws.com":
			io.WriteString(rw, "@example.com\n@example.net")
		default:
			http.NotFound(rw, req)
		}
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)

	mockSigner := &mockSigner{}
	mockDoer := &mockDoer{url: tsURL}

	authzr := &Authorizer{
		Signer: mockSigner,
		Doer:   mockDoer,
		Cache:  cache.New(time.Minute, time.Minute),
	}

	t.Run("success fetch policy", func(t *testing.T) {
		assert := assert.New(t)

		policy, err := authzr.fetchPolicy(S3Endpoint{Bucket: "test", Region: "success"})
		assert.NoError(err)
		assert.EqualValues([]string{"@example.com", "@example.net"}, policy)
	})

	t.Run("success lookup policy", func(t *testing.T) {
		defer authzr.Cache.Flush()

		assert := assert.New(t)

		s3ep := S3Endpoint{Bucket: "test", Region: "success"}
		expected := []string{"@example.com", "@example.net"}

		policy, err := authzr.lookupPolicy(s3ep)
		assert.NoError(err)
		assert.EqualValues(expected, policy)

		cachedPolicy, found := authzr.Cache.Get(s3ep.URL().String())
		assert.True(found)
		assert.EqualValues(expected, cachedPolicy.([]string))
	})

	t.Run("success lookup cached policy", func(t *testing.T) {
		defer authzr.Cache.Flush()

		s3ep := S3Endpoint{Bucket: "test", Region: "success-cached"}
		expected := []string{"@cached.example.com", "@cached.example.net"}
		authzr.Cache.Set(s3ep.URL().String(), expected, cache.DefaultExpiration)

		assert := assert.New(t)

		policy, err := authzr.lookupPolicy(s3ep)
		assert.NoError(err)
		assert.EqualValues(expected, policy)
	})

	t.Run("ServeHTTP", func(t *testing.T) {
		handler := func(rw http.ResponseWriter, req *http.Request) {
			io.WriteString(rw, "it worked.")
		}

		type testCase struct {
			Email  string
			Region string

			ExpectedCode int
		}

		for tn, tc := range map[string]testCase{
			"ok authz": {
				Email:        "@example.com",
				Region:       "success",
				ExpectedCode: http.StatusOK,
			},
			"bad authz due to bad claim": {
				Email:        "@bad.example.com",
				Region:       "success",
				ExpectedCode: http.StatusUnauthorized,
			},
			"bad authz due to no policy": {
				Email:        "@bad.example.com",
				Region:       "unknown",
				ExpectedCode: http.StatusUnauthorized,
			},
		} {
			t.Run(tn, func(t *testing.T) {
				rw := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "https://example.com:8080/", nil)
				req = req.WithContext(context.WithValue(req.Context(), ctxS3Endpoint, S3Endpoint{
					Bucket: "test",
					Region: tc.Region,
				}))

				req = req.WithContext(context.WithValue(
					req.Context(),
					ctxClaimSet,
					ALBOIDCClaimSet{
						Email: tc.Email,
					},
				))

				authzr.ServeHTTP(rw, req, handler)

				assert := assert.New(t)
				assert.Equal(tc.ExpectedCode, rw.Code)
			})
		}
	})
}
