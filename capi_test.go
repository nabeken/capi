package capi

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
