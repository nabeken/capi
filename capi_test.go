package capi

import (
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
	assert := assert.New(t)

	cache := cache.New(time.Minute, time.Minute)
	mockClient := &psMockClient{}

	r := &S3EndpointResolver{
		Cache:    cache,
		PSClient: mockClient,
	}

	expected := S3Endpoint{
		Bucket: "test",
		Region: "test",
	}

	mockClient.Param = `{"bucket":"test","region":"test"}`

	actual, err := r.resolveEndpoint("example.com")
	assert.NoError(err)
	assert.Equal(expected, actual)
}
