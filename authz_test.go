package capi

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorize(t *testing.T) {
	for i, tc := range []struct {
		Target     string
		Pattern    string
		Authorized bool
	}{
		{
			Target:     "foo@example.com",
			Pattern:    "Foo@example.com",
			Authorized: true,
		},
		{
			Target:     "foo@example.com",
			Pattern:    "foo@example.com",
			Authorized: true,
		},
		{
			Target:     "foo@example.com",
			Pattern:    "@example.com",
			Authorized: false,
		},

		{
			Target:     "foo@example.com",
			Pattern:    `re/@example\.com$`,
			Authorized: true,
		},
		{
			Target:     "foo@example.com",
			Pattern:    `re/@Example\.com$`,
			Authorized: true,
		},
		{
			Target:     "foo@foo.example.com",
			Pattern:    `re/@example\.com$`,
			Authorized: false,
		},

		{
			Target:     "foo@foo.example.com",
			Pattern:    "re/@example(.com$",
			Authorized: false,
		},

		{
			Target:     "",
			Pattern:    "",
			Authorized: false,
		},
		{
			Target:     "foo@example.com",
			Pattern:    "",
			Authorized: false,
		},
		{
			Target:     "",
			Pattern:    "foo@example.com",
			Authorized: false,
		},
	} {
		t.Run(fmt.Sprintf("#%d", i+1), func(t *testing.T) {
			assert := assert.New(t)
			actual := Authorize(tc.Target, tc.Pattern)
			assert.Equal(tc.Authorized, actual)
		})
	}
}
