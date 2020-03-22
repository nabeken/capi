package main

import (
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	v4signer "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/fujiwara/ridge"
	"github.com/nabeken/capi"
	"github.com/nabeken/go-jwkset"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	"github.com/urfave/negroni"
	"gopkg.in/square/go-jose.v2"
)

func main() {
	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "capi").
		Logger()

	region := os.Getenv("AWS_REGION")
	if region == "" {
		log.Fatal().Msg("Please set AWS_REGION environment variable.")
	}

	dnsSigningKeyPath := os.Getenv("CAPI_DNS_SIGNING_KEY_PATH")
	if dnsSigningKeyPath == "" {
		log.Fatal().Msg("Please set CAPI_DNS_SIGNING_KEY_PATH environment variable.")
	}

	sess := session.Must(session.NewSession())

	dnsSigningKey, err := capi.GetDNSSigningKey(secretsmanager.New(sess), dnsSigningKeyPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load the DNS signing key")
	}

	signer := &capi.Signer{
		Signer: v4signer.NewSigner(sess.Config.Credentials),
	}

	rp := capi.NewProxy(signer)

	cacher := jwkset.NewCacher(10*time.Minute, time.Minute, &jwkset.ALBFetcher{
		Client: &http.Client{},
		Region: region,
		Algo:   jose.ES256,
	})

	authenticator := &capi.Authenticator{
		JWKFetcher: cacher,
	}

	authorizer := &capi.Authorizer{
		Signer: signer,
		Cache:  cache.New(time.Minute, time.Minute),
	}

	s3EndpointResolver := &capi.DNSS3EndpointResolver{
		Cache: cache.New(time.Minute, time.Minute),
		JWK:   dnsSigningKey,
	}

	n := negroni.New(
		negroni.NewRecovery(),
		&capi.Logger{L: log},
	)

	// check the requested host configures the DNS record to establish a S3 bucket mapping
	n.Use(s3EndpointResolver)

	// check the ALB-signed JWT
	n.Use(authenticator)
	n.UseFunc(authenticator.LogWithSub)

	// check ACL in the requested S3 bucket
	n.Use(authorizer)

	mux := http.NewServeMux()
	mux.Handle("/", rp)
	mux.HandleFunc("/_debug", capi.DebugHandler(rp.Director))
	n.UseHandler(mux)

	ridge.Run(":8080", "/", n)
}
