package main

import (
	"flag"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	v4signer "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/fujiwara/ridge"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/nabeken/capi"
	"github.com/nabeken/go-jwkset"
	"github.com/nabeken/psadm"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	"gopkg.in/square/go-jose.v2"
)

func main() {
	var dev = flag.Bool("dev", false, "enable dev mode")
	flag.Parse()

	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "capi").
		Logger()

	region := os.Getenv("AWS_REGION")
	if region == "" {
		log.Fatal().Msg("Please set AWS_REGION environment variable.")
	}

	sess := session.Must(session.NewSession())

	signer := &capi.AWSSigner{
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
		Doer:   http.DefaultClient,
		Cache:  cache.New(time.Minute, time.Minute),
	}

	resolverCache := cache.New(time.Minute, time.Minute)
	s3EndpointResolver := &capi.S3EndpointResolver{
		PSClient: psadm.NewClient(sess).CachedClient(resolverCache),
		Cache:    resolverCache,
	}

	logger := &capi.Logger{L: log}

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(logger.Handler)

	// check whether the requested host is allowed
	r.Use(s3EndpointResolver.Handler)

	// check the ALB-signed JWT
	if !*dev {
		r.Use(authenticator.Handler)

		// check ACL in the requested S3 bucket
		r.Use(authorizer.Handler)
	} else {
		log.Warn().Msg("dev mode is enabled. Authn and authz is completely disabled.")
	}

	r.Get("/_debug", capi.DebugHandler(rp.Director))
	r.Handle("/*", rp)

	ridge.Run(":8080", "/", r)
}
