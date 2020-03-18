package main

import (
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	v4signer "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/fujiwara/ridge"
	"github.com/nabeken/capi"
	"github.com/urfave/negroni"
)

func main() {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		log.Fatal("Please set AWS_REGION environment variable.")
	}

	s3Bucket := os.Getenv("CAPI_S3_BUCKET")
	if s3Bucket == "" {
		log.Fatal("Please set CAPI_S3_BUCKET environment variable.")
	}

	s3Endpoint, err := url.Parse(
		fmt.Sprintf("https://%s.s3-%s.amazonaws.com", s3Bucket, region),
	)
	if err != nil {
		log.Fatal(err)
	}

	signer := &capi.Signer{
		Region: region,
		Signer: v4signer.NewSigner(session.Must(session.NewSession()).Config.Credentials),
	}

	rp := capi.NewProxy(signer, s3Endpoint)

	n := negroni.Classic()
	n.UseHandler(rp)

	ridge.Run(":8080", "/", n)
}
