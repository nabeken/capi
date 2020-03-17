package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/aws/aws-sdk-go/aws/session"
	v4signer "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/nabeken/capi"
)

func main() {
	s3Bucket := flag.String("s3-bucket", "", "S3 bucket name")
	s3Region := flag.String("s3-region", "ap-northeast-1", "S3 bucket region")

	flag.Parse()

	s3Endpoint, err := url.Parse(
		fmt.Sprintf("https://%s.s3-%s.amazonaws.com", *s3Bucket, *s3Region),
	)
	if err != nil {
		log.Fatal(err)
	}

	signer := &capi.Signer{
		Region: *s3Region,
		Signer: v4signer.NewSigner(session.Must(session.NewSession()).Config.Credentials),
	}

	rp := capi.NewProxy(signer, s3Endpoint)
	http.Handle("/", rp)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
