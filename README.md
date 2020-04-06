# capi - A S3 Gateway protected by OpenID Connect on top of Application Load Balancer

`capi` is a S3 gateway protected by OpenID Connect on top of [AWS's Application Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html).

## Use-case

**Problem**: You want to host a static website on S3 but don't want to expose to everyone.

**Solution**: You can setup ALB with OpenID Connect and route requests to `capi` so that you can expose a static website on a private S3 bucket with the simple ACL by email address.

## How it works

- `ALB` authenticates you by OpenID Connect.
- After the authentication succeeds, that, `ALB` routes a request to `capi` running on Lambda.
- `capi` checks the JWT signed by `ALB` in `x-amzn-oidc-data` request header.
- `capi` picks up a destination backend S3 by looking up `host` request header.
  - `capi` use AWS Parameter Store to store the configuration.
- `capi` performs authorization before proxying a request to backend S3.
  - ACL (Access Control List; `capiaccess.txt`) is fetched from the destination S3 bucket so the owner can maintain it.
- After the user is authorized to access the destination S3 bucket, `capi` proxyies requests to the S3 bucket.

## Configuration

Let's say you want `capi` to route `example.com` to `example-com` S3 bucket in `ap-northeast-1` region. You need to put the following JSON to the path on Parameter Store:

```sh
aws ssm put-parameter \
  --type String \
  --name '/capi/hosts/example.com' \
  --value '{"bucket": "example-com", "region": "ap-northeast-1"}'
```

then if you want give `me@example.com` and `you@example.com` access to your bucket, you can put ACL file (`capiaccess.txt`) to the root of the bucket (`s3://example-com/capiaccess.txt`):

```
me@example.com
you@example.com
```

or use [the regular expression](https://golang.org/s/re2syntax):
```
re/^(?:me|you)@example\.com$
```

Probably, you should have `$` at the end.

## ALB

Please read [the ALB documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html) to setup ALB and OpenID Connect. ALB needs to route requests to `capi` lambda function.

## IAM

At least, you need to grant the lambda function to access S3 and SSM Parameter Store.

## Deploy

```sh
make LAMBDA_FUNC_NAME=capi
```
