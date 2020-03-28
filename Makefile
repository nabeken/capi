LAMBDA_FUNC_NAME=capi-dev
CMD=github.com/nabeken/capi/cmd/capi

publish: zip
	aws lambda update-function-code \
	  --function-name $(LAMBDA_FUNC_NAME) \
	  --zip-file fileb://_build/main.zip \
	  --publish

zip: build
	zip _build/main.zip _build/main

build:
	GOOS=linux GOARCH=amd64 go build -o _build/main $(CMD)

clean:
	@rm -rf _build

.PHONY: build zip publish
