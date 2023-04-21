SHELL := /bin/sh
UNAME := $(shell uname)

.PHONY: build clean run test e2e-test docker-build docker-run

build: clean
	go build -o github-oidc-auth-app

run:
	export PORT=8080 && ./github-oidc-auth-app

clean:
	rm -f github-oidc-auth-app

test:
	go test

docker-build:
	make build && docker build -t github-oidc-auth-app .

docker-run:
	docker run -it --rm --name github-oidc-auth-app -p 8080:8080 --env-file=.env.docker github-oidc-auth-app


