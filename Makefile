SHELL := /bin/sh
UNAME := $(shell uname)

.PHONY: build clean run run-dev test e2e-test docker-build

build: clean
	go build -o github-oidc-auth-app

run-dev:
	export PORT=8080 && ./github-oidc-auth-app

run:
	./github-oidc-auth-app

clean:
	rm -f github-oidc-auth-app

test:
	go test

e2e-test:
	cd test && ./test.sh && cd ..

docker-build:
	docker build -t github-oidc-auth-app .

docker-run:
	docker run -it --rm --name github-oidc-auth-app -p 8080:8080 --env-file=.env.docker github-oidc-auth-app


