FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.20.3 as builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0
ENV GO111MODULE=on

WORKDIR /go/src/github.com/helaili/github-oidc-auth-app

# Cache the download before continuing
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY .  .

RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go test -v ./...

RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -ldflags "-s -w" \
  -buildvcs=false \
  -a -installsuffix cgo -o /usr/bin/github-oidc-auth-app .

FROM --platform=${BUILDPLATFORM:-linux/amd64} gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.source=https://github.com/helaili/github-oidc-auth-app

ENV PORT=8080

WORKDIR /
COPY --from=builder /usr/bin/github-oidc-auth-app /
USER nonroot:nonroot

EXPOSE ${PORT}

CMD ["/github-oidc-auth-app"]
