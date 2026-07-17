# syntax=docker/dockerfile:1.7

ARG GO_IMAGE=golang:1.26.5-bookworm

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src

ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=vendor

COPY go.mod go.sum ./
COPY vendor/ ./vendor/
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    target_os="${TARGETOS:-linux}"; \
    target_arch="${TARGETARCH:-$(go env GOARCH)}"; \
    GOOS="$target_os" GOARCH="$target_arch" go build \
        -trimpath \
        -buildvcs=false \
        -ldflags="-s -w -buildid= -X main.version=${VERSION}" \
        -o /out/opendkim-manage \
        ./cmd/opendkim-manage

FROM scratch

ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown
ARG SOURCE=https://github.com/croessner/opendkim-manage-go

LABEL org.opencontainers.image.title="opendkim-manage-go" \
      org.opencontainers.image.description="Manage OpenDKIM keys in LDAP and DNS" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/opendkim-manage /usr/local/bin/opendkim-manage

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/opendkim-manage"]
