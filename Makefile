SHELL := /bin/sh

APP_NAME := opendkim-manage
MAIN_PKG := ./cmd/opendkim-manage
BUILD_DIR := ./bin
BINARY := $(BUILD_DIR)/$(APP_NAME)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
REVISION ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= unknown
IMAGE_SOURCE ?= https://github.com/croessner/opendkim-manage-go
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
GO ?= go
GOFLAGS ?= -mod=vendor
DOCKER ?= docker
IMAGE_REPO ?= ghcr.io/croessner/opendkim-manage-go
IMAGE_TAG ?= $(VERSION)
IMAGE ?= $(IMAGE_REPO):$(IMAGE_TAG)

.PHONY: help all build build-check run test test-race test-cover coverage fmt fmt-check vet lint vuln govulncheck tidy tidy-check vendor vendor-check clean install check guardrails release-guardrails image image-smoke image-push

help:
	@echo "Common targets:"
	@echo "  make build       - Build binary to $(BINARY)"
	@echo "  make build-check - Compile all packages without replacing $(BINARY)"
	@echo "  make run         - Run application"
	@echo "  make test        - Run unit tests"
	@echo "  make test-race   - Run tests with race detector"
	@echo "  make test-cover  - Run tests with coverage profile"
	@echo "  make coverage    - Show function coverage from coverage.out"
	@echo "  make fmt         - Run gofmt on all Go files"
	@echo "  make fmt-check   - Fail when any Go file is not gofmt-clean"
	@echo "  make vet         - Run go vet"
	@echo "  make lint        - Run golangci-lint (if installed)"
	@echo "  make vuln        - Check all packages with govulncheck"
	@echo "  make tidy        - Run go mod tidy"
	@echo "  make vendor      - Synchronize vendored dependencies"
	@echo "  make install     - Install binary to GOPATH/bin"
	@echo "  make clean       - Remove build artifacts"
	@echo "  make check       - Non-mutating fast guardrail set"
	@echo "  make guardrails  - Full repository quality gate"
	@echo "  make release-guardrails - Guardrails plus vulnerability scan"
	@echo "  make image       - Build container image $(IMAGE)"
	@echo "  make image-smoke - Build and smoke-test container image"
	@echo "  make image-push  - Push container image"

all: build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -trimpath $(LDFLAGS) -o $(BINARY) $(MAIN_PKG)

build-check:
	$(GO) build $(GOFLAGS) -trimpath $(LDFLAGS) ./...

run:
	$(GO) run $(GOFLAGS) $(LDFLAGS) $(MAIN_PKG)

test:
	$(GO) test $(GOFLAGS) ./...

test-race:
	$(GO) test $(GOFLAGS) -race ./...

test-cover: coverage.out

coverage.out:
	$(GO) test $(GOFLAGS) -coverprofile=coverage.out ./...

coverage: coverage.out
	$(GO) tool cover -func=coverage.out

fmt:
	@files="$$(find . -type f -name '*.go' -not -path './vendor/*')"; \
	if [ -n "$$files" ]; then \
		gofmt -w $$files; \
	fi

fmt-check:
	@files="$$(find . -type f -name '*.go' -not -path './vendor/*')"; \
	unformatted="$$(gofmt -l $$files)"; \
	if [ -n "$$unformatted" ]; then \
		echo "These files need gofmt:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

vet:
	$(GO) vet $(GOFLAGS) ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not installed. See: https://golangci-lint.run/usage/install/"; \
		exit 1; \
	}
	golangci-lint run --timeout=5m ./...

govulncheck:
	@command -v govulncheck >/dev/null 2>&1 || { \
		echo "govulncheck not installed. Run: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
		exit 1; \
	}
	env GOFLAGS="$(GOFLAGS)" govulncheck ./...

vuln: govulncheck

tidy:
	$(GO) mod tidy

tidy-check:
	$(GO) mod tidy -diff

vendor:
	$(GO) mod vendor

vendor-check:
	@tmp_root="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp_root"' EXIT; \
	$(GO) mod vendor -o "$$tmp_root/vendor"; \
	diff -qr vendor "$$tmp_root/vendor"

install:
	$(GO) install $(GOFLAGS) $(MAIN_PKG)

clean:
	rm -rf $(BUILD_DIR) coverage.out

check: fmt-check tidy-check vendor-check vet test

guardrails: fmt-check tidy-check vendor-check vet lint test test-race build-check

release-guardrails: guardrails govulncheck

image:
	$(DOCKER) build \
		--build-arg VERSION="$(VERSION)" \
		--build-arg REVISION="$(REVISION)" \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg SOURCE="$(IMAGE_SOURCE)" \
		-t $(IMAGE) -f Dockerfile .

image-smoke:
	./scripts/check-container-contract.sh $(IMAGE) $(VERSION)

image-push: image-smoke
	$(DOCKER) push $(IMAGE)
