# opendkim-manage-go

[![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Guardrails](https://github.com/croessner/opendkim-manage-go/actions/workflows/guardrails.yaml/badge.svg)](https://github.com/croessner/opendkim-manage-go/actions/workflows/guardrails.yaml)
[![CodeQL](https://github.com/croessner/opendkim-manage-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/croessner/opendkim-manage-go/actions/workflows/codeql.yml)

`opendkim-manage-go` manages DKIM keys in LDAP and synchronizes their DNS TXT
records through authenticated TSIG updates. It is a Go 1.26 rewrite of the
legacy Python `opendkim-manage` utility and is distributed under the MIT
license.

The current prerelease is `v1.0.0-beta.1`.

## Features

- Manage RSA and ED25519 DKIM keys in LDAP
- List, create, delete, revoke, activate, rotate, and reorder selectors
- Verify published DNS keys before activation
- Run key-age checks and automated lifecycle maintenance
- Add missing keys per domain
- Print zonefile-compatible DKIM records
- Apply authenticated DNS updates with mandatory TSIG validation
- Preview LDAP and DNS changes with `--dry-run`
- Require explicit non-interactive write confirmation with `--yes`
- Load and validate YAML configuration through Viper

## Installation

Install the latest source version:

```bash
go install github.com/croessner/opendkim-manage-go/cmd/opendkim-manage@latest
```

Release archives for Linux on AMD64 and ARM64 are published on the
[GitHub Releases](https://github.com/croessner/opendkim-manage-go/releases)
page.

## Build from source

The repository vendors all dependencies. Build the binary with:

```bash
make build
./bin/opendkim-manage --version
```

The source default is `dev`. Release and container builds replace
`main.version` with Go linker flags:

```bash
go build -mod=vendor -trimpath \
  -ldflags "-X main.version=v1.0.0-beta.1" \
  -o bin/opendkim-manage ./cmd/opendkim-manage
```

Refresh dependencies and the vendor tree before validating a release:

```bash
go get -u ./...
go mod tidy
go mod vendor
GOEXPERIMENT=runtimesecret make release-guardrails
```

## Container image

GitHub Actions publishes multi-architecture images to:

```text
ghcr.io/croessner/opendkim-manage-go
```

The `features` branch publishes `:dev` and `:features`; release tags publish
an image with the exact Git tag. Build and smoke-test an image locally with:

```bash
make image-smoke
```

The runtime image is based on `scratch`, contains only the static binary and
CA certificates, and runs as UID/GID `65532:65532`.

## Configuration

The default configuration path is `/etc/opendkim-manage.yaml`. A complete
example is available in
[`examples/opendkim-manage.yaml`](examples/opendkim-manage.yaml).

The parity and lifecycle contract is documented in
[`docs/specs/PARITY-AND-LIFECYCLE.md`](docs/specs/PARITY-AND-LIFECYCLE.md). Testing
and quality-gate details are in [`docs/TESTING.md`](docs/TESTING.md).

## Usage

```bash
opendkim-manage --help
```

Primary commands are mutually exclusive:

- `--list`
- `--create`
- `--delete`
- `--rotate`
- `--add-missing`
- `--add-new`
- `--print-dns`
- `--auto`

Common options include:

- `--domain` / `-D`
- `--selectorname` / `-s`
- `--keytype` (`both`, `rsa`, or `ed25519`)
- `--update-dns`
- `--dry-run`
- `--yes`
- `--interactive`
- `--verbose`
- `--debug`

## Security behavior

- SASL `EXTERNAL` is supported directly.
- Other SASL mechanisms are rejected without a simple-bind fallback.
- LDAP must use LDAPS or StartTLS unless `ldap.allow_insecure: true` enables a
  deliberate legacy exception.
- `ldap.ciphers` and `ldap.authz_id` are rejected until implemented.
- DNS writes require a complete TSIG key-name/key-file pair and a signed
  success response.

## Project layout

- `internal/config`: configuration loading and strict validation
- `internal/ldapstore`: LDAP client and tree model
- `internal/dnsupdate`: dynamic DNS updates and TXT formatting
- `internal/dkim`: RSA/ED25519 key generation and public-key derivation
- `internal/selector`: selector parsing and DNS record-name validation
- `internal/app`: command orchestration and lifecycle logic
- `internal/cli`: flag parsing and command validation

Development, commit, and release requirements are defined in
[`AGENTS.md`](AGENTS.md) and [`POLICY.md`](POLICY.md).

## License

Copyright (c) 2026 Christian Rößner. Released under the [MIT License](LICENSE).
