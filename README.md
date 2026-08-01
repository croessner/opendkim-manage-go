# opendkim-manage-go

[![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Guardrails](https://github.com/croessner/opendkim-manage-go/actions/workflows/guardrails.yaml/badge.svg)](https://github.com/croessner/opendkim-manage-go/actions/workflows/guardrails.yaml)
[![CodeQL](https://github.com/croessner/opendkim-manage-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/croessner/opendkim-manage-go/actions/workflows/codeql.yml)

`opendkim-manage-go` manages DKIM keys in LDAP and synchronizes their DNS TXT
records through authenticated TSIG updates. Its default `opendkim` mode is a
Go 1.26 rewrite of the legacy Python `opendkim-manage` utility. The separate
`dkim2` mode manages immutable native DKIM2 datasource generations. The
project is distributed under the MIT license.

The current prerelease is `v1.0.0-beta.1`.

## Features

- Select either the legacy OpenDKIM or native DKIM2 LDAP model
- Manage RSA and ED25519 DKIM keys in LDAP
- List, create, delete, revoke, activate, rotate, and reorder OpenDKIM selectors
- Create and activate complete immutable DKIM2 datasource generations
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

### Operating modes

`global.mode` accepts exactly `opendkim` or `dkim2`. Omitting it preserves the
backward-compatible `opendkim` default. `--mode opendkim` or `--mode dkim2`
provides an exact command-line override; an explicitly empty or unknown value
is rejected before an LDAP manager is constructed.

The modes use structurally separate LDAP managers:

- `opendkim` retains the existing mutable selector-object lifecycle, including
  rotation, revocation, deletion, retention, and CNAME slot reconciliation.
- `dkim2` manages complete, immutable `dkim2-datasource-v2` generations. The
  configured LDAP URI base DN is the dataset base, and the schema must already
  be installed before this mode is used. The dataset base and its fixed
  `ou=generations` child are directory prerequisites; this application creates
  generation-local records and `cn=current`, not those administrative parents.

DKIM2 mode also requires a closed policy configuration:

```yaml
global:
  mode: dkim2

dkim2:
  tenant_id: tenant-example
  profile_use: originator
  rollout: enforce
  compatibility: strict
  feedback_route_id: ""
```

`profile_use` accepts `originator` or `ordinary_transit` for native key
custody; `rollout` accepts `enforce`, `observe`, or `off`; and
`compatibility` accepts only `strict`. DKIM2 identifiers are lowercase ASCII,
start with an alphanumeric character, contain only letters, digits, `.`, `_`,
or `-`, and are limited to 128 bytes.

Each DKIM2 candidate is a complete snapshot of all managed domains. It stores
handles, profiles, credentials, policies, and native key material in one new
generation. Publication validates and reads back the staged subtree before
committing it, then advances `cn=current` with a critical RFC 4528 assertion.
An uncertain, partial, mismatched, stale, or concurrent result fails without
reporting publication success. Committed generations are not edited in place.

Native key material uses distinct canonical encodings:

- LDAP private material is unencrypted PKCS#8 DER.
- LDAP public material is SubjectPublicKeyInfo DER.
- RSA DNS `p=` data is PKCS#1 `RSAPublicKey` DER.
- Ed25519 DNS `p=` data is the raw 32-byte public key.

The stored DKIM2 algorithms are exactly `rsa-sha256` and
`ed25519-sha256`. A profile may contain at most one credential per algorithm;
RSA and Ed25519 credentials use different selectors and handles.

DKIM2 mode supports only these commands:

- `--list` reports the current generation and bounded public state without
  private material, raw handles, or LDAP DNs.
- `--create --domain ... [--keytype ...]` publishes a new disabled native
  profile and its complete supporting records. A new domain starts with a
  disabled/off policy. `--keytype both` creates distinct RSA and Ed25519
  credentials in deterministic RSA-then-Ed25519 order.
- `--active --domain ... --selectorname ...` requires a fresh exact DNS proof
  before publishing an enabled profile and policy.
- `--testkey` requires exactly one logical TXT RR whose algorithm and public
  key match the LDAP credential exactly.
- `--print-dns` emits DNS-04-compatible `v=DKIM1` records with the algorithm's
  correct RSA PKCS#1 or Ed25519 raw public-key encoding.

`--delete`, `--force-delete`, `--age`, `--add-missing`, `--add-new`,
`--rotate`, `--auto`, and CNAME-oriented behavior are unsupported in DKIM2
mode and fail before LDAP or DNS writes. A native DKIM2 lifecycle-history and
retention contract is required before these operations can be implemented
truthfully.

DKIM2 creation first publishes an inactive LDAP generation. An optional DNS
update follows that successful publication. Activation always performs a new
DNS lookup, and a failed proof leaves the previous current generation active.
DNS writes retain the existing complete-TSIG and signed-success requirements
and replace only the target TXT RRset. `--dry-run` may load and validate a
complete candidate but performs no LDAP or DNS writes and does not expose
private DER, public SPKI, raw handles, bind values, or TSIG material.

There is no automatic conversion from legacy OpenDKIM objects. Tenant,
profile use, rollout, identity, validity, and immutable history are never
inferred from legacy attributes. Use the separate DKIM2 bootstrap or migration
tooling for imports; this application creates new native DKIM2 key material.

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

The exact command subset available in `dkim2` mode is documented under
[Operating modes](#operating-modes). Unsupported lifecycle commands fail
closed rather than being mapped onto immutable generations.

Common options include:

- `--mode` (`opendkim` or `dkim2`)
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
