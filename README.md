# opendkim-manage-go

[![Go Version](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Guardrails](https://github.com/croessner/opendkim-manage-go/actions/workflows/guardrails.yaml/badge.svg)](https://github.com/croessner/opendkim-manage-go/actions/workflows/guardrails.yaml)
[![CodeQL](https://github.com/croessner/opendkim-manage-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/croessner/opendkim-manage-go/actions/workflows/codeql.yml)

`opendkim-manage-go` manages DKIM keys in LDAP and synchronizes their DNS TXT
records through authenticated TSIG updates. Its default `opendkim` mode is a
Go 1.27 rewrite of the legacy Python `opendkim-manage` utility. The separate
`dkim2` mode manages immutable native DKIM2 datasource generations. The
project is distributed under the MIT license.

The current prerelease is `v1.0.0-beta.12`.

## Features

- Select either the legacy OpenDKIM or native DKIM2 LDAP model
- Manage RSA and ED25519 DKIM keys in LDAP, plus the post-quantum composite
  `mldsa44-ed25519-sha512` in DKIM2 mode
- List, create, delete, revoke, activate, rotate, and reorder OpenDKIM selectors
- Create and activate complete immutable DKIM2 datasource generations with
  crash-resumable rotation
- Run default-off, bounded autonomous DKIM2 campaigns that rotate every due
  binding in one generation and retain a configured finite history
- Recover by rebasing a retained DKIM2 generation forward without moving the
  current pointer backward
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
and quality-gate details are in [`docs/TESTING.md`](docs/TESTING.md). The native
rotation and recovery contract is specified separately in
[`docs/specs/DKIM2-ROTATION.md`](docs/specs/DKIM2-ROTATION.md).

### Operating modes

`global.mode` accepts exactly `opendkim` or `dkim2`. Omitting it preserves the
backward-compatible `opendkim` default. `--mode opendkim` or `--mode dkim2`
provides an exact command-line override; an explicitly empty or unknown value
is rejected before an LDAP manager is constructed.

The modes use structurally separate LDAP managers:

- `opendkim` retains the existing mutable selector-object lifecycle, including
  rotation, revocation, deletion, retention, and CNAME slot reconciliation.
- `dkim2` autonomously manages complete immutable native generations. It reads
  retained v2 compatibility state and writes operation-bound v3 campaign
  candidates without importing, executing, or packaging another DKIM project.
  The configured LDAP URI base DN is the dataset base, and the schema must already
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

`profile_use` accepts `originator`, `ordinary_transit`, or `delivery_status`
for native key custody; `rollout` accepts `enforce`, `observe`, or `off`; and
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
- New RSA DNS `p=` data is SubjectPublicKeyInfo DER, matching OpenDKIM mode;
  proof also accepts canonical PKCS#1 `RSAPublicKey` DER for the same key.
- Ed25519 DNS `p=` data is the raw 32-byte public key.
- `mldsa44-ed25519-sha512` private material is the exact
  id-MLDSA44-Ed25519-SHA512 PKCS#8 encoding (OID 1.3.6.1.5.5.7.6.39) of the
  32-byte ML-DSA-44 seed followed by the 32-byte Ed25519 seed. Its DNS `p=`
  data is the raw 1344-byte ML-DSA-44 public key followed by the Ed25519 public
  key, published as `v=DKIM1; k=mldsa44-ed25519-sha512; p=...` without `h=`.
  The record is about 1.9 KB and is split into 254-byte character-strings;
  the serving nameservers and resolvers must answer it over EDNS0 or TCP.
  The encodings match the DKIM2 reference implementation byte for byte.

The stored DKIM2 algorithms are exactly `rsa-sha256`, `ed25519-sha256`, and
`mldsa44-ed25519-sha512`, in that canonical order. A profile may contain at
most one credential per algorithm; every credential uses its own selector and
handle. The composite algorithm requires a `dkim2d` that signs it (v0.1.40 or
later); publish composite credentials only to daemons of that version.
`dkim2.max_attribute_bytes` must be at least 2048 so the 1365-byte composite
SPKI fits; the former 1024 minimum is rejected at configuration load.

DKIM2 mode supports only these commands:

- `--list` reports the current generation and bounded public state without
  private material, raw handles, or LDAP DNs.
- `--create --domain ... [--keytype ...]` publishes a new disabled native
  profile and its complete supporting records. A new domain starts with a
  disabled/off policy. `--keytype both` creates distinct RSA and Ed25519
  credentials, `--keytype composite` only `mldsa44-ed25519-sha512`, and
  `--keytype all` all three, in canonical order.
- `--create --resume-generation <G>` explicitly recovers one complete native
  v3 creation with the same domain set, tenant, profile use, algorithms, RSA
  size, and feedback route. It validates all unchanged source records and
  exactly the new disabled/off/strict profiles, reuses their stored keys, and
  never stages a replacement. An already-current candidate can finish its
  optional new-selector DNS publication. Dry-run validates without randomness,
  TSIG access, or writes. Native authorities and `rotation_enabled: true` are
  required; activation remains a separate DNS-verified operation. See the
  [exact recovery contract](docs/specs/DKIM2-ROTATION.md#commands-and-authorization)
  and [source qualification](docs/CREATE-RECOVERY-QUALIFICATION-2026-09.md).
- `--active --domain ... --selectorname ...` requires a fresh exact DNS proof
  before publishing an enabled profile and policy.
- `--testkey` requires exactly one logical TXT RR whose algorithm and public
  key match the LDAP credential exactly.
- `--print-dns` emits DNS-04-compatible `v=DKIM1` records with RSA
  SubjectPublicKeyInfo or Ed25519 raw public-key encoding. RSA proof accepts
  both canonical SPKI and PKCS#1 representations of the exact stored key.
- `--rotate --domain ... --update-dns` rotates exactly one active native
  binding with fresh keys for its current algorithm set. An explicit
  `--keytype` may extend that set, never shrink it: `--keytype all` on an RSA
  and Ed25519 binding adds `mldsa44-ed25519-sha512` beside fresh RSA and
  Ed25519 keys and runs the normal publication, proof, activation, and
  retirement lifecycle. To extend every binding at once, use the global
  extension campaign `--auto --keytype all --update-dns` described below.
  `--prepare-only` stops after exact LDAP staging and readback, before TSIG or
  DNS access. `--resume-generation <G>` continues only the exact protected
  candidate already stored in LDAP and never generates replacement keys.
- `--auto --update-dns` is available only when `dkim2.rotation_enabled: true`.
  It resumes one pending candidate first or freezes every binding and rotates
  every due binding in one complete generation. The default age is 30 days.
  When no binding is due, it also reconciles every bounded active current DNS
  RRset from the immutable current LDAP generation. Exact records are read-only;
  an otherwise exact RSA or Ed25519 record may use RFC 6376's omitted `h=`
  default. Absent records are recreated under `NXRRSET`, while conflicts or
  uncertain results fail closed before retention. Before the first DNS write,
  every unique signing domain is resolved against the configured authoritative
  primary to its exact SOA-bearing update zone; delegated child names may use
  a proven enclosing parent zone. Missing, ambiguous, non-authoritative, or
  malformed SOA evidence stops the complete campaign before publication. Fresh
  authoritative and recursive proof is required, no generation is created or
  activated, and the outcome is `reconciled` only when this invocation created
  at least one RRset; otherwise it remains `idle`. After activation or an
  idle/reconciled run it
  applies the configured bounded v3 retention policy; current, staging,
  malformed, legacy, and rollback-reserve generations are never deleted.
  Automatic LDAP access uses distinct snapshot, staging, activation, and purge
  identities. A canonical
  owner-only journal resumes the exact purge plan after partial leaf-first
  deletion or restart.
- `--auto --keytype <set> --update-dns` is the operator-run global extension
  campaign. It rotates every active native binding (`originator`,
  `delivery_status`, `ordinary_transit`), due or not, into fresh keys of
  exactly the requested set in one generation, through the same staging, TSIG
  publication, proof, activation, and retention path. The set must keep every
  current algorithm of every binding; a request that would drop one fails
  closed before any write. Once every binding already carries exactly the
  requested set, the campaign is idle and behaves like an idle `--auto` run.
  An interrupted campaign resumes with the same command or through the daily
  `--auto`; with `--keytype`, the stored candidate must be exactly that
  extension of every binding. `--dry-run` plans it without writes. Run
  `--auto --keytype all --update-dns --yes` once to add
  `mldsa44-ed25519-sha512` beside fresh RSA and Ed25519 keys everywhere. The
  daily `--auto` without `--keytype` keeps rotating only due bindings with
  their current sets.
- `--observe --domain ...` reports the bounded LDAP/DNS lifecycle phase for
  exactly one native binding without performing a write or opening TSIG
  material.
- `--retire-generation <G-old> --domain ... --update-dns` removes only the
  exact predecessor TXT values after the minimum overlap and all seven external
  operator attestations have been revalidated. Partial progress continues only
  through `--resume-retirement`.
- `--rollback-from-generation <G-source> --domain ... --update-dns` rebases
  retained approved content and protected key material into a new generation
  higher than every retained root. It never moves `cn=current` backward and
  continues a staged rebase only with `--resume-generation <G-new>`.

`--delete`, `--force-delete`, `--age`, `--add-missing`, `--add-new`, and
CNAME-oriented behavior remain unsupported in DKIM2 mode and fail before LDAP
or DNS writes. Automatic DNS retirement, pointer rollback, and implicit
rollback remain unavailable. Automatic LDAP deletion is limited to the strict
configured v3 retention contract.

DKIM2 creation first publishes an inactive LDAP generation. An optional DNS
update follows that successful publication. Activation always performs a new
DNS lookup, and a failed proof leaves the previous current generation active.
DNS writes retain the complete-TSIG and signed-success requirements. Rotation
creates an absent TXT RRset under `NXRRSET`; retirement deletes only an exact
old TXT value under a value-aware prerequisite. Fresh authoritative and
recursive proof uses separate, normalized `host:port` endpoints. A conflict,
ambiguous answer, or uncertain result fails closed.

`--dry-run` validates and plans without LDAP or DNS writes and without opening
the TSIG key. A later non-resume apply creates new random keys; dry-run output
is not a reusable key plan. Only `--resume-generation` reuses the protected key
material of an already staged LDAP candidate. Lifecycle, status, error,
dry-run, JSON, verbose, and metrics output never includes private DER, public
SPKI, DNS key payloads, raw handles, LDAP DNs, configured endpoints, bind
values, or TSIG material. The existing explicit `--print-dns` command is the
sole public-DNS-payload output path.

Automatic eligibility is based on the earliest retained root
`createTimestamp` for each exact current selector, algorithm, public-SPKI, and
handle lineage. The timestamp must be a single canonical UTC generalized time.
Incomplete, truncated, ambiguous, malformed, or excessively future-dated
history makes eligibility unknown and prevents a write. `modifyTimestamp` and
profile validity are not key age.

Bounded observation derives closed state from LDAP and DNS rather than a local
journal. It can distinguish idle, staged, DNS pending or conflict,
committed-but-unreachable, activated, observing, and retire-eligible states
using only generation, phase, domain, selector, and algorithm facts. These
source-code contracts do not assert that a deployment, runtime reload, queue
drain, signature switchover, external verification, or backup has occurred.

The exact retirement invocation is intentionally explicit:

```bash
opendkim-manage --mode dkim2 --retire-generation 7 \
  --domain tenant.example.test --update-dns \
  --attest-runtime-reload --attest-readiness --attest-queues \
  --attest-emitted-signatures --attest-external-verification \
  --attest-backup --attest-rollback-authority --yes
```

All seven attestations are boolean flags. After partial or response-uncertain
deletion, the only continuation is the same authorized command with
`--resume-retirement`. The program rechecks every precondition and never
recreates an old value that authoritative DNS proves absent.

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
- `--observe`
- `--retire-generation <G>`
- `--rollback-from-generation <G>`

The exact command subset available in `dkim2` mode is documented under
[Operating modes](#operating-modes). Unsupported lifecycle commands fail
closed rather than being mapped onto immutable generations.

Common options include:

- `--mode` (`opendkim` or `dkim2`)
- `--domain` / `-D`
- `--selectorname` / `-s`
- `--keytype` (`both`, `rsa`, or `ed25519`; DKIM2 mode also `composite` and
  `all`, which legacy OpenDKIM mode rejects)
- `--update-dns`
- `--prepare-only`
- `--resume-generation <G>`
- `--resume-retirement`
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
