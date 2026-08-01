# Testing

Run all unit tests:

```bash
GOEXPERIMENT=runtimesecret go test -mod=vendor ./...
```

Run the complete non-mutating quality gate (apart from Go tool caches):

```bash
GOEXPERIMENT=runtimesecret make guardrails
```

It checks formatting, module tidiness, and vendor consistency without
rewriting sources, then runs `go vet`, `golangci-lint run ./...`, unit tests,
race tests, and a compile-only build. `vendor/` is excluded from formatting
and lint input.

Run the release gate, including `govulncheck`, with:

```bash
GOEXPERIMENT=runtimesecret make release-guardrails
```

Run the container contract:

```bash
make image-smoke
```

This builds the default image tag and verifies version output, help output,
non-root runtime user and absence of `/bin/sh`.

## DKIM2 prerequisites and focused contracts

Integration tests for `dkim2` mode require an isolated LDAP directory with the
immutable `dkim2-datasource-v2` schema installed. The configured LDAP URI base
DN is the dataset base, and the fixture must pre-create that base and its fixed
`ou=generations` child. Fixtures must use synthetic `example.*` names and
placeholder credentials, and must not reuse a production directory or import
legacy OpenDKIM objects.

The DKIM2 test matrix must cover:

- exact `opendkim` default, exact `--mode` override, invalid-mode rejection,
  and proof that either dispatch path constructs only its selected manager;
- closed `tenant_id`, `profile_use`, `rollout`, `compatibility`, and optional
  `feedback_route_id` validation, including bounded canonical identifiers;
- RSA PKCS#8 private, SPKI public, and DNS PKCS#1 separation, plus Ed25519
  PKCS#8 private, SPKI public, and raw 32-byte DNS public-key separation;
- rejection of noncanonical DER, private/public/algorithm mismatches, unsafe
  RSA sizes, duplicate selectors or handles, and duplicate profile algorithms;
- complete preservation of unrelated domains when a single-domain mutation
  creates a new immutable generation;
- exact `dkim2-datasource-v2` validation, monotonic generation numbers,
  bootstrap conflicts, staged readback mismatches, and concurrent
  `cn=current` assertion failures;
- bounded and escaped LDAP searches, with referrals, aliases, mixed
  generations, unknown structural classes, missing attributes, and surplus
  values rejected;
- DNS rejection for a wrong algorithm, multiple logical TXT RRs, a missing or
  revoked key, and any public-key mismatch;
- no LDAP or DNS write calls in `--dry-run` and assertions that output and
  errors contain no private key, raw handle, bind, or TSIG markers;
- `--delete`, `--force-delete`, `--age`, `--add-missing`, `--add-new`,
  `--rotate`, `--auto`, and CNAME behavior failing before writes in DKIM2 mode;
- unchanged legacy OpenDKIM manager and lifecycle regressions.

Tests that exercise DNS writes must prove a complete TSIG name/file pair and a
signed successful response. Activation tests must perform a fresh exact DNS
lookup before the current generation changes; a failed proof must leave the
previous generation current. Creation tests must prove that optional DNS
publication occurs only after the inactive LDAP generation was published.

Run a single package:

```bash
GOEXPERIMENT=runtimesecret go test -mod=vendor ./internal/dkim -v
```

## Covered areas

- Selector parsing and DNS record validation
- RSA/ED25519 key generation and public key derivation
- DNS TXT chunking helper (`make254` equivalent)
- Strict YAML config parsing and validation
- LDAP generalized time conversion
- CLI parsing for `--dry-run` and `--yes`
- LDAP filter escaping while keeping the internal `*` wildcard
- literal `DKIMDomain=*` lookup constrained by `associatedDomain`
- exact-one-TXT-RR parsing and TXT-RRset replacement
- TSIG response presence and DNS failure propagation
- time-based direct-record tombstone retention
- CNAME rename dependency/cycle planning and dry-run write suppression
- exact mode selection and isolated OpenDKIM/DKIM2 construction
- immutable DKIM2 generation validation, readback, and asserted publication
- canonical DKIM2 LDAP and DNS key encodings
- DKIM2 unsupported-command and secret-safe dry-run enforcement
