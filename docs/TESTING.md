# Testing

Run all unit tests:

```bash
GOEXPERIMENT=runtimesecret go test -mod=vendor ./...
```

Run the complete non-mutating quality gate (apart from Go tool caches):

```bash
make guardrails
```

It checks formatting, module tidiness, and vendor consistency without
rewriting sources, then runs `go vet`, `golangci-lint run ./...`, unit tests,
race tests, and a compile-only build. `vendor/` is excluded from formatting
and lint input.

Run the release gate, including `govulncheck`, with:

```bash
make release-guardrails
```

Run the container contract:

```bash
make image-smoke
```

This builds the default image tag and verifies version output, help output,
non-root runtime user and absence of `/bin/sh`.

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
