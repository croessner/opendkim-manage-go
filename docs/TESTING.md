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
versioned v2/v3 DKIM2 schema installed. The configured LDAP URI base
DN is the dataset base, and the fixture must pre-create that base and its fixed
`ou=generations` child. Fixtures must use synthetic `example.*` names and
placeholder credentials, and must not reuse a production directory or import
legacy OpenDKIM objects.

The DKIM2 test matrix must cover:

- exact `opendkim` default, exact `--mode` override, invalid-mode rejection,
  and proof that either dispatch path constructs only its selected manager;
- closed `tenant_id`, native-key `profile_use` including `delivery_status`,
  `rollout`, `compatibility`, and optional `feedback_route_id` validation,
  including bounded canonical identifiers;
- RSA PKCS#8 private, SPKI LDAP/new-DNS public payloads, and proof compatibility
  with canonical SPKI or PKCS#1 for the same key, plus Ed25519 PKCS#8 private,
  SPKI public, and raw 32-byte DNS public-key separation;
- rejection of noncanonical DER, private/public/algorithm mismatches, unsafe
  RSA sizes, duplicate selectors or handles, and duplicate profile algorithms;
- complete preservation of unrelated domains when a single-domain mutation
  creates a new immutable generation;
- exact v2 compatibility and operation-bound v3 candidate validation, monotonic generation numbers,
  bootstrap conflicts, staged readback mismatches, and concurrent
  `cn=current` assertion failures;
- bounded and escaped LDAP searches, with referrals, aliases, mixed
  generations, unknown structural classes, missing attributes, and surplus
  values rejected;
- DNS rejection for a wrong algorithm, multiple logical TXT RRs, a missing or
  revoked key, and any public-key mismatch;
- no LDAP or DNS write calls in `--dry-run` and assertions that output and
  errors contain no private key, raw handle, bind, or TSIG markers;
- `--delete`, `--force-delete`, `--age`, `--add-missing`, `--add-new`, and
  CNAME behavior failing before writes in DKIM2 mode;
- exact manual RSA-only, Ed25519-only, and dual rotation, including
  whole-binding replacement, unrelated-domain preservation, and
  `--prepare-only` stopping before TSIG or DNS construction;
- `--resume-generation` reusing only the exact stored candidate without random
  key generation, including partial DNS, lost-response, committed-unreachable,
  pointer-switch, and already-current recovery classifications;
- default-off `--auto`, exact complete selector/algorithm/SPKI/handle lineage,
  canonical root `createTimestamp`, injected-clock age decisions, all-due
  bindings in exactly one v3 successor, non-due preservation, and
  pending-candidate-first behavior;
- bounded observation states for idle, staged, DNS pending/conflict,
  committed-unreachable, activated, observing, and retire-eligible results
  without protected values;
- all seven retirement attestations, exact `cn=current` generation plus
  canonical `modifyTimestamp` overlap evidence, value-aware TXT delete CAS,
  partial RSA-only/Ed25519-only/dual resume, and current-change rejection;
- permanent denial of automatic DNS retirement plus bounded v3 retention that
  preserves current, pending, malformed, legacy, and configured rollback roots;
- forward-only rollback into a generation higher than every retained root,
  with exact-source rebasing and explicit stored-candidate resume;
- unchanged legacy OpenDKIM manager and lifecycle regressions.

Tests that exercise DNS writes must prove a complete TSIG name/file pair and a
signed successful response. Activation tests must perform a fresh exact DNS
lookup before the current generation changes; a failed proof must leave the
previous generation current. Creation tests must prove that optional DNS
publication occurs only after the inactive LDAP generation was published.

Dry-run tests must use writer fakes that fail if called and must prove that the
TSIG file is not opened. A normal apply after dry-run must generate new random
keys; only a protected `--resume-generation` may reuse an already staged
candidate. Formatting and error tests must reject disclosure of private PKCS#8,
public SPKI, DNS key payloads, fingerprints, raw handles, LDAP DNs, configured
DNS endpoints, bind values, and TSIG material.

Rotation proof tests require two distinct normalized DNS endpoints with an
explicit port. The authoritative path uses direct TCP with recursion disabled
and requires an authoritative response. The recursive path uses direct TCP
with recursion desired and must not accept an authoritative answer as a
substitute. Both paths reject CNAMEs, referrals, truncation, error RCODEs,
wrong question/owner, multiple logical TXT RRs, wrong algorithm/key, and
revoked keys.

Run the focused native lifecycle packages with:

```bash
GOEXPERIMENT=runtimesecret go test -mod=vendor \
  ./internal/dkim2model ./internal/dkim2store ./internal/dnsupdate \
  ./internal/cli ./internal/config ./internal/app
```

The normal package run includes the critical local, synthetic LDAP publication
state-machine contract. The tagged form below remains available as an explicit
compatibility repeat of that contract; it is not the only state-machine gate:

```bash
GOEXPERIMENT=runtimesecret go test -mod=vendor \
  -tags=dkim2rotationwrite ./internal/dkim2store
```

Require the real temporary slapd contract explicitly with:

```bash
OPENDKIM_MANAGE_REQUIRE_SLAPD=1 \
GOCACHE=/tmp/opendkim-manage-go-rotation-cache \
GOEXPERIMENT=runtimesecret go test -mod=vendor ./internal/dkim2store \
  -run TestLDAPV2RepositoryAgainstSlapd -count=1
```

This gate starts only a temporary loopback listener, creates a temporary MDB
database, installs the exact `testdata/rnsdkim2.schema` fixture, and uses only
synthetic `example.test` directory entries. When the environment variable is
set, an unavailable executable, schema rejection, startup failure, bind
failure, or contract failure is fatal and is never converted into a skip.

Neither command authorizes a connection to production LDAP or DNS. External
runtime reload, readiness, queues, emitted signatures, independent
verification, backup readiness, and rollback authority are operator
attestations; unit tests can verify the gate but cannot prove those operational
facts.

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
- bidirectional active-selector `DKIMDomain` reconciliation, idempotence,
  inactive-history preservation, and dry-run write suppression
- exact-one-TXT-RR parsing and TXT-RRset replacement
- TSIG response presence and DNS failure propagation
- time-based direct-record tombstone retention
- CNAME rename dependency/cycle planning and dry-run write suppression
- exact mode selection and isolated OpenDKIM/DKIM2 construction
- immutable DKIM2 generation validation, readback, and asserted publication
- canonical DKIM2 LDAP and DNS key encodings
- DKIM2 crash-resumable rotation, bounded automation, explicit DNS retirement,
  forward-only rollback, and secret-safe dry-run enforcement
