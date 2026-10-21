# Native create recovery qualification

Explicit `--create --resume-generation <G>` can recover a complete protected
v3 candidate after staging succeeded but its process or later DNS publication
failed. The implementation preserves the inherited native administrative
publisher, four-authority repository, and activation-marker work. It neither
changes LDAP limits nor publishes a release or deployment.

The [normative recovery contract](specs/DKIM2-ROTATION.md#commands-and-authorization)
defines the exact scope. Recovery reconstructs the expected inactive addition
from the immutable source and stored keys, requires full semantic equality,
and reuses the existing commit/current operation. It never substitutes new
keys, selectors, handles, or operation identity. An already-current candidate
can finish only its exact new-selector DNS publication. New signing permission
remains disabled until the separate existing DNS-verified activation command.

## Evidence

The initial reproducer failed before implementation at both the CLI command
constraint and the existing higher-generation create fence. Those same cases
now pass without bypassing either native publication or write authorization.

The final focused run passed 18 top-level tests and 87 subtests without skips.
It covers:

- stored staging, committed-unreachable, lost-success, uncertain final
  readback, restart, and already-current continuation;
- exact domains, tenant, profile use, algorithm set, RSA size, explicit
  selectors, feedback route, and unchanged inherited profiles, policies,
  credentials, handles, and protected material;
- every existing native key-custody use with RSA, Ed25519, and dual keys;
- incomplete or extra history, missing/changed commitments, current drift,
  absent authorities, old key/selector/handle lineage, and cross-domain key
  reuse;
- authorization and full dry-run validation before TSIG access or writes;
- partial DNS publication and retry without restaging or rekeying, including
  current drift between individual records;
- actual loopback UDP SOA lookup, TCP TXT updates with verified TSIG requests
  and signed responses, a signed server failure, and fresh-updater recovery;
- rejection of automatic rotation as a substitute for additive recovery.

A negative fixture initially assumed that duplicate selectors across domains
were structurally valid. Source inspection showed that the existing generation
constructor already rejects them globally. The fixture now checks that earlier
rejection, and the new recovery validator reuses that existing invariant.

The complete frozen-source gate passed with Go 1.26.8,
`GOEXPERIMENT=runtimesecret`, vendored dependencies, and the CI-pinned
golangci-lint 2.12.1:

```sh
OPENDKIM_MANAGE_REQUIRE_SLAPD=1 GOEXPERIMENT=runtimesecret make guardrails
GOEXPERIMENT=runtimesecret make govulncheck
```

Formatting, module tidiness, vendor consistency, vet, lint, unit tests, race
tests, and compilation passed. The explicit slapd environment made the
existing real isolated native LDAP/authority checks mandatory in both the
unit and race runs. The new orchestration cases use controlled repository
fixtures; this is not a claim of a live-directory recovery.

govulncheck 1.3.0 found no called vulnerabilities and no affected imported
packages. It reported four module-level advisories outside the affected
imported package set. Dependencies were not changed by this work.

## Operating boundaries

Resume requires the complete exact source to remain retained. It deliberately
rejects bootstrap, legacy or missing commitments, ambiguous roots, changed
requests, and later active generations. Dry-run validates the same source and
candidate contract without writing a recovery journal or creating future key
material.

The create DNS updater retains its existing authenticated TXT-only upsert
semantics. Full candidate/current readback fences every resumed record; there
is no atomic transaction across LDAP and DNS. Operators must maintain the
existing single-writer requirement and repeat the same explicit request after
an uncertain outcome. Activation and any production readback remain separate
operations. No production directory, DNS zone, runtime, or mail data was
changed by this qualification.
