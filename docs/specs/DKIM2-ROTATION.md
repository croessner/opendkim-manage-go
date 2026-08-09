# Autonomous Native DKIM2 Rotation And Retention

Status: source-code implementation contract. This document does not claim a
deployment, runtime reload, queue drain, mail-flow verification, backup, or
external signature switchover.

This specification extends only `mode: dkim2`. The OpenDKIM mode, its default
selection, mutable selector lifecycle, and command semantics remain unchanged.
The implementation is an autonomous lifecycle owner. It neither imports nor
executes another DKIM implementation and it does not require another project's
binary, image, command line, journal, report, or private API. Interoperability
is limited to the independently implemented, versioned LDAP and DNS wire
contracts. Manual compatibility operations may read retained
`dkim2-datasource-v2` generations. Every new automatic campaign candidate uses
the complete operation-bound `dkim2-datasource-v3` wire format.

## Security Invariants

- The current committed generation remains active until every new DNS record
  passes fresh authoritative and recursive proof.
- A candidate is one complete frozen all-domain snapshot. One automatic run
  determines every due active binding before key generation, replaces all of
  those bindings in the same candidate, preserves every non-due binding, and
  creates at most one generation. `cn=current` moves at most once, and only
  after every candidate DNS record has passed fresh proof.
- Selectors and handles are allocated with bounded cryptographic randomness
  and may not collide with any retained generation.
- Private PKCS#8 material is stored only in an unreachable LDAP candidate. It
  is never written to a local plan, command line, log, error, metric, report,
  or generic formatter.
- Incomplete history, ambiguous bindings, unexpected higher roots, arithmetic
  exhaustion, algorithm-set changes, uncertain LDAP results, and DNS conflicts
  fail closed before the next write.
- A retained generation 1 from the pre-custody bootstrap may use the bound
  `dkim2-datasource-v1` predecessor marker and omit only its `key-material`
  container. Its handles, credentials, profiles, and policies must still prove
  one complete unambiguous public lineage per binding. A v1 root with key
  material is malformed. Generation 2 and every later root require
  `dkim2-datasource-v2` and full native key-material parity. This compatibility
  rule is read-only and never mutates retained history.
- `cn=current` moves only forward under a critical exact-current assertion.
  A staging root becomes committed only under a critical exact-staging
  assertion. Committed generation contents are never edited.
- Automatic retention is a separate phase after activation or an idle run. It
  never deletes current, staging, committed-but-unreachable, malformed,
  incomplete, foreign, or rollback-reserve generations. Each deletion is
  leaf-first/root-last, bounded, exact-readback verified, and fenced by a fresh
  unchanged current pointer.
- Automatic snapshot, staging, activation, and purge operations use four
  distinct LDAP identities. Passwords are read only from distinct owner-only
  files. A single omnibus automatic bind is invalid configuration.
- Before its first destructive LDAP request, retention durably creates one
  canonical key-free purge journal. A restart resumes that exact current-,
  operation-, source-, generation-, and candidate-digest-bound plan. Partial
  leaf deletion therefore cannot strand later inventory forever; the root is
  still deleted last, and the journal is removed only after exact absence.
- Protocol grammar and cryptographic constraints are constants. Every
  operational time, count, byte, request, history, batch, retry, and retention
  limit is supplied by the strict configuration and validated before LDAP,
  random, key, or DNS work begins.

## Configuration

The rotation fields and defaults are:

```yaml
dkim2:
  rotation_enabled: false
  rotate_after_days: 30
  history_limit: 16384
  max_campaign_bindings: 16384
  max_generation_entries: 131072
  max_attribute_bytes: 65536
  max_dataset_bytes: 1073741824
  max_ldap_requests: 262144
  max_ldap_bytes: 1073741824
  max_retained_root_visits: 32768
  identifier_allocation_attempts: 32
  publication_readback_attempts: 8
  publication_readback_interval_millis: 25
  ldap_search_time_limit_seconds: 30
  ldap_operation_timeout_seconds: 60
  authority_password_max_bytes: 16384
  ldap_authorities:
    snapshot:
      bind_dn: "cn=dkim2-snapshot,o=company"
      password_file: "/run/secrets/dkim2-snapshot-password"
    staging:
      bind_dn: "cn=dkim2-staging,o=company"
      password_file: "/run/secrets/dkim2-staging-password"
    activation:
      bind_dn: "cn=dkim2-activation,o=company"
      password_file: "/run/secrets/dkim2-activation-password"
    purge:
      bind_dn: "cn=dkim2-purge,o=company"
      password_file: "/run/secrets/dkim2-purge-password"
  max_clock_skew_seconds: 300
  run_timeout_seconds: 86400
  proof_poll_interval_seconds: 5
  proof_max_attempts: 3600
  dns_query_timeout_seconds: 5
  retirement_min_overlap_seconds: 604800
  retention:
    enabled: true
    max_generations: 12
    min_rollback_generations: 2
    max_delete_batch: 64
    journal_file: "/var/lib/opendkim-manage-go/dkim2-retention-plan.json"
    max_journal_bytes: 4096
dns:
  primary_nameserver: "127.0.0.1:53"
  recursive_nameserver: "127.0.0.2:53"
```

All displayed values are centralized, documented defaults and every one is
overrideable. Validation applies finite lower and upper bounds before use.
Explicit zero is accepted only where zero has a documented safe meaning; an
omitted value receives the displayed default, while an invalid explicit value
is never replaced silently. `retention.max_generations` must be greater than
`retention.min_rollback_generations`, and `max_delete_batch` may not exceed the
maximum recoverable history.
Both DNS endpoints require a canonical host or IP plus explicit port and must
be distinct after normalization.

One top-level run context covers the complete lifecycle command. Before every
LDAP search, add, modify, or delete, cancellation is checked again. A shared
cumulative work frame uses the explicit `max_ldap_requests`, `max_ldap_bytes`,
and `max_retained_root_visits` values across all repeated readback and recovery
phases; crossing any bound fails closed instead of starting another LDAP
operation.

Automatic eligibility uses the earliest retained root `createTimestamp` for
the exact selector, algorithm, public-SPKI, and handle lineage of every current
credential. Only canonical UTC generalized time (`YYYYmmddHHMMSSZ`) is valid.
Missing, duplicate, truncated, ambiguous, or excessively future-dated evidence
makes eligibility unknown. `modifyTimestamp` and profile validity are not key
age.

## Commands And Authorization

Manual rotation uses:

```text
--mode dkim2 --rotate --domain example.test --update-dns
```

It accepts exactly one canonical domain, no selector or wildcard scope, no
CNAME behavior, and no force option. A `--keytype` override is valid only when
it exactly equals the binding's current RSA, Ed25519, or dual algorithm set.
`--prepare-only` stages and exactly reads back the candidate, then stops before
TSIG access or DNS activity. `--resume-generation <G>` accepts one canonical
nonzero decimal and resumes only the protected stored candidate.

Rotation, automatic rotation, retirement, and forward rollback are mutually
exclusive. Every production mutation requires `--yes` or affirmative
interaction before random-key generation, TSIG loading, or a write.

`--auto --update-dns` additionally requires `rotation_enabled: true` and no
explicit domain, selector, or lifecycle subcommand. It first resumes the one
exact pending candidate if present. Otherwise it freezes every active binding,
selects all due bindings deterministically from trustworthy lineage evidence,
and builds one successor. Publication and proof cover the union of every new
record before the single commit-and-current operation. A timer invocation with
no due binding creates no generation. With the default configuration, a
binding becomes due after 30 days.

When retention is enabled, automatic execution also inventories the complete
bounded history and deletes at most `max_delete_batch` oldest eligible
generations until no more than `max_generations` remain. The newest
`min_rollback_generations` non-current committed generations are always
retained. Retention policy and inventory are recomputed immediately before
each destructive batch; any current-pointer or inventory drift stops the run.
Legacy v1/v2 roots are retained automatically. In particular, the first
v2-to-v3 campaign never adds v3 activation metadata to its immutable v2 source.
Old legacy cleanup remains an explicit migration operation, not automatic
retention. A retained legacy root does not block deletion of a separately
eligible older v3 root; it remains counted toward `max_generations`.

## Prepare, Publish, Prove, And Activate

The normal candidate number is exactly current plus one, and current must be
the maximum retained root. The empty dataset may allocate only generation 1.
At most one higher non-current candidate may exist. A partial, malformed, or
additional candidate requires explicit repair.

The repository stages the complete candidate and reads it back without moving
the current pointer. New DNS owners are created only with an RFC 2136
`NXRRSET` prerequisite. An exact existing value is resumable; a different,
multiple, malformed, revoked, CNAME, or uncertain value is a conflict. RSA
`p=` values contain the canonical SubjectPublicKeyInfo DER stored in LDAP,
matching OpenDKIM-mode DNS publication. Proof, presence checks, resumable
publication, and value-aware retirement also accept canonical PKCS#1
`RSAPublicKey` DER when it represents the exact same key. Ed25519 `p=` values
remain the raw 32-byte public key. Other encodings and key mismatches fail
closed.

Immediately before activation, the authoritative endpoint is queried directly
over TCP with recursion disabled and must answer authoritatively. The recursive
endpoint is queried directly over TCP with recursion desired. Both must return
exactly one logical TXT RR with the exact owner, algorithm, and public-key
bytes, without CNAME, referral, truncation, or error RCODE. Polling and every
exchange are bounded by the configured attempt, interval, query, and run
deadlines.

After proof, the root is committed under its critical staging assertion and
`cn=current` is advanced under the critical expected-current assertion. Lost
responses are classified by fresh authoritative readback; they are never
blindly retried. Resume reuses the candidate's exact LDAP key material and
never generates replacement keys.

Dry-run validates and builds an in-memory candidate but performs no LDAP or
DNS write and does not open the TSIG key. Except for a protected
`--resume-generation`, a later apply creates new random keys; dry-run output is
not persistent recovery state.

## Observation, Retirement, And Forward Rollback

Observation derives state from bounded LDAP and DNS reads; no local journal is
authoritative. Its closed state vocabulary distinguishes:

- `idle`: one complete current generation and no higher candidate;
- `staged`: one complete unreachable staging candidate;
- `dns-pending`: at least one required candidate RRset is authoritatively
  absent or not yet recursively proven;
- `dns-conflict`: a required owner has different, multiple, malformed,
  revoked, aliased, or otherwise ambiguous DNS data;
- `committed-unreachable`: the candidate root is committed but `cn=current`
  still names its exact predecessor;
- `activated`: the candidate is the exact current generation;
- `observing`: the new generation is current while predecessor DNS remains
  available or recursive caches still retain retired values;
- `retire-eligible`: the exact current-pointer activation clock proves the
  configured minimum overlap and all other static retirement prerequisites
  are unambiguous.

Partial/malformed staging, uncertain commit or activation, ambiguous history,
and untrusted clocks remain closed error states, not success variants.
Observation reports only bounded generation, phase, domain, selector, and
algorithm facts. It does not expose handles, DNs, private or public DER, DNS
key payloads, fingerprints, digests, endpoints, or secret material.

Read-only observation is invoked for exactly one binding with:

```text
--mode dkim2 --observe --domain example.test
```

Retirement names one retained predecessor and is invoked only with:

```text
--mode dkim2 --retire-generation <G-old> --domain example.test --update-dns \
  --attest-runtime-reload --attest-readiness --attest-queues \
  --attest-emitted-signatures --attest-external-verification \
  --attest-backup --attest-rollback-authority --yes
```

All seven attestation flags are mandatory booleans and are legal only with
`--retire-generation`; interactive confirmation does not replace one. They
assert that runtime reload, repeated readiness, queue, emitted-signature,
external-verification, backup, and rollback-authority checks were completed
outside this program. The program does not perform or infer those checks.

The current pointer's canonical operational `modifyTimestamp` is overlap
evidence only when read atomically with the exact current generation. Missing,
duplicate, malformed, fractional, offset, or excessively future-dated evidence
fails closed; `modifyTimestamp` is not key age. Every old TXT deletion has an
exact value prerequisite. Partial or response-uncertain deletion continues
only through the same command plus `--resume-retirement`, after all
attestations and preconditions are revalidated and authoritative state is read
back. An absent old record is success-so-far and is never recreated. This is
cardinality-neutral for RSA-only, Ed25519-only, and dual bindings. Recursive
cache retention is an observing condition, not a reason to repeat deletion.
Automatic DNS retirement remains forbidden. LDAP deletion occurs only through
the separate bounded v3 retention phase and its durable purge journal.

Lifecycle mutations are mutually exclusive within one process. Retirement
also reloads complete contiguous history and the exact current activation
facts immediately before every DNS delete. Any staging or committed successor
blocks retirement. These checks deliberately do not claim cross-host atomicity
between LDAP and DNS: operators must preserve the documented single-writer
authority, and a concurrently appearing successor causes the observable
retirement path to fail closed as soon as it is visible.

Rollback never moves the pointer backward. It rebases an explicitly selected
retained committed generation, including its protected key material, into a
new generation higher than every retained root and repeats the normal DNS,
staging, proof, commit, and pointer fences. Continuation names the exact new
candidate with `--resume-generation`:

```text
--mode dkim2 --rollback-from-generation <G-source> \
  --domain example.test --update-dns --yes
```

After staging, explicit continuation adds `--resume-generation <G-new>` to the
same rollback command. The stored candidate must be the exact rebase of the
named source. Partial DNS, a lost DNS response, an uncertain root commit, an
uncertain pointer switch, and already-current success are classified through
fresh readback; transport errors are never blindly retried and rollback never
triggers automatically.

## Verification Boundary

The source verification contract covers autonomous operation without another
DKIM executable, exact algorithm preservation, all-due-binding replacement in
one generation, unrelated-binding preservation, clone isolation, complete
retained-history prerequisites, v3 operation/source/content commitments,
canonical lineage and activation clocks, strict configuration propagation to
every operational bound, LDAP staging and crash reconciliation, NXRRSET
publication, all-record dual-channel proof, bounded retention with current and
rollback fences, explicit value-aware retirement, forward-only rollback,
dry-run no-write behavior, and protected formatting. Integration fixtures must
remain synthetic and isolated from production LDAP and DNS. Passing source
tests proves these code contracts; it does not prove deployment, runtime,
mail-flow, backup, or external operational state.
