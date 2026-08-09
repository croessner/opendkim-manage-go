# Native DKIM2 Rotation And Global Campaign Automation

Status: source-code implementation contract. This document does not claim a
deployment, runtime reload, queue drain, mail-flow verification, backup, or
external signature switchover.

This specification extends only `mode: dkim2`. The OpenDKIM mode, its default
selection, mutable selector lifecycle, and command semantics remain unchanged.
The original native key-management commands remain compatible with
`dkim2-datasource-v2`. Automatic rotation is a separate global campaign path
for `dkim2-datasource-v3`. It consumes the versioned DKIM2 offline campaign
command and report contract and never writes v3 LDAP or SQL records itself.
`opendkim-manage-go` is the automation and DNS-publication owner; `dkim2d` is
the sole datasource transaction, key-generation, and current-pointer owner.

## Security Invariants

- The current committed generation remains active until every new DNS record
  passes fresh authoritative and recursive proof.
- A normal automatic candidate is one complete frozen all-binding snapshot.
  Every due active binding is rotated in that single candidate. Bindings which
  are not due remain logically equal. The campaign creates at most one
  generation and moves `current` at most once.
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
- Automatic rotation never uses the legacy one-binding rotation path. It never
  retires DNS or deletes datasource history. Retirement and purge remain
  separate explicit operations.

## Owner Boundary

One scheduled `opendkim-manage-go --mode dkim2 --auto` invocation serially:

1. starts or resumes one `dkim2d datasource rotation run --automatic`
   campaign using a protected journal;
2. obtains every bounded deterministic DNS batch from `dkim2d`;
3. parses the closed DNS export grammar and publishes each exact absent TXT
   RRset through the configured authenticated DNS update authority;
4. resumes the same campaign so `dkim2d` proves all records and performs one
   exact-current activation; and
5. removes only the completed campaign journal and its transient DNS exports
   after an exact machine report proves `activated`.

When `campaign.retention_enabled` is explicitly enabled, a successful campaign
then invokes the separate `dkim2d datasource rotation purge plan` command,
persists only its protected key-free artifact, and invokes exact `purge apply
--apply`. The manager has no purge or closer credential, does not infer
eligibility, and treats pending, reconcile-required, malformed, or ambiguous
reports as non-success. A present artifact is retried only by exact apply;
legacy deletion remains disabled unless the datasource owner marks it eligible.

The manager executable does not receive any snapshot, staging, activation,
purge, or closer credential. The DKIM2 command receives no TSIG secret and has
no DNS write transport. Command stderr, provider errors, private keys, DNS
record contents, domains, and protected paths are never copied into manager
reports or logs.

## Configuration

The rotation fields and defaults are:

```yaml
dkim2:
  rotation_enabled: false
  rotate_after_days: 365
  history_limit: 1024
  max_clock_skew_seconds: 300
  run_timeout_seconds: 900
  proof_poll_interval_seconds: 5
  proof_max_attempts: 60
  dns_query_timeout_seconds: 5
  retirement_min_overlap_seconds: 604800
  campaign:
    enabled: false
    executable: /usr/local/bin/dkim2d
    config_file: /path/to/rotation.yaml
    journal_file: /path/to/state/campaign.json
    cadence_file: /path/to/state/cadence.json
    artifact_directory: /path/to/state
    max_batches: 1024
    retention_enabled: false
    retention_artifact: /path/to/state/retention-plan.json
dns:
  primary_nameserver: "127.0.0.1:53"
  recursive_nameserver: "127.0.0.2:53"
```

The integer ranges are respectively `1..36500`, `2..4096`, `0..3600`,
`30..86400`, `1..300`, `1..3600`, `1..30`, and `3600..31536000`.
Both DNS endpoints require a canonical host or IP plus explicit port and must
be distinct after normalization.

One top-level run context covers the complete lifecycle command. Before every
LDAP search, add, or modify, cancellation is checked again. A shared cumulative
work frame derived from `history_limit` bounds request count, response and
request bytes, and retained-root visits across all repeated readback and
recovery phases; crossing any bound fails closed instead of starting another
LDAP operation.

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

`--auto --update-dns` additionally requires `rotation_enabled: true`, the
complete `campaign` configuration, and no explicit domain, selector, key type,
or lifecycle subcommand. It exclusively runs the global v3 campaign adapter;
falling back to the old per-binding v2 implementation is forbidden. A dry run
invokes the DKIM2 read-only global preview and performs no journal, key, DNS,
datasource, or pointer write.

The executable, configuration, journal, cadence, and artifact paths must be absolute
and canonical. The journal must be a direct child of the artifact directory.
The batch cap is finite (`1..1024`). Existing export files must be regular,
owner-only files with exact deterministic content; conflicts, symbolic links,
unknown report fields, noncanonical JSON, malformed zone records, partial
publication, command ambiguity, and cleanup ambiguity fail closed.

The owner-only cadence document is written atomically before an activated
journal is removed. While no journal exists, a new campaign is started only
after `rotate_after_days` has elapsed since that durable activation. A present
journal is always resumed regardless of cadence. This makes a daily timer safe:
restarts and repeated invocations cannot create one generation per timer run.

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
Automatic retirement and LDAP deletion are forbidden.

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

The source verification contract covers exact algorithm preservation,
whole-binding replacement, unrelated-domain preservation, clone isolation,
complete retained-history prerequisites, canonical lineage and activation
clocks, deterministic batch-one automation, strict CLI/configuration
isolation, LDAP staging and crash reconciliation, NXRRSET publication,
dual-channel proof, explicit value-aware retirement, forward-only rollback,
dry-run no-write behavior, and protected formatting. Integration fixtures must
remain synthetic and isolated from production LDAP and DNS. Passing source
tests proves these code contracts; it does not prove deployment, runtime,
mail-flow, backup, or external operational state.
