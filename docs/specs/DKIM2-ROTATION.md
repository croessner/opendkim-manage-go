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
- The v3 source activation marker is monotonic: add `dkim2WasActive=TRUE`
  under the exact source commitment and an absent-marker assertion. Its
  authority requires attribute addition, never replacement/deletion. An
  existing marker or uncertain write result is accepted only after exact
  source-bound readback of `TRUE`; a conflicting or malformed marker is
  retained and stops activation.
  The production LDAP transport permits this single Add only for the activation
  authority, on a canonical positive generation root below the configured base,
  with one critical assertion control. Other attribute additions remain rejected.
  The isolated LDAP acceptance test exercises this actual authority client as
  well as the server's add-only ACL, including a fresh-client retry.
- With the four-authority native runtime enabled, explicit creation and
  activation of profiles on an existing dataset also publish one complete
  operation-bound v3 successor. They do not fall back to the legacy v2
  publication path. Create keeps new bindings disabled; activate retains its
  preceding DNS checks. Dry-runs stop before staging. An uncertain stage or
  current switch is accepted only after readback of the exact candidate and
  commitment; foreign pending work is never replaced.
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
  authority_password_preserve_trailing_newline: false
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

`authority_password_preserve_trailing_newline` is an explicit compatibility
switch for pre-existing LDAP credentials whose final LF or CRLF is part of
the password itself. It defaults to `false`; embedded control characters are
always rejected and the password files remain owner-only regular files.

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
Native administrative create and activation also use this deadline and the
same in-process mutation fence when the four-authority runtime is enabled.

Automatic eligibility uses the earliest retained root `createTimestamp` for
the exact selector, algorithm, public-SPKI, and handle lineage of every current
credential. Only canonical UTC generalized time (`YYYYmmddHHMMSSZ`) is valid.
Missing, duplicate, truncated, ambiguous, or excessively future-dated evidence
makes eligibility unknown. `modifyTimestamp` and profile validity are not key
age.

## Commands And Authorization

Explicit creation recovery uses the original complete domain scope and
configuration plus the exact stored successor number:

```text
--mode dkim2 --create --domain example.test --domain other.example \
  --keytype ed25519 --resume-generation <G> --update-dns --dry-run
```

After a successful read-only validation, replace `--dry-run` with `--yes` to
continue that operation. Recovery requires `rotation_enabled: true` and the
native campaign repository. Bootstrap generation 1 and candidates without a
valid v3 operation/source/content commitment cannot be resumed this way.
`--prepare-only` remains restricted to rotation and rollback.

The named generation must be the one complete immediate successor of its
retained committed source. Current must still name that exact source or the
already-committed candidate; any other higher root, incomplete retained
history, absent source, unknown metadata, or changed current fails closed.
The frozen candidate is reconstructed in memory from the source and exactly
the requested tenant, domain set, profile use, algorithm set, RSA size, and
feedback route. Supplied explicit selectors must match their stored algorithm
positions; generated selectors are reused without allocation. Each addition
must be a new disabled profile without a validity window, bound to exactly one
disabled/off/strict policy and matching credentials, handles, and private key
material. Selectors and public keys must be distinct within the additions and
must not reuse retained selector, handle, or public-key lineage.

All pre-existing records and protected key material must compare exactly
after rebasing only their generation number. Extra, removed, activated, or
otherwise modified records are rejected even when their candidate commitment
is valid. The v3 metadata does not claim which CLI originally produced a
candidate; the explicit requested generation, complete content comparison,
native authority boundaries, and repeated exact readback authorize this
semantically precise continuation.

Recovery never stages another generation or requests randomness, keys,
selectors, handles, or a new operation identity. A full dry-run performs the
same commitment, source, lineage, intent, and fresh-readback checks without
opening TSIG material or writing LDAP/DNS. Apply uses the existing native
`CommitCampaignAndSwitch`, then requires complete exact current readback even
after a reported success or a lost response. Already-current recovery does
not repeat that mutation. It may finish optional DNS publication for only
the new stored selector records using the existing create updater. Each
record is fenced by fresh exact current/operation/content readback. An error
retains the candidate and remaining work for the same explicit command;
previously published exact records can be repeated. This does not claim an
atomic LDAP/DNS transaction, change the create updater's TXT-only semantics,
or remove the existing single-writer operational requirement.

Committing the create generation keeps every new signing permission disabled.
Activation remains a separate `--active` operation with its existing fresh
DNS proof. `--auto` is not a substitute for explicit additive recovery: its
changed-active-binding contract is unchanged.

Manual rotation uses:

```text
--mode dkim2 --rotate --domain example.test --update-dns
```

It accepts exactly one canonical domain, no selector or wildcard scope, no
CNAME behavior, and no force option. A `--keytype` override may equal the
binding's current algorithm set or extend it, never shrink it: `--keytype all`
on an RSA and Ed25519 binding stages fresh RSA, Ed25519, and
`mldsa44-ed25519-sha512` keys. Every current credential is still replaced, and
lifecycle classification accepts exactly the added algorithms, each with its
own fresh selector, handle, and key material of the same binding. Resume
compares an explicit `--keytype` with the stored candidate's exact set.
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
no due binding creates no generation. Instead, it derives the bounded complete
active RRset inventory from the immutable current generation, checks each exact
record through the collision-safe publisher, recreates only authoritative
absence under `NXRRSET`, and then requires fresh authoritative and recursive
proof for every current record. Exact presence performs no DNS write or TSIG
load. Key comparison accepts the RFC 6376 default when an otherwise exact RSA
or Ed25519 record omits the optional `h=` tag; an explicit `h=` value must
remain exactly `sha256`. Conflict, ambiguity, cancellation, or uncertain
publication/proof fails closed before retention and without any LDAP or
generation mutation. Before the first publication, every unique logical
signing domain is resolved by bounded direct TCP SOA queries to the configured
authoritative primary. The resolver accepts only canonical authoritative
evidence and selects either the exact logical zone or its nearest proven
enclosing SOA-bearing parent, never a TLD or the DNS root. Every domain must
resolve successfully before any campaign RRset is written; malformed,
truncated, non-authoritative, ambiguous, missing, timed-out, or cancelled
evidence fails the whole preflight closed. A run that creates at least one
missing RRset reports `reconciled`; an exact no-op reports `idle`. With the
default configuration, a binding becomes due after 30 days.

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
Validated retained roots have one contiguous legacy prefix followed by one
contiguous v3 suffix. Retention may leave a gap only at that schema transition,
between the last retained legacy anchor and the first remaining v3 root.
The legacy prefix itself is not rewritten or given new gap tolerance. A v1
root remains limited to the existing generation-1 bootstrap contract. Unknown
or absent schemas, duplicate roots, a legacy root after v3, or a gap inside
either segment remain errors. The history model retains the validated schema
so inventory, publication preflight, and pending-candidate discovery use the
same rule. Current must still be present and exact; a successor remains exactly
current plus one with its original source and commitment checks.

The purge identity needs only structural deletion rights: `delete (=z)` on
the target's `entry` pseudo-attribute and on its parent's `children`, including
the generation container when deleting a root last. The synthetic
[`examples/dkim2-purge.acl`](../../examples/dkim2-purge.acl) fragment is tested
against isolated OpenLDAP with the actual snapshot and purge clients. It must
precede overlapping deny rules, preserve other authorities through `by * break`,
and keep current, legacy, staging, and never-active targets protected. No add,
attribute-update, or private-material-read rights are needed for the purger;
snapshot reads remain a separate authority. Server ACLs do not replace the
manager's full current, inventory, rollback-reserve, operation, digest, partial
subtree, and journal fences. Deployments must qualify their complete ACL order
and exact directory names before applying the fragment.

Current DNS reconciliation completes and proves all current records before an
idle or reconciled run enters this retention phase.

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

The DNS UPDATE question uses the SOA-bearing authority proven in the bounded
preflight, not an assumed equality between signing domain and update zone.
Manual rotation resolves its one logical domain before its first DNS write.
Automatic current reconciliation and candidate publication resolve every
unique logical domain before the first write, so a later resolution failure
cannot leave an earlier domain partially published.

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
independent of the set sizes: replacement proof covers every active record,
including algorithms added by an extending rotation, and retirement deletes
every predecessor record. Recursive
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
