# Parity and Lifecycle Specification

Status: 2026-07-17

This document is the normative behavioral contract for the Go implementation.
The historical Python implementation was used as the migration reference, but
its bugs and unsafe fallbacks are explicitly not compatibility requirements.

## Normative Lifecycle Policy

[RFC 6376, Section 3.6.1](https://www.rfc-editor.org/rfc/rfc6376.html#section-3.6.1)
defines an empty `p=` value as a revoked public key. A verifier must treat a
signature referring to that key as permanently failed. RFC 6376 also notes
that a signer should stop using a key before its DNS record is revoked or
removed, so existing signatures still have a chance to be verified.

[RFC 5863, Sections 3.5.1 and 3.5.2](https://www.rfc-editor.org/rfc/rfc5863.html#section-3.5)
requires a new DNS key to be published and verified before it is used. During
retirement, use of the private key stops first; DNS revocation or removal
follows later according to local policy. RFC 5863 describes `p=` as a
gravestone that helps prevent accidental selector reuse.

The following lifecycle applies to direct DNS records:

1. Generate a new key and replace its complete TXT RRset.
2. Activate the new LDAP key after successful DNS verification.
3. Only then deactivate previously active keys of the same algorithm.
4. After `delete_delay` days, revoke an inactive old key in LDAP and publish a
   syntactically valid DKIM record with an empty `p=` value in DNS.
5. Retain the tombstone for at least `revoked_retention` days from the LDAP
   `modifyTimestamp`. The default is 30 days. Only after that period may the
   TXT RRset and LDAP object be removed.
6. `revoked_retention: 0` deliberately enables legacy compatibility mode. In
   that mode, `max_revoked` retains the newest revoked entries. An explicit
   CLI value of `--max-revoked 0` is valid and retains no entries.

The RFCs do not prescribe a fixed number of days. The 30-day default is local
policy, not an RFC-derived minimum.

## CNAME Model

CNAME domains intentionally do not use an unbounded, time-based selector
history. Each algorithm has three static slots with separate prefixes:

| Slot | Required LDAP and DNS state |
|---|---|
| 1 | Newest key, active, complete `p=` value |
| 2 | Immediate predecessor, inactive, complete `p=` value |
| 3 | DKIM tombstone with an empty `p=` value |

Customer domains point static CNAMEs at these records. The program does not
modify those customer CNAMEs. On every run, it reconciles the central TXT
RRsets: slot 3 is written as a tombstone even when fewer than three LDAP keys
exist, while an unused slot 1 or 2 is removed as a TXT RRset. A production
`--auto` run with CNAME domains therefore requires `--update-dns`; otherwise,
the preflight fails before the first LDAP mutation. Dry-run mode simulates the
same sequence without writes.

Before a production LDAP rename, the corresponding key is placed in the
target DNS slot. Dependent renames run in collision-free order. A rename cycle
may only be resolved through a temporary name belonging to an inactive key; a
cycle containing only active keys fails closed. After the rename, slot 1 is
activated first, old active keys of the same algorithm are then deactivated,
and only afterward is slot 3 reconciled as the final tombstone.

Every `destinationIndicator` must be allowlisted as an exact DNS name in
`dns.cnames`. An empty allowlist fails closed. Source and target names must be
LDH-compliant. In particular, underscores are forbidden in customer domains
so mapping dots to underscores remains collision-free.

## Parity Matrix

| Area | Go behavior | Relationship to the legacy implementation |
|---|---|---|
| List/Create/Delete/Age/Active/TestKey | Same primary domain operations | Compatible, with stricter errors |
| AddMissing/AddNew/Rotate/Auto | Same lifecycle sequence | Compatible; revoked keys do not count as usable keys |
| PrintDNS | Zone-file TXT output for RSA/Ed25519 with optional `s=` | Compatible; syntax errors and ambiguity are fatal |
| CNAME reorder | Three static slots per algorithm | Intentional project-specific logic with more robust reconciliation |
| Configuration | Strict YAML | Intentional deviation from the legacy INI parser |
| Write authorization | Requires `--yes`, `--interactive`, or `--dry-run` | Intentional safety extension |
| Dry-run | No LDAP or DNS writes; Create, Delete, Revoke, Rename, and activation update the in-memory model | New functionality |
| LDAP transport | LDAPS/StartTLS and certificate verification by default; `allow_insecure` must be explicit | Intentional hardening |
| SASL | EXTERNAL with a client certificate only; no fallback | Intentional hardening |
| Selector resolution | Global ambiguity is an error; domain context resolves exactly | Fixes first-match behavior |
| Multiple signatures | Literal `DKIMDomain=*` lookup is combined with `associatedDomain` | Fixes a legacy gap |
| DNS update | Replaces only the complete TXT RRset; other RR types remain intact | Fixes add/delete semantics |
| DNS authentication | Requires TSIG configuration and a signed success response | Intentional hardening |
| DNS test | Requires exactly one logical TXT RR; strings are joined only within that RR | Prevents concatenation of multiple RRs |
| Direct tombstones | Time-based retention through `revoked_retention` | Intentional RFC-oriented replacement for a faulty positional counter |
| Private keys | Never written to terminal output; passed only to LDAP | Intentional hardening |

## Error and Write Contract

- LDAP, key-generation, timestamp, SOA, DNS-update, and random-source errors
  are returned to the caller. A missing DNS TXT record during `--testkey` is a
  negative verification result, not an internal application error.
- DNS updates use TCP and TSIG. A missing response, an error RCODE, or an
  unsigned response is a failure.
- Add/Change atomically replaces the TXT RRset at the target name. Remove
  deletes only that TXT RRset and never all RR types at the name.
- `--dry-run` must not invoke any client method that writes to LDAP or DNS.
  Planned state changes are simulated in the loaded in-memory tree so later
  automatic steps do not plan against stale state.

## Deliberate Current Limitations

- `ldap.ciphers` and `ldap.authz_id` are not implemented and are rejected
  instead of being silently ignored.
- SASL mechanisms other than EXTERNAL are not implemented.
- Customer-side static CNAMEs are neither created nor verified; they are an
  external operational prerequisite.
- DNSSEC validation is outside the program's scope. Dynamic DNS updates are
  authenticated with TSIG.
