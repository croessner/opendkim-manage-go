---
name: opendkim-manage-go-dkim-lifecycle
description: Use for opendkim-manage-go selector creation, activation, rotation, revocation, deletion, direct-record tombstones, CNAME slot reconciliation, DNS verification, dry-run planning, and parity changes governed by docs/specs/PARITY-AND-LIFECYCLE.md.
---

# OpenDKIM Manage Go DKIM Lifecycle

## Source of Truth

Read `docs/specs/PARITY-AND-LIFECYCLE.md` before changing lifecycle behavior.
Treat it as the normative contract; historical implementation bugs are not
compatibility requirements.

## Direct-Record Invariants

1. Generate and publish the new key's complete TXT RRset.
2. Verify DNS before activating the LDAP key.
3. Deactivate older active keys of the same algorithm only after activation.
4. After `delete_delay`, revoke the inactive key and publish an empty-`p=`
   tombstone.
5. Retain the tombstone for `revoked_retention` before deleting DNS and LDAP
   state.
6. Apply `max_revoked` only in explicit legacy mode with
   `revoked_retention: 0`.

## CNAME Invariants

- Maintain three static slots per algorithm: newest active key, immediate
  inactive predecessor, and revoked tombstone.
- Require `--update-dns` for production `--auto` CNAME reconciliation.
- Prepare the destination DNS slot before LDAP rename.
- Order dependent renames without collisions.
- Resolve a rename cycle only through a temporary inactive-key name; fail
  closed for active-only cycles.
- Activate slot 1 before deactivating older keys and finalizing slot 3.
- Require exact allowlisting and LDH-compliant source and target names.

## Implementation Workflow

1. Add a focused regression test before behavior changes.
2. Review orchestration in `internal/app`, selector parsing in
   `internal/selector`, LDAP state in `internal/ldapstore`, and DNS behavior in
   `internal/dnsupdate` together.
3. Keep dry-run planning behaviorally equivalent while performing no writes.
4. Preserve exact-one-logical-TXT-RR verification and TXT-only RRset updates.
5. Update the normative specification when intended lifecycle behavior changes.
6. Run focused tests, then `GOEXPERIMENT=runtimesecret make guardrails`.
