# Retention with preserved legacy generations

Automatic retention intentionally preserves legacy snapshots. Previously,
removing the first eligible v3 generation left a gap after its retained v2
predecessor, and the following inventory or history read rejected that valid
state. Application mutation preflight repeated the same overly broad numeric
contiguity requirement.

The store and application now share one schema-aware root-sequence validator.
An unchanged contiguous legacy prefix and a contiguous v3 suffix may be
separated by the retention gap. No other hole is accepted. The history DTO
retains the already validated wire schema; missing or unknown schema facts
cannot stand in for a legacy anchor. Current, immediate-successor, source,
commitment, rollback, and purge-journal contracts are unchanged.

The focused reproducer failed after the first actual fake-repository v3
deletion while its complete v2 predecessor remained. Regression coverage keeps
all legacy entry bytes and metadata unchanged across repeated native purges,
then loads current/history and stages and activates the exact successor.
Negative cases cover schema ambiguity, internal gaps, duplicates, current
drift before and during deletion, changed operation/source/digest/state,
malformed partial remainders, and extra candidates. Existing retention-count,
rollback-reserve, journal, and dry-run tests remain required.

The accompanying synthetic OpenLDAP ACL example grants only `=z` on structural
`entry` and `children` pseudo-attributes. It does not grant attribute updates,
adds, or private-key visibility. The real isolated LDAP test uses the existing
authority-bound clients, deletes one leaf, interrupts before the next request,
reconnects with the same bound journal, and completes root-last. It verifies
current protection even when current has an activation marker, and separately
tests staging, never-active, legacy, missing-current, invalid current schema
and state, foreign subtree, and other-role fall-through.

The ACL fragment must be placed before overlapping deny rules. Its exact
identity and directory base are examples, not deployment configuration. The
server's structural permission is only one authorization layer; the manager
retains all full-data and lifecycle checks. In particular, an operator must
not repair a blocked retention run by widening general LDAP write privileges,
discarding the existing purge journal, removing protected legacy roots, or
loosening read and retention limits.

Required qualification is `GOEXPERIMENT=runtimesecret make guardrails` with
`OPENDKIM_MANAGE_REQUIRE_SLAPD=1`, followed by `make govulncheck` before release.
Source fingerprints, binary build information, and gate logs are recorded
separately for each frozen build. These tests do not claim a production ACL
change, successful live purge, DNS update, or runtime rollout.

OpenLDAP documents the separate add/delete privileges and ordered ACL control
in [slapd.access(5)](https://www.openldap.org/software/man.cgi?query=slapd.access&sektion=5).
The set predicates use the conjunctions documented by the
[OpenLDAP set syntax reference](https://www.openldap.org/faq/data/cache/1133.html).
