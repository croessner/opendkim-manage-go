---
name: opendkim-manage-go-config-security
description: Use for opendkim-manage-go configuration, LDAP transport or binding, DNS updates, TSIG, CNAME allowlists, secret handling, example configuration, logging, and public-repository leak reviews where strict validation and fail-closed behavior are required.
---

# OpenDKIM Manage Go Configuration Security

## Safety Model

- Require LDAPS or StartTLS with certificate verification by default.
- Permit insecure LDAP only through the explicit `allow_insecure` compatibility
  setting.
- Support SASL EXTERNAL only when the configured certificate identity is
  usable. Reject unsupported SASL modes without fallback.
- Require a complete TSIG key-name/key-file pair for DNS writes.
- Require a signed successful DNS response. Treat missing, unsigned, or
  error-RCODE responses as failures.
- Require every `destinationIndicator` to match the exact `dns.cnames`
  allowlist. An empty allowlist fails closed.

## Secret Boundaries

- Never print, log, commit, or place in metrics: LDAP passwords, private DKIM
  keys, TSIG material, tokens, client private keys, or partially expanded
  secret values.
- Keep private key material in memory only as long as required to persist it to
  LDAP.
- Treat config dumps, errors, dry-run output, tests, examples, and release
  archives as potential disclosure surfaces.
- Use only synthetic public examples such as `example.org`, `localhost`,
  loopback addresses, `o=company`, and unmistakable placeholder values.

## Change Workflow

1. Read `internal/config`, `internal/ldapstore`, `internal/dnsupdate`, and the
   relevant tests before changing behavior.
2. Add focused tests first for validation or security regressions.
3. Keep config validation typed, explicit, and deterministic.
4. Preserve dry-run as a no-write contract.
5. Search project-owned files and reachable Git history for environment-specific
   hosts, domains, IPs, paths, registries, credentials, and private-key markers
   before public release.
6. Run `GOEXPERIMENT=runtimesecret make guardrails` and, before publication,
   `GOEXPERIMENT=runtimesecret make release-guardrails`.
