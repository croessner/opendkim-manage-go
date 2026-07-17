# opendkim-manage-go Development Guidelines

This repository is a security-sensitive Go 1.26 project for DKIM key lifecycle
management across LDAP and DNS. Keep `go.mod`, Docker builds, GitHub Actions,
vendored dependencies, and technical documentation aligned with Go 1.26.

## Required Workflow

- Read `POLICY.md` and the task-relevant documents under `docs/` before making
  changes.
- Check `git status --short --branch` before edits and preserve unrelated user
  changes and ignored local artifacts.
- Perform all development and editing on `features`. Use `main` only for
  release integration after the exact commit has been validated.
- Prefer Makefile targets over ad hoc command variants.
- Run every Go test command with `GOEXPERIMENT=runtimesecret`.
- Use focused unit-test-first development for core and lifecycle behavior when
  practical. For bugs, add a failing reproducer before changing production
  code and retain stable reproducers as regression tests.
- Determine whether a failing test exposes a production defect before changing
  the test.
- Run `GOEXPERIMENT=runtimesecret make guardrails` before every commit or pull
  request.
- Run `GOEXPERIMENT=runtimesecret make release-guardrails` on the exact clean
  commit before pushing `main` or a `v*` tag.

## Design and Dependency Rules

- Apply security-by-design and security-by-default. Ambiguous selector,
  transport, authentication, DNS, or lifecycle state must fail closed.
- Encapsulate state in cohesive Go types, expose behavior through methods and
  narrow interfaces, and prefer composition over package-level mutable state.
- Apply DRY intentionally. Selector parsing, lifecycle decisions, LDAP rules,
  DNS update behavior, config validation, and safety checks must each have one
  authoritative implementation.
- Keep dependencies intentional. Prefer the standard library or a small local
  implementation for simple security-sensitive behavior. Add a dependency only
  when it clearly reduces risk, complexity, or maintenance cost.
- Build and test with vendored dependencies. After dependency changes, run
  `go mod tidy` and `go mod vendor` and verify `vendor/modules.txt`.
- Keep the public module path and internal imports rooted at
  `github.com/croessner/opendkim-manage-go`.

## Security Boundaries

- Require LDAPS or StartTLS with certificate verification by default.
- Allow insecure LDAP only through the explicit compatibility setting.
- Require complete TSIG configuration and a signed successful response for DNS
  writes.
- Require exact CNAME destination allowlisting and LDH-compliant names.
- Preserve dry-run as a strict no-write mode while simulating planned state
  transitions in memory.
- Never log, print, commit, package, or expose passwords, private DKIM keys,
  TSIG material, client private keys, tokens, or partially expanded secrets.
- Never commit environment-specific infrastructure details such as internal
  domains, hosts, addresses, registries, filesystem paths, or service names.
- Keep public examples synthetic with `example.*`, loopback addresses,
  `o=company`, and unmistakable placeholder credentials.
- Before public publication, scan both the current tree and reachable Git
  history for secrets and environment-specific infrastructure identifiers.

## Version and Packaging Contract

- Keep `var version = "dev"` in the main package as the single source default.
- Inject packaged versions with `-X main.version=...` in Makefile, Docker, and
  release builds.
- Use the `scratch` runtime image, a non-root user, and vendor-only compilation.
- Keep container labels, source URLs, license identifiers, and embedded version
  values consistent.
- Publish Linux AMD64 and ARM64 release archives with checksums and build
  provenance, plus a multi-architecture GHCR image.

## Comments and Documentation

- Write code comments and technical documentation in English.
- Give new or changed hand-written named functions and receiver methods concise
  English comments that explain responsibility, invariants, side effects, or
  non-obvious behavior.
- Keep durable documentation under `docs/` and formal behavioral specifications
  under `docs/specs/`.
- Keep product and architecture documentation vendor-neutral unless a named
  system is an actual dependency or protocol peer.
- Keep local plans, prompts, handoffs, and scratch artifacts out of the
  repository.

## Commit Log Format

Use structured commit messages:

```text
Prefix: Concise headline

- Detail the essential implementation work
- Mention tests, guardrails, or generated files
- Call out operator, packaging, dependency, or release impact
```

Allowed prefixes:

- `Add`
- `Change`
- `Fix`
- `Remove`
- `Refactor`
- `Test`
- `Docs`
- `Build`
- `Ci`
- `Vendor`
- `Security`
- `Chore`

The release workflow uses these prefixes as its authoritative release-note
categories. Split unrelated changes into separate commits.

## Quality Gates

`make guardrails` verifies:

- Go formatting
- module tidiness
- vendor consistency
- `go vet`
- `golangci-lint`
- unit tests
- race tests
- compile-only build

`make release-guardrails` adds `govulncheck`. Use `make image-smoke` after
container changes and `actionlint .github/workflows/*` after workflow changes.
