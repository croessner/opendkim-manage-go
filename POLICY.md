# Engineering Policy

These rules are mandatory for every code, documentation, dependency,
configuration, packaging, and release change.

## Must Rules

- MUST: Keep the project on Go 1.26 across module metadata, CI, Docker builds,
  vendored dependencies, and documentation.
- MUST: Keep the module path and internal imports rooted at
  `github.com/croessner/opendkim-manage-go`.
- MUST: Apply security-by-design and security-by-default. Ambiguous selector,
  LDAP, DNS, TSIG, CNAME, or lifecycle state must fail closed.
- MUST: Use cohesive Go types, methods, narrow interfaces, and composition to
  encapsulate domain state and side effects.
- MUST: Apply DRY intentionally. Shared lifecycle, selector, config, LDAP, DNS,
  and security rules must not be duplicated.
- MUST: Keep dependencies intentional and minimal. Prefer clear local code for
  small helpers when a dependency would increase risk or maintenance cost.
- MUST: Build and test with `-mod=vendor` and keep `go.mod`, `go.sum`, and
  `vendor/` synchronized after dependency changes.
- MUST: Perform development and editing on `features`. Integrate into `main`
  only after the exact commit has passed local and GitHub validation.
- MUST: Run every Go test command with `GOEXPERIMENT=runtimesecret`.
- MUST: Prefer unit-test-first development for core and lifecycle behavior.
- MUST: Add a focused failing reproducer before bug fixes when stable
  reproduction is practical, and keep useful reproducers as regression tests.
- MUST: Determine whether production behavior or test logic is wrong before
  changing a failing test.
- MUST: Require LDAPS or StartTLS with certificate verification by default.
- MUST: Make insecure LDAP an explicit compatibility exception.
- MUST: Support SASL EXTERNAL only under its strict certificate-based contract
  and reject unsupported mechanisms without fallback.
- MUST: Require complete TSIG configuration and a signed successful DNS
  response for DNS writes.
- MUST: Replace only the target TXT RRset and preserve unrelated RR types.
- MUST: Require exact CNAME destination allowlisting and LDH-compliant names.
- MUST: Keep `--dry-run` free of LDAP and DNS writes while maintaining an
  accurate in-memory plan for subsequent lifecycle steps.
- MUST: Never log, print, commit, package, or expose LDAP passwords, DKIM
  private keys, TSIG secrets, TLS private keys, tokens, or partially expanded
  secret values.
- MUST: Never publish environment-specific infrastructure identifiers,
  including internal domains, hosts, addresses, registries, filesystem paths,
  or service inventory names.
- MUST: Keep public examples synthetic and obviously non-production.
- MUST: Scan the current tree and reachable Git history for secrets and private
  infrastructure details before first public publication or history-sensitive
  release replacement.
- MUST: Keep `var version = "dev"` as the source default and inject release
  versions only through `-X main.version=...`.
- MUST: Keep `.golangci.yml`, Makefile validation, CI, and Docker packaging
  aligned.
- MUST: Run `make guardrails` before every commit or pull request.
- MUST: Run `make release-guardrails` on the exact clean commit before pushing
  `main` or any `v*` tag.
- MUST: Treat called vulnerabilities reported by `govulncheck` as release
  blockers unless the maintainer records an explicit exception.
- MUST: Publish release-sensitive refs only from a clean checkout whose `HEAD`
  is the exact validated commit.
- MUST: Write code comments and technical documentation in English.
- MUST: Give new or changed hand-written named functions and receiver methods
  concise English comments describing intent or non-obvious behavior.
- MUST: Keep durable docs under `docs/` and formal behavioral specifications
  under `docs/specs/`.
- MUST: Keep product and architecture docs vendor-neutral unless naming an
  actual dependency or protocol peer.
- MUST: Write commit subjects as `Prefix: Concise headline` using only `Add`,
  `Change`, `Fix`, `Remove`, `Refactor`, `Test`, `Docs`, `Build`, `Ci`,
  `Vendor`, `Security`, or `Chore`.
- MUST: Use a concise bullet-list commit body for non-trivial changes.
- MUST: Split unrelated work into separate commits.
- MUST: Use the approved commit prefixes as release-note categories.
- MUST: Publish prerelease tags as GitHub prereleases, not as the latest stable
  release.
- MUST: Never move or replace a published tag without explicit maintainer
  authorization.

## Definition of Done

- [ ] Work was performed on `features`.
- [ ] Focused tests were added or updated where behavior changed.
- [ ] Bug fixes started with a reproducer when practical.
- [ ] DRY and responsibility boundaries were reviewed.
- [ ] Security defaults remain restrictive and fail closed.
- [ ] Secret-bearing values cannot reach logs, output, examples, release
      archives, or metrics.
- [ ] Public files and reachable history contain no private infrastructure
      identifiers or credentials.
- [ ] `go.mod`, `go.sum`, and `vendor/` are synchronized.
- [ ] Comments and technical docs changed by the work are English-only.
- [ ] Durable docs and formal specifications are in the correct paths.
- [ ] `GOEXPERIMENT=runtimesecret make guardrails` passes.
- [ ] `actionlint` passes when workflows changed.
- [ ] `make image-smoke` passes when container packaging changed.
- [ ] `GOEXPERIMENT=runtimesecret make release-guardrails` passes before
      publishing `main` or a version tag.
- [ ] Commit messages use an approved prefix and bullet-list body.
- [ ] GitHub branch and release workflows complete successfully.
- [ ] Release notes group commits by the approved prefixes.
- [ ] Release archives, checksums, attestations, and GHCR image are present.
- [ ] Final branch and worktree state are reported.
