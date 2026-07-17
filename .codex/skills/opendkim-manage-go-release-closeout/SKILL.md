---
name: opendkim-manage-go-release-closeout
description: Use for opendkim-manage-go validation, dependency and vendor closure, structured commits, features-to-main integration, GitHub Actions observation, release guardrails, tag or prerelease publication, release-note verification, GHCR image verification, and final clean-state reporting.
---

# OpenDKIM Manage Go Release Closeout

## Resolve Scope

Confirm whether the user requested validation, commit, push, main integration,
tagging, release publication, or release replacement. Do not widen mutation
scope implicitly.

## Preflight

1. Check `git status --short --branch`, the current branch, remotes, and recent
   commits.
2. Preserve unrelated changes and ignored artifacts.
3. Confirm all development commits were created on `features`.
4. Confirm `go.mod`, `go.sum`, and `vendor/` are synchronized.
5. Check public files and reachable history for secrets or private
   infrastructure details before first publication or a history rewrite.

## Validation Order

1. Run focused tests when useful.
2. Run `git diff --check` excluding untouched upstream whitespace under
   `vendor/` when necessary.
3. Run `actionlint .github/workflows/*` after CI changes.
4. Run `GOEXPERIMENT=runtimesecret make guardrails` before commits.
5. Run `GOEXPERIMENT=runtimesecret make release-guardrails` on the exact clean
   commit before pushing `main` or a `v*` tag.
6. Run `make image-smoke VERSION=<tag>` when container packaging changes.

Treat called vulnerabilities from `govulncheck`, stale vendor output, failed
race tests, workflow syntax errors, or dirty release checkouts as blockers.

## Commit Format

Use:

```text
Prefix: Concise headline

- Essential implementation detail
- Validation or generated-output detail
- Operator, packaging, dependency, or release impact
```

Allowed prefixes are `Add`, `Change`, `Fix`, `Remove`, `Refactor`, `Test`,
`Docs`, `Build`, `Ci`, `Vendor`, `Security`, and `Chore`. Split unrelated work.

## Publication Choreography

1. Commit and validate on `features`.
2. Push `features` and wait for Unit Tests, Guardrails, CodeQL, and development
   container builds.
3. Fast-forward `main` only after those gates pass.
4. Re-run release guardrails on the exact clean `main` commit.
5. Push `main` and wait for its Unit Tests, Guardrails, CodeQL, and
   `govulncheck` gate.
6. Create and push an annotated release tag.
7. Wait for release archives, checksums, attestations, structured release
   notes, and the multi-architecture GHCR image.
8. Verify the GitHub release is marked as a prerelease when the tag contains a
   prerelease component.
9. Return to `features` when requested by repository policy.

Never move or replace a published tag without explicit maintainer approval.

## Final Report

Report validation outcomes, commit hashes, pushed refs, release URL, artifact
names, workflow results, final branch, and worktree state. Name skipped checks
and their reasons.
