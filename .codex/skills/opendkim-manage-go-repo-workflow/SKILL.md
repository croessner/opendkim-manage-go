---
name: opendkim-manage-go-repo-workflow
description: Use for any code, documentation, configuration, dependency, test, review, or maintenance task in the opendkim-manage-go repository that must follow AGENTS.md, POLICY.md, features-branch development, focused reproducer-first debugging, vendor-only builds, English technical documentation, restrictive security defaults, and Makefile-driven validation.
---

# OpenDKIM Manage Go Repository Workflow

## Core Workflow

1. Read `AGENTS.md`, `POLICY.md`, and task-relevant documents under `docs/`.
2. Check `git status --short --branch` before edits.
3. Preserve unrelated changes and ignored local artifacts.
4. Perform development and editing on `features`.
5. Prefer Makefile targets over ad hoc command variants.
6. Run every Go test with `GOEXPERIMENT=runtimesecret`.
7. Run focused checks while iterating and `make guardrails` before commit.

## Engineering Rules

- Start bug fixes with a focused failing reproducer when stable reproduction is
  practical. Keep useful tests as regression coverage.
- Encapsulate state in cohesive types with methods and narrow interfaces.
- Share selector, lifecycle, LDAP, DNS, config, and safety rules instead of
  duplicating them.
- Keep dependencies intentional. Prefer a clear standard-library or local
  implementation for small security-sensitive helpers.
- Keep Go 1.26 aligned across `go.mod`, Docker, CI, and docs.
- Run `go mod tidy` and `go mod vendor` after dependency changes.
- Build and test with `-mod=vendor`.

## Security and Documentation

- Fail closed on ambiguous selector, LDAP transport, DNS update, TSIG, and
  CNAME state.
- Never log or commit passwords, private keys, TSIG material, tokens, internal
  infrastructure identifiers, or environment-specific credentials.
- Keep public examples synthetic with `example.*`, loopback addresses, and
  obvious placeholder credentials.
- Write comments and technical documentation in English.
- Put formal behavioral specifications under `docs/specs/`.
- Keep durable docs vendor-neutral unless a named system is an actual protocol
  or runtime dependency.

## Closeout

- Run `git diff --check` for project-owned files.
- Run `actionlint .github/workflows/*` after workflow changes.
- Run `GOEXPERIMENT=runtimesecret make guardrails` before commit or pull
  request.
- Use `opendkim-manage-go-release-closeout` for commit, push, merge, tag, or
  release-sensitive publication.
