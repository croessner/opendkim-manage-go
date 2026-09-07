# September 2026 maintenance assessment

Assessment date: 2026-09-07. Base revision: `5e6705c` (`v1.0.0-beta.9`).
The imported scanner snapshot was treated as an untrusted claim set. Its raw
original report was unavailable; a fresh Trivy 0.74.0 filesystem scan reproduced
all nine security entries. This assessment is scoped to those entries and the
reported GitHub coverage gap, not an exhaustive security audit or deployment proof.

## Findings

| Finding | Disposition | Evidence and next action |
| --- | --- | --- |
| CVE-2026-56854 (critical in export) | Not applicable to current product | [GO-2026-6303](https://pkg.go.dev/vuln/GO-2026-6303) affects `x/crypto/ssh.NewServerConn`. Only `x/crypto/md4` is vendored; no SSH package is shipped. |
| CVE-2026-56864 (high) | Not applicable to current product | [GO-2026-6180](https://pkg.go.dev/vuln/GO-2026-6180) affects `x/mod/sumdb.Client.Lookup`. Only `x/mod/semver` is vendored. The separate toolchain fix is already present in Go 1.26.6. |
| CVE-2026-56865 (high) | Not applicable to current product | [GO-2026-6179](https://pkg.go.dev/vuln/GO-2026-6179) affects `x/mod/sumdb/tlog`; that package is absent. Go 1.26.6 already contains the toolchain fix. |
| DS-0002, vendored TOML Dockerfile (high) | Not applicable to product image | [Rule](https://avd.aquasec.com/misconfig/dockerfile/general/ds-0002/). The upstream utility Dockerfile has no non-root user, but Makefile and container workflows select the root Dockerfile. Its final stage uses `USER 65532:65532`. |
| Go toolchain patch behind current (medium) | Updated | Pin Go 1.26.8 in `go.mod`, Dockerfile and every setup-go job. [Release history](https://go.dev/doc/devel/release#go1.26.8) confirms this supported patch; AGENTS.md and POLICY.md require the 1.26 series. |
| CVE-2026-56855 (medium) | Not applicable to current product | [GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355) affects SSH channel processing; the package is absent. |
| CVE-2026-78662 (medium) | Not applicable to current product | [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) affects SSH channel processing; the package is absent. |
| GO-2026-5932 (medium) | Not applicable to current product | [Advisory](https://pkg.go.dev/vuln/GO-2026-5932) concerns unmaintained OpenPGP packages; none are vendored or imported. No fixed module version exists for this advisory. |
| Raise Go baseline to 1.27 (low) | Not applicable as a required fix | Go 1.26 remains supported. Keep `go 1.26`; a major-version migration requires a separate policy change and compatibility assessment. |
| DS-0026, root Dockerfile (low) | Not applicable to CLI lifecycle | [Rule](https://avd.aquasec.com/misconfig/dockerfile/general/ds-0026/). This executable performs an operation and exits. Monitor invocation exit status and results; a periodic container service healthcheck does not establish operation success. |
| DS-0026, vendored TOML Dockerfile (low) | Not applicable to product image | The upstream utility image is not built or shipped by this project's packaging. |

The module-version warnings remain reproducible. No dependency version was
changed merely to suppress findings about absent packages, and no scanner
ignore was added. Reassess these decisions whenever imports or packaging change.
`vendor/modules.txt` records only `x/crypto/md4` and `x/mod/semver`; the latter
comes from the DNS dependency's Go tooling. The sumdb advisories do not prove
historical module-cache integrity; that was not forensically assessed here.

## Local validation

- `GOTOOLCHAIN=go1.26.8 GOEXPERIMENT=runtimesecret make release-guardrails`
  passed with writable temporary build/lint caches: formatting, tidy diff,
  regenerated-vendor comparison, vet, lint, unit tests, race tests, build and
  govulncheck. No dependency content or checksum update was needed.
- Govulncheck on both Go 1.26.6 and Go 1.26.8 reported zero affected symbols
  and zero affected imported packages, with four module-only crypto advisories.
  The sumdb disposition additionally uses the vendored-package evidence above.
- `actionlint .github/workflows/*` and `git diff --check` passed.
- `make image-smoke IMAGE=opendkim-manage-maint:local VERSION=dev` passed:
  local Linux AMD64 build, version/help output, non-root user, entrypoint and
  absence of a shell. ARM64 and deployment behavior were not tested.
- A separate read-only candidate review found no concrete bypass or regression.

No application behavior changed, so existing tests were used without adding
artificial CVE reproducers for absent packages. These results validate the local
working tree; they are not the required clean-commit publication gate.

## Coverage gaps and release readiness

GitHub code-scanning access succeeded. Its open alert #1,
`go/disabled-certificate-check` in `internal/ldapstore/client.go`, describes the
documented explicit legacy exception: `config.Load` calls `Validate`, which
rejects `reqcert: never`, `allow`, and `try` unless `allow_insecure` is true.
The default empty/`demand` path verifies certificates. No supported attacker
path bypassing that guard was established; the alert was not dismissed remotely.

Dependabot alerts are disabled (HTTP 403), so that source is unavailable rather
than clean. The repository-advisory endpoint returned an empty visible list;
this does not prove access to every private report. Open issues were empty.
Existing main workflows succeeded for the base revision, not for this patch.

The latest published prerelease was independently verified as `v1.0.0-beta.9`.
A suitable next prerelease after validation and integration is
`v1.0.0-beta.10`; there is no evidence here to justify promotion to stable or RC.
Publication still requires an exact clean committed revision, branch CI,
release guardrails on that revision, required publication scans, and explicit
authorization. Release artifacts, provenance, checksums, multi-architecture
images and live runtime behavior must be verified during a separately authorized
release. Nothing in this assessment authorizes deployment or publication.
