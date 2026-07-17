#!/usr/bin/env bash
set -euo pipefail

image="${1:-ghcr.io/croessner/opendkim-manage-go:dev}"
expected_version="${2:-dev}"
docker_bin="${DOCKER:-docker}"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

command -v "${docker_bin}" >/dev/null 2>&1 || fail "docker CLI is required"
[[ -f Dockerfile ]] || fail "run from repository root"

"${docker_bin}" build \
  --build-arg VERSION="${expected_version}" \
  -t "${image}" \
  -f Dockerfile \
  .

version="$("${docker_bin}" run --rm "${image}" --version)"
[[ "${version}" == "Version ${expected_version}" ]] || fail "unexpected version output: ${version}"

help_output="$("${docker_bin}" run --rm "${image}" --help 2>&1)"
[[ "${help_output}" == *"--dry-run"* ]] || fail "help output missing --dry-run"
[[ "${help_output}" == *"--yes"* ]] || fail "help output missing --yes"

user="$("${docker_bin}" image inspect -f '{{.Config.User}}' "${image}")"
[[ "${user}" == "65532:65532" ]] || fail "image must run as non-root 65532:65532, got ${user}"

entrypoint="$("${docker_bin}" image inspect -f '{{json .Config.Entrypoint}}' "${image}")"
[[ "${entrypoint}" == '["/usr/local/bin/opendkim-manage"]' ]] || fail "unexpected entrypoint: ${entrypoint}"

if "${docker_bin}" run --rm --entrypoint /bin/sh "${image}" -c true >/dev/null 2>&1; then
  fail "runtime image unexpectedly contains /bin/sh"
fi

printf 'container contract ok: %s\n' "${image}"
