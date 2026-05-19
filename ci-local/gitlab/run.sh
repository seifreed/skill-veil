#!/usr/bin/env bash
# Run the local GitLab pipeline. Prefers `gitlab-ci-local` (the de-facto
# faithful local executor of .gitlab-ci.yml — GitLab Runner removed
# `exec` in 16.x). Falls back to a docker-run of each job in its declared
# `image:` when gitlab-ci-local is not installed (zero extra host deps).
#
# The docker-run fallback uses the example corpus baked into the image
# from the git-tracked tree (= a CI checkout) and writes artifacts to a
# container-only path, so it never touches or pollutes the host repo.
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO="$PWD"
IMG="${SV_IMAGE:-skill-veil-ci:local}"
ART=/tmp/sv-artifacts

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo ">> building $IMG (one-time)…"
  docker build -f ci-local/Dockerfile -t "$IMG" .
fi

run_gcl() {
  echo ">> engine: gitlab-ci-local"
  # gitlab-ci-local writes artifacts/ + .gitlab-ci-local/ into cwd; drop
  # them so the harness never dirties the host working tree.
  trap 'rm -rf "$REPO/artifacts" "$REPO/.gitlab-ci-local"' RETURN
  "$@" --file ci-local/gitlab/.gitlab-ci.yml --cwd . --variable "SV_IMAGE=$IMG"
}

if command -v gitlab-ci-local >/dev/null 2>&1; then
  run_gcl gitlab-ci-local; exit $?
elif command -v npx >/dev/null 2>&1; then
  run_gcl npx --yes gitlab-ci-local; exit $?
fi

echo ">> engine: docker-run fallback (no gitlab-ci-local on host)"
echo ">> each job runs in its declared image, in order, like a GitLab runner"
JOB_PRE="mkdir -p $ART; SV=skill-veil; \$SV --version | head -1"

echo; echo "### job: skill_veil_gate (must pass)"
docker run --rm "$IMG" bash -lc "
set -euo pipefail; $JOB_PRE
\$SV scan-package examples/safe-skill --preset ci --no-update-check --format json --output $ART/current.json
\$SV scan-package examples/safe-skill --no-update-check --format sarif --output $ART/current.sarif
\$SV baseline create $ART/current.json --output $ART/baseline.json
\$SV diff $ART/current.json $ART/current.json --baseline $ART/baseline.json --ci-summary --fail-on new-active
"
echo "PASS: skill_veil_gate"

echo; echo "### job: legacy_diff_flag_rejected (allow_failure: demonstrates the examples/ci bug)"
rc=0
docker run --rm "$IMG" bash -lc "
set -euo pipefail; $JOB_PRE
\$SV scan-package examples/safe-skill --preset ci --no-update-check --format json --output $ART/current.json
\$SV baseline create $ART/current.json --output $ART/baseline.json
echo 'Running the flag exactly as examples/ci/gitlab-ci.yml ships it...'
\$SV diff $ART/current.json $ART/current.json --baseline $ART/baseline.json --ci-summary --fail-on-new-active
" || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "EXPECTED-FAIL (rc=$rc): legacy '--fail-on-new-active' form correctly rejected by the CLI."
else
  echo "WARNING: legacy flag form was accepted — the contract pinned by"
  echo "  diff_fail_on_accepts_value_form_and_rejects_flag_suffix_form is broken."
  exit 1
fi
echo; echo "GitLab pipeline OK (gate green; legacy-form rejection re-verified)."
