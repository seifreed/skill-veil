#!/usr/bin/env bash
# Run the workflow with `act` — the real GitHub Actions local runner. act
# itself spins the job inside a Docker runner via the host docker socket,
# so this IS the dockerised GitHub environment. act is fetched (no sudo)
# into ci-local/.bin if not already on PATH.
#
# ubuntu-latest is mapped to the prebuilt skill-veil-ci:local image so the
# binary + example corpus are present (no qemu cargo build). Pinning the
# image via -P also stops act's first-run interactive image prompt.
set -euo pipefail
cd "$(dirname "$0")/../.."
IMG="${SV_IMAGE:-skill-veil-ci:local}"
BIN_DIR="ci-local/.bin"
mkdir -p "$BIN_DIR"

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo ">> building $IMG (one-time)…"
  docker build -f ci-local/Dockerfile -t "$IMG" .
fi

if command -v act >/dev/null 2>&1; then
  ACT="act"
elif [ -x "$BIN_DIR/act" ]; then
  ACT="$BIN_DIR/act"
else
  echo ">> fetching act into $BIN_DIR (one-time)…"
  curl -fsSL https://raw.githubusercontent.com/nektos/act/master/install.sh \
    | bash -s -- -b "$BIN_DIR"
  ACT="$BIN_DIR/act"
fi

"$ACT" --version
exec "$ACT" push \
  -W ci-local/github/workflow.yml \
  -P ubuntu-latest="$IMG" \
  --pull=false \
  "$@"
