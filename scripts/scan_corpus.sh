#!/usr/bin/env bash
# scan_corpus.sh — re-scan the VT corpora with the release binary and the
# official rule pack (auto-loaded from ./rules/official/), then rebuild the
# per-skill JSONL and aggregate summary.
#
# Each `scan-dataset` run is internally multithreaded (rayon par_iter over
# package roots), so it already saturates every core. The corpora are scanned
# sequentially because running them concurrently would only oversubscribe the
# same CPU pool; total wall-clock is the sum of three already-parallel scans.
#
# Usage:
#   bash scripts/scan_corpus.sh
#   CORPORA="benign malicious" bash scripts/scan_corpus.sh
#   SVBIN=target/debug/skill-veil bash scripts/scan_corpus.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SVBIN="${SVBIN:-target/release/skill-veil}"
CORPUS_ROOT="${CORPUS_ROOT:-data/vt-corpus}"
RESULTS_DIR="${RESULTS_DIR:-$CORPUS_ROOT/scan-results}"
CORPORA="${CORPORA:-malicious benign github}"

if [ ! -x "$SVBIN" ]; then
  echo "error: scanner binary not found at $SVBIN (run: cargo build --release -p skill-veil-cli)" >&2
  exit 1
fi

mkdir -p "$RESULTS_DIR"
rm -f "$RESULTS_DIR/summary.json"

for corpus in $CORPORA; do
  src="$CORPUS_ROOT/$corpus"
  if [ ! -d "$src" ]; then
    echo "skip: $src does not exist" >&2
    continue
  fi
  echo "=== scanning $corpus ($(date -u +%H:%M:%S)) ===" >&2
  rm -f "$RESULTS_DIR/$corpus.raw.json"
  "$SVBIN" scan-dataset "$src" \
    --quiet \
    --format json \
    --no-vt-enrich --no-llm-enrich --no-promptintel-enrich \
    --no-update-check --no-nova \
    --output "$RESULTS_DIR/$corpus.raw.json"
  echo "    wrote $RESULTS_DIR/$corpus.raw.json ($(date -u +%H:%M:%S))" >&2
done

GEN_UTC="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
python3 scripts/corpus_summary.py \
  --results-dir "$RESULTS_DIR" \
  --corpora $CORPORA \
  --generated-utc "$GEN_UTC"

echo "=== done; summary at $RESULTS_DIR/summary.json ===" >&2
