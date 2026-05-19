#!/usr/bin/env bash
# CI-agnostic deployment + detection gate. This is the "truth" test every
# CI flavour (GitHub/GitLab/Bitbucket/Jenkins) ultimately reduces to:
# does the deployed binary detect known-malicious input and stay quiet on
# known-benign input, fully offline, with the right exit codes and clean
# machine output.
#
# Hard gates are deterministic (pinned examples/fixtures). The labelled
# corpus is reported but NOT gated here — the Rust test
# `labeled_corpus_meets_phase1_baseline` owns that statistical contract.
#
# Env:
#   SKILL_VEIL_BIN          path to a prebuilt binary (default in Docker)
#   SKILL_VEIL_ONLINE_INIT  =1 to also exercise the signed-pack download
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=ci-local/lib.sh
source ci-local/lib.sh

echo "=== skill-veil CI harness — deployment + detection ==="
resolve_bin
sv --version | head -1 || true
# Air-gapped HOME so no cached rule pack / config leaks into the offline gate.
export HOME; HOME="$(mktemp -d)"

echo
echo "--- Gate 1: malicious detection (must verdict=malicious, exit 1 @ --fail-on medium) ---"
assert_scan "mal/approval-bypass-exec" scan-package \
  benchmarks/fixtures/malicious/approval-bypass-exec malicious 1 --fail-on medium
assert_scan "mal/token-exfiltration" scan-package \
  benchmarks/fixtures/malicious/token-exfiltration malicious 1 --fail-on medium
assert_scan "examples/malicious-skill SKILL.md" scan-file \
  examples/malicious-skill/SKILL.md malicious 1 --fail-on medium

echo
echo "--- Gate 2: benign stays clean (verdict=benign, exit 0 even @ --fail-on medium) ---"
assert_scan "examples/safe-skill" scan-package \
  examples/safe-skill benign 0 --fail-on medium
assert_scan "fixtures/benign/agent-guidelines" scan-package \
  benchmarks/fixtures/benign/agent-guidelines benign 0 --fail-on medium

echo
echo "--- Gate 3: SARIF 2.1.0 is well-formed with results (GitHub/GitLab ingest) ---"
assert_sarif "sarif/malicious" scan-package \
  benchmarks/fixtures/malicious/approval-bypass-exec

echo
echo "--- Gate 4: machine output purity (--output file must be pure JSON) ---"
purej="$(mktemp)"
sv scan-package benchmarks/fixtures/malicious/approval-bypass-exec \
  --no-update-check --format json --output "$purej" >/dev/null 2>&1 || true
if jq -e 'type=="array"' "$purej" >/dev/null 2>&1; then
  record 1 "json file via --output parses cleanly (no tracing-log contamination)"
else
  record 0 "json file via --output parses cleanly (no tracing-log contamination)"
fi
rm -f "$purej"

echo
echo "--- Soft report: labelled corpus (informational, NOT a gate) ---"
for label in malicious suspicious benign; do
  total=0; hit=0
  for d in benchmarks/fixtures/"$label"/*/; do
    [ -d "$d" ] || continue
    total=$((total + 1))
    o="$(mktemp)"
    sv scan-package "$d" --no-update-check --no-vt-enrich --no-llm-enrich \
       --no-promptintel-enrich --format json --output "$o" >/dev/null 2>&1 || true
    v="$(jq -r '.[0].verdict // "?"' "$o" 2>/dev/null || echo '?')"
    [ "$v" = "$label" ] && hit=$((hit + 1))
    rm -f "$o"
  done
  printf '  %-10s %d/%d match dir label\n' "$label" "$hit" "$total"
done

if [ "${SKILL_VEIL_ONLINE_INIT:-0}" = "1" ]; then
  echo
  echo "--- Optional: online signed-pack init (needs network; tolerated to fail) ---"
  CACHE_DIR="$(mktemp -d)/sv-cache"
  init_rc=0
  sv init --cache-dir "$CACHE_DIR" 2>&1 | tail -8 || init_rc=$?
  if [ "$init_rc" -eq 0 ]; then
    sv rules status --cache-dir "$CACHE_DIR" 2>&1 | tail -5 || true
    if [ -d "$CACHE_DIR/rules" ]; then
      echo "  installed under $CACHE_DIR:"
      find "$CACHE_DIR/rules" -maxdepth 4 -type f | head -10 | sed 's/^/    /'
    fi
    name="post-init re-scan with external pack"
    out="$(mktemp)"; rc=0
    sv scan-package benchmarks/fixtures/malicious/token-exfiltration \
       --cache-dir "$CACHE_DIR" --no-vt-enrich --no-llm-enrich \
       --no-promptintel-enrich --format json --output "$out" \
       --fail-on medium >/dev/null 2>&1 || rc=$?
    got="$(jq -r '.[0].verdict // "?"' "$out" 2>/dev/null || echo '?')"
    [ "$got" = "malicious" ] && [ "$rc" = 1 ] && record 1 "$name (verdict=$got exit=$rc)" \
      || record 0 "$name (verdict=$got exit=$rc want=malicious/1)"
    rm -f "$out"
  else
    echo "  $(_c y)SKIP$(_c 0) init failed rc=$init_rc (offline or upstream unavailable) — embedded baseline still gated above"
  fi
fi

summary
