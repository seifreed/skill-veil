#!/usr/bin/env bash
# fp_triage.sh — for each "malicious-per-skill-veil" SHA from
# results-clean.json, run skill-veil scan-package with each LLM
# provider and append a JSONL line with {sha, provider, verdict,
# confidence, agreement} to fp-triage.jsonl. Idempotent: SHAs already
# in the JSONL for a given (sha, provider) pair are skipped.
#
# macOS-friendly (bash 3.2: no `mapfile`, no `declare -A`).
#
# Usage:
#   bash scripts/fp_triage.sh                # sequential per pair
#   N=4 bash scripts/fp_triage.sh            # 4 pairs in flight via xargs
#   PROVIDERS="openai grok" N=2 bash scripts/fp_triage.sh

set -u

JSONL="${JSONL:-fp-triage.jsonl}"
RESULTS_JSON="${RESULTS_JSON:-results-clean.json}"
EXTRACTED_BASE="${EXTRACTED_BASE:-data-clean/.skill-veil-cache/extracted}"
PROVIDERS="${PROVIDERS:-openai grok ollama-cloud}"
N="${N:-1}"
SVBIN="${SVBIN:-target/release/skill-veil}"

triage_one() {
  local sha="$1"
  local provider="$2"
  local extracted="$EXTRACTED_BASE/$sha"
  if [ ! -d "$extracted" ]; then
    jq -cn --arg sha "$sha" --arg provider "$provider" \
      '{sha:$sha, provider:$provider, verdict:"missing", error:"no extracted dir"}' >> "$JSONL"
    return
  fi
  local out
  out=$("$SVBIN" scan-package "$extracted" \
    --llm-provider "$provider" --no-vt-enrich --no-promptintel-enrich \
    --no-update-check --no-nova --quiet --quiet-summary 2>&1) || true
  local verdict_line
  verdict_line=$(printf '%s\n' "$out" | grep -m1 'llm verdict' || true)
  if [ -z "$verdict_line" ]; then
    local err
    err=$(printf '%s\n' "$out" | grep -iE "error|fail|skipped|not configured" | head -3 | tr -d '\n' | head -c 400)
    jq -cn --arg sha "$sha" --arg provider "$provider" --arg err "$err" \
      '{sha:$sha, provider:$provider, verdict:"error", error:$err}' >> "$JSONL"
    return
  fi
  local verdict confidence agreement
  verdict=$(printf '%s' "$verdict_line" | awk -F': ' '{print $2}' | awk '{print $1}')
  confidence=$(printf '%s' "$verdict_line" | grep -oE 'confidence [0-9.]+' | awk '{print $2}')
  agreement=$(printf '%s' "$verdict_line" | grep -oE 'agreement=[a-z]+' | cut -d= -f2)
  jq -cn --arg sha "$sha" --arg provider "$provider" \
    --arg verdict "$verdict" --arg confidence "$confidence" \
    --arg agreement "$agreement" \
    '{sha:$sha, provider:$provider, verdict:$verdict,
      confidence:(if $confidence == "" then null else ($confidence|tonumber?) end),
      agreement:(if $agreement == "" then null else $agreement end)}' >> "$JSONL"
}

export -f triage_one
export EXTRACTED_BASE SVBIN JSONL

# Build the candidate (sha, provider) list and the already-done list,
# then subtract via `comm`. All sets are sorted byte-wise so `comm -13`
# (lines unique to the right side) yields the pending pairs.
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
ALL_PAIRS="$TMP_DIR/all"
DONE_PAIRS="$TMP_DIR/done"
PENDING_PAIRS="$TMP_DIR/pending"

jq -r '.verdicts[] | select(.final_verdict == "malicious") | .package_id' "$RESULTS_JSON" \
  | while IFS= read -r sha; do
      for provider in $PROVIDERS; do
        printf '%s\t%s\n' "$sha" "$provider"
      done
    done | sort -u > "$ALL_PAIRS"

if [ -s "$JSONL" ]; then
  jq -r 'select(.sha != null and .provider != null) | "\(.sha)\t\(.provider)"' "$JSONL" \
    | sort -u > "$DONE_PAIRS"
else
  : > "$DONE_PAIRS"
fi

comm -23 "$ALL_PAIRS" "$DONE_PAIRS" > "$PENDING_PAIRS"

TOTAL=$(wc -l < "$ALL_PAIRS" | tr -d ' ')
DONE_COUNT=$(wc -l < "$DONE_PAIRS" | tr -d ' ')
PENDING=$(wc -l < "$PENDING_PAIRS" | tr -d ' ')
echo "[fp-triage] total pairs: $TOTAL  done: $DONE_COUNT  pending: $PENDING  parallel: N=$N"

if [ "$PENDING" -eq 0 ]; then
  echo "[fp-triage] nothing to do; all (sha,provider) pairs already in $JSONL"
  exit 0
fi

: > "$JSONL.tmp_touch"; rm "$JSONL.tmp_touch" 2>/dev/null || true  # ensure $JSONL is writable
START_TS=$(date +%s)
# macOS `xargs` lacks `-a`; pipe stdin instead.
xargs -P "$N" -L1 < "$PENDING_PAIRS" bash -c 'triage_one "$1" "$2"' _

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))
DONE_NOW=0
if [ -s "$JSONL" ]; then
  DONE_NOW=$(wc -l < "$JSONL" | tr -d ' ')
fi
echo "[fp-triage] done in ${ELAPSED}s; jsonl total lines: $DONE_NOW"
