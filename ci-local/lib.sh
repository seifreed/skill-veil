# Shared assertions for the skill-veil CI harness. Sourced, not executed.
# Contract pinned from the real binary (verified 2026-05-19):
#   - exit 0 = clean, 1 = findings >= --fail-on threshold, 2 = runtime error
#   - machine output is ONLY clean via --output <file>; stdout carries
#     tracing logs that corrupt captured JSON/SARIF
#   - per-result verdict lives at .[].verdict (malicious|suspicious|benign)

PASS=0
FAIL=0
RESULTS=()

_c() { case "$1" in g) printf '\033[32m';; r) printf '\033[31m';; y) printf '\033[33m';; *) printf '\033[0m';; esac; }

resolve_bin() {
  if [ -n "${SKILL_VEIL_BIN:-}" ] && command -v "${SKILL_VEIL_BIN}" >/dev/null 2>&1; then
    BIN=("${SKILL_VEIL_BIN}")
  elif command -v skill-veil >/dev/null 2>&1; then
    BIN=(skill-veil)
  elif [ -x target/release/skill-veil ]; then
    BIN=(target/release/skill-veil)
  else
    BIN=(cargo run --release -q -p skill-veil --)
  fi
  echo "binary: ${BIN[*]}"
}

# Run scan, never abort the harness on its non-zero gate exit.
sv() {
  local rc=0
  "${BIN[@]}" "$@" || rc=$?
  return "$rc"
}

record() {
  local ok="$1" name="$2"
  if [ "$ok" = 1 ]; then
    PASS=$((PASS + 1)); RESULTS+=("$(_c g)PASS$(_c 0) $name")
    echo "  $(_c g)PASS$(_c 0) $name"
  else
    FAIL=$((FAIL + 1)); RESULTS+=("$(_c r)FAIL$(_c 0) $name")
    echo "  $(_c r)FAIL$(_c 0) $name"
  fi
}

# assert_scan <name> <mode> <target> <expect_verdict> <expect_exit> [extra flags...]
assert_scan() {
  local name="$1" mode="$2" target="$3" want_v="$4" want_e="$5"; shift 5
  local out; out="$(mktemp)"
  local rc=0
  sv "$mode" "$target" --no-update-check --no-vt-enrich --no-llm-enrich \
     --no-promptintel-enrich --format json --output "$out" "$@" >/dev/null 2>&1 || rc=$?
  local got_v; got_v="$(jq -r '.[0].verdict // "PARSE_ERROR"' "$out" 2>/dev/null || echo PARSE_ERROR)"
  local ok=1
  [ "$got_v" = "$want_v" ] || ok=0
  [ "$rc" = "$want_e" ] || ok=0
  record "$ok" "$name (verdict=$got_v want=$want_v | exit=$rc want=$want_e)"
  rm -f "$out"
}

# assert_sarif <name> <mode> <target> [extra flags...]
assert_sarif() {
  local name="$1" mode="$2" target="$3"; shift 3
  local out; out="$(mktemp --suffix=.sarif)"
  sv "$mode" "$target" --no-update-check --no-vt-enrich --no-llm-enrich \
     --no-promptintel-enrich --format sarif --output "$out" "$@" >/dev/null 2>&1 || true
  local ver res ok=1
  ver="$(jq -r '.version // "x"' "$out" 2>/dev/null || echo x)"
  res="$(jq -r '[.runs[].results[]] | length' "$out" 2>/dev/null || echo -1)"
  [ "$ver" = "2.1.0" ] || ok=0
  [ "${res:-0}" -ge 1 ] || ok=0
  record "$ok" "$name (sarif version=$ver results=$res)"
  rm -f "$out"
}

summary() {
  echo
  echo "================ harness summary ================"
  printf '%s\n' "${RESULTS[@]}"
  echo "------------------------------------------------"
  echo "PASS=$PASS FAIL=$FAIL"
  [ "$FAIL" -eq 0 ]
}
