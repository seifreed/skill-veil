#!/usr/bin/env bash
# Sequential dynamic-analysis runner for the malicious skill corpus.
#
# Runs each skill ONE AT A TIME (no behavior mixing) through BOTH dynamic
# engines under gVisor and persists a standalone behavior report per skill:
#   - observer  (--dynamic --sandbox-record-network)  -> reports/dyn/<hash>.json
#   - detonation(--sandbox-detonate-agent)            -> reports/det/<hash>.json
# Resumable: a completed hash is appended to done.txt and skipped on restart.
set -u

BIN=/root/sv-run/target/release/skill-veil
DATA=/root/sv-data/malicious
OUT=/root/sv-out
EXTRACT=$OUT/extracted

# Agent-detonation LLM: the free opencode zen gateway ECONNRESETs from this
# datacenter IP, so drive the agent with the operator's configured Ollama
# Cloud provider (GLM-5). The patched binary forwards these into the
# container; detonate.py writes the opencode config from them.
OC_CFG=/root/.config/opencode/opencode.json
export SV_DETONATE_MODEL="${SV_DETONATE_MODEL:-ollama-cloud/devstral-small-2:24b}"
export SV_OPENCODE_BASEURL="${SV_OPENCODE_BASEURL:-https://ollama.com/v1}"
if [ -z "${SV_OPENCODE_API_KEY:-}" ] && [ -f "$OC_CFG" ]; then
  SV_OPENCODE_API_KEY=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["provider"]["ollama-cloud"]["options"]["apiKey"])' "$OC_CFG" 2>/dev/null)
  export SV_OPENCODE_API_KEY
fi
mkdir -p "$OUT/reports/dyn" "$OUT/reports/det" "$EXTRACT"
DONE=$OUT/done.txt
ERR=$OUT/errors.log
LOG=$OUT/run.log
touch "$DONE" "$ERR" "$LOG"

OBS_TIMEOUT=${OBS_TIMEOUT:-600}
DET_TIMEOUT=${DET_TIMEOUT:-420}
# Which engines to run per skill: obs | det | both.
RUN_MODE=${RUN_MODE:-both}
# Per-engine resumable manifests so observer and detonation passes are
# independent (the detonation engine is still being brought online).
DONE_OBS=$OUT/done_obs.txt
DONE_DET=$OUT/done_det.txt
touch "$DONE_OBS" "$DONE_DET"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

mapfile -t ALL < <(find "$DATA" -maxdepth 1 -type f -regextype posix-extended \
  -regex '.*/[0-9a-f]{64}$' -printf '%f\n' | sort)
TOTAL=${#ALL[@]}
log "corpus: $TOTAL skills; mode=$RUN_MODE; obs done $(wc -l < "$DONE_OBS"), det done $(wc -l < "$DONE_DET")"

want_obs() { [ "$RUN_MODE" = obs ] || [ "$RUN_MODE" = both ]; }
want_det() { [ "$RUN_MODE" = det ] || [ "$RUN_MODE" = both ]; }

skill_root() {
  # If the extraction has exactly one top-level dir and no top-level files,
  # use that dir; otherwise use the extraction root.
  local base=$1 dirs files
  dirs=$(find "$base" -maxdepth 1 -mindepth 1 -type d | wc -l)
  files=$(find "$base" -maxdepth 1 -mindepth 1 -type f | wc -l)
  if [ "$dirs" = "1" ] && [ "$files" = "0" ]; then
    find "$base" -maxdepth 1 -mindepth 1 -type d
  else
    echo "$base"
  fi
}

for hash in "${ALL[@]}"; do
  do_obs=0; do_det=0
  want_obs && ! grep -qx "$hash" "$DONE_OBS" && do_obs=1
  want_det && ! grep -qx "$hash" "$DONE_DET" && do_det=1
  [ "$do_obs" = 0 ] && [ "$do_det" = 0 ] && continue

  zip="$DATA/$hash"
  dest="$EXTRACT/$hash"
  rm -rf "$dest"; mkdir -p "$dest"
  if ! unzip -q -o "$zip" -d "$dest" 2>>"$ERR"; then
    log "EXTRACT-FAIL $hash"; echo "$hash extract_fail" >> "$ERR"
    [ "$do_obs" = 1 ] && echo "$hash" >> "$DONE_OBS"
    [ "$do_det" = 1 ] && echo "$hash" >> "$DONE_DET"
    rm -rf "$dest"; continue
  fi
  root=$(skill_root "$dest")
  t0=$(date +%s); obs_rc=-; det_rc=-

  if [ "$do_obs" = 1 ]; then
    timeout "$OBS_TIMEOUT" "$BIN" scan-package "$root" \
      --dynamic --sandbox-record-network \
      --dynamic-report "$OUT/reports/dyn/$hash.json" \
      --format json >/dev/null 2>>"$ERR"
    obs_rc=$?
    echo "$hash" >> "$DONE_OBS"
  fi
  if [ "$do_det" = 1 ]; then
    timeout "$DET_TIMEOUT" "$BIN" scan-package "$root" \
      --sandbox-detonate-agent \
      --dynamic-report "$OUT/reports/det/$hash.json" \
      --format json >/dev/null 2>>"$ERR"
    det_rc=$?
    echo "$hash" >> "$DONE_DET"
  fi

  t1=$(date +%s)
  rm -rf "$dest"
  log "done obs=$(wc -l < "$DONE_OBS") det=$(wc -l < "$DONE_DET") /$TOTAL $hash obs_rc=$obs_rc det_rc=$det_rc $((t1-t0))s"
done

touch "$OUT/COMPLETE.$RUN_MODE"
log "MODE $RUN_MODE COMPLETE"
