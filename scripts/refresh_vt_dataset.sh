#!/usr/bin/env bash
set -euo pipefail

QUERY='codeinsight:openclaw codeinsight_verdict:malicious'
LIMIT=300
BATCH_SIZE=50
THREADS=5
DATASET_DIR="dataset"
EXTRACTED_DIR="dataset_extracted"
STATE_DIR="dataset_vt_new"

usage() {
  cat <<'EOF'
Usage: scripts/refresh_vt_dataset.sh [options]

Refresh the local VirusTotal OpenClaw dataset by:
1. Searching VT with pagination
2. Collecting up to N unique hashes
3. Replacing dataset/ and dataset_extracted/
4. Downloading archives into dataset/
5. Extracting them into dataset_extracted/<sha256>/

Options:
  --query <query>           VT Intelligence query
  --limit <n>               Maximum unique samples to download
  --batch-size <n>          VT page size per request
  --threads <n>             Parallel download threads
  --dataset-dir <path>      Raw archive output directory
  --extracted-dir <path>    Extracted dataset output directory
  --state-dir <path>        Query state and hash list directory
  -h, --help                Show this help

Examples:
  scripts/refresh_vt_dataset.sh
  scripts/refresh_vt_dataset.sh --limit 100 --query "codeinsight:openclaw"
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --query)
      QUERY="$2"
      shift 2
      ;;
    --limit)
      LIMIT="$2"
      shift 2
      ;;
    --batch-size)
      BATCH_SIZE="$2"
      shift 2
      ;;
    --threads)
      THREADS="$2"
      shift 2
      ;;
    --dataset-dir)
      DATASET_DIR="$2"
      shift 2
      ;;
    --extracted-dir)
      EXTRACTED_DIR="$2"
      shift 2
      ;;
    --state-dir)
      STATE_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

for cmd in vt python3 unzip mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

HASHES_FILE="$TMP_DIR/all_hashes.txt"
MANIFEST_FILE="$TMP_DIR/query_manifest.json"

echo "Searching VirusTotal for: $QUERY"
echo "Target samples: $LIMIT"
echo "Batch size: $BATCH_SIZE"
echo "================================"

python3 - "$QUERY" "$LIMIT" "$BATCH_SIZE" "$HASHES_FILE" "$MANIFEST_FILE" <<'PY'
import json
import re
import subprocess
import sys
from pathlib import Path

query = sys.argv[1]
limit = int(sys.argv[2])
batch_size = int(sys.argv[3])
hashes_path = Path(sys.argv[4])
manifest_path = Path(sys.argv[5])

cursor = None
batch = 1
hashes = []
seen = set()

while len(hashes) < limit:
    per_page = min(batch_size, limit - len(hashes))
    cmd = ["vt", "search", query, "--limit", str(per_page), "--format", "json"]
    if cursor:
        cmd.extend(["--cursor", cursor])

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr or proc.stdout)
        sys.exit(proc.returncode)

    stdout = proc.stdout
    next_cursor = None
    json_payload = stdout

    marker = "MORE WITH:\n"
    if marker in stdout:
        json_payload, tail = stdout.split(marker, 1)
        match = re.search(r"--cursor=([^\s]+)", tail)
        if match:
            next_cursor = match.group(1)

    data = json.loads(json_payload)
    if not data:
        break

    before = len(hashes)
    for item in data:
        sha256 = item.get("_id")
        if not sha256 or sha256 in seen:
            continue
        seen.add(sha256)
        hashes.append(sha256)
        if len(hashes) >= limit:
            break

    added = len(hashes) - before
    print(f"Batch {batch}: +{added} (total {len(hashes)})", file=sys.stderr)

    if not next_cursor:
        break

    cursor = next_cursor
    batch += 1

hashes_path.write_text("\n".join(hashes) + ("\n" if hashes else ""), encoding="utf-8")
manifest_path.write_text(
    json.dumps(
        {
            "query": query,
            "requested_limit": limit,
            "batch_size": batch_size,
            "downloaded_hashes": len(hashes),
            "final_cursor": cursor,
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY

ACTUAL_COUNT="$(wc -l < "$HASHES_FILE" | tr -d ' ')"
if [[ "$ACTUAL_COUNT" -eq 0 ]]; then
  echo "No hashes returned by VT for query: $QUERY" >&2
  exit 1
fi

if [[ "$ACTUAL_COUNT" -lt "$LIMIT" ]]; then
  echo "Warning: requested $LIMIT samples but VT returned only $ACTUAL_COUNT unique hashes." >&2
fi

rm -rf "$DATASET_DIR" "$EXTRACTED_DIR" "$STATE_DIR"
mkdir -p "$DATASET_DIR" "$EXTRACTED_DIR" "$STATE_DIR"

cp "$HASHES_FILE" "$STATE_DIR/all_hashes.txt"
cp "$MANIFEST_FILE" "$STATE_DIR/query_manifest.json"

echo "Downloading $ACTUAL_COUNT samples into $DATASET_DIR ..."
vt download -o "$DATASET_DIR" -t "$THREADS" - < "$STATE_DIR/all_hashes.txt"

echo "Extracting archives into $EXTRACTED_DIR ..."
while IFS= read -r sha256; do
  [[ -z "$sha256" ]] && continue
  archive_path="$DATASET_DIR/$sha256"
  target_dir="$EXTRACTED_DIR/$sha256"
  mkdir -p "$target_dir"

  if unzip -qq "$archive_path" -d "$target_dir" >/dev/null 2>&1; then
    :
  else
    cp "$archive_path" "$target_dir/$sha256"
  fi
done < "$STATE_DIR/all_hashes.txt"

echo "================================"
echo "Query: $QUERY"
echo "Raw dataset: $DATASET_DIR"
echo "Extracted dataset: $EXTRACTED_DIR"
echo "State directory: $STATE_DIR"
echo "Downloaded samples: $ACTUAL_COUNT"
