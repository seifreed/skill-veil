#!/bin/bash
# Download all VirusTotal samples matching query with pagination

QUERY='codeinsight:openclaw codeinsight_verdict:malicious'
OUTPUT_DIR="dataset_vt_new"
HASHES_FILE="$OUTPUT_DIR/all_hashes.txt"
BATCH_SIZE=50

mkdir -p "$OUTPUT_DIR"
> "$HASHES_FILE"

echo "Searching VirusTotal for: $QUERY"
echo "================================"

# First batch
CURSOR=""
BATCH=1
TOTAL=0

while true; do
    echo "Fetching batch $BATCH..."

    if [ -z "$CURSOR" ]; then
        OUTPUT=$(vt search "$QUERY" --limit $BATCH_SIZE --format json 2>&1)
    else
        OUTPUT=$(vt search "$QUERY" --limit $BATCH_SIZE --cursor "$CURSOR" --format json 2>&1)
    fi

    # Check if there's a MORE WITH line (contains cursor for next page)
    NEXT_CURSOR=$(echo "$OUTPUT" | grep "MORE WITH:" | sed 's/.*--cursor=//')

    # Extract JSON (everything before MORE WITH)
    JSON_DATA=$(echo "$OUTPUT" | sed '/MORE WITH:/,$d')

    # Extract hashes
    COUNT=$(echo "$JSON_DATA" | python3 -c "
import json
import sys
try:
    data = json.load(sys.stdin)
    for item in data:
        print(item['_id'])
    print(f'COUNT:{len(data)}', file=sys.stderr)
except Exception as e:
    print(f'ERROR:{e}', file=sys.stderr)
" 2>&1 | tee -a "$HASHES_FILE" | grep -c '^[a-f0-9]\{64\}$' || echo 0)

    TOTAL=$((TOTAL + COUNT))
    echo "  Batch $BATCH: $COUNT hashes (Total: $TOTAL)"

    # Check if we have more pages
    if [ -z "$NEXT_CURSOR" ]; then
        echo "No more pages."
        break
    fi

    CURSOR="$NEXT_CURSOR"
    BATCH=$((BATCH + 1))

    # Safety limit
    if [ $BATCH -gt 100 ]; then
        echo "Reached batch limit (100)"
        break
    fi

    sleep 1  # Rate limiting
done

# Clean up hashes file (remove non-hash lines)
grep -E '^[a-f0-9]{64}$' "$HASHES_FILE" | sort -u > "$HASHES_FILE.clean"
mv "$HASHES_FILE.clean" "$HASHES_FILE"

UNIQUE=$(wc -l < "$HASHES_FILE" | tr -d ' ')
echo "================================"
echo "Total unique hashes: $UNIQUE"
echo "Hashes saved to: $HASHES_FILE"
