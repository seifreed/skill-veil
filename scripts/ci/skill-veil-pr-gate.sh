#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <previous-report.json> <current-report.json> [baseline.json] [waivers.yaml]" >&2
  exit 1
fi

previous_report="$1"
current_report="$2"
baseline_path="${3:-}"
waivers_path="${4:-}"

cmd=(cargo run -p skill-veil -- diff "$previous_report" "$current_report" --ci-summary --fail-on new-active)

if [[ -n "$baseline_path" && -f "$baseline_path" ]]; then
  cmd+=(--baseline "$baseline_path")
fi

if [[ -n "$waivers_path" && -f "$waivers_path" ]]; then
  cmd+=(--waivers "$waivers_path")
fi

"${cmd[@]}"
