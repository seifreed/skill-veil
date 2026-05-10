#!/usr/bin/env bash
# fp_triage_analyze.sh — read fp-triage.jsonl + results-clean.json,
# emit:
#   1. Per-SHA consensus: how many of {openai, grok, ollama-cloud}
#      voted benign vs non-benign.
#   2. fp-triage-consensus.jsonl — one line per SHA with the consensus
#      (LLM_FP if ≥2 of 3 LLMs say benign, AGREE if ≥2 say non-benign).
#   3. Per-rule FP rate: for the rule that fired (top_rule from
#      results-clean.json), how many of its packages turned into LLM_FP
#      vs AGREE — surfaces the rules with the worst signal-to-noise
#      against the LLM consensus.
#
# Inputs (override via env):
#   JSONL=fp-triage.jsonl
#   RESULTS_JSON=results-clean.json
# Outputs:
#   fp-triage-consensus.jsonl
#   fp-triage-by-rule.tsv  (count_total \t count_fp \t fp_rate \t rule)

set -u
JSONL="${JSONL:-fp-triage.jsonl}"
RESULTS_JSON="${RESULTS_JSON:-results-clean.json}"
OUT_CONSENSUS="${OUT_CONSENSUS:-fp-triage-consensus.jsonl}"
OUT_BY_RULE="${OUT_BY_RULE:-fp-triage-by-rule.tsv}"

if [ ! -s "$JSONL" ]; then
  echo "no triage data at $JSONL"; exit 1
fi
if [ ! -s "$RESULTS_JSON" ]; then
  echo "no scan results at $RESULTS_JSON"; exit 1
fi

# Group LLM votes by SHA: count benign votes and non-benign (suspicious|malicious) votes.
# Provider verdict "error" / "missing" → not counted.
# Consensus thresholds:
#   - LLM_FP if benign_votes >= 2 (majority of 3 LLMs say benign)
#   - AGREE if non_benign_votes >= 2
#   - SPLIT otherwise (ties or 1-1 with one error)
jq -s '
  # Group raw triage by sha.
  group_by(.sha)
  | map({
      sha: .[0].sha,
      providers: (map(select(.verdict | IN("benign","suspicious","malicious")))
                  | map({provider, verdict, confidence})),
      benign_votes: ([.[] | select(.verdict == "benign")] | length),
      non_benign_votes: ([.[] | select(.verdict | IN("suspicious","malicious"))] | length),
      error_votes: ([.[] | select(.verdict | IN("error","missing"))] | length),
    })
  | map(. + {
      consensus: (
        if .benign_votes >= 2 then "LLM_FP"
        elif .non_benign_votes >= 2 then "AGREE"
        else "SPLIT" end
      )
    })
  | .[]
' "$JSONL" > "$OUT_CONSENSUS"

# Top-line consensus tally.
echo "=== consensus tally ==="
jq -r '.consensus' "$OUT_CONSENSUS" | sort | uniq -c | sort -rn

# Provider-level disagreement: which LLM disagrees most with skill-veil?
echo
echo "=== per-provider verdict tally (only complete (sha,provider) calls) ==="
jq -r '.verdict' "$JSONL" \
  | sort | uniq -c | sort -rn

echo
echo "=== per-provider benign rate ==="
for prov in openai grok ollama-cloud; do
  total=$(jq -r --arg p "$prov" 'select(.provider == $p) | .verdict' "$JSONL" \
    | grep -cE "benign|suspicious|malicious")
  benign=$(jq -r --arg p "$prov" 'select(.provider == $p and .verdict == "benign") | .sha' "$JSONL" | wc -l | tr -d ' ')
  if [ "$total" -gt 0 ]; then
    pct=$(awk -v b="$benign" -v t="$total" 'BEGIN { printf "%.1f%%", (b/t)*100 }')
    echo "$prov  benign=$benign / $total  ($pct)"
  fi
done

# Cross-tab consensus against top_rule from skill-veil's verdict.
# results-clean.json verdicts has {package_id, top_rule, ...}; join on
# sha to get per-rule LLM_FP rate.
echo
echo "=== per-rule LLM_FP rate (top 25 rules by count) ==="
jq -r '.verdicts[] | [.package_id, .top_rule] | @tsv' "$RESULTS_JSON" \
  | sort > /tmp/_pkg_rule.tsv
jq -r '[.sha, .consensus] | @tsv' "$OUT_CONSENSUS" \
  | sort > /tmp/_pkg_consensus.tsv
join -t $'\t' /tmp/_pkg_rule.tsv /tmp/_pkg_consensus.tsv \
  | awk -F'\t' '
      { rule=$2; consensus=$3;
        total[rule]++;
        if (consensus == "LLM_FP") fp[rule]++;
        else if (consensus == "SPLIT") split_[rule]++;
      }
      END {
        for (r in total) {
          fc = (fp[r]+0); sc = (split_[r]+0); tc = total[r];
          rate = (fc / tc) * 100;
          printf "%d\t%d\t%d\t%.1f%%\t%s\n", tc, fc, sc, rate, r
        }
      }
    ' \
  | sort -k1,1nr > "$OUT_BY_RULE"
echo "total / fp_count / split / fp_rate / rule"
head -25 "$OUT_BY_RULE" | awk -F'\t' '{ printf "%4d  %4d  %3d  %6s  %s\n", $1,$2,$3,$4,$5 }'

echo
echo "wrote: $OUT_CONSENSUS  $OUT_BY_RULE"
