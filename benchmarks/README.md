# skill-veil benchmarks

Source-of-truth corpora and metrics for evaluating skill-veil
precision and recall.

## Layout

| Path | What it is |
|---|---|
| `vt-baseline.json` | Canonical VirusTotal corpus (2976 samples) with current verdicts and recomputed metrics. The single file the project measures itself against. |
| `vt-baseline-overrides.yaml` | Manual / LLM-validated mislabel overrides applied to the baseline. Each entry carries `sha256`, `new_label`, `confidence`, `source`, `reason` for audit. |
| `vt-corpus.yaml` | The VirusTotal **malicious** sample list (query `codeinsight_verdict:malicious`, 2976 SHAs). Used by `skill-veil vt download` to reproduce the cached extracts under `data/.skill-veil-cache/`. |
| `vt-clean-corpus.yaml` | The VirusTotal **benign** sample list (query `codeinsight_verdict:benign`, 4000 SHAs). Used by `skill-veil vt download --clean` to reproduce `data-clean/.skill-veil-cache/`. This is the false-positive corpus: every FP measurement (`scripts/fp_triage.sh`, the `0/4000-benign` membership criterion for `verdict::predicates::CONCLUSIVE_SINGLE_RULE_IDS`) is verified against exactly this manifest. |
| `corpus.yaml` | Smaller fixture-based benchmark (41 labelled samples) used for per-family precision/recall tuning. Run with `cargo run -p skill-veil -- benchmark benchmarks/corpus.yaml`. |
| `fixtures/` | Curated benign / malicious / suspicious markdown samples used by rule-pack fixtures and by `corpus.yaml`. |
| `history/` | Per-release benchmark snapshots (consumed by `crates/skill-veil-cli/src/commands/benchmark.rs`). See `history/README.md`. |
| `CLAUDE.md` | Re-labeling workflow + override schema docs. |

## Current metrics

See the top of `vt-baseline.json` (`metrics` block). Refresh after
adding overrides:

```bash
python3 scripts/regenerate_baseline.py        # apply overrides to baseline
cargo run -p skill-veil -- benchmark benchmarks/corpus.yaml --format text   # small-corpus metrics
```

## Reproducing the corpus

```bash
# 1) Download VT samples listed in vt-corpus.yaml (requires ~/.vt.toml)
cargo run -p skill-veil -- vt download --corpus benchmarks/vt-corpus.yaml

# 2) Cross-check against current rules + write to baseline
cargo run -p skill-veil -- vt cross-check --dir data --output benchmarks/vt-baseline.json --format json

# 3) Re-apply mislabel overrides (idempotent)
python3 scripts/regenerate_baseline.py
```

See `CLAUDE.md` for the override workflow and schema.
