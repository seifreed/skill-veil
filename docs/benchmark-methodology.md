# Benchmark Methodology

`skill-veil` uses a labeled static corpus to track signal quality over time.

## Goals

The benchmark is designed to answer:

- did precision improve or regress?
- did recall improve or regress?
- did false positives increase?
- did a release change the balance between benign, suspicious, and malicious classifications?

## Corpus design

The benchmark corpus mixes:

- curated benign samples
- suspicious gray-area samples
- clearly malicious samples
- project examples

Current manifest:

- `benchmarks/corpus.yaml`

Current fixture groups:

- `benchmarks/fixtures/benign/`
- `benchmarks/fixtures/suspicious/`
- `benchmarks/fixtures/malicious/`

## Labels

Each sample is labeled as:

- `benign`
- `suspicious`
- `malicious`

Samples can also carry an optional `attack_family` to track family-specific
coverage and threshold behavior. Current families include:

- `remote_exec`
- `exfiltration`
- `autonomy_bypass`
- `scope_abuse`
- `webhook_risk`
- `mcp_remote_risk`

The benchmark converts the scanner's final action into a predicted label:

- `log` -> `benign`
- `require_approval` -> `suspicious`
- `block` -> `malicious`

## Reported metrics

Current metrics:

- `precision`
- `recall`
- `false_positive_rate`
- `accuracy`
- `exact_label_accuracy`
- `true_positive`
- `false_positive`
- `true_negative`
- `false_negative`
- `deduplication` counts
- corpus coverage by label and focus category
- corpus coverage by attack family
- family-specific metrics and threshold recommendations
- evidence/category/signal-pair calibration buckets with observed precision
- threshold recommendations tuned against false positives and label-jump penalties

These are binary risk metrics over:

- risky = suspicious or malicious
- non-risky = benign

## Limitations

This benchmark is useful but not complete:

- it does not separate suspicious vs malicious confusion as its own metric
- it still depends on a relatively small labeled corpus
- confidence calibration is corpus-driven, so it improves only as the corpus improves

## CI usage

CI runs the benchmark against `benchmarks/corpus.yaml` and uploads the result as
an artifact. That makes it possible to compare releases and inspect regressions
without rerunning the benchmark locally.

The default CI flow now seeds history from `benchmarks/history/releases.json`
and always publishes three artifacts:

- `benchmark-latest.json`
- `benchmark-history.json`
- `benchmark-dashboard.md`
- `benchmark-tuning-report.md`

Tagged releases also publish:

- `benchmark-report.json`
- `benchmark-history.json`
- `benchmark-dashboard.md`
- `benchmark-tuning-report.md`

This creates a public per-release history outside ephemeral CI artifacts.

## Persisting release history locally

```bash
cargo run -p skill-veil -- benchmark benchmarks/corpus.yaml \
  --format json \
  --output benchmarks/history/latest.json \
  --history-file benchmarks/history/releases.json \
  --release-id v0.1.0 \
  --dashboard-output benchmarks/history/dashboard.md
```

That command also writes `benchmarks/history/benchmark-tuning-report.md`,
which summarizes per-family metric quality and threshold recommendations.

## How to extend the corpus

When adding a new sample:

1. place it under the right fixture directory
2. add it to `benchmarks/corpus.yaml`
3. choose the label conservatively
4. set `attack_family` when the sample targets a specific attack pattern
5. prefer samples with a single clear reason for the label
6. avoid duplicating near-identical examples unless they target a distinct regression
