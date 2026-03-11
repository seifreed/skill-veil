## Benchmark History

`skill-veil` keeps benchmark history in a portable JSON format so release metrics
are visible outside ephemeral CI artifacts.

Files:

- `releases.json`: optional repository-tracked history file
- `benchmark-latest.json`: latest CI evaluation output
- `benchmark-report.json`: per-release evaluation output
- `benchmark-history.json`: per-release history file generated in the release workflow
- `benchmark-dashboard.md`: markdown trend view generated from the history file

To update history locally:

```bash
cargo run -p skill-veil -- benchmark benchmarks/corpus.yaml \
  --format json \
  --output benchmarks/history/latest.json \
  --history-file benchmarks/history/releases.json \
  --release-id v0.1.0-local \
  --dashboard-output benchmarks/history/dashboard.md
```

The release workflow also publishes `benchmark-report.json`,
`benchmark-history.json`, and `benchmark-dashboard.md` as GitHub Release assets
for each tagged version. The regular CI workflow publishes
`benchmark-latest.json`, `benchmark-history.json`, and `benchmark-dashboard.md`
as build artifacts for every run on `main` and PRs.
