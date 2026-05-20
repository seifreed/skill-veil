# Usage: CI

This guide shows the minimum flows needed to use `skill-veil` in CI without
creating unnecessary noise.

## 0. Reusable CI assets in this repository

- reusable GitHub composite action: `.github/actions/skill-veil/action.yml`
- CI templates per engine: `examples/ci/{github-actions-pr-gating.yml,
  github-actions-sarif-upload.yml, gitlab-ci.yml, bitbucket-pipelines.yml,
  jenkins.Jenkinsfile}`
- local verification harness: `ci-local/` — multi-stage Dockerfile + smoke
  gate (offline + optional online init) + GitLab/`act` runners. Use it to
  verify the deployment + detection contract before wiring skill-veil into
  your real pipeline. See [ci-local/README.md](../ci-local/README.md).
- local CI gate (pre-PR): `cargo fmt --all --check`, `cargo clippy
  --all-targets --all-features -- -D warnings`, and `cargo test
  --all-targets --all-features`

## 1. Generate current reports

```bash
skill-veil scan-package . --format json --output current.json
skill-veil scan-package . --format sarif --output current.sarif
skill-veil scan-package . --preset ci --format text
skill-veil scan-dataset ./marketplace-mirror --preset ci --format json --output dataset.json
```

Typical use:

- keep `json` for diff, baseline, and waiver-aware gating
- upload `sarif` to GitHub Code Scanning
- use `scan-dataset` for large mirrors, catalogs, or monorepos with many package roots

## 2. Gate on newly introduced active findings

```bash
skill-veil diff previous.json current.json --ci-summary --fail-on new-active
```

This fails only when the current scan introduces active findings that were not
present in the previous report.

## 3. Gate only on new blocking findings

```bash
skill-veil diff previous.json current.json --ci-summary --fail-on new-blocking
```

Use this if you want a softer policy that only stops the pipeline when new
findings are already `block`.

## 4. Respect accepted baseline and waivers

```bash
skill-veil diff previous.json current.json \
  --baseline .skill-veil/baseline.json \
  --waivers .skill-veil/waivers.yaml \
  --ci-summary \
  --fail-on new-active
```

This makes the diff classify current findings into:

- `new_active`
- `resolved`
- `waived`
- `baselined`
- `unchanged`

## 5. Machine-friendly text summary

The compact summary is stable and easy to parse:

```text
DIFF new_active=0 resolved=2 waived=1 baselined=3 unchanged=5
```

For larger repositories, prefer `--preset ci` or `--preset enterprise` for
summary-first output with fewer per-file findings rendered in text logs.

## 6. GitHub Actions

The repository already contains:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `.github/actions/skill-veil/action.yml`

`ci.yml`:

- runs tests on:
  - Linux x86_64
  - Linux arm64
  - Windows x86_64
  - Windows arm64
  - macOS x86_64
  - macOS arm64
- runs clippy on Linux
- generates JSON and SARIF
- uploads SARIF to GitHub Code Scanning

The composite action wraps `cargo run -p skill-veil -- ...` and accepts the
most common scan inputs:

- `command`: `scan-package` by default
- `path`: target file or directory to scan
- `format`: `json`, `sarif`, `text`, or `shield`
- `output`: report path relative to the Cargo workspace root
- `fail-on`, `min-severity`, `baseline`, `waivers`, `policy`, `profile`
- `preset`
- `finding-limit`

Minimal usage inside a workflow:

```yaml
- uses: ./.github/actions/skill-veil
  with:
    path: .
    format: json
    output: artifacts/current.json
```

The action also exposes:

- `report-path`
- `sarif-path`
- `command-line`

## 6.1 GitLab CI

Ship `examples/ci/gitlab-ci.yml` to the project root as `.gitlab-ci.yml`.
It triggers on merge requests, materialises the target branch via `git
worktree`, scans both sides, and gates with `diff … --fail-on new-active`.
The same three artifacts are produced (current JSON, previous JSON,
current SARIF) and uploaded.

## 6.2 Bitbucket Pipelines

Ship `examples/ci/bitbucket-pipelines.yml` to the project root as
`bitbucket-pipelines.yml`. Bitbucket exposes the PR base branch as
`$BITBUCKET_PR_DESTINATION_BRANCH`; the template uses it the same way
the GitLab template uses `$CI_MERGE_REQUEST_TARGET_BRANCH_NAME`.
Bitbucket has no native SARIF UI, so treat `artifacts/current.sarif` as
a build artifact for offline analyst review.

## 6.3 Jenkins

`examples/ci/jenkins.Jenkinsfile` is a minimal declarative pipeline.
Wire your own scm step (the example assumes the workspace is already
checked out) and pre-stage a `previous.json` from the target branch the
same way the GitLab template materialises it via `git worktree`. The
diff/gate stage is identical.

## 7. Recommended PR flow

1. Restore or fetch the previous JSON report from the base branch.
2. Generate `current.json` in the PR run.
3. Run `skill-veil diff ... --ci-summary --fail-on new-active`.
4. Upload SARIF for triage in the GitHub Security UI.

Minimal SARIF upload flow:

```yaml
- id: scan
  uses: ./.github/actions/skill-veil
  with:
    path: .
    format: sarif
    output: artifacts/current.sarif
    preset: ci

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.scan.outputs.sarif-path }}
```

Reference templates:

- GitHub Actions PR gate: `examples/ci/github-actions-pr-gating.yml`
- GitHub Actions SARIF upload: `examples/ci/github-actions-sarif-upload.yml`
- GitLab merge request gate: `examples/ci/gitlab-ci.yml`
- Jenkins pipeline example: `examples/ci/jenkins.Jenkinsfile`

## 8. Recommended repository layout

```text
.skill-veil/
  baseline.json
  waivers.yaml
```

Keep these files in version control if your team wants reproducible gating.

## 9. Local gate example

Use a conservative local gate before opening a PR:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

That local sequence is useful for fast developer feedback before the CI diff gate
runs on the merge request or pull request.

## 10. Large datasets, marketplace mirrors, and monorepos

Use the explicit dataset mode when the root contains many packages:

```bash
skill-veil scan-dataset ./marketplace-mirror --preset ci --format json --output dataset.json
```

`scan-dataset` discovers package roots by looking for `SKILL.md` under the root
and scans each package with package semantics. This is the intended mode for:

- marketplace mirrors
- large internal skill catalogs
- monorepos with many package roots
- dataset curation workflows

## 11. Exit codes (essential for CI gating)

The CLI returns three exit codes that every CI gate must understand:

| Code | Meaning |
|------|---------|
| `0`  | Clean run. No finding crossed `--fail-on`. |
| `1`  | Findings at or above the `--fail-on` threshold. CI gate should fail. |
| `2`  | Runtime error (panic at the boundary, I/O failure, malformed config). Distinct from `1` so a failed gate never looks the same as a crash. |

Without `--fail-on`, `skill-veil scan` always returns `0` even when it
emits Critical findings — the JSON/SARIF report is the source of truth,
and the threshold is an explicit operator decision per pipeline.

```bash
skill-veil scan-package . --fail-on medium   # exit 1 if any medium+ finding
skill-veil scan-package . --fail-on high     # exit 1 only at high+
```

The `diff` subcommand uses a different (gate-specific) flag:

```bash
skill-veil diff prev.json cur.json --baseline base.json \
  --ci-summary --fail-on new-active     # exit 1 if any new active finding
skill-veil diff prev.json cur.json --baseline base.json \
  --ci-summary --fail-on new-blocking   # exit 1 only on new BLOCK findings
```

Note the value form (`--fail-on new-active`), not a flag suffix
(`--fail-on-new-active`) — clap rejects the suffix form as `unexpected
argument`. Pinned by `crates/skill-veil-cli/src/main_tests.rs`.

## 12. Machine output must use `--output`

`tracing` emits log lines to **stdout**, so capturing stdout corrupts
machine formats:

```bash
# WRONG: stdout has a leading WARN/INFO line, jq fails
skill-veil scan-package . --format json > report.json

# RIGHT: --output writes pure JSON/SARIF to the file, logs go to stdout separately
skill-veil scan-package . --format json --output report.json
skill-veil scan-package . --format sarif --output report.sarif
```

The shipped CI templates and the composite action already do this; if
you script `skill-veil` yourself in CI, always use `--output`.

## 13. Offline / air-gapped CI

`skill-veil scan` works fully offline against the **embedded baseline
ruleset** (`crates/skill-veil-core/src/builtin_rules.yaml` plus
`resources/official/{core,behavioral}.yaml` are `include_str!`'d at
build time). No `init`, no network call, no rule download — the binary
detects out of the box.

Disable every optional network path with these flags:

```bash
skill-veil scan-package . \
  --no-update-check      \   # skip the once-per-24h GitHub version check
  --no-vt-enrich         \   # skip VirusTotal enrichment
  --no-llm-enrich        \   # skip LLM consensus enrichment
  --no-promptintel-enrich    # skip PromptIntel feed lookup
```

The `harness` service in `ci-local/docker-compose.yml` runs the smoke
gate with `network_mode: none` to prove this contract.

## 14. First-time setup: signed rule pack via `init` (optional)

`skill-veil init` downloads the latest signed
[`skill-veil-rules`](https://github.com/seifreed/skill-veil-rules)
release into `~/.cache/skill-veil/rules/<version>/` and verifies the
Ed25519 signature against keys embedded in the binary. It also pulls
the [NOVA rule pack](https://github.com/Nova-Hunting/nova-rules) pinned
by commit SHA.

`init` is **not required for CI**: the binary ships with the same rules
embedded as a baseline. Run it only if:

- you want the latest external rules without rebuilding skill-veil, or
- you want to evaluate NOVA semantic rules in your pipeline.

If you do run it in CI, pin the version and the cache dir so it is
reproducible and not user-cache-dependent:

```bash
skill-veil init --version v0.1.0 --cache-dir .skill-veil-cache/rules
skill-veil scan-package . --cache-dir .skill-veil-cache/rules \
  --format json --output current.json
```

For air-gapped environments, copy a verified
`~/.cache/skill-veil/rules/<version>/` tree into the build runner and
point `--cache-dir` at it.

## 15. Local verification before going live

Before merging skill-veil into your CI, run the bundled harness to
verify the deployment + detection + gate contract end-to-end inside
Docker, on your machine:

```bash
docker compose -f ci-local/docker-compose.yml run --rm harness         # offline gates
docker compose -f ci-local/docker-compose.yml run --rm harness-online  # + signed-pack init
bash ci-local/gitlab/run.sh                                            # real GitLab pipeline
bash ci-local/github/run.sh                                            # real act / GitHub
```

See [ci-local/README.md](../ci-local/README.md) for details. The harness
asserts: malicious fixture → `verdict=malicious, exit 1`; benign →
`verdict=benign, exit 0`; SARIF is 2.1.0 with results; `--output` JSON
is pure; and (online) the downloaded pack still detects correctly.
