# Usage: CI

This guide shows the minimum flows needed to use `skill-veil` in CI without
creating unnecessary noise.

## 0. Reusable CI assets in this repository

Phase 7.1 ships three adoption assets:

- reusable GitHub composite action: `.github/actions/skill-veil/action.yml`
- CI templates: `examples/ci/github-actions-pr-gating.yml` and `examples/ci/gitlab-ci.yml`
- local CI gate: run `cargo fmt --all --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`
- extra CI examples: `examples/ci/github-actions-sarif-upload.yml` and `examples/ci/jenkins.Jenkinsfile`

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
