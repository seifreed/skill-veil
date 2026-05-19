# ci-local — local CI deployment + detection harness

Reproduces, on your machine with Docker, what skill-veil does when wired
into a real pipeline: it **builds as a binary**, **deploys self-contained**,
and **detects** known-malicious input while staying quiet on benign input —
with the exit codes and machine output a CI gate depends on.

Three environments, all dockerised:

| Env | What it proves | Run |
|---|---|---|
| **Base harness** | Release build from a clean Rust image; binary runs on `debian-slim`; offline detection + exit codes + SARIF (+ optional signed-pack download) | `docker compose -f ci-local/docker-compose.yml run --rm harness` |
| **GitLab** | The `.gitlab-ci.yml` execution model: jobs run in their declared `image:`, scan → SARIF → baseline → diff gate | `bash ci-local/gitlab/run.sh` |
| **GitHub Actions** | A real workflow under `act` (GitHub-runner emulator), using the prebuilt image as the runner | `bash ci-local/github/run.sh` |

## 1. Base harness (the source of truth)

```bash
docker compose -f ci-local/docker-compose.yml build
docker compose -f ci-local/docker-compose.yml run --rm harness          # offline
docker compose -f ci-local/docker-compose.yml run --rm harness-online   # + init
```

**Deployment.** Multi-stage `Dockerfile` builds `cargo build --release
--locked` in `rust:1.94-bookworm`, then copies *only the binary* into
`debian:bookworm-slim`. If it runs there, the artifact is self-contained
(pure-Rust, rustls — no OpenSSL/system libs).

**Offline by contract.** The `harness` service runs with
`network_mode: none`. Detection uses the **embedded baseline ruleset**
(`include_str!`'d) — no `init`, no enrichment, no update check. This is
the air-gapped-CI guarantee.

**Hard gates** (deterministic, fail the harness if broken):
- malicious fixtures → `verdict=malicious`, exit `1` at `--fail-on medium`
- benign → `verdict=benign`, exit `0`
- SARIF is 2.1.0 with ≥1 result (GitHub/GitLab ingest)
- `--output` JSON is pure (see *gotcha* below)
- *(online only)* post-init re-scan with the external pack still gates
  malicious → `7/7` PASS offline, `8/8` PASS with `harness-online`.

**Soft report.** Labelled-corpus match counts, informational only — the
Rust test `labeled_corpus_meets_phase1_baseline` owns the statistical
precision/recall contract; duplicating it here would just be flaky.

**Online path (`harness-online`).** Runs `skill-veil init --cache-dir
<tmp>`, which:
1. Downloads `manifest.json` + `manifest.json.sig` + the tarball from
   `github.com/seifreed/skill-veil-rules/releases/latest`.
2. Verifies the Ed25519 signature against keys embedded in the binary
   (logs `manifest signature verified against trusted key key_id=…`).
3. Downloads the NOVA rule pack from `Nova-Hunting/nova-rules`, pinned
   by SHA256, and installs it.
4. Re-scans a malicious fixture with `--cache-dir <new>` and asserts
   `verdict=malicious, exit=1` — proving the external pack works.

Skipped (not failed) if upstream is unreachable; the offline gates
above still apply.

## 2. GitLab

```bash
bash ci-local/gitlab/run.sh
```

Prefers `gitlab-ci-local` (the de-facto local executor — GitLab Runner
removed `exec` in 16.x), invoked via host `npx` if present. Falls back
to running each job in its declared `image:` via plain `docker run` —
the fallback does *not* mount the host repo (the image already has the
git-tracked `examples/` baked in, and artifacts go to a container-only
`/tmp/`), so the harness never dirties the host working tree.

The pipeline scans `examples/safe-skill` (a clean target — same shape
as the shipped template's `scan .` of a clean CI checkout) and then
exercises the diff gate: `baseline create` → `diff cur cur --baseline
b --fail-on new-active` → expect exit 0 (no new findings).

Jobs:
- `skill_veil_gate` — must PASS.
- `legacy_diff_flag_rejected` — `allow_failure: true`. Runtime mirror
  of the Rust negative test
  `diff_fail_on_accepts_value_form_and_rejects_flag_suffix_form`:
  the legacy `--fail-on-new-active` form MUST stay rejected
  (`exit 2: unexpected argument`).

The `gitlab-ci-local` engine writes `artifacts/` + `.gitlab-ci-local/`
into cwd; `run.sh` cleans both via a `RETURN` trap.

## 3. GitHub Actions

```bash
bash ci-local/github/run.sh
```

Fetches `act` (no sudo) into `ci-local/.bin/` if absent, then runs
`ci-local/github/workflow.yml`. The runner image is mapped to the
prebuilt `skill-veil-ci:local` via `-P ubuntu-latest=skill-veil-ci:local`,
so the binary + example corpus are already present — no qemu cargo
build, no big runner-image pull, no first-run prompt.

The workflow uses only `run:` steps and scans the image-baked
`/work/...` paths, so it never mounts the host working tree. Steps:
version → benign scan (JSON + SARIF) → gate a malicious fixture
(`exit 1`, verdict malicious) → legacy-flag step (`continue-on-error`,
mirrors the GitLab `legacy_diff_flag_rejected` job).

The reusable composite action `.github/actions/skill-veil` (still
shipped for downstream consumers) is covered by the static
`shipped_ci_template_invocations_parse_under_current_cli` Rust test;
exercising its `cargo run` path under `act` on Apple Silicon would
mean a 20-min qemu compile and isn't worth the wall time.

## Findings this harness surfaced (resolved)

**`examples/ci/*` shipped a stale diff flag (fixed).** The templates
invoked `skill-veil diff … --fail-on-new-active`; the current CLI
expects `--fail-on new-active` (value, not flag suffix). Three files
were corrected (`gitlab-ci.yml`, `github-actions-pr-gating.yml`,
`jenkins.Jenkinsfile`) and two regression tests in
`crates/skill-veil-cli/src/main_tests.rs` pin both sides of the
contract:

- `shipped_ci_template_invocations_parse_under_current_cli` — every
  `cargo run -p skill-veil --` invocation in `examples/ci/*` must
  parse, and at least one MUST exercise `diff --fail-on` (the original
  regression site).
- `diff_fail_on_accepts_value_form_and_rejects_flag_suffix_form` —
  `--fail-on new-active` parses, `--fail-on-new-active` is rejected by
  clap as `unexpected argument`.

The harness's `legacy_diff_flag_rejected` job (GitLab) and the matching
step in the act workflow run the legacy form at runtime as a redundant
cross-check.

## Gotcha: machine output must use `--output`

`tracing` logs go to **stdout**, so `skill-veil … --format json > f.json`
yields a file with a leading `WARN`/`INFO` line that breaks `jq`. Always
use `--format json --output f.json` (and `--format sarif --output
f.sarif`). The shipped CI templates already do this; the harness asserts
it as Gate 4.

## Iteration cache

The Dockerfile separates the heavy and light layers:

```
[builder]  COPY Cargo.toml Cargo.lock + COPY crates  →  cargo build --release --locked
[runtime]  COPY examples / benchmarks/fixtures / ci-local  (independent)
```

Editing `ci-local/*` invalidates only the final `COPY ci-local` layer;
`cargo build` stays CACHED. Measured: cold build ~4m18s, rebuild after a
`smoke.sh` edit ~3s.

## Files

```
ci-local/
  Dockerfile             multi-stage: release build → debian-slim runtime
  docker-compose.yml     harness (offline) + harness-online services
  smoke.sh               CI-agnostic deployment + detection gate
  lib.sh                 assertion helpers (verdict/exit/SARIF), contract-pinned
  gitlab/.gitlab-ci.yml  self-contained mirror of examples/ci/gitlab-ci.yml
  gitlab/run.sh          gitlab-ci-local, or docker-run fallback
  github/workflow.yml    workflow run under act, uses our image as runner
  github/run.sh          fetch act (no sudo) + run with -P ubuntu-latest mapping
  .gitignore             ignores .bin/ (fetched act binary)
```

`/.dockerignore` (repo root) keeps the build context to the ~7 MB
git-tracked tree (the working copy carries ~13 GB of `target/` + corpora).
