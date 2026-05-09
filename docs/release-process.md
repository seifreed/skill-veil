# Release Process

## Goals

The release process exists to keep `skill-veil` reproducible, benchmarked, and
auditable.

## Preconditions

Before tagging a release:

1. `cargo test` passes.
2. official rule packs validate and fixtures pass (run against the
   sibling `../skill-veil-rules/` checkout).
3. benchmark runs successfully on `benchmarks/corpus.yaml`.
4. `docs/changelog.md` is updated.
5. security-relevant changes are reflected in release notes.
6. embedded baseline at `crates/skill-veil-core/resources/official/`
   matches the latest signed `skill-veil-rules` release the binary is
   intended to ship with — bump it via the release-time sync if a
   newer rule pack is in flight.
7. `crates/skill-veil-cli/src/init/keys.rs` lists every Ed25519 key
   that has signed a release the binary needs to verify (additions
   are MINOR-safe; removals are MAJOR — see `docs/versioning.md`).

## Release Steps

1. Review benchmark output and dashboard.
2. Confirm no unintended benchmark regression.
3. Update `docs/changelog.md`.
4. Create a version tag `vX.Y.Z`.
5. Let `.github/workflows/release.yml` build binaries and publish assets.
6. Verify release assets include:
   - Linux and macOS archives
   - checksums
   - benchmark report
   - benchmark history
   - benchmark dashboard

## Post-Release Checks

After publishing:

- verify the GitHub Release contains expected assets
- verify installation instructions still match release artifacts
- verify benchmark artifacts are readable
- note any compatibility-impacting change in docs if needed

## Hotfix Rule

Hotfix releases should be limited to:

- broken release packaging
- severe false-negative regressions
- severe false-positive regressions
- crashes or corrupt report output

## Cutting a `skill-veil-rules` release (paired repo)

The rule packs live in [`skill-veil-rules`](https://github.com/seifreed/skill-veil-rules)
and are distributed as Ed25519-signed GitHub Releases consumed by
`skill-veil init`. That repo has its own release cadence; coordinate
the two when shipping a `skill-veil` binary that needs new rules to
be available immediately on `init`.

### Standard `skill-veil-rules` release flow

```bash
cd ../skill-veil-rules

# 1. Move CHANGELOG entries from `## [Unreleased]` to a new
#    `## [v0.X.Y]` heading with today's date.

# 2. Tag and push.
git tag v0.X.Y
git push origin v0.X.Y
```

The push triggers `.github/workflows/release.yml` in the rules repo,
which:

1. Runs `scripts/build-manifest.sh v0.X.Y` to compute SHA-256s of
   every distributable file.
2. Runs `scripts/sign-manifest.sh` using the
   `SKILL_VEIL_RULES_SIGNING_KEY` GitHub Actions secret (a PKCS#8
   PEM Ed25519 private key — see Key custody below).
3. Verifies the signature against the committed public key as a
   sanity check.
4. Runs `scripts/build-tarball.sh v0.X.Y` to package everything
   reproducibly.
5. Uploads `manifest.json`, `manifest.json.sig`, and
   `skill-veil-rules-v0.X.Y.tar.gz` as release assets via
   `softprops/action-gh-release`.

Watch and verify:

```bash
gh run list --repo seifreed/skill-veil-rules --workflow=Release --limit 1
gh release view v0.X.Y --repo seifreed/skill-veil-rules
```

### End-to-end smoke test before announcing a rules release

```bash
cargo run -p skill-veil -- init --version v0.X.Y \
  --cache-dir /tmp/sv-init-smoke
cargo run -p skill-veil -- rules status \
  --cache-dir /tmp/sv-init-smoke
rm -rf /tmp/sv-init-smoke
```

Successful output reports `trusted key: <active key id>`, `<N> files
installed`, and the install path. Any signature or per-file SHA-256
mismatch surfaces as a non-zero exit with a path-anchored error
message. **Do not announce the release if this fails.**

### Local rehearsal (no push, no tag)

When iterating on the release scripts, run the pipeline locally:

```bash
cd ../skill-veil-rules

SKILL_VEIL_RULES_SIGNING_KEY=keys/skill-veil-rules-2026.ed25519.priv.pem \
  scripts/build-manifest.sh v0.X.Y-rehearsal && \
  scripts/sign-manifest.sh && \
  scripts/build-tarball.sh v0.X.Y-rehearsal

openssl pkeyutl -verify \
  -pubin -inkey keys/skill-veil-rules-2026.ed25519.pub.pem \
  -rawin -in manifest.json \
  -sigfile <(base64 -d < manifest.json.sig)
```

## Adding a rule (cross-repo flow)

Rules ship from the `skill-veil-rules` repo, not this one. Full
authoring guide: [`docs/rule-authoring.md`](rule-authoring.md). High
level:

1. PR in `skill-veil-rules` adding the rule + positive AND negative
   fixtures + `CHANGELOG.md` entry.
2. After PR lands, cut a `skill-veil-rules` release (above).
3. Optionally mirror the new rule into this repo's embedded baseline
   (`crates/skill-veil-core/resources/official/<topic>.yaml` for
   official-pack rules; `crates/skill-veil-core/src/builtin_rules.yaml`
   for supplementary rules) so the next `skill-veil` binary release
   ships with it. The duplicate-id check in `get_builtin_rules`
   catches accidental id collisions at build time.

## Key custody (release-signing keys)

`skill-veil` verifies releases against Ed25519 public keys embedded
at `crates/skill-veil-cli/src/init/keys.rs`. The verification path
accepts ANY trusted key; keys are added before the corresponding
private key signs a release (**adopt-then-rotate, never the
reverse**) so no release exists that no shipped binary trusts.

### Adopting a new key (paired PR across both repos)

1. **In `skill-veil-rules`:**
   ```bash
   scripts/generate-keypair.sh keys/skill-veil-rules-<year>
   ```
   Commit only the `.pub.*` files (`.priv.pem` MUST never be
   committed — see `keys/README.md`). Add the base64 public key to
   `KEYS.md` under `## Active keys`.

2. **In `skill-veil`:** add the raw 32 bytes from
   `<prefix>.ed25519.pub.raw` to `TRUSTED_KEYS` in
   `crates/skill-veil-cli/src/init/keys.rs`. Update the
   `<key-id>_key_matches_published_hex` test (or add a new one) so
   a typo in the byte literal surfaces at test time, not at the
   first user's `init`.

3. Ship a `skill-veil` release containing the new key BEFORE the
   first `skill-veil-rules` release signed by it.

4. Upload the new private key to the
   `SKILL_VEIL_RULES_SIGNING_KEY` GitHub Actions secret in the
   rules repo:
   ```bash
   gh secret set SKILL_VEIL_RULES_SIGNING_KEY \
     --repo seifreed/skill-veil-rules \
     < keys/<prefix>.ed25519.priv.pem
   ```
   Back the file up offline (hardware key store / offline password
   manager) and then delete the on-disk copy.

### Retiring a key

Move the entry to `## Retired keys` in `KEYS.md` with the revocation
date and the SHA-256 of the last release that key signed. Do NOT
remove the key from `TRUSTED_KEYS` until every consumer has had time
to upgrade past the last release that trusted it — removal is a
**MAJOR-version** change in `skill-veil`
(see [`docs/versioning.md`](versioning.md)).
