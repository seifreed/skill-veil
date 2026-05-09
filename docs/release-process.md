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
