# Maintainers

## Current Ownership

`skill-veil` currently has a single primary maintainer:

- Project maintainer: repository owner

Until additional maintainers are added, the repository owner is responsible for:

- release approval
- rule pack curation for [`skill-veil-rules/official/`](https://github.com/seifreed/skill-veil-rules)
- release-signing key custody (Ed25519, see
  [`skill-veil-rules/KEYS.md`](https://github.com/seifreed/skill-veil-rules/blob/main/KEYS.md))
- security triage
- benchmark quality gates
- roadmap acceptance and scope decisions

## Maintainer Responsibilities

Maintainers are expected to:

- review code, rule, and benchmark changes
- preserve compatibility promises documented in [versioning.md](versioning.md)
- keep `skill-veil-rules/official/` curated and reproducible
- own the Ed25519 signing keypair lifecycle (rotation, revocation,
  embedded-key updates in `crates/skill-veil-cli/src/init/keys.rs`)
- review vulnerability and bypass reports through the maintainer contact process
- ensure releases follow [release-process.md](release-process.md)

## Adding Maintainers

New maintainers should be added only after they have demonstrated:

- repeated high-signal contributions
- responsible handling of security-sensitive material
- willingness to maintain rule quality and benchmark discipline
- ability to review community rule pack proposals

The repository owner adds maintainers by updating this file and the governance
docs in the same change.

## Areas of Ownership

Until the maintainer set grows, ownership is split by responsibility rather than
by person:

- core engine: `crates/skill-veil-core/`
- CLI and integration UX: `crates/skill-veil-cli/`
- embedded baseline rules: `crates/skill-veil-core/src/builtin_rules.yaml` and `crates/skill-veil-core/resources/official/`
- distributed rule packs: [`skill-veil-rules`](https://github.com/seifreed/skill-veil-rules) repo (separate)
- benchmark corpus and dashboards: `benchmarks/`
- release and CI automation: `.github/workflows/` (this repo) and `skill-veil-rules/.github/workflows/release.yml` (rules repo)
