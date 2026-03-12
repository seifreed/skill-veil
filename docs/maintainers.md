# Maintainers

## Current Ownership

`skill-veil` currently has a single primary maintainer:

- Project maintainer: repository owner

Until additional maintainers are added, the repository owner is responsible for:

- release approval
- rule pack curation for `rules/official/`
- security triage
- benchmark quality gates
- roadmap acceptance and scope decisions

## Maintainer Responsibilities

Maintainers are expected to:

- review code, rule, and benchmark changes
- preserve compatibility promises documented in [versioning.md](versioning.md)
- keep `rules/official/` curated and reproducible
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
- official rule packs: `rules/official/`
- benchmark corpus and dashboards: `benchmarks/`
- release and CI automation: `.github/workflows/`
