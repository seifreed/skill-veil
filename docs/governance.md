# Governance

## Model

`skill-veil` uses a maintainer-led governance model.

The project optimizes for:

- security signal quality
- reproducibility
- contributor clarity
- conservative change control for defaults

## Decision Rules

The repository owner has final decision authority until additional maintainers
are named in [maintainers.md](maintainers.md).

Maintainers should prefer:

- documented decisions over implicit convention
- compatibility for public formats
- benchmark evidence over intuition when changing defaults
- conservative handling of `official` rule packs

## Change Classes

### Low-risk changes

These can be merged with standard maintainer review:

- documentation
- examples
- CI templates
- community rule packs
- benchmark fixture additions

### Medium-risk changes

These require explicit benchmark review:

- threshold changes
- confidence calibration changes
- deduplication logic changes
- policy default changes
- new official rules that can affect false positives

### High-risk changes

These require explicit maintainer sign-off and release-note coverage:

- public schema changes
- rule pack schema changes
- default policy precedence changes
- SARIF/JSON contract changes
- removal or severe downgrade of official detections

## Rule Pack Policy

The project maintains two pack classes:

- `official`: curated defaults, benchmark-reviewed, compatibility-sensitive
- `community`: incubation and local experimentation

Rules move from `community` to `official` only after:

- fixtures exist
- false-positive behavior is explained
- benchmark impact is acceptable
- the rule is maintainable in open source

## ADR Expectation

When a change materially affects scanner behavior, public formats, policy
semantics, or governance, maintainers should record the rationale in the
relevant doc or release notes. Formal ADR files are optional, but the decision
must be discoverable.
