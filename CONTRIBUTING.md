# Contributing

Project governance and maintenance expectations:

- [docs/maintainers.md](docs/maintainers.md)
- [docs/governance.md](docs/governance.md)
- [docs/versioning.md](docs/versioning.md)
- [docs/support.md](docs/support.md)
- [docs/release-process.md](docs/release-process.md)

## Development

```bash
cargo test
cargo run -p skill-veil -- scan-file examples/malicious-skill/SKILL.md
```

## What to contribute

- new rules with fixtures
- false-positive reductions
- artifact analyzers
- benchmark corpus improvements
- documentation

## Contribution rules

- Add tests for behavior changes.
- Do not remove or rewrite existing findings without explaining the regression risk.
- Prefer small, reviewable changes.
- If you add a rule, add at least one positive and one negative fixture.

## Rule pack changes

- Put official pack changes in `rules/official/`.
- Use `rules/community/` for incubating rules that are not yet ready as defaults.
- Add or update fixtures in `rules/fixtures/`.
- Append notable changes to `rules/CHANGELOG.md`.
- Treat `official` packs as compatibility-sensitive and benchmark-reviewed.
