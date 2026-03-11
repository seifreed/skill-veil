# Versioning

## Public Contract

`skill-veil` uses semantic versioning for project releases:

- `MAJOR`: breaking changes in CLI behavior, public report formats, policy
  schema, rule pack schema, or documented compatibility guarantees
- `MINOR`: backward-compatible features, new analyzers, new commands, new
  optional report fields, new official rules
- `PATCH`: bug fixes, benchmark updates, documentation, tuning that preserves
  public compatibility

## Stable Surfaces

The following are treated as public compatibility surfaces:

- CLI command names and primary flags
- JSON report structure
- SARIF output structure as documented by the tool
- policy file schema
- baseline and waiver formats
- rule pack schema under `rules/schema/`

## Compatibility Rules

- Breaking schema changes require a `MAJOR` release.
- Adding optional fields is `MINOR` if old consumers continue to work.
- Tightening validation on malformed inputs is usually `PATCH` unless it breaks
  previously documented valid files.
- Changes to `official` rules that materially alter defaults should be called
  out in `docs/changelog.md`.

## Rule Pack Compatibility

`official` and `community` rule packs should declare compatibility with the
current schema version. If a schema version changes incompatibly, the project
must:

- version the schema explicitly
- document the migration path
- note the break in release notes

## Benchmark Discipline

Every release should carry benchmark output and history artifacts. If quality
changes materially, the release notes should explain why.
