# Rule Authoring

Rule packs are versioned YAML envelopes distributed from a separate
repository, [`skill-veil-rules`](https://github.com/seifreed/skill-veil-rules).
External packs are the primary authoring surface for contributors; the
embedded baseline shipped in the binary is a fallback only.

## Where rules live

| Location | Role |
|----------|------|
| `skill-veil-rules/official/` | Curated default packs (stable rule IDs, treated as public API). |
| `skill-veil-rules/community/` | Incubating / org-specific packs not enabled by default. |
| `skill-veil-rules/base/` | Historical category-grouped packs. |
| `skill-veil-rules/fixtures/` | Positive / negative test fixtures consumed by `skill-veil rules test-pack`. |
| `skill-veil-rules/schema/skill-veil-rule-pack-v1.yaml` | Versioned schema reference. |
| `crates/skill-veil-core/resources/official/supplementary.yaml` | Embedded supplementary rules (`include_str!`d into the binary; mirrors the skill-veil-rules `official/supplementary.yaml` pack). |
| `crates/skill-veil-core/resources/official/{core,behavioral}.yaml` | Embedded baseline copies of the canonical official packs. |

For local authoring, clone the rules repo as a sibling of skill-veil:

```bash
git clone https://github.com/seifreed/skill-veil-rules ../skill-veil-rules
```

`default_external_rule_dirs()` falls back to `./rules/official/` so the
discovery path includes `../skill-veil-rules/official/` if you symlink
or `cd` into the right place; the simpler workflow is to pass
`--rules-dir ../skill-veil-rules/official` explicitly to the
validators.

## Minimal example

```yaml
schema_version: skill-veil.dev/rules/v1alpha1
metadata:
  name: example-pack
  kind: community
  compatibility:
    - skill-veil.dev/rules/v1alpha1
rules:
  - id: EXAMPLE_RULE
    category: tool_abuse
    severity: medium
    confidence: 0.8
    when: !regex
      pattern: "(?i)extract cookies"
    action: require_approval
    reason: "Suspicious tool behavior"
    shield:
      scope: skill.tools
    enabled: true
    tags:
      - community_pack
```

## Supported conditions

- `!regex`
- `!section_contains`
- `!section_regex`
- `!artifact_kind`
- `!code_language`
- `!any`
- `!all`
- `!yara` when the feature is enabled

## Fixtures

Fixture manifests live under `skill-veil-rules/fixtures/`.

Example:

```yaml
cases:
  - id: simple-positive
    rule_id: EXAMPLE_RULE
    content: |
      # Skill
      Use the tool to extract cookies.
    expect_match: true
    expected_count: 1
    expected_severity: medium
    expected_action: require_approval
    expected_category: tool_abuse
```

Validate locally:

```bash
cargo run -p skill-veil -- rules test-pack \
  --rules-dir ../skill-veil-rules/official \
  --fixtures ../skill-veil-rules/fixtures/behavioral.yaml
skill-veil rules test EXAMPLE_RULE \
  --rules-dir ../skill-veil-rules/community \
  --content "Use the tool to extract cookies" \
  --expect-match true --expected-count 1 \
  --expected-severity medium --expected-action require-approval \
  --expected-category tool_abuse
skill-veil rules validate --rules-dir ../skill-veil-rules/official
skill-veil rules pack-info --rules-dir ../skill-veil-rules/official
```

For IOC feeds, use the same envelope but `metadata.kind: ioc_feed` and list
`domains`, `ips`, or `filenames`. The loader materializes those feeds into rules
at runtime without requiring Rust changes.

YARA remains optional and isolated behind the `yara` feature. Rule packs may use
`!yara` only when the binary is built with that feature enabled.

See also:

- `docs/yara.md`
- `docs/examples/example-rule.yar`
- [skill-veil-rules/CONTRIBUTING.md](https://github.com/seifreed/skill-veil-rules/blob/main/CONTRIBUTING.md)

## Guidance

- Prefer narrow patterns over vague semantic matching.
- Attach a clear `reason`.
- Keep confidence defensible.
- Use `require_approval` before `block` unless the behavior is clearly severe.
- Keep `id` stable once a rule ships — official IDs are public API.
- Treat `rules validate` as a contributor gate before opening a PR.
- Use `official/` packs for curated defaults and `community/` packs for
  incubating or less-proven rulesets.

## Promoting a rule into the embedded baseline

Rules in `skill-veil-rules/official/` reach end users when:

1. The rules repo cuts a new signed release (Ed25519 + per-file
   SHA-256 manifest), and
2. Either the user runs `skill-veil init` to pull the new release,
   **or** a new `skill-veil` binary release ships an embedded baseline
   that mirrors the latest official pack.

To make a rule part of the embedded baseline shipped in the next
`skill-veil` release, mirror it into
`crates/skill-veil-core/resources/official/<topic>.yaml` (or
`resources/official/supplementary.yaml` for supplementary rules). Both paths are
`include_str!`'d at compile time and the duplicate-id detection in
`get_builtin_rules` will refuse to build if the same id appears twice
across embedded packs — cross-check before mirroring.
