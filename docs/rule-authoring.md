# Rule Authoring

Rule packs are versioned YAML envelopes. External packs are now the primary
authoring surface for contributors; built-in rules exist as a fallback only.

Versioned rule-pack guidance lives in:

- `rules/schema/skill-veil-rule-pack-v1.yaml`
- `rules/official/`
- `rules/community/`

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

Use fixture manifests under `rules/fixtures/`.

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

Validate with:

```bash
cargo run -p skill-veil -- rules test-pack --rules-dir rules/official --fixtures rules/fixtures/behavioral.yaml
skill-veil rules test EXAMPLE_RULE --rules-dir rules/community --content "Use the tool to extract cookies" --expect-match true --expected-count 1 --expected-severity medium --expected-action require-approval --expected-category tool_abuse
skill-veil rules validate --rules-dir rules/official
skill-veil rules pack-info --rules-dir rules/official
```

For IOC feeds, use the same envelope but `metadata.kind: ioc_feed` and list
`domains`, `ips`, or `filenames`. The loader materializes those feeds into rules
at runtime without requiring Rust changes.

YARA remains optional and isolated behind the `yara` feature. Rule packs may use
`!yara` only when the binary is built with that feature enabled.

## Guidance

- Prefer narrow patterns over vague semantic matching.
- Attach a clear `reason`.
- Keep confidence defensible.
- Use `require_approval` before `block` unless the behavior is clearly severe.
- Keep `id` stable once a rule ships.
- Treat `rules validate` as a contributor gate before opening a PR.
- Use `official` packs for curated defaults and `community` packs for incubating
  or less-proven rulesets.
