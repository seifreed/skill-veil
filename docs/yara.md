# YARA Support

`skill-veil` supports optional YARA matching behind the `yara` feature.

This is intended for:

- curated high-signal signatures
- supplemental pattern matching in official or community rule packs
- targeted detection experiments without changing Rust code

## Build with YARA enabled

```bash
cargo run -p skill-veil --features yara -- rules validate --rules-dir rules/official
```

## Rule pack usage

Versioned rule packs may use `!yara` conditions when the binary is built with
the `yara` feature enabled.

Example:

```yaml
rules:
  - id: EXAMPLE_YARA_RULE
    category: remote_exec
    severity: high
    confidence: 0.9
    when: !yara
      path: docs/examples/example-rule.yar
    action: require_approval
    reason: "Matched a curated YARA signature"
    shield:
      scope: skill.runtime
    enabled: true
    tags:
      - yara
      - example
```

## When to use YARA

Prefer YARA for:

- stable, high-confidence signatures
- polyglot patterns that are awkward in plain regex
- cases where you want shared signatures across multiple rule packs

Prefer normal rule conditions for:

- simple regex/section checks
- author-facing rules that should be easy to review and maintain

## Notes

- YARA support is optional by design.
- CI validates the feature with `--all-features`.
- Keep YARA rules narrow; avoid replacing clear semantic rules with opaque YARA
  when readability matters.
