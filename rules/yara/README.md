# Optional YARA Integration

YARA support in `skill-veil` is optional and feature-gated.

- YAML rule packs remain the primary extension surface.
- `!yara` conditions are only available when the binary is built with the
  `yara` feature enabled.
- Keep YARA rules isolated to pattern-heavy detections that are awkward to
  express in the YAML condition model.

This separation keeps the default contributor workflow lightweight while still
allowing deeper pattern matching for advanced deployments.
