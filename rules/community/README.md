# Community Rule Packs

This directory is reserved for community-maintained packs that are not bundled
as official defaults.

Recommended structure:

```text
rules/community/<pack-name>.yaml
rules/fixtures/<pack-name>.yaml
```

Community packs should use the same versioned envelope as official packs:

```yaml
schema_version: skill-veil.dev/rules/v1alpha1
metadata:
  name: community-pack-name
  kind: community
  compatibility:
    - skill-veil.dev/rules/v1alpha1
rules:
  - id: COMMUNITY_RULE
    category: tool_abuse
    severity: medium
    when: !regex
      pattern: "(?i)extract cookies"
    action: require_approval
    reason: "Community-contributed rule"
```

Useful commands:

```bash
skill-veil rules validate --rules-dir rules/community
skill-veil rules pack-info --rules-dir rules/community
skill-veil rules test-pack --rules-dir rules/community --fixtures rules/fixtures/<pack-name>.yaml
```

Before proposing migration into `rules/official`, contributors should provide:

- positive fixtures
- negative fixtures
- false positive analysis
- category, severity, action, and confidence rationale
