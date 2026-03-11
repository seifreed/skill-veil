# Official Rule Packs

`rules/official/` contains the curated default rule packs that `skill-veil`
loads before falling back to embedded built-ins.

Policy:

- `official` packs are reviewed, versioned, and expected to keep stable rule IDs.
- `community` packs are incubating or organization-specific and should not be
  assumed safe as defaults.
- IOC feeds may be distributed as `metadata.kind: ioc_feed` packs when the feed
  is static and reviewable.
- YARA rules remain optional and isolated from the YAML pack model.

Contributor workflow:

```bash
skill-veil rules validate --rules-dir rules/official
skill-veil rules pack-info --rules-dir rules/official
skill-veil rules test-pack --rules-dir rules/official --fixtures rules/fixtures/behavioral.yaml
```

Every official pack should declare:

- `schema_version`
- `metadata.name`
- `metadata.kind`
- `metadata.compatibility`
- rule-level `reason`, `action`, and stable `id`
