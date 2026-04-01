# Skill SBOM

`skill-veil` can generate a skill-specific SBOM / extension inventory with:

```bash
skill-veil sbom /path/to/package --format text
skill-veil sbom /path/to/package --format json
```

This is not a generic software SBOM focused only on package metadata. It is an
inventory for agent extensions that combines:

- entrypoints and supporting artifacts
- effective capabilities
- declared permissions
- inferred dependencies and tools
- remote endpoints
- package-level risk and blast radius

## Fields

Main fields:

- `skill`
- `version`
- `package_id`
- `extension_kind`
- `ecosystem_profile`
- `components`
- `capabilities`
- `declared_permissions`
- `dependencies`
- `remote_endpoints`
- `risk_score`
- `risk_band`
- `verdict`
- `blast_radius`

## Why it exists

The SBOM output is useful for:

- supply-chain inventory
- marketplaces
- enterprise review workflows
- compliance and internal registries

It complements:

- `verdict`
- `behavior_graph`
- `execution_model`
- `blast_radius_summary`

## Example

See:

- [docs/examples/json-report-v3-example.json](examples/json-report-v3-example.json)
- [docs/examples/skill-sbom-example.json](examples/skill-sbom-example.json)
