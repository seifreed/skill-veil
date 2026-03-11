# Analyst Interpretation Guide

`skill-veil` is designed to answer one primary question:

> Is this agent extension package benign, suspicious, or malicious?

The package is the unit of judgment. A package can be risky because of the main
agent entrypoint, supporting artifacts, or package-level manifests and configs.

## Read results in this order

1. `verdict`
2. `why`
3. `scope`
4. `top rule`
5. `blast radius`
6. detailed findings

This order keeps triage fast and avoids overreacting to low-signal hygiene
findings.

## Verdicts

- `benign`
  No strong hostile behavior was found. The package may still have hygiene or
  maintenance issues.

- `suspicious`
  The package contains risky instructions, unsafe workflow semantics, or other
  causes that justify review before trust.

- `malicious`
  The package contains strong hostile behavior or a clearly dangerous delegated
  workflow such as remote fetch-and-exec, token theft, or explicit approval
  bypass combined with dangerous actions.

## Package health vs verdict

`package_health` is not the same thing as `verdict`.

- `package_health=healthy`
  No notable hygiene or package posture problems were found.

- `package_health=elevated`
  The package has non-trivial hygiene or posture concerns.

- `package_health=needs_review`
  The package should be reviewed for posture or trust reasons, even if the
  final package verdict is still `benign`.

This distinction is important. A package can be:

- `verdict=benign`
- `package_health=needs_review`

That means the package is not currently classified as malicious or suspicious,
but its manifests, scopes, or packaging choices should still be reviewed.

## Artifact scopes

Each cause is tied to an `artifact_scope`.

- `agent_entrypoint`
  The main skill, prompt, or instruction file.

- `supporting_artifact`
  Referenced scripts, helper files, lockfiles, or related artifacts that change
  the package behavior.

- `package_root_artifact`
  Top-level manifests and package configuration such as `package.json`,
  `requirements.txt`, lockfiles, `Dockerfile`, `docker-compose`, `.npmrc`, or
  similar files.

Use the scope to answer:

> Is the problem in the main skill itself, or delegated to supporting files?

## Declared permissions

`declared_permissions` summarize what the package explicitly requests or
assumes, for example:

- `browser_full`
- `file_write`
- `shell_exec`
- `network_access`
- `secrets_access`
- `o_auth_scopes`

These are static signals inferred from the package contents. They are not a
runtime permission audit.

## Blast radius

`blast_radius` is a package-level estimate of impact if the workflow runs as
described.

- `low`
  Limited impact surface.

- `medium`
  Non-trivial permissions, network access, or behavioral risk.

- `high`
  Remote execution, exfiltration, privileged runtime, credential access, or
  other high-impact combinations.

`blast_radius_factors` explain why the package was scored that way.

## Common analyst patterns

### Malicious main artifact

Typical signs:

- `curl | bash`
- prompt says to bypass consent and execute actions
- direct token/session export

Typical reading:

- `verdict=malicious`
- `scope=agent_entrypoint`
- `top_rule=SKILL_REMOTE_EXEC_CURL_BASH`

### Malicious delegated workflow

Typical signs:

- `SKILL.md` looks mild
- referenced `install.sh`, `bootstrap.py`, or `server.js` fetches or executes
  remote code

Typical reading:

- `verdict=malicious`
- `scope=supporting_artifact`
- main artifact may still be clean

### Benign but poor package hygiene

Typical signs:

- missing lockfiles
- unpinned dependencies
- broad manifests without direct hostile behavior

Typical reading:

- `verdict=benign`
- `package_health=needs_review`
- `scope=package_root_artifact`

## Dataset triage view

For large corpora, prefer:

```bash
skill-veil scan-dataset ./dataset --dataset-view verdicts --format text
```

The compact dataset view is intended to answer:

- which packages are `malicious`
- which packages are `suspicious`
- why they were classified that way
- whether the cause is `main`, `supporting`, or `package_root`
- what declared permissions and blast radius they imply

Use `--format json` when you want the same verdict-oriented view in a compact
machine-readable structure.
