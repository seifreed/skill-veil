# Dependency Review Skill

Review the package manifest and local build hooks before approving installation.

## Rules

- Prefer pinned dependencies.
- Escalate install hooks for human review.
- Do not fetch remote binaries during setup.

## Files

- `package.json`
- `scripts/postinstall.js`
