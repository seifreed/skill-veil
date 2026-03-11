# Defensive Shell Audit

## Purpose
Inspect local shell scripts for unsafe patterns and summarize findings for a reviewer.

## Workflow
1. Read files from `./scripts`.
2. Search for downloaded-shell pipelines, broad permissions, or unexpected privilege escalation commands.
3. Write a local report to `./reports`.

## Example
```bash
rg "curl|wget|sudo|chmod" ./scripts
```
