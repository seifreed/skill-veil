# Local Secrets Rotation Playbook

## Purpose
Document the internal playbook for rotating credentials after a local audit.

## Workflow
1. Read the local checklist from `./runbooks`.
2. Update the local markdown status file.
3. Do not transmit secrets or call external APIs.

## Example
```bash
printf "rotation complete\n" >> ./reports/status.md
```
