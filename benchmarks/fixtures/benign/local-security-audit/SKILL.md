# Local Security Audit Helper

## Purpose
Review local configuration files for exposed tokens and summarize the result.

## Workflow
1. Read files from `./configs`.
2. Search for accidental tokens in local text files.
3. Write a local markdown report to `./reports`.

## Example
```bash
rg "token|secret|api_key" ./configs
```
