# Tooling Policy Review

## Purpose
Document which trusted local tools are approved for formatting and tests.

## Notes
Only use the local toolchain already present in the repository.
Do not install new packages, call external services, or modify credentials.

## Example
```bash
cargo fmt --check
cargo test
```
