# Installation

## Cargo

```bash
cargo install --path crates/skill-veil-cli
```

## GitHub Releases

Tagged releases publish prebuilt archives for:

- Linux x86_64
- macOS x86_64
- macOS arm64

Each release archive contains:

- `skill-veil`
- `README.md`
- `LICENSE`

Release assets also include:

- `benchmark-report.json`
- `benchmark-history.json`
- `checksums.txt`

## Recommended first-run check

```bash
skill-veil --version
skill-veil scan-file examples/malicious-skill/SKILL.md
```

## Integrity

Use `checksums.txt` from the release to verify downloaded archives before
placing the binary in your `PATH`.
