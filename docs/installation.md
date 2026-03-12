# Installation

## Cargo

```bash
cargo install --path crates/skill-veil-cli
```

## GitHub Releases

Tagged releases publish prebuilt archives for:

- Linux x86_64
- Linux arm64
- Windows x86_64
- Windows arm64
- macOS x86_64
- macOS arm64

Each release archive contains:

- `skill-veil` or `skill-veil.exe`
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

## Install helper

The repository ships a small helper that understands both `.tar.gz` and `.zip`
release artifacts:

```bash
./scripts/install-release.sh skill-veil-linux-x86_64.tar.gz "$HOME/.local/bin"
./scripts/install-release.sh skill-veil-windows-x86_64.zip "$HOME/bin"
```
