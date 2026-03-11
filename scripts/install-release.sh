#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <archive.tar.gz> <install-dir>" >&2
  exit 1
fi

archive="$1"
install_dir="$2"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

tar -xzf "$archive" -C "$tmp_dir"
binary_path="$(find "$tmp_dir" -type f -name skill-veil | head -n 1)"

if [[ -z "${binary_path:-}" ]]; then
  echo "skill-veil binary not found inside archive" >&2
  exit 1
fi

mkdir -p "$install_dir"
install -m 0755 "$binary_path" "$install_dir/skill-veil"
echo "installed to $install_dir/skill-veil"
