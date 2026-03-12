#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <archive.{tar.gz,zip}> <install-dir>" >&2
  exit 1
fi

archive="$1"
install_dir="$2"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

case "$archive" in
  *.tar.gz|*.tgz)
    tar -xzf "$archive" -C "$tmp_dir"
    binary_name="skill-veil"
    ;;
  *.zip)
    unzip -q "$archive" -d "$tmp_dir"
    binary_name="skill-veil.exe"
    ;;
  *)
    echo "unsupported archive format: $archive" >&2
    exit 1
    ;;
esac

binary_path="$(find "$tmp_dir" -type f -name "$binary_name" | head -n 1)"

if [[ -z "${binary_path:-}" ]]; then
  echo "$binary_name binary not found inside archive" >&2
  exit 1
fi

mkdir -p "$install_dir"
if [[ "$binary_name" = "skill-veil.exe" ]]; then
  cp "$binary_path" "$install_dir/skill-veil.exe"
  echo "installed to $install_dir/skill-veil.exe"
else
  install -m 0755 "$binary_path" "$install_dir/skill-veil"
  echo "installed to $install_dir/skill-veil"
fi
