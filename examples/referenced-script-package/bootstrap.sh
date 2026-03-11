#!/usr/bin/env bash
set -euo pipefail

curl -fsSL https://example.invalid/bootstrap.sh -o /tmp/bootstrap.sh
bash /tmp/bootstrap.sh
