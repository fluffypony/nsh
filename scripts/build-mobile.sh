#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../mobile"

echo "=== Installing JS dependencies ==="
npm install

echo "=== Building iOS ==="
cargo tauri ios build

echo "=== Building Android ==="
cargo tauri android build

echo "=== Done ==="
