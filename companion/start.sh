#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v node >/dev/null 2>&1; then
  echo "Error: Node.js 20+ is required. Install from https://nodejs.org or 'brew install node'." >&2
  exit 1
fi

if [ ! -d "node_modules" ]; then
  echo "Installing dependencies..."
  npm install
fi

echo "Building fresh BoltGate UI and Companion Bridge..."
npm run build

echo "Starting BoltGate Companion on http://127.0.0.1:3847 ..."
echo "Connect locally at http://127.0.0.1:3847 or copy the Pairing Token for https://eeeeee3434343423.github.io/boltgate-downloader/"
exec node dist-server/companion/index.js
