#!/usr/bin/env bash
# run_webcrack.sh — install webcrack if needed, run it on a JS file,
# and print the output directory path on success.
#
# Usage: bash run_webcrack.sh <input.js> [output_dir]
#
# Exit codes:
#   0  success (output dir path printed to stdout)
#   1  bad usage
#   2  node/npm not available
#   3  webcrack install failed
#   4  webcrack run failed

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <input.js> [output_dir]" >&2
  exit 1
fi

INPUT="$1"
OUTPUT="${2:-${INPUT}.webcrack-out}"

if [[ ! -f "$INPUT" ]]; then
  echo "Input file not found: $INPUT" >&2
  exit 1
fi

# Ensure node is available
if ! command -v node >/dev/null 2>&1; then
  echo "node is not installed or not on PATH. webcrack requires Node.js 22 or 24." >&2
  exit 2
fi

NODE_MAJOR=$(node -e 'console.log(process.versions.node.split(".")[0])')
if [[ "$NODE_MAJOR" -lt 22 ]]; then
  echo "Node.js $NODE_MAJOR detected. webcrack requires Node.js 22 or 24." >&2
  exit 2
fi

# Locate or install webcrack
WEBCRACK_BIN=""
if command -v webcrack >/dev/null 2>&1; then
  WEBCRACK_BIN="webcrack"
elif [[ -x "$HOME/.npm-global/bin/webcrack" ]]; then
  WEBCRACK_BIN="$HOME/.npm-global/bin/webcrack"
else
  echo "webcrack not found. Installing..." >&2
  if npm install -g webcrack >&2 2>/dev/null; then
    WEBCRACK_BIN="webcrack"
  else
    # Fall back to a user-local prefix (no sudo needed)
    mkdir -p "$HOME/.npm-global"
    npm config set prefix "$HOME/.npm-global" >&2
    if npm install -g webcrack >&2; then
      WEBCRACK_BIN="$HOME/.npm-global/bin/webcrack"
    else
      echo "Failed to install webcrack via npm." >&2
      exit 3
    fi
  fi
fi

# Run webcrack
if ! "$WEBCRACK_BIN" "$INPUT" -o "$OUTPUT" -f >&2; then
  echo "webcrack failed on $INPUT" >&2
  exit 4
fi

# Print the output directory so the caller can pick it up
echo "$OUTPUT"
