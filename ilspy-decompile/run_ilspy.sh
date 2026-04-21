#!/usr/bin/env bash
# run_ilspy.sh — install ilspycmd if needed, run it on a .NET assembly
# in project mode, and print the output directory path on success.
#
# Usage: bash run_ilspy.sh <input.dll|exe|netmodule|winmd> [output_dir]
#
# Exit codes:
#   0  success (output dir path printed to stdout)
#   1  bad usage / input missing
#   2  dotnet SDK not available
#   3  ilspycmd install failed
#   4  ilspycmd run failed

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <input.dll|exe|netmodule|winmd> [output_dir]" >&2
  exit 1
fi

INPUT="$1"
OUTPUT="${2:-${INPUT}.ilspy-out}"

if [[ ! -f "$INPUT" ]]; then
  echo "Input file not found: $INPUT" >&2
  exit 1
fi

# Ensure dotnet SDK is available (not just the runtime).
if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet is not installed or not on PATH. ilspycmd requires the .NET SDK (9.0+ recommended)." >&2
  exit 2
fi

if ! dotnet --list-sdks >/dev/null 2>&1 || [[ -z "$(dotnet --list-sdks 2>/dev/null)" ]]; then
  echo "No .NET SDKs are installed (only runtime was found). ilspycmd needs the SDK to run as a global tool." >&2
  exit 2
fi

# Locate or install ilspycmd.
TOOLS_DIR="${DOTNET_TOOLS_DIR:-$HOME/.dotnet/tools}"
ILSPY_BIN=""
if command -v ilspycmd >/dev/null 2>&1; then
  ILSPY_BIN="ilspycmd"
elif [[ -x "$TOOLS_DIR/ilspycmd" ]]; then
  ILSPY_BIN="$TOOLS_DIR/ilspycmd"
else
  echo "ilspycmd not found. Installing as a dotnet global tool..." >&2
  if dotnet tool install -g ilspycmd >&2; then
    if command -v ilspycmd >/dev/null 2>&1; then
      ILSPY_BIN="ilspycmd"
    elif [[ -x "$TOOLS_DIR/ilspycmd" ]]; then
      ILSPY_BIN="$TOOLS_DIR/ilspycmd"
    else
      echo "ilspycmd installed but not on PATH. Add $TOOLS_DIR to PATH and retry." >&2
      exit 3
    fi
  else
    # Fall back to a local tool manifest in the current directory.
    echo "Global install failed; falling back to a local tool manifest." >&2
    dotnet new tool-manifest --force >&2
    if dotnet tool install ilspycmd >&2; then
      ILSPY_BIN="dotnet tool run ilspycmd --"
    else
      echo "Failed to install ilspycmd via dotnet tool." >&2
      exit 3
    fi
  fi
fi

mkdir -p "$OUTPUT"

# Resolve sibling DLLs from the input's directory so references don't warn.
INPUT_DIR="$(cd "$(dirname "$INPUT")" && pwd)"

# Run ilspycmd in project mode.
# shellcheck disable=SC2086  # ILSPY_BIN may legitimately contain multiple words for the local-manifest fallback.
if ! $ILSPY_BIN "$INPUT" -p -r "$INPUT_DIR" -o "$OUTPUT" >&2; then
  echo "ilspycmd failed on $INPUT" >&2
  exit 4
fi

# Print the output directory so the caller can pick it up.
echo "$OUTPUT"
