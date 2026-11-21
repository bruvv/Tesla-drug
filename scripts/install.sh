#!/bin/bash
# macOS 27 Apple Silicon CLI-only installer. No sudo and no network configuration.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Darwin ]]; then
  echo "macOS is required" >&2
  exit 1
fi
if [[ "$(uname -m)" != arm64 ]]; then
  echo "An Apple Silicon Mac is required" >&2
  exit 1
fi
version="$(sw_vers -productVersion)"
if (( ${version%%.*} < 27 )); then
  echo "Requires macOS 27 or newer; detected $version" >&2
  exit 1
fi
if ! command -v brew >/dev/null 2>&1; then
  echo "Install Homebrew from https://brew.sh first" >&2
  exit 1
fi
brew install python@3.13
py="$(brew --prefix python@3.13)/bin/python3.13"
"$py" -m venv .venv
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/tesla-netlab doctor
printf '\nInstalled. Run: .venv/bin/tesla-netlab --help\n'
