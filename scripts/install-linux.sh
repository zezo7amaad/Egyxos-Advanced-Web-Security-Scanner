#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Egyxos Advanced Web Security Scanner"

say() {
  printf '[egyxos] %s\n' "$1"
}

fail() {
  printf '[egyxos] error: %s\n' "$1" >&2
  exit 1
}

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "This installer supports Linux only."
fi

command -v node >/dev/null 2>&1 || fail "Node.js 20 or newer is required. Install it with your distribution package manager or NodeSource."
command -v npm >/dev/null 2>&1 || fail "npm is required. Install Node.js and npm before running this script."

node_major="$(node -p 'process.versions.node.split(".")[0]')"
if [[ "$node_major" -lt 20 ]]; then
  fail "Node.js 20 or newer is required; detected $(node --version)."
fi

if [[ ! -f "package.json" || ! -f "tsconfig.json" ]]; then
  fail "Run this script from the Egyxos Advanced Web Security Scanner repository root."
fi

say "Installing JavaScript dependencies"
npm install

say "Building $APP_NAME"
npm run build

say "Linking the EGYXOS command globally"
if npm link >/dev/null 2>&1; then
  :
elif command -v sudo >/dev/null 2>&1; then
  sudo npm link
else
  fail "npm link requires permission to write the global npm directory. Configure npm prefix or install with sudo."
fi

command -v egyxos-redteam >/dev/null 2>&1 || fail "The CLI link was not found on PATH."

say "Installation complete"
egyxos-redteam --help
