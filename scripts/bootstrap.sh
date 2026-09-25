#!/usr/bin/env bash
# Bootstraps a fresh checkout: creates the gitignored Secrets.xcconfig from the example (if missing)
# and regenerates PhishGuard.xcodeproj from project.yml with XcodeGen.
set -euo pipefail
cd "$(dirname "$0")/.."

CONFIG_DIR="App/PhishGuard/Config"
if [ ! -f "$CONFIG_DIR/Secrets.xcconfig" ]; then
  cp "$CONFIG_DIR/Secrets.example.xcconfig" "$CONFIG_DIR/Secrets.xcconfig"
  echo "Created $CONFIG_DIR/Secrets.xcconfig from Secrets.example.xcconfig — fill in real values (it is gitignored)."
fi

XCODEGEN="${XCODEGEN:-}"
if [ -z "$XCODEGEN" ]; then
  if command -v xcodegen >/dev/null 2>&1; then
    XCODEGEN="$(command -v xcodegen)"
  elif [ -x /opt/homebrew/bin/xcodegen ]; then
    XCODEGEN=/opt/homebrew/bin/xcodegen
  else
    echo "xcodegen not found. Install with: brew install xcodegen" >&2
    exit 1
  fi
fi

"$XCODEGEN" generate --spec project.yml
echo "Generated PhishGuard.xcodeproj"
