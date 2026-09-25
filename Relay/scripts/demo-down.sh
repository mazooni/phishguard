#!/usr/bin/env bash
# Stops the relay and the ngrok tunnel started by scripts/demo-up.sh.
LOG_DIR="${TMPDIR:-/tmp}/phishguard-demo"
if [ -f "$LOG_DIR/relay.pid" ]; then kill "$(cat "$LOG_DIR/relay.pid")" 2>/dev/null && echo "relay stopped"; rm -f "$LOG_DIR/relay.pid"; fi
pkill -f "ngrok http" 2>/dev/null && echo "ngrok stopped" || true
