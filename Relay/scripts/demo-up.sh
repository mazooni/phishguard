#!/usr/bin/env bash
# Brings the Call Guard demo up on this Mac: ngrok tunnel → Relay/.env PUBLIC_BASE_URL → built relay in the
# background → Twilio webhooks (calls:setup) → the app's RELAY_BASE_URL in Secrets.xcconfig. Idempotent: run it
# again after a reboot or whenever the tunnel URL changed (then rebuild the app once). `scripts/demo-down.sh` stops it.
set -euo pipefail
cd "$(dirname "$0")/.."
ENV_FILE=.env
XCCONFIG=../App/PhishGuard/Config/Secrets.xcconfig
LOG_DIR="${TMPDIR:-/tmp}/phishguard-demo"
mkdir -p "$LOG_DIR"
[ -f "$ENV_FILE" ] || { echo "Relay/.env is missing (copy .env.example and fill it in)"; exit 1; }
port=$(grep -E '^PORT=' "$ENV_FILE" | cut -d= -f2); port=${port:-8080}

# 1. Tunnel (kept if one is already running). NGROK_DOMAIN in .env (a free static domain claimed in the ngrok
#    dashboard) keeps the URL stable across restarts, so the app never needs rebuilding for a new URL.
domain=$(grep -E '^NGROK_DOMAIN=' "$ENV_FILE" | cut -d= -f2 || true)
if ! curl -sf localhost:4040/api/tunnels >/dev/null 2>&1; then
  echo "starting ngrok http $port ${domain:+--url=$domain }…"
  nohup ngrok http "$port" ${domain:+--url="$domain"} --log=stdout > "$LOG_DIR/ngrok.log" 2>&1 &
  for _ in $(seq 1 30); do sleep 1; curl -sf localhost:4040/api/tunnels >/dev/null 2>&1 && break; done
fi
url=$(curl -sf localhost:4040/api/tunnels | python3 -c "import sys,json; print([t['public_url'] for t in json.load(sys.stdin)['tunnels'] if t['public_url'].startswith('https')][0])") \
  || { echo "ngrok did not come up; see $LOG_DIR/ngrok.log (run 'ngrok config add-authtoken <token>' once if you never have)"; exit 1; }
echo "tunnel: $url"

# 2. Relay config + restart.
sed -i '' "s|^PUBLIC_BASE_URL=.*|PUBLIC_BASE_URL=${url}|" "$ENV_FILE"
if [ -f "$LOG_DIR/relay.pid" ] && kill -0 "$(cat "$LOG_DIR/relay.pid")" 2>/dev/null; then
  kill "$(cat "$LOG_DIR/relay.pid")"; sleep 1
fi
npm run build --silent
nohup node --env-file="$ENV_FILE" dist/index.js > "$LOG_DIR/relay.log" 2>&1 &
echo $! > "$LOG_DIR/relay.pid"
for _ in $(seq 1 20); do sleep 1; curl -sf "localhost:$port/healthz" >/dev/null 2>&1 && break; done
curl -sf "localhost:$port/healthz" >/dev/null || { echo "relay did not start; see $LOG_DIR/relay.log"; exit 1; }
echo "relay: running (log $LOG_DIR/relay.log)"

# 3. Twilio webhooks.
npm run calls:setup --silent

# 4. The app's relay URL (xcconfig needs the empty $() to keep // from starting a comment).
if [ -f "$XCCONFIG" ]; then
  xc_url=$(echo "$url" | sed 's|https://|https:/$()/|')
  sed -i '' "s|^RELAY_BASE_URL = .*|RELAY_BASE_URL = ${xc_url}|" "$XCCONFIG"
  echo "app: RELAY_BASE_URL set in Secrets.xcconfig → rebuild the app in Xcode if the URL changed"
fi

key=$(grep -E '^CALLS_CONSOLE_KEY=' "$ENV_FILE" | cut -d= -f2)
[ -n "$key" ] || key=$(grep -E '^RELAY_API_KEY=' "$ENV_FILE" | cut -d= -f2)
console_url="${url}/v1/calls/console?key=${key}"
echo
echo "Operator console: ${console_url}"
echo "Guard number:     $(grep -E '^TWILIO_NUMBER=' "$ENV_FILE" | cut -d= -f2)"
echo "Stop everything:  scripts/demo-down.sh"
command -v open >/dev/null && open "$console_url"
