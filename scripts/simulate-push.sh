#!/usr/bin/env bash
# Sends the relay's silent ("content-available") push to the iOS Simulator with `xcrun simctl push`.
#
#   scripts/simulate-push.sh                      # gmail sample payload → booted simulator
#   scripts/simulate-push.sh microsoft            # microsoft sample payload
#   scripts/simulate-push.sh gmail <accountKey>   # override the accountKey (64 hex chars; see AppConfig.accountKey)
#   DEVICE=<udid> scripts/simulate-push.sh        # target a specific simulator (default: booted)
#   BUNDLE_ID=<id> scripts/simulate-push.sh       # override the target bundle id (default: com.mazooni.PhishGuard)
#
# The sample accountKey is SHA256("foo@example.com:salt") — it matches a LinkedAccount only if you set
# RELAY_SALT=salt and link foo@example.com; otherwise the app scans every enabled account (by design).
#
# CAVEAT — the Simulator may misroute silent pushes. Apple confirmed (forum thread 652649) that the Simulator used
# to deliver content-available pushes to application(_:performFetchWithCompletionHandler:), which iOS disables once
# BGTaskSchedulerPermittedIdentifiers is present, so the push may not reach
# application(_:didReceiveRemoteNotification:fetchCompletionHandler:) at all. Recent Xcode releases reportedly
# fixed this, but it is not documented. Treat the Simulator as a smoke test only: DEVICE TESTING IS AUTHORITATIVE
# (send a real background push through the relay / APNs sandbox and watch the "app" and "scan" log categories).
#
# Requirements: the app must be installed and have been launched at least once on the target simulator
# (a force-quit app never receives silent pushes, on device or simulator). Payload must stay <= 4096 bytes.
set -euo pipefail
cd "$(dirname "$0")/.."

PROVIDER="${1:-gmail}"
ACCOUNT_KEY="${2:-}"
DEVICE="${DEVICE:-booted}"
BUNDLE_ID="${BUNDLE_ID:-com.mazooni.PhishGuard}"

case "$PROVIDER" in
  gmail|microsoft) ;;
  *) echo "provider must be 'gmail' or 'microsoft' (got '$PROVIDER')" >&2; exit 2 ;;
esac

PAYLOAD_FILE="scripts/push-${PROVIDER}.apns"
if [ ! -f "$PAYLOAD_FILE" ]; then
  echo "missing $PAYLOAD_FILE" >&2
  exit 2
fi

if [ -n "$ACCOUNT_KEY" ]; then
  if ! [[ "$ACCOUNT_KEY" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "accountKey must be 64 hex characters (SHA-256)" >&2
    exit 2
  fi
  PAYLOAD=$(printf '{"aps":{"content-available":1},"provider":"%s","accountKey":"%s"}' "$PROVIDER" "$ACCOUNT_KEY")
  echo "Pushing to $DEVICE ($BUNDLE_ID): $PAYLOAD"
  printf '%s' "$PAYLOAD" | xcrun simctl push "$DEVICE" "$BUNDLE_ID" -
else
  echo "Pushing $PAYLOAD_FILE to $DEVICE ($BUNDLE_ID)"
  xcrun simctl push "$DEVICE" "$BUNDLE_ID" "$PAYLOAD_FILE"
fi

echo "Sent. Watch the log with:"
echo "  xcrun simctl spawn $DEVICE log stream --predicate 'subsystem == \"com.mazooni.PhishGuard\"' --level info"
