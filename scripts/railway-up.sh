#!/usr/bin/env bash
# Deploy a service directory to Railway via the /up endpoint directly.
#
# Workaround for `railway up` (CLI 5.23.x) whose upload path times out /
# mis-indexes on this machine: every CLI upload of authzen-extauthz died in
# SNAPSHOT_CODE ("Failed to create code snapshot") after 15 minutes, while a
# plain tarball POST of the same directory deploys in seconds (2026-07-10).
#
# Usage:
#   RAILWAY_API_TOKEN=... scripts/railway-up.sh <service-dir> <serviceId> [environmentId]
# Example (authzen-extauthz, staging):
#   scripts/railway-up.sh demo/coaz-pep 856fcefd-39b1-446d-a3e2-3a7c9faf32b4
set -euo pipefail

PROJECT_ID="ac9af096-edc5-48b9-a147-beb71ed275ea"
DEFAULT_ENV_ID="88d3b0c8-de04-4cac-a3ec-e78e822735cc" # staging

DIR="${1:?service directory}"
SERVICE_ID="${2:?serviceId}"
ENV_ID="${3:-$DEFAULT_ENV_ID}"
TOKEN="${RAILWAY_API_TOKEN:?set RAILWAY_API_TOKEN}"

TARBALL=$(mktemp -t railway-up).tar.gz
# tar the service dir only, honouring .gitignore via git's exclude machinery
(cd "$DIR" && git ls-files -co --exclude-standard -z | tar czf "$TARBALL" --null -T -)
echo "payload: $(du -h "$TARBALL" | cut -f1) from $DIR"

RESP=$(curl -sf -X POST \
  "https://backboard.railway.com/project/$PROJECT_ID/environment/$ENV_ID/up?serviceId=$SERVICE_ID" \
  -H "authorization: Bearer $TOKEN" \
  -H "content-type: application/gzip" \
  --data-binary @"$TARBALL")
rm -f "$TARBALL"

DEPLOY_ID=$(echo "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['deploymentId'])")
echo "deployment: $DEPLOY_ID"

# poll to terminal state
while :; do
  STATUS=$(curl -s https://backboard.railway.com/graphql/v2 \
    -H "content-type: application/json" -H "authorization: Bearer $TOKEN" \
    -d "{\"query\":\"query { deployment(id: \\\"$DEPLOY_ID\\\") { status } }\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['deployment']['status'])")
  echo "  $STATUS"
  case "$STATUS" in
    SUCCESS) exit 0 ;;
    FAILED|CRASHED|REMOVED) echo "deploy did not succeed" >&2; exit 1 ;;
  esac
  sleep 10
done
