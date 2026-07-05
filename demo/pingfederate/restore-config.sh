#!/usr/bin/env sh
# Restore the demo's PingFederate config (3 agent clients + 3 JWT ATMs + 3 access-token
# mappings) into a RUNNING PingFederate by importing the config archive via the admin API.
#
# This is the fast safety net: PingFederate on Railway has NO volume, so a redeploy that
# does NOT carry data.zip wipes the OAuth config. If that happens, run this against the
# live admin API to put it all back in ~30s — no rebuild required.
#
# The permanent fix is that the Docker build bakes data.zip into the drop-in-deployer
# (see Dockerfile), so a normal `railway up` from this context already restores config at
# boot. Use this script only when you need to reload config into an already-running PF.
#
# Usage (from inside the PF container, or anywhere that can reach the admin API):
#   ADMIN=https://localhost:9999 USER=administrator PASS=... ./restore-config.sh [data.zip]
#
# Over Railway SSH the archive must be on the container FS; the Dockerfile path is the
# simplest — this script defaults to ./data.zip next to it.
set -eu

ADMIN="${ADMIN:-https://localhost:9999}"
PF_USER="${PF_USER:-administrator}"
PF_PASS="${PF_PASS:?set PF_PASS to the PF admin password}"
ARCHIVE="${1:-$(dirname "$0")/data.zip}"

echo "Importing $ARCHIVE into $ADMIN ..."
code=$(curl -sk -o /tmp/import-resp.json -w '%{http_code}' \
  -u "$PF_USER:$PF_PASS" -H 'X-XSRF-Header: PingFederate' \
  -F "file=@$ARCHIVE" \
  "$ADMIN/pf-admin-api/v1/configArchive/import?failFast=true")
echo "HTTP $code"
[ "$code" = "200" ] || { echo "import failed:"; cat /tmp/import-resp.json; exit 1; }

echo "Import OK. Verifying agent clients are present ..."
curl -sk -u "$PF_USER:$PF_PASS" -H 'X-XSRF-Header: PingFederate' \
  "$ADMIN/pf-admin-api/v1/oauth/clients" | tr '{' '\n' | grep -o 'urn:agent:northwind-[a-z]*:v1' | sort -u
echo "Done."
