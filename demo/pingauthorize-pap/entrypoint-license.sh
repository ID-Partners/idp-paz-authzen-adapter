#!/usr/bin/env sh
# Materialize the PingAuthorize license from the PING_LICENSE env var (kept only
# in Railway, never in git or the image), then hand off to the stock PingAuthorize
# bootstrap. Railway's build upload only ships git-tracked files, so the license
# can't be baked into the image; injecting it at runtime keeps it out of both.
set -e

LICENSE_DIR="${LICENSE_DIR:-/opt/in/instance}"
if [ -n "${PING_LICENSE:-}" ]; then
  mkdir -p "$LICENSE_DIR" 2>/dev/null || true
  printf '%s\n' "$PING_LICENSE" > "$LICENSE_DIR/PingAuthorize.lic"
  echo "entrypoint-license: wrote $LICENSE_DIR/PingAuthorize.lic"
else
  echo "entrypoint-license: WARNING PING_LICENSE not set; expecting a license elsewhere"
fi

exec /opt/bootstrap.sh "$@"
