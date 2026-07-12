#!/usr/bin/env sh
# Vendor the pf-rar-paz-plugin into this PingFederate image build context FROM ITS OWN REPO.
#
# The plugin is maintained in a standalone repo (default ~/Source/pf-rar-paz-plugin). This
# builds it there and copies the two artifacts the Dockerfile bakes:
#   - pf.plugins.pf-rar-paz-plugin.jar            (→ PF deploy/)
#   - integration/consent-template/…html          (→ PF conf/template/)
# Run this after pulling plugin changes, then deploy with:
#   railway up demo/pingfederate --path-as-root --service pingfederate --no-gitignore
#
# Override the repo location:  PLUGIN_REPO=/path/to/pf-rar-paz-plugin ./vendor-plugin.sh
set -eu
PLUGIN_REPO="${PLUGIN_REPO:-$HOME/Source/pf-rar-paz-plugin}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ -f "$PLUGIN_REPO/pom.xml" ] || { echo "plugin repo not found at $PLUGIN_REPO (set PLUGIN_REPO)"; exit 1; }

echo "Building plugin in $PLUGIN_REPO ..."
( cd "$PLUGIN_REPO" && mvn -q package )

JAR="$PLUGIN_REPO/target/pf.plugins.pf-rar-paz-plugin.jar"
TPL="$PLUGIN_REPO/integration/consent-template/oauth.approval.page.template.html"

cp "$JAR" "$HERE/pf.plugins.pf-rar-paz-plugin.jar"
cp "$TPL" "$HERE/template/oauth.approval.page.template.html"

echo "Vendored:"
echo "  jar      → $HERE/pf.plugins.pf-rar-paz-plugin.jar  ($(wc -c < "$JAR") bytes)"
echo "  template → $HERE/template/oauth.approval.page.template.html"
echo "Commit these, then deploy (see header)."
