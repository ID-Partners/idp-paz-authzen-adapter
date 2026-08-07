#!/usr/bin/env bash
# Configure the PingOne Recognize (Keyless) Swift package registry so the iOS approver can link
# the real Mobile SDK. Run this ONCE per machine, then add the package in Xcode.
#
# The token is the dashboard's **Download Key** (Access Control → API Management), which is the
# Cloudsmith entitlement token — NOT the Mobile API Key (that's a runtime value, see Info.plist's
# RecognizeApiKey) and NOT the Secret API Key (backend REST only). Mixing these up produces a
# 401 from Cloudsmith that reads like a bad token rather than the wrong *kind* of token.
#
# Usage:
#   KEYLESS_DOWNLOAD_KEY=xxxx ./setup-keyless-sdk.sh
#   ./setup-keyless-sdk.sh --check          # report state, change nothing
#
# The token is never written to this repo. `swift package-registry login` stores it in the macOS
# keychain and writes only non-secret config to ~/.swiftpm/configuration/registries.json.
set -euo pipefail

REGISTRY="https://swift.cloudsmith.io/keyless/partners/"
SCOPE="keyless"
PACKAGE="keyless.mobile-sdk"          # renamed from keyless.KeylessSDK — see the SDK changelog
MODULE="Keyless"                      # what you `import`; NOT the package id, they differ
CONFIG="$HOME/.swiftpm/configuration/registries.json"

say() { printf '%s\n' "$*"; }

check() {
  say "── Keyless SPM registry state ─────────────────────────────────"
  if [ -f "$CONFIG" ]; then
    say "  config: $CONFIG"
    if grep -q 'swift.cloudsmith.io' "$CONFIG" 2>/dev/null; then
      say "  registry configured: yes"
    else
      say "  registry configured: NO (file exists but has no cloudsmith entry)"
    fi
  else
    say "  config: absent ($CONFIG)"
    say "  registry configured: NO"
  fi
  # canImport(Keyless) is what actually gates the real verifier in MFAManager.swift
  if grep -rq "import $MODULE" "$(dirname "$0")/IDPApprover" 2>/dev/null; then
    say "  source references 'import $MODULE': yes (guarded by #if canImport)"
  fi
  say "  package to add in Xcode: $PACKAGE"
  say "────────────────────────────────────────────────────────────────"
}

if [ "${1:-}" = "--check" ]; then check; exit 0; fi

TOKEN="${KEYLESS_DOWNLOAD_KEY:-}"
if [ -z "$TOKEN" ]; then
  say "ERROR: set KEYLESS_DOWNLOAD_KEY (the dashboard's Download Key)."
  say "       KEYLESS_DOWNLOAD_KEY=xxxx $0"
  exit 1
fi

# The vendor docs are explicit that Xcode should be closed: it caches registry configuration at
# launch and will keep failing to resolve the package until restarted otherwise.
if pgrep -xq Xcode; then
  say "WARNING: Xcode is running. It caches registry config at launch — quit it, re-run this,"
  say "         then reopen Xcode, or the package will fail to resolve for no visible reason."
fi

say "Configuring registry (scope: $SCOPE) …"
# --global because Xcode does not read project-local registry configuration at all.
swift package-registry set --global --scope "$SCOPE" "$REGISTRY"
say "Logging in …"
swift package-registry login "$REGISTRY" --token "$TOKEN"

say ""
check
say ""
say "Next, in Xcode:"
say "  1. File → Add Package Dependencies…"
say "  2. Search for:  $PACKAGE"
say "  3. Add the library to the IDPApprover target."
say ""
say "Then set the RUNTIME config (separate from the Download Key above) — these feed"
say "Info.plist via build-setting substitution, so nothing secret is committed:"
say "  RECOGNIZE_API_KEY   = the dashboard's Mobile API Key"
say "  RECOGNIZE_HOSTS     = comma-separated node URLs, NO trailing slashes"
say ""
say "e.g.  xcodebuild … RECOGNIZE_API_KEY=xxxx RECOGNIZE_HOSTS=https://host-a,https://host-b"
say ""
say "No code change is needed: MFAManager.swift guards the real verifier with"
say "#if canImport($MODULE), so linking the package is what switches it on. With the package"
say "linked but the runtime config unset it stays SIMULATED — deliberately fail-closed."
