#!/usr/bin/env sh
# Register the autonomous agent as a CIBA client in PingFederate via the admin API.
#
# CIBA is already enabled on the PF (OP metadata advertises /as/bc-auth.ciba + the
# urn:openid:params:grant-type:ciba grant + poll/ping). This creates the client the agent
# (and ciba-cli) authenticate as: CIBA grant, private_key_jwt auth with our public JWK,
# poll delivery, signed request objects required (FAPI), and the payment RAR type enabled
# so the existing pf-rar-paz-plugin governs the payment at issuance.
#
# Prereq: a CIBA Request Policy must exist (the PingOne MFA CIBA Authenticator) — set
# CIBA_POLICY_ID to its id. Until then this still creates the client; CIBA calls will fail
# with an "no request policy" style error until the policy is wired.
#
# Usage:
#   ADMIN=https://localhost:9999 PF_USER=administrator PF_PASS=… CIBA_POLICY_ID=<id> \
#   ./register-ciba-client.sh
#
# NOTE: exact PF admin-API enum values (grantTypes, clientAuthnType, cibaDeliveryMode) vary
# by version — verify against $ADMIN/pf-admin-api/api-docs or by GETting an existing client.
set -eu
ADMIN="${ADMIN:-https://localhost:9999}"
PF_USER="${PF_USER:-administrator}"
: "${PF_PASS:?set PF_PASS}"
CLIENT_ID="${CLIENT_ID:-northwind-autonomous-agent}"
CIBA_POLICY_ID="${CIBA_POLICY_ID:-}"
JWKS="$(cat "$(dirname "$0")/ciba-pub-jwk.json")"

curl -sk -u "$PF_USER:$PF_PASS" -H 'X-XSRF-Header: PingFederate' -H 'Content-Type: application/json' \
  -X POST "$ADMIN/pf-admin-api/v1/oauth/clients" -d @- <<JSON
{
  "clientId": "$CLIENT_ID",
  "name": "Autonomous Agent (CIBA · principal=Bob)",
  "grantTypes": ["CIBA"],
  "clientAuthnType": "PRIVATE_KEY_JWT",
  "jwksSettings": { "jwks": $(printf '%s' "$JWKS" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))') },
  "cibaDeliveryMode": "POLL",
  "cibaRequireSignedRequests": true,
  "cibaPolicyRef": $( [ -n "$CIBA_POLICY_ID" ] && printf '{ "id": "%s" }' "$CIBA_POLICY_ID" || printf 'null' ),
  "requireSignedRequests": true,
  "restrictScopes": true,
  "restrictedScopes": ["openid", "banking:payments:transfer"],
  "restrictedAuthorizationDetailTypes": ["payment_initiation"],
  "authorizationDetailTypesRestricted": true
}
JSON
echo
