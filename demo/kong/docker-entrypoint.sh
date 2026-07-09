#!/bin/sh
# Render the declarative config from its template (substituting upstream URLs
# that differ between docker-compose and Railway), then start Kong.
set -e

: "${BANK_MCP_URL:=http://bank-mcp:8090}"
: "${BANK_API_URL:=http://bank-api:8070}"
: "${AUTHZEN_URL:=http://authzen-adapter:8080}"
: "${COAZ_URL:=http://coaz-pep:9192}"

sed -e "s|__BANK_MCP_URL__|${BANK_MCP_URL}|g" \
    -e "s|__BANK_API_URL__|${BANK_API_URL}|g" \
    -e "s|__AUTHZEN_URL__|${AUTHZEN_URL}|g" \
    -e "s|__COAZ_URL__|${COAZ_URL}|g" \
    /kong/kong.yml.template > /kong/kong.yml

exec /docker-entrypoint.sh kong docker-start
