package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// decodeJWTClaims decodes (without verifying) the claim set from a compact JWT.
//
// The gateway uses these claims (sub, aud, client_id) only to build the AuthZEN
// request; the authoritative authorization decision is made by the PDP. Token
// signature validation / introspection is expected to be performed upstream
// (e.g. by the MCP server's OAuth resource-server layer) or added here before
// production use — see the README.
func decodeJWTClaims(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a JWT: expected at least 2 segments, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Tolerate tokens encoded with padding.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("decoding JWT payload: %w", err)
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims: %w", err)
	}
	return claims, nil
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header
// value, or returns "" when absent/malformed.
func bearerToken(authHeader string) string {
	const prefix = "Bearer "
	if len(authHeader) < len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(authHeader[len(prefix):])
}
