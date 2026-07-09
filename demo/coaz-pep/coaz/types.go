// Package coaz implements the PEP side of the OpenID AuthZEN MCP profile
// ("COAZ"): discovery of x-coaz-mapping declarations from an MCP server's
// tools/list, CEL evaluation of the mapping against a tools/call request and
// the caller's token claims, construction of AuthZEN evaluation(s) requests
// per the profile's processing rules, and the profile's JSON-RPC error
// semantics.
//
// Spec: https://github.com/openid/authzen/blob/main/profiles/authzen-mcp-profile-1_0.md
package coaz

import "encoding/json"

// JSON-RPC error codes defined (or adopted) by the COAZ profile.
const (
	// CodeMappingError: the PEP could not construct a valid AuthZEN request
	// from the x-coaz-mapping and the tools/call parameters (Invalid params).
	CodeMappingError = -32602
	// CodeDenied: the AuthZEN PDP returned a deny decision.
	CodeDenied = -32401
	// CodePDPError: the PEP could not complete the check (PDP unreachable /
	// invalid response). Standard JSON-RPC internal error.
	CodePDPError = -32603
)

// Mapping is a parsed x-coaz-mapping object. Field elements are raw AuthZEN
// objects whose string leaves are CEL expressions (static values are CEL
// string literals, e.g. `'customer'`).
type Mapping struct {
	Subject  []map[string]any `json:"subject"`
	Action   []map[string]any `json:"action"`
	Resource []map[string]any `json:"resource"`
	Context  []map[string]any `json:"context"`
}

// Tool is the subset of an MCP tools/list entry the PEP needs.
type Tool struct {
	Name        string         `json:"name"`
	Coaz        bool           `json:"coaz"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Verdict is the outcome of a COAZ check for one tools/call.
type Verdict struct {
	// CoazTool is false when the tool does not declare coaz:true — the caller
	// should apply its non-COAZ (legacy) behaviour.
	CoazTool bool
	// Decision is the PDP outcome (only meaningful when CoazTool).
	Decision bool
	// JSONRPCError is the profile-mandated protocol error response body to
	// return to the MCP client (HTTP 200, application/json) when the call must
	// not proceed. Nil on permit.
	JSONRPCError json.RawMessage
	// Reason is a human-readable summary for logs / decision headers.
	Reason string
	// PDPRequest is the AuthZEN request that was sent (for transcripts/tests).
	PDPRequest json.RawMessage
}

// jsonRPCError renders a JSON-RPC 2.0 error response with the request's id.
func jsonRPCError(id any, code int, message string) json.RawMessage {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": message},
	}
	raw, _ := json.Marshal(resp)
	return raw
}
