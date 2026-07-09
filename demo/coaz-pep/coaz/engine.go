package coaz

// Engine ties discovery + mapping + PDP together: given one tools/call
// JSON-RPC request and the caller's token claims, produce a Verdict with the
// profile's JSON-RPC error semantics.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PDPConfig locates the AuthZEN PDP (e.g. the Ping Authorize authzen-adapter).
type PDPConfig struct {
	// URL is the AuthZEN API base, e.g. http://authzen-adapter:8080 — the
	// engine appends /access/v1/evaluation(s).
	URL string
	// APIKey is sent as a Bearer token to the PDP.
	APIKey string
	// HTTPClient overrides the default (10s timeout) client.
	HTTPClient *http.Client
}

// Options configures an Engine.
type Options struct {
	PDP PDPConfig
	// DiscoveryTTL bounds how long a tools/list snapshot is reused (default 60s).
	DiscoveryTTL time.Duration
	// DiscoveryHTTPClient overrides the client used for tools/list fetches.
	DiscoveryHTTPClient *http.Client
}

type Engine struct {
	pdp   PDPConfig
	pdpc  *http.Client
	disco *discoveryCache
}

func NewEngine(opts Options) *Engine {
	ttl := opts.DiscoveryTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	pdpc := opts.PDP.HTTPClient
	if pdpc == nil {
		pdpc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Engine{
		pdp:   opts.PDP,
		pdpc:  pdpc,
		disco: newDiscoveryCache(ttl, opts.DiscoveryHTTPClient),
	}
}

// CheckToolCall runs the COAZ flow for one tools/call JSON-RPC request.
//
//	upstreamURL   — the MCP server whose tools/list declares the mappings
//	authorization — the caller's Authorization header (reused for discovery)
//	rpcBody       — the raw tools/call JSON-RPC request body
//	tokenClaims   — decoded claims of the caller's access token
func (e *Engine) CheckToolCall(ctx context.Context, upstreamURL, authorization string, rpcBody []byte, tokenClaims map[string]any) Verdict {
	var rpc struct {
		ID     any            `json:"id"`
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(rpcBody, &rpc); err != nil || rpc.Method != "tools/call" {
		return Verdict{CoazTool: false, Decision: true, Reason: "not a tools/call request"}
	}
	toolName, _ := rpc.Params["name"].(string)
	if toolName == "" {
		return Verdict{CoazTool: false, Decision: true, Reason: "tools/call without a tool name"}
	}

	dt, err := e.disco.lookup(ctx, upstreamURL, authorization, toolName)
	if err != nil {
		// Cannot know whether the tool is COAZ — fail closed per the
		// profile's PDP-communication semantics.
		return Verdict{CoazTool: true, Decision: false,
			Reason:       fmt.Sprintf("COAZ discovery failed: %v", err),
			JSONRPCError: jsonRPCError(rpc.ID, CodePDPError, "Authorization check unavailable: tool discovery failed")}
	}
	if dt == nil || !dt.tool.Coaz {
		return Verdict{CoazTool: false, Decision: true, Reason: "tool is not COAZ-declared"}
	}
	if dt.mappingErr != nil {
		return Verdict{CoazTool: true, Decision: false,
			Reason:       fmt.Sprintf("COAZ mapping error: %v", dt.mappingErr),
			JSONRPCError: jsonRPCError(rpc.ID, CodeMappingError, fmt.Sprintf("COAZ mapping error: %v", dt.mappingErr))}
	}

	built, err := dt.mapping.Build(rpc.Params, tokenClaims)
	if err != nil {
		return Verdict{CoazTool: true, Decision: false,
			Reason:       fmt.Sprintf("COAZ mapping error: %v", err),
			JSONRPCError: jsonRPCError(rpc.ID, CodeMappingError, fmt.Sprintf("COAZ mapping error: %v", err))}
	}

	decision, reason, err := e.evaluate(ctx, built)
	if err != nil {
		return Verdict{CoazTool: true, Decision: false, PDPRequest: built.Body,
			Reason:       fmt.Sprintf("PDP error: %v", err),
			JSONRPCError: jsonRPCError(rpc.ID, CodePDPError, "Authorization service unavailable")}
	}
	if !decision {
		msg := "Access denied"
		if reason != "" {
			msg = "Access denied: " + reason
		}
		return Verdict{CoazTool: true, Decision: false, PDPRequest: built.Body, Reason: msg,
			JSONRPCError: jsonRPCError(rpc.ID, CodeDenied, msg)}
	}
	if reason == "" {
		reason = "Permitted by policy."
	}
	return Verdict{CoazTool: true, Decision: true, PDPRequest: built.Body, Reason: reason}
}

// evaluate POSTs the built request to the AuthZEN PDP and folds the
// decision(s): every decision must be true for a permit.
func (e *Engine) evaluate(ctx context.Context, built *BuiltRequest) (bool, string, error) {
	endpoint := e.pdp.URL + "/access/v1/evaluation"
	if built.Batch {
		endpoint = e.pdp.URL + "/access/v1/evaluations"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(built.Body))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.pdp.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.pdp.APIKey)
	}
	resp, err := e.pdpc.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, "", fmt.Errorf("PDP returned %d", resp.StatusCode)
	}

	type decision struct {
		Decision bool `json:"decision"`
		Context  *struct {
			Reason string `json:"reason"`
		} `json:"context"`
	}
	if !built.Batch {
		var d decision
		if err := json.Unmarshal(raw, &d); err != nil {
			return false, "", fmt.Errorf("bad PDP response: %w", err)
		}
		reason := ""
		if d.Context != nil {
			reason = d.Context.Reason
		}
		return d.Decision, reason, nil
	}
	var batch struct {
		Evaluations []decision `json:"evaluations"`
	}
	if err := json.Unmarshal(raw, &batch); err != nil {
		return false, "", fmt.Errorf("bad PDP evaluations response: %w", err)
	}
	if len(batch.Evaluations) == 0 {
		return false, "", fmt.Errorf("PDP evaluations response was empty")
	}
	for _, d := range batch.Evaluations {
		if !d.Decision {
			reason := ""
			if d.Context != nil {
				reason = d.Context.Reason
			}
			return false, reason, nil
		}
	}
	return true, "", nil
}
