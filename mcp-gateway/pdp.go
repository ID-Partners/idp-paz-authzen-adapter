package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// pdpClient calls a standards-compliant AuthZEN PDP Access Evaluation endpoint.
type pdpClient struct {
	url        string // full AuthZEN evaluation URL, e.g. https://pdp/access/v1/evaluation
	authHeader string // header used to authenticate to the PDP (e.g. "Authorization")
	authValue  string // value for that header (e.g. "Bearer <key>"); empty to omit
	http       *http.Client
}

// decision is the outcome of an AuthZEN evaluation.
type decision struct {
	Allow  bool
	Reason string
}

// evaluate POSTs an AuthZEN evaluation request and parses the boolean decision.
func (c *pdpClient) evaluate(ctx context.Context, azReq map[string]interface{}) (decision, error) {
	body, err := json.Marshal(azReq)
	if err != nil {
		return decision{}, fmt.Errorf("marshaling AuthZEN request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return decision{}, fmt.Errorf("building PDP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if c.authValue != "" {
		httpReq.Header.Set(c.authHeader, c.authValue)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return decision{}, fmt.Errorf("calling PDP: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return decision{}, fmt.Errorf("reading PDP response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return decision{}, fmt.Errorf("PDP returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed struct {
		Decision bool                   `json:"decision"`
		Context  map[string]interface{} `json:"context"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return decision{}, fmt.Errorf("decoding PDP response: %w", err)
	}

	return decision{Allow: parsed.Decision, Reason: reasonFromContext(parsed.Context)}, nil
}

// reasonFromContext extracts a human-readable reason from an AuthZEN decision
// context, tolerating the several shapes seen in the wild.
func reasonFromContext(ctx map[string]interface{}) string {
	if ctx == nil {
		return ""
	}
	if s := getStr(ctx, "reason"); s != "" {
		return s
	}
	if s := getStr(ctx, "message"); s != "" {
		return s
	}
	// AuthZEN reason objects, e.g. {"reason_user": {"en": "..."}}.
	for _, key := range []string{"reason_user", "reason_admin"} {
		if m := toMap(ctx[key]); m != nil {
			if s := getStr(m, "en"); s != "" {
				return s
			}
			for _, v := range m {
				if s, ok := v.(string); ok && s != "" {
					return s
				}
			}
		}
	}
	return ""
}
