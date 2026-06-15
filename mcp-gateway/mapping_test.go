package main

import "testing"

func testClaims() map[string]interface{} {
	return map[string]interface{}{
		"sub":       "user-123",
		"aud":       "https://mcp.example.com",
		"client_id": "agent-app",
	}
}

func TestBuildEvaluationRequest_ToolsCall(t *testing.T) {
	params := map[string]interface{}{
		"name":      "fintech_approve_expense",
		"arguments": map[string]interface{}{"expense_id": "exp-123", "amount": float64(5000)},
	}
	req, err := buildEvaluationRequest("tools/call", params, testClaims(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := req["action"].(map[string]interface{})["name"]; got != "fintech_approve_expense" {
		t.Errorf("action.name = %v, want tool name", got)
	}
	res := req["resource"].(map[string]interface{})
	if res["type"] != "tool" || res["id"] != "fintech_approve_expense" {
		t.Errorf("unexpected resource: %#v", res)
	}
	sub := req["subject"].(map[string]interface{})
	if sub["type"] != "identity" || sub["id"] != "user-123" {
		t.Errorf("unexpected subject: %#v", sub)
	}
	if req["context"].(map[string]interface{})["agent"] != "agent-app" {
		t.Errorf("unexpected context: %#v", req["context"])
	}
}

func TestBuildEvaluationRequest_CoazOverride(t *testing.T) {
	params := map[string]interface{}{
		"name":      "get_customer",
		"arguments": map[string]interface{}{"id": "cust-1"},
	}
	mapping := map[string]interface{}{
		"resource": map[string]interface{}{"type": "customer", "id": "$.properties['id']"},
		"subject":  map[string]interface{}{"type": "user", "id": "$.token['sub']"},
	}
	req, err := buildEvaluationRequest("tools/call", params, testClaims(), mapping)
	if err != nil {
		t.Fatal(err)
	}
	res := req["resource"].(map[string]interface{})
	if res["type"] != "customer" || res["id"] != "cust-1" {
		t.Errorf("coaz override not applied: %#v", res)
	}
	if got := req["action"].(map[string]interface{})["name"]; got != "get_customer" {
		t.Errorf("action.name = %v, want get_customer", got)
	}
}

func TestBuildEvaluationRequest_ListScopedToServer(t *testing.T) {
	req, _ := buildEvaluationRequest("tools/list", nil, testClaims(), nil)
	res := req["resource"].(map[string]interface{})
	if res["type"] != "mcp_server" || res["id"] != "https://mcp.example.com" {
		t.Errorf("list should be scoped to mcp_server/aud: %#v", res)
	}
}

func TestBuildEvaluationRequest_ResourcesAndTasks(t *testing.T) {
	req, _ := buildEvaluationRequest("resources/read", map[string]interface{}{"uri": "file:///a"}, testClaims(), nil)
	if res := req["resource"].(map[string]interface{}); res["type"] != "resource" || res["id"] != "file:///a" {
		t.Errorf("resources/read: %#v", res)
	}
	req, _ = buildEvaluationRequest("tasks/cancel", map[string]interface{}{"taskId": "t-1"}, testClaims(), nil)
	if res := req["resource"].(map[string]interface{}); res["type"] != "task" || res["id"] != "t-1" {
		t.Errorf("tasks/cancel: %#v", res)
	}
}

func TestBuildEvaluationRequest_PromptsGet(t *testing.T) {
	req, _ := buildEvaluationRequest("prompts/get", map[string]interface{}{"name": "summarize"}, testClaims(), nil)
	if req["subject"].(map[string]interface{})["type"] != "user" {
		t.Error("prompts/get subject.type should be user")
	}
	if res := req["resource"].(map[string]interface{}); res["type"] != "prompt" || res["id"] != "summarize" {
		t.Errorf("prompts/get resource: %#v", res)
	}
}

func TestBuildEvaluationRequest_ElicitationURL(t *testing.T) {
	params := map[string]interface{}{"mode": "url", "elicitationId": "el-1", "url": "https://pay"}
	req, _ := buildEvaluationRequest("elicitation/create", params, testClaims(), nil)
	ctx := req["context"].(map[string]interface{})
	if ctx["mode"] != "url" || ctx["elicitation_id"] != "el-1" || ctx["url"] != "https://pay" {
		t.Errorf("elicitation context: %#v", ctx)
	}
}

func TestDecodeJWTClaims(t *testing.T) {
	// {"sub":"user-1","aud":"svc","client_id":"agent"} with header/sig segments.
	token := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEiLCJhdWQiOiJzdmMiLCJjbGllbnRfaWQiOiJhZ2VudCJ9.sig"
	claims, err := decodeJWTClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "user-1" || claims["aud"] != "svc" || claims["client_id"] != "agent" {
		t.Errorf("unexpected claims: %#v", claims)
	}
}

func TestBearerToken(t *testing.T) {
	if got := bearerToken("Bearer abc.def.ghi"); got != "abc.def.ghi" {
		t.Errorf("got %q", got)
	}
	if got := bearerToken("bearer xyz"); got != "xyz" {
		t.Errorf("case-insensitive scheme: got %q", got)
	}
	if got := bearerToken("Basic abc"); got != "" {
		t.Errorf("non-bearer should be empty, got %q", got)
	}
}

func TestAudienceString(t *testing.T) {
	if got := audienceString(map[string]interface{}{"aud": []interface{}{"first", "second"}}); got != "first" {
		t.Errorf("array aud = %q, want first", got)
	}
	if got := audienceString(map[string]interface{}{}); got != "" {
		t.Errorf("missing aud = %q", got)
	}
}
