package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestTokenizeCoazPath(t *testing.T) {
	cases := map[string][]string{
		"$.properties['id']":        {"properties", "id"},
		"$.token['sub']":            {"token", "sub"},
		"$.token.sub":               {"token", "sub"},
		"$.properties.foo['bar']":   {"properties", "foo", "bar"},
		`$.token["realm_access"]`:   {"token", "realm_access"},
		"$.token['realm'].roles[0]": {"token", "realm", "roles", "0"},
		"$.properties":              {"properties"},
	}
	for expr, want := range cases {
		got, err := tokenizeCoazPath(expr)
		if err != nil {
			t.Fatalf("tokenizeCoazPath(%q) error: %v", expr, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("tokenizeCoazPath(%q) = %v, want %v", expr, got, want)
		}
	}

	if _, err := tokenizeCoazPath("$.token['sub'"); err == nil {
		t.Error("expected error for unterminated bracket")
	}
}

// resolves the canonical COAZ example from the specification.
func TestResolveCoazMappingSpecExample(t *testing.T) {
	mappingJSON := `{
		"resource": {"id": "$.properties['id']", "type": "customer"},
		"subject": {"type": "user", "id": "$.token['sub']"},
		"context": {"agent": "$.token['client_id']", "case": "$.properties['case']"}
	}`
	var mapping map[string]interface{}
	if err := json.Unmarshal([]byte(mappingJSON), &mapping); err != nil {
		t.Fatal(err)
	}

	sources := map[string]interface{}{
		"properties": map[string]interface{}{"id": "cust-1", "case": "case-42"},
		"token":      map[string]interface{}{"sub": "u-9", "client_id": "agent-app"},
	}

	resolvedAny, err := resolveCoazValue(mapping, sources)
	if err != nil {
		t.Fatalf("resolveCoazValue error: %v", err)
	}
	resolved := resolvedAny.(map[string]interface{})

	resource := resolved["resource"].(map[string]interface{})
	if resource["id"] != "cust-1" || resource["type"] != "customer" {
		t.Errorf("unexpected resource: %#v", resource)
	}
	subject := resolved["subject"].(map[string]interface{})
	if subject["id"] != "u-9" || subject["type"] != "user" {
		t.Errorf("unexpected subject: %#v", subject)
	}
	context := resolved["context"].(map[string]interface{})
	if context["agent"] != "agent-app" || context["case"] != "case-42" {
		t.Errorf("unexpected context: %#v", context)
	}
}

func TestResolveCoazPreservesNonReferenceValues(t *testing.T) {
	mapping := map[string]interface{}{
		"resource": map[string]interface{}{
			"type":    "mcp-tool",
			"id":      "literal-id",
			"amount":  float64(5000),
			"enabled": true,
		},
	}
	resolved, err := resolveCoazValue(mapping, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	res := resolved.(map[string]interface{})["resource"].(map[string]interface{})
	if res["id"] != "literal-id" || res["amount"] != float64(5000) || res["enabled"] != true {
		t.Errorf("literal values not preserved: %#v", res)
	}
}

func TestResolveCoazNestedAndArray(t *testing.T) {
	mapping := map[string]interface{}{
		"subject": map[string]interface{}{
			"id":   "$.token['sub']",
			"role": "$.token['roles'][0]",
		},
	}
	sources := map[string]interface{}{
		"properties": map[string]interface{}{},
		"token": map[string]interface{}{
			"sub":   "u-1",
			"roles": []interface{}{"analyst", "admin"},
		},
	}
	resolved, err := resolveCoazValue(mapping, sources)
	if err != nil {
		t.Fatal(err)
	}
	subject := resolved.(map[string]interface{})["subject"].(map[string]interface{})
	if subject["id"] != "u-1" || subject["role"] != "analyst" {
		t.Errorf("unexpected subject: %#v", subject)
	}
}

func TestResolveCoazMissingKeyErrors(t *testing.T) {
	mapping := map[string]interface{}{"subject": map[string]interface{}{"id": "$.token['missing']"}}
	sources := map[string]interface{}{"token": map[string]interface{}{}}
	if _, err := resolveCoazValue(mapping, sources); err == nil {
		t.Error("expected error for missing token key")
	}
}

func TestEvaluationRequestFromResolved(t *testing.T) {
	resolved := map[string]interface{}{
		"subject":  map[string]interface{}{"type": "user", "id": "u-1", "properties": map[string]interface{}{"roles": []interface{}{"analyst"}}},
		"resource": map[string]interface{}{"type": "tool", "id": "fintech_approve_expense"},
		"action":   map[string]interface{}{"name": "tools/call"},
		"context":  map[string]interface{}{"agent": "agent-app"},
	}
	er := evaluationRequestFromResolved(resolved)
	if er.Subject.ID != "u-1" || er.Subject.Type != "user" {
		t.Errorf("unexpected subject: %#v", er.Subject)
	}
	if er.Resource.Type != "tool" || er.Resource.ID != "fintech_approve_expense" {
		t.Errorf("unexpected resource: %#v", er.Resource)
	}
	if er.Action.Name != "tools/call" {
		t.Errorf("unexpected action: %#v", er.Action)
	}
	if er.Context == nil || (*er.Context)["agent"] != "agent-app" {
		t.Errorf("unexpected context: %#v", er.Context)
	}
}

func TestMCPHelpers(t *testing.T) {
	if !isMCPResourceType(ResourceTypeTool) || !isMCPResourceType(ResourceTypePrompt) ||
		!isMCPResourceType(ResourceTypeTask) || !isMCPResourceType(ResourceTypeMCPServer) {
		t.Error("expected MCP resource types to be recognized")
	}
	if isMCPResourceType("document") {
		t.Error("non-MCP type should not be recognized")
	}
	if !isMCPListAction(ActionToolsList) || !isMCPListAction(ActionPromptsList) ||
		!isMCPListAction(ActionTasksList) || !isMCPListAction(ActionRootsList) {
		t.Error("expected list actions to be recognized")
	}
	if isMCPListAction("tools/call") {
		t.Error("tools/call is not a list action")
	}
}

func claims() map[string]interface{} {
	return map[string]interface{}{
		"sub":       "user-123",
		"aud":       "https://mcp.example.com",
		"client_id": "agent-app",
	}
}

func TestBuildMCPEvaluationRequest_ToolsCall(t *testing.T) {
	params := map[string]interface{}{
		"name":      "fintech_approve_expense",
		"arguments": map[string]interface{}{"expense_id": "exp-123", "amount": float64(5000)},
	}
	req, err := buildMCPEvaluationRequest("tools/call", params, claims(), nil)
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

func TestBuildMCPEvaluationRequest_ToolsCallWithCoazOverride(t *testing.T) {
	params := map[string]interface{}{
		"name":      "get_customer",
		"arguments": map[string]interface{}{"id": "cust-1"},
	}
	mapping := map[string]interface{}{
		"resource": map[string]interface{}{"type": "customer", "id": "$.properties['id']"},
		"subject":  map[string]interface{}{"type": "user", "id": "$.token['sub']"},
	}
	req, err := buildMCPEvaluationRequest("tools/call", params, claims(), mapping)
	if err != nil {
		t.Fatal(err)
	}
	res := req["resource"].(map[string]interface{})
	if res["type"] != "customer" || res["id"] != "cust-1" {
		t.Errorf("coaz override not applied to resource: %#v", res)
	}
	// action defaults to the tool name when the mapping omits one.
	if got := req["action"].(map[string]interface{})["name"]; got != "get_customer" {
		t.Errorf("action.name = %v, want get_customer", got)
	}
}

func TestBuildMCPEvaluationRequest_ListScopedToServer(t *testing.T) {
	req, err := buildMCPEvaluationRequest("tools/list", nil, claims(), nil)
	if err != nil {
		t.Fatal(err)
	}
	res := req["resource"].(map[string]interface{})
	if res["type"] != "mcp_server" || res["id"] != "https://mcp.example.com" {
		t.Errorf("list should be scoped to mcp_server/aud: %#v", res)
	}
	if req["action"].(map[string]interface{})["name"] != "tools/list" {
		t.Errorf("unexpected action: %#v", req["action"])
	}
}

func TestBuildMCPEvaluationRequest_ResourcesRead(t *testing.T) {
	params := map[string]interface{}{"uri": "file:///docs/report.pdf"}
	req, _ := buildMCPEvaluationRequest("resources/read", params, claims(), nil)
	res := req["resource"].(map[string]interface{})
	if res["type"] != "resource" || res["id"] != "file:///docs/report.pdf" {
		t.Errorf("unexpected resource: %#v", res)
	}
}

func TestBuildMCPEvaluationRequest_PromptsGet(t *testing.T) {
	params := map[string]interface{}{"name": "summarize"}
	req, _ := buildMCPEvaluationRequest("prompts/get", params, claims(), nil)
	if req["subject"].(map[string]interface{})["type"] != "user" {
		t.Errorf("prompts/get subject.type should be user per spec")
	}
	res := req["resource"].(map[string]interface{})
	if res["type"] != "prompt" || res["id"] != "summarize" {
		t.Errorf("unexpected resource: %#v", res)
	}
}

func TestBuildMCPEvaluationRequest_TaskMethods(t *testing.T) {
	params := map[string]interface{}{"taskId": "task-9"}
	for _, m := range []string{"tasks/get", "tasks/result", "tasks/cancel"} {
		req, _ := buildMCPEvaluationRequest(m, params, claims(), nil)
		res := req["resource"].(map[string]interface{})
		if res["type"] != "task" || res["id"] != "task-9" {
			t.Errorf("%s: unexpected resource: %#v", m, res)
		}
	}
}

func TestBuildMCPEvaluationRequest_CompletionComplete(t *testing.T) {
	params := map[string]interface{}{
		"ref":      map[string]interface{}{"type": "ref/prompt", "name": "code_review"},
		"argument": map[string]interface{}{"name": "language", "value": "go"},
	}
	req, _ := buildMCPEvaluationRequest("completion/complete", params, claims(), nil)
	res := req["resource"].(map[string]interface{})
	if res["type"] != "ref/prompt" || res["id"] != "code_review" {
		t.Errorf("unexpected resource: %#v", res)
	}
	if req["context"].(map[string]interface{})["argument_name"] != "language" {
		t.Errorf("unexpected context: %#v", req["context"])
	}
}

func TestBuildMCPEvaluationRequest_ElicitationURLMode(t *testing.T) {
	params := map[string]interface{}{"mode": "url", "elicitationId": "el-1", "url": "https://pay.example.com"}
	req, _ := buildMCPEvaluationRequest("elicitation/create", params, claims(), nil)
	ctx := req["context"].(map[string]interface{})
	if ctx["mode"] != "url" || ctx["elicitation_id"] != "el-1" || ctx["url"] != "https://pay.example.com" {
		t.Errorf("unexpected context: %#v", ctx)
	}
}

func TestAudienceString(t *testing.T) {
	if got := audienceString(map[string]interface{}{"aud": "a"}); got != "a" {
		t.Errorf("string aud = %q", got)
	}
	if got := audienceString(map[string]interface{}{"aud": []interface{}{"first", "second"}}); got != "first" {
		t.Errorf("array aud = %q, want first", got)
	}
	if got := audienceString(map[string]interface{}{}); got != "" {
		t.Errorf("missing aud = %q, want empty", got)
	}
}
