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
		"resource": map[string]interface{}{"type": "mcp-tool", "id": "fintech_approve_expense"},
		"action":   map[string]interface{}{"name": "tools/call"},
		"context":  map[string]interface{}{"agent": "agent-app"},
	}
	er := evaluationRequestFromResolved(resolved)
	if er.Subject.ID != "u-1" || er.Subject.Type != "user" {
		t.Errorf("unexpected subject: %#v", er.Subject)
	}
	if er.Resource.Type != "mcp-tool" || er.Resource.ID != "fintech_approve_expense" {
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
	if !isMCPResourceType(ResourceTypeMCPTool) || !isMCPResourceType(ResourceTypeMCPPrompt) {
		t.Error("expected MCP resource types to be recognized")
	}
	if isMCPResourceType("document") {
		t.Error("non-MCP type should not be recognized")
	}
	if !isMCPListAction(ActionToolsList) || !isMCPListAction(ActionPromptsList) {
		t.Error("expected list actions to be recognized")
	}
	if isMCPListAction(ActionToolsCall) {
		t.Error("tools/call is not a list action")
	}
}
