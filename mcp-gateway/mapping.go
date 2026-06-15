package main

import (
	"fmt"
	"strconv"
	"strings"
)

// Default AuthZEN Mappings for MCP JSON-RPC Messages (MCP Specification
// 2025-11-25). Each MCP method is projected onto the AuthZEN
// Subject-Action-Resource-Context model.

// AuthZEN resource types reflecting the MCP primitive being accessed.
const (
	resourceTypeTool      = "tool"
	resourceTypeResource  = "resource"
	resourceTypePrompt    = "prompt"
	resourceTypeTask      = "task"
	resourceTypeMCPServer = "mcp_server"
)

// buildEvaluationRequest maps an MCP method + params and the caller's decoded
// JWT claims onto an AuthZEN evaluation request. When method is "tools/call"
// and coazMapping is non-nil, the tool's x-coaz-mapping overrides the default
// subject/resource/action/context.
func buildEvaluationRequest(method string, params, claims, coazMapping map[string]interface{}) (map[string]interface{}, error) {
	sub := getStr(claims, "sub")
	aud := audienceString(claims)
	agent := getStr(claims, "client_id")

	subject := map[string]interface{}{"type": "identity", "id": sub}
	context := map[string]interface{}{"agent": agent}

	// Default: scoped to the MCP server. Covers list/discovery methods,
	// lifecycle (initialize, ping), and any unrecognized method.
	req := map[string]interface{}{
		"subject":  subject,
		"action":   map[string]interface{}{"name": method},
		"resource": map[string]interface{}{"type": resourceTypeMCPServer, "id": aud},
		"context":  context,
	}
	setAction := func(name string) { req["action"] = map[string]interface{}{"name": name} }
	setResource := func(typ, id string) { req["resource"] = map[string]interface{}{"type": typ, "id": id} }

	switch method {
	case "tools/call":
		toolName := getStr(params, "name")
		setAction(toolName)
		setResource(resourceTypeTool, toolName)
		if task := toMap(params["task"]); task != nil {
			if v, ok := task["ttl"]; ok {
				context["task_ttl"] = v
			}
		}
		if coazMapping != nil {
			sources := map[string]interface{}{
				"properties": coalesceMap(toMap(params["arguments"])),
				"token":      coalesceMap(claims),
			}
			resolvedAny, err := resolveCoazValue(coazMapping, sources)
			if err != nil {
				return nil, fmt.Errorf("coaz override: %w", err)
			}
			if resolved, ok := resolvedAny.(map[string]interface{}); ok {
				for _, k := range []string{"subject", "resource", "action", "context"} {
					if v, present := resolved[k]; present {
						req[k] = v
					}
				}
			}
		}

	case "resources/read", "resources/subscribe", "resources/unsubscribe":
		setResource(resourceTypeResource, getStr(params, "uri"))

	case "prompts/get":
		// Per the spec's per-method mapping, prompts/get uses subject.type "user".
		subject["type"] = "user"
		setResource(resourceTypePrompt, getStr(params, "name"))

	case "completion/complete":
		ref := toMap(params["ref"])
		refID := getStr(ref, "name")
		if refID == "" {
			refID = getStr(ref, "uri")
		}
		setResource(getStr(ref, "type"), refID)
		context["argument_name"] = getStr(toMap(params["argument"]), "name")

	case "tasks/get", "tasks/result", "tasks/cancel":
		setResource(resourceTypeTask, getStr(params, "taskId"))

	case "sampling/createMessage":
		if v, ok := params["maxTokens"]; ok {
			context["max_tokens"] = v
		}

	case "elicitation/create":
		mode := getStr(params, "mode")
		if mode == "" {
			mode = "form"
		}
		context["mode"] = mode
		if mode == "url" {
			context["elicitation_id"] = getStr(params, "elicitationId")
			context["url"] = getStr(params, "url")
		}

	case "logging/setLevel":
		context["level"] = getStr(params, "level")

	case "initialize":
		context["protocol_version"] = getStr(params, "protocolVersion")
	}

	return req, nil
}

// ------------------------------
// COAZ x-coaz-mapping resolution ($.properties[...] / $.token[...])
// ------------------------------

func resolveCoazValue(v interface{}, sources map[string]interface{}) (interface{}, error) {
	switch val := v.(type) {
	case string:
		if strings.HasPrefix(val, "$.") {
			return resolveCoazRef(val, sources)
		}
		return val, nil
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, item := range val {
			r, err := resolveCoazValue(item, sources)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, item := range val {
			r, err := resolveCoazValue(item, sources)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	default:
		return v, nil
	}
}

func resolveCoazRef(expr string, sources map[string]interface{}) (interface{}, error) {
	segs, err := tokenizeCoazPath(expr)
	if err != nil {
		return nil, err
	}
	if len(segs) == 0 {
		return nil, fmt.Errorf("empty coaz reference %q", expr)
	}
	cur, ok := sources[segs[0]]
	if !ok {
		return nil, fmt.Errorf("unknown coaz reference root %q in %q (expected one of: properties, token)", segs[0], expr)
	}
	for _, seg := range segs[1:] {
		switch node := cur.(type) {
		case map[string]interface{}:
			next, ok := node[seg]
			if !ok {
				return nil, fmt.Errorf("coaz reference %q: key %q not found", expr, seg)
			}
			cur = next
		case []interface{}:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, fmt.Errorf("coaz reference %q: invalid array index %q", expr, seg)
			}
			cur = node[idx]
		default:
			return nil, fmt.Errorf("coaz reference %q: cannot traverse into segment %q", expr, seg)
		}
	}
	return cur, nil
}

func tokenizeCoazPath(expr string) ([]string, error) {
	path := strings.TrimPrefix(expr, "$.")
	var segs []string
	i := 0
	for i < len(path) {
		switch path[i] {
		case '.':
			i++
		case '[':
			j := strings.IndexByte(path[i:], ']')
			if j < 0 {
				return nil, fmt.Errorf("unterminated '[' in coaz reference %q", expr)
			}
			inner := strings.TrimSpace(path[i+1 : i+j])
			inner = strings.Trim(inner, `'"`)
			segs = append(segs, inner)
			i += j + 1
		default:
			j := i
			for j < len(path) && path[j] != '.' && path[j] != '[' {
				j++
			}
			segs = append(segs, path[i:j])
			i = j
		}
	}
	return segs, nil
}

// ------------------------------
// helpers
// ------------------------------

func toMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

func coalesceMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return map[string]interface{}{}
	}
	return m
}

func getStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		return toStringValue(v)
	}
	return ""
}

func toStringValue(v interface{}) string {
	switch s := v.(type) {
	case nil:
		return ""
	case string:
		return s
	case bool:
		return strconv.FormatBool(s)
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// audienceString returns the JWT "aud" claim as a string, taking the first
// element when the claim is an array (as permitted by RFC 7519).
func audienceString(claims map[string]interface{}) string {
	if claims == nil {
		return ""
	}
	switch a := claims["aud"].(type) {
	case nil:
		return ""
	case string:
		return a
	case []interface{}:
		if len(a) > 0 {
			return toStringValue(a[0])
		}
		return ""
	default:
		return toStringValue(a)
	}
}
