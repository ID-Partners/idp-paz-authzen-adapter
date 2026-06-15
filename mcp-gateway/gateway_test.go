package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newTestGateway wires a gateway to test PDP and upstream servers. The PDP
// allows a request unless its resource.id is in deny.
func newTestGateway(t *testing.T, deny map[string]bool, upstreamHit *bool) *gateway {
	t.Helper()

	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		res, _ := req["resource"].(map[string]interface{})
		id, _ := res["id"].(string)
		allow := !deny[id]
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{"decision": allow}
		if !allow {
			resp["context"] = map[string]interface{}{"reason": "policy denied " + id}
		}
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(pdp.Close)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*upstreamHit = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	}))
	t.Cleanup(upstream.Close)

	target, _ := url.Parse(upstream.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	return &gateway{
		cfg: config{
			requireToken: false,
			failOpen:     false,
			skipMethods:  map[string]bool{"initialize": true, "ping": true},
			maxBodyBytes: 1 << 20,
			healthPath:   "/healthz",
		},
		proxy: proxy,
		pdp:   &pdpClient{url: pdp.URL, http: &http.Client{Timeout: 2 * time.Second}},
	}
}

func doPost(t *testing.T, g *gateway, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	return rec.Result()
}

func TestGatewayAllowsAndForwards(t *testing.T) {
	hit := false
	g := newTestGateway(t, nil, &hit)
	resp := doPost(t, g, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}`)
	if !hit {
		t.Fatal("allowed request should reach upstream")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"ok":true`) {
		t.Errorf("expected upstream response, got %s", body)
	}
}

func TestGatewayDeniesWithJSONRPCError(t *testing.T) {
	hit := false
	g := newTestGateway(t, map[string]bool{"delete_everything": true}, &hit)
	resp := doPost(t, g, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_everything"}}`)
	if hit {
		t.Fatal("denied request must not reach upstream")
	}
	var parsed struct {
		ID    float64 `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("invalid JSON-RPC error response %s: %v", body, err)
	}
	if parsed.Error.Code != jsonRPCErrUnauthorized {
		t.Errorf("error code = %d, want %d", parsed.Error.Code, jsonRPCErrUnauthorized)
	}
	if parsed.ID != 7 {
		t.Errorf("error id = %v, want 7", parsed.ID)
	}
	if !strings.Contains(parsed.Error.Message, "policy denied") {
		t.Errorf("expected PDP reason in message, got %q", parsed.Error.Message)
	}
}

func TestGatewaySkipsNotifications(t *testing.T) {
	hit := false
	// Even though the PDP would deny everything, a notification is forwarded.
	g := newTestGateway(t, map[string]bool{"": true}, &hit)
	doPost(t, g, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if !hit {
		t.Fatal("notification should be forwarded without authorization")
	}
}

func TestGatewaySkipsListedMethods(t *testing.T) {
	hit := false
	g := newTestGateway(t, map[string]bool{"": true, "anything": true}, &hit)
	doPost(t, g, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
	if !hit {
		t.Fatal("skip-listed initialize should be forwarded")
	}
}

func TestGatewayRequireTokenRejects(t *testing.T) {
	hit := false
	g := newTestGateway(t, nil, &hit)
	g.cfg.requireToken = true
	resp := doPost(t, g, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if hit {
		t.Fatal("missing-token request must not reach upstream")
	}
}

func TestGatewayHealth(t *testing.T) {
	hit := false
	g := newTestGateway(t, nil, &hit)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("health status = %d", rec.Code)
	}
}
