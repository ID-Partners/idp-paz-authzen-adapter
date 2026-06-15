package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// jsonRPCErrUnauthorized is the JSON-RPC error code used by the COAZ profile to
// signal an authorization denial.
const jsonRPCErrUnauthorized = -32401

type config struct {
	listenAddr   string
	upstreamURL  string
	pdpURL       string
	pdpAuthHdr   string
	pdpAuthVal   string
	requireToken bool
	failOpen     bool
	skipMethods  map[string]bool
	insecureTLS  bool
	maxBodyBytes int64
	healthPath   string
	coazMappings map[string]map[string]interface{} // tool name -> x-coaz-mapping
	pdpTimeout   time.Duration
}

type gateway struct {
	cfg   config
	proxy *httputil.ReverseProxy
	pdp   *pdpClient
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cfg := loadConfig()

	target, err := url.Parse(cfg.upstreamURL)
	if err != nil {
		log.Fatalf("invalid MCP_UPSTREAM_URL %q: %v", cfg.upstreamURL, err)
	}

	transport := &http.Transport{}
	if cfg.insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		log.Printf("ERROR: upstream proxy error: %v", e)
		http.Error(w, "Bad gateway", http.StatusBadGateway)
	}

	g := &gateway{
		cfg:   cfg,
		proxy: proxy,
		pdp: &pdpClient{
			url:        cfg.pdpURL,
			authHeader: cfg.pdpAuthHdr,
			authValue:  cfg.pdpAuthVal,
			http:       &http.Client{Timeout: cfg.pdpTimeout, Transport: transport},
		},
	}

	log.Printf("MCP AuthZEN gateway listening on %s -> upstream %s (PDP %s)", cfg.listenAddr, cfg.upstreamURL, cfg.pdpURL)
	if err := http.ListenAndServe(cfg.listenAddr, g); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == g.cfg.healthPath {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
		return
	}

	// Only POSTed JSON-RPC bodies carry client->server requests that require
	// authorization. Everything else (GET SSE streams, DELETE session
	// teardown, non-JSON bodies) is proxied straight through.
	if r.Method != http.MethodPost || !isJSONContentType(r.Header.Get("Content-Type")) {
		g.proxy.ServeHTTP(w, r)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.cfg.maxBodyBytes))
	if err != nil {
		http.Error(w, "Request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}

	token := bearerToken(r.Header.Get("Authorization"))
	if g.cfg.requireToken && token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "Unauthorized: missing bearer token", http.StatusUnauthorized)
		return
	}

	var claims map[string]interface{}
	if token != "" {
		if claims, err = decodeJWTClaims(token); err != nil {
			log.Printf("WARN: could not decode JWT claims: %v", err)
			claims = map[string]interface{}{}
		}
	}

	allowed, denyBody := g.authorize(r.Context(), body, claims)
	if !allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // JSON-RPC errors travel in a 200 body
		w.Write(denyBody)
		return
	}

	// Authorized: restore the consumed body and forward upstream.
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	g.proxy.ServeHTTP(w, r)
}

// authorize parses a single or batched JSON-RPC payload and evaluates every
// request message against the PDP. It returns (true, nil) when all messages are
// allowed (or are notifications/responses that need no check), otherwise
// (false, <JSON-RPC error body>).
func (g *gateway) authorize(ctx context.Context, body []byte, claims map[string]interface{}) (bool, []byte) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return true, nil // nothing to authorize; let upstream reject if invalid
	}

	if trimmed[0] == '[' {
		return g.authorizeBatch(ctx, trimmed, claims)
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		// Unparseable JSON-RPC: fail closed.
		return false, marshalError(nil, jsonRPCErrUnauthorized, "Malformed JSON-RPC request")
	}

	skip, allow, reason := g.evaluateMessage(ctx, msg, claims)
	if skip || allow {
		return true, nil
	}
	return false, marshalError(msg["id"], jsonRPCErrUnauthorized, denyMessage(reason))
}

func (g *gateway) authorizeBatch(ctx context.Context, body []byte, claims map[string]interface{}) (bool, []byte) {
	var msgs []map[string]interface{}
	if err := json.Unmarshal(body, &msgs); err != nil {
		return false, marshalError(nil, jsonRPCErrUnauthorized, "Malformed JSON-RPC batch")
	}

	type denied struct {
		id     interface{}
		reason string
	}
	var denials []denied
	var requestIDs []interface{}

	for _, msg := range msgs {
		skip, allow, reason := g.evaluateMessage(ctx, msg, claims)
		if skip {
			continue
		}
		requestIDs = append(requestIDs, msg["id"])
		if !allow {
			denials = append(denials, denied{id: msg["id"], reason: reason})
		}
	}

	if len(denials) == 0 {
		return true, nil
	}

	// Any denial fails the whole batch: respond with a JSON-RPC error per
	// request message so the client receives a well-formed batch response.
	reasonByID := make(map[interface{}]string, len(denials))
	for _, d := range denials {
		reasonByID[d.id] = d.reason
	}
	errs := make([]json.RawMessage, 0, len(requestIDs))
	for _, id := range requestIDs {
		reason := reasonByID[id]
		if reason == "" {
			reason = "Request denied because another message in the batch was unauthorized"
		}
		errs = append(errs, marshalError(id, jsonRPCErrUnauthorized, denyMessage(reason)))
	}
	out, _ := json.Marshal(errs)
	return false, out
}

// evaluateMessage decides one JSON-RPC message. It returns skip=true for
// notifications/responses and skip-listed methods (no authorization needed).
func (g *gateway) evaluateMessage(ctx context.Context, msg, claims map[string]interface{}) (skip, allow bool, reason string) {
	method, _ := msg["method"].(string)
	_, hasID := msg["id"]

	// Notifications (no id) and client responses (id but no method) are not
	// authorization targets.
	if method == "" || !hasID {
		return true, false, ""
	}
	if g.cfg.skipMethods[method] {
		return true, false, ""
	}

	params := toMap(msg["params"])
	coaz := g.coazFor(method, params)

	azReq, err := buildEvaluationRequest(method, params, claims, coaz)
	if err != nil {
		log.Printf("ERROR: mapping %s: %v", method, err)
		return false, g.cfg.failOpen, "Authorization mapping error"
	}

	dec, err := g.pdp.evaluate(ctx, azReq)
	if err != nil {
		log.Printf("ERROR: PDP evaluation for %s: %v", method, err)
		// Fail closed by default; fail open only if explicitly configured.
		return false, g.cfg.failOpen, "Authorization service unavailable"
	}
	return false, dec.Allow, dec.Reason
}

// coazFor returns the configured x-coaz-mapping for a tools/call invocation, if any.
func (g *gateway) coazFor(method string, params map[string]interface{}) map[string]interface{} {
	if method != "tools/call" || len(g.cfg.coazMappings) == 0 {
		return nil
	}
	return g.cfg.coazMappings[getStr(params, "name")]
}

func denyMessage(reason string) string {
	if reason != "" {
		return reason
	}
	return "Request denied due to authorization policy"
}

func marshalError(id interface{}, code int, message string) []byte {
	out, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]interface{}{"code": code, "message": message},
	})
	return out
}

func isJSONContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}

func loadConfig() config {
	cfg := config{
		listenAddr:   ":" + envOr("PORT", "8080"),
		upstreamURL:  os.Getenv("MCP_UPSTREAM_URL"),
		pdpURL:       os.Getenv("PDP_URL"),
		pdpAuthHdr:   envOr("PDP_AUTH_HEADER", "Authorization"),
		requireToken: envBool("REQUIRE_TOKEN", true),
		failOpen:     envBool("PDP_FAIL_OPEN", false),
		insecureTLS:  envBool("INSECURE_SKIP_VERIFY", false),
		maxBodyBytes: int64(envInt("MAX_BODY_BYTES", 4<<20)),
		healthPath:   envOr("GATEWAY_HEALTH_PATH", "/healthz"),
		pdpTimeout:   time.Duration(envInt("PDP_TIMEOUT_MS", 5000)) * time.Millisecond,
		skipMethods:  parseSkipMethods(envOr("SKIP_METHODS", "initialize,ping")),
		coazMappings: loadCoazMappings(os.Getenv("COAZ_MAPPINGS_FILE")),
	}

	// PDP auth: a bearer key (PDP_API_KEY) or a raw header value (PDP_AUTH_VALUE).
	if v := os.Getenv("PDP_AUTH_VALUE"); v != "" {
		cfg.pdpAuthVal = v
	} else if key := os.Getenv("PDP_API_KEY"); key != "" {
		cfg.pdpAuthVal = envOr("PDP_AUTH_SCHEME", "Bearer") + " " + key
	}

	if cfg.upstreamURL == "" {
		log.Fatal("MCP_UPSTREAM_URL is required (base URL of the MCP server to protect)")
	}
	if cfg.pdpURL == "" {
		log.Fatal("PDP_URL is required (AuthZEN evaluation endpoint, e.g. https://pdp/access/v1/evaluation)")
	}
	return cfg
}

func parseSkipMethods(s string) map[string]bool {
	out := map[string]bool{}
	for _, m := range strings.Split(s, ",") {
		if m = strings.TrimSpace(m); m != "" {
			out[m] = true
		}
	}
	return out
}

func loadCoazMappings(path string) map[string]map[string]interface{} {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("reading COAZ_MAPPINGS_FILE %q: %v", path, err)
	}
	var mappings map[string]map[string]interface{}
	if err := json.Unmarshal(data, &mappings); err != nil {
		log.Fatalf("parsing COAZ_MAPPINGS_FILE %q: %v", path, err)
	}
	log.Printf("loaded %d COAZ tool mapping(s) from %s", len(mappings), path)
	return mappings
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Fatalf("invalid boolean for %s=%q", key, v)
	}
	return b
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("invalid integer for %s=%q", key, v)
	}
	return n
}
