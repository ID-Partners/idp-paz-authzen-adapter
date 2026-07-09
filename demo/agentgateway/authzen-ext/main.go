package main

// authzen-extauthz: an agentgateway extension that turns the gateway into a
// Policy Enforcement Point (PEP) for the AuthZEN PDP (Ping Authorize).
//
// agentgateway's extAuthz policy speaks the Envoy External Authorization gRPC
// protocol (envoy.service.auth.v3.Authorization). This service implements
// Check() and, for every proxied request:
//
//   1. extracts the delegated access token (DPoP or Bearer) and reads its
//      claims (sub = principal, act.sub = acting agent, scope, cnf.jkt);
//   2. if DPoP is required, checks the sender-constraint binding: the SHA-256
//      JWK thumbprint of the DPoP proof header key must equal the access
//      token's cnf.jkt (RFC 9449), and the proof must carry htm/ath;
//   3. builds an AuthZEN evaluation request (subject=agent on behalf of
//      principal, action+resource+context derived from the HTTP request) and
//      POSTs it to the Go authzen-adapter, which asks Ping Authorize;
//   4. PERMIT -> lets agentgateway forward the request, injecting
//      X-Auth-Principal / X-Auth-Agent / X-Auth-Scope for the Resource
//      Server's audit trail (and X-PDP-* response headers for the demo
//      transcript);
//      DENY   -> returns the exact 401/403 challenge (JSON body +
//      WWW-Authenticate) via Envoy's DeniedHttpResponse passthrough.
//
// Per-route PEP behaviour (style, step-up, DPoP) is configured in the
// agentgateway config via `extAuthz.protocol.grpc.context`, which arrives
// here as CheckRequest context_extensions — the same knobs as the Kong
// authzen-pdp plugin's per-route config block.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// pepConfig mirrors the Kong plugin's per-route config, populated from the
// extAuthz `context` map in the agentgateway config.
type pepConfig struct {
	pepLabel         string
	style            string // "mcp" | "rest"
	requireToken     bool
	requireDpop      bool
	requireUserLogin bool
	stepupScope      string
	stepupAction     string
}

func configFrom(ext map[string]string) pepConfig {
	get := func(k, def string) string {
		if v, ok := ext[k]; ok && v != "" {
			return v
		}
		return def
	}
	isTrue := func(k string) bool { return strings.EqualFold(ext[k], "true") }
	return pepConfig{
		pepLabel:         get("pep_label", "agentgateway-pep"),
		style:            get("style", "rest"),
		requireToken:     isTrue("require_token"),
		requireDpop:      isTrue("require_dpop"),
		requireUserLogin: isTrue("require_user_login"),
		stepupScope:      ext["stepup_scope"],
		stepupAction:     get("stepup_action", "make_payment"),
	}
}

type server struct {
	authzenURL    string
	authzenAPIKey string
	httpc         *http.Client
}

// ---------- CheckResponse builders ----------

func headerOpts(h map[string]string) []*corev3.HeaderValueOption {
	out := make([]*corev3.HeaderValueOption, 0, len(h))
	for k, v := range h {
		out = append(out, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: k, Value: sanitizeHeader(v)},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return out
}

// sanitizeHeader keeps policy reasons from breaking the header framing.
func sanitizeHeader(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}

func deny(httpStatus typev3.StatusCode, rpcCode codes.Code, body map[string]any, headers map[string]string) *authv3.CheckResponse {
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = "application/json"
	raw, _ := json.Marshal(body)
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(rpcCode)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: httpStatus},
				Headers: headerOpts(headers),
				Body:    string(raw),
			},
		},
	}
}

// denySimple matches the Kong plugin's deny() JSON shape.
func denySimple(pep string, httpStatus typev3.StatusCode, rpcCode codes.Code, reason string, extraHeaders map[string]string) *authv3.CheckResponse {
	return deny(httpStatus, rpcCode, map[string]any{
		"error":  "authorization_failed",
		"pep":    pep,
		"reason": reason,
	}, extraHeaders)
}

// permit lets the request through, tagging the upstream request with the
// delegation identity and the response with the PDP decision.
func permit(pep, action, reason, sub, act, scope string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: headerOpts(map[string]string{
					"X-Auth-Principal": sub,
					"X-Auth-Agent":     act,
					"X-Auth-Scope":     scope,
				}),
				ResponseHeadersToAdd: headerOpts(map[string]string{
					"X-PDP-PEP":      pep,
					"X-PDP-Decision": "PERMIT",
					"X-PDP-Action":   action,
					"X-PDP-Reason":   reason,
				}),
			},
		},
	}
}

// ---------- the PEP ----------

func (s *server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	attrs := req.GetAttributes()
	httpReq := attrs.GetRequest().GetHttp()
	conf := configFrom(attrs.GetContextExtensions())
	pep := conf.pepLabel

	headers := map[string]string{}
	for k, v := range httpReq.GetHeaders() {
		headers[strings.ToLower(k)] = v
	}
	method := httpReq.GetMethod()
	path := httpReq.GetPath()
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	body := httpReq.GetBody()

	// 0) Step-up: require a logged-in END USER (RFC 9470 step-up challenge).
	//    The principal (Alice) authenticates at PingFederate; the app forwards
	//    her PF token down the agent chain as X-User-Token. Without a valid
	//    one, the gateway pushes back a login challenge.
	if conf.requireUserLogin {
		uclaims := jwtClaims(headers["x-user-token"])
		if claimString(uclaims, "sub") == "" {
			log.Printf("[%s] 401 login_required %s %s", pep, method, path)
			return deny(typev3.StatusCode_Unauthorized, codes.Unauthenticated, map[string]any{
				"error":      "login_required",
				"pep":        pep,
				"reason":     "The gateway requires an authenticated user (no valid X-User-Token).",
				"acr_values": "urn:pingidentity:loa:password",
			}, map[string]string{
				"WWW-Authenticate": `Bearer error="insufficient_user_authentication", ` +
					`error_description="Login required", acr_values="urn:pingidentity:loa:password"`,
			}), nil
		}
	}

	// 1) token + claims
	token, scheme := extractToken(headers["authorization"])
	if token == "" && conf.requireToken {
		return denySimple(pep, typev3.StatusCode_Unauthorized, codes.Unauthenticated,
			"No access token presented to the gateway.", nil), nil
	}

	claims := jwtClaims(token)
	sub := claimString(claims, "sub")
	act := actorSub(claims)
	scope := scopeString(claims)
	clientID := claimString(claims, "client_id")
	if clientID == "" {
		clientID = claimString(claims, "azp")
	}

	if conf.requireToken && sub == "" {
		return denySimple(pep, typev3.StatusCode_Unauthorized, codes.Unauthenticated,
			"Access token missing or unreadable (no subject claim).", nil), nil
	}

	// 2) DPoP sender-constraint binding (RFC 9449)
	if conf.requireDpop {
		if resp := checkDpop(pep, scheme, method, path, headers, claims); resp != nil {
			return resp, nil
		}
	}

	// 3) map the HTTP request to an AuthZEN action/resource/context
	m := mapRequest(conf.style, method, path, body)

	// MCP handshake / non-tool traffic: allow on a valid token, skip the PDP.
	if m.action == allowAction {
		return permit(pep, "mcp-handshake",
			"MCP handshake allowed (authenticated); policy applies to tool calls.",
			sub, act, scope), nil
	}

	// 3b) Step-up scope: a sensitive action (make_payment) requires a scope the
	//     USER (Alice) consented to. Check HER token (X-User-Token); if she
	//     lacks it, return a 401 insufficient_scope challenge so the app can
	//     step her up at PingFederate to approve the scope, then retry.
	if conf.stepupScope != "" && m.action == conf.stepupAction {
		uscope := scopeString(jwtClaims(headers["x-user-token"]))
		if !strings.Contains(" "+uscope+" ", " "+conf.stepupScope+" ") {
			log.Printf("[%s] 401 insufficient_scope (%s) %s %s", pep, conf.stepupScope, method, path)
			return deny(typev3.StatusCode_Unauthorized, codes.Unauthenticated, map[string]any{
				"error":  "insufficient_scope",
				"scope":  conf.stepupScope,
				"pep":    pep,
				"reason": "This action requires the '" + conf.stepupScope + "' scope; sign in to approve it.",
			}, map[string]string{
				"WWW-Authenticate": `Bearer error="insufficient_scope", scope="` + conf.stepupScope + `"`,
			}), nil
		}
	}

	// 4) evaluate at the PDP and enforce (fail closed on PDP error)
	agent := act
	if agent == "" {
		agent = clientID
	}
	if agent == "" {
		agent = "unknown-agent"
	}
	authzenReq := map[string]any{
		"subject": map[string]any{
			"type":     "agent",
			"identity": agent,
			"properties": map[string]any{
				"on_behalf_of": sub,
				"agent_type":   "ai_assistant",
				"scope":        scope,
				"client_id":    clientID,
			},
		},
		"action":   map[string]any{"name": m.action},
		"resource": map[string]any{"type": m.rtype, "id": m.rid, "properties": m.rprops},
		"context":  m.ctx,
	}

	decision, reason, err := s.evaluate(ctx, authzenReq)
	if err != nil {
		log.Printf("[%s] PDP call failed: %v", pep, err)
		return denySimple(pep, typev3.StatusCode_ServiceUnavailable, codes.Unavailable,
			"Authorization service unreachable; denying (fail-closed).", nil), nil
	}

	if !decision {
		log.Printf("[%s] DENY %s %s: %s", pep, m.action, m.rid, reason)
		// same JSON as Kong's deny(), plus the X-PDP-* decision headers that
		// Kong's header_filter adds to PDP-backed denials.
		return denySimple(pep, typev3.StatusCode_Forbidden, codes.PermissionDenied, reason,
			map[string]string{
				"X-PDP-PEP":      pep,
				"X-PDP-Decision": "DENY",
				"X-PDP-Action":   m.action,
				"X-PDP-Reason":   sanitizeHeader(reason),
			}), nil
	}

	log.Printf("[%s] PERMIT %s %s (principal=%s agent=%s)", pep, m.action, m.rid, sub, agent)
	return permit(pep, m.action, reason, sub, act, scope), nil
}

// extractToken parses Authorization: "DPoP <t>" or "Bearer <t>".
func extractToken(auth string) (token, scheme string) {
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", ""
	}
	return strings.TrimSpace(parts[1]), strings.ToLower(parts[0])
}

// checkDpop enforces the DPoP proof / cnf.jkt binding; nil means pass.
func checkDpop(pep, scheme, method, path string, headers map[string]string, claims map[string]any) *authv3.CheckResponse {
	fail := func(reason string) *authv3.CheckResponse {
		return denySimple(pep, typev3.StatusCode_Unauthorized, codes.Unauthenticated, reason, nil)
	}
	if scheme != "dpop" {
		return fail("DPoP-bound token required but Authorization scheme was not DPoP.")
	}
	proof := headers["dpop"]
	if proof == "" {
		return fail("Missing DPoP proof header.")
	}
	phdr := jwtHeader(proof)
	pclaims := jwtClaims(proof)
	var jkt string
	if jwk, ok := phdr["jwk"].(map[string]any); ok {
		jkt = jwkThumbprint(jwk)
	}
	var cnfJkt string
	if cnf, ok := claims["cnf"].(map[string]any); ok {
		cnfJkt, _ = cnf["jkt"].(string)
	}
	if jkt == "" || cnfJkt == "" || jkt != cnfJkt {
		return fail("DPoP proof key does not match the token's cnf.jkt binding.")
	}
	if claimString(pclaims, "htm") != method {
		return fail("DPoP proof htm does not match the request method.")
	}
	if pclaims["ath"] == nil {
		return fail("DPoP proof missing ath (access-token hash).")
	}
	// htu is validated best-effort: hosts get rewritten behind the platform
	// proxy, so a mismatch is logged rather than fatal for the demo.
	if htu := claimString(pclaims, "htu"); htu != "" && !strings.Contains(htu, path) {
		log.Printf("[%s] DPoP htu path mismatch: %s", pep, htu)
	}
	return nil
}

// evaluate POSTs the AuthZEN evaluation request to the authzen-adapter.
func (s *server) evaluate(ctx context.Context, authzenReq map[string]any) (bool, string, error) {
	payload, _ := json.Marshal(authzenReq)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.authzenURL+"/access/v1/evaluation", bytes.NewReader(payload))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.authzenAPIKey)
	resp, err := s.httpc.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, "", err
	}
	var data struct {
		Decision bool `json:"decision"`
		Context  struct {
			Reason string `json:"reason"`
		} `json:"context"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return false, "", fmt.Errorf("bad PDP response (%d): %w", resp.StatusCode, err)
	}
	reason := data.Context.Reason
	if reason == "" {
		if data.Decision {
			reason = "Permitted by policy."
		} else {
			reason = "Denied by policy."
		}
	}
	return data.Decision, reason, nil
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9191"
	}
	authzenURL := strings.TrimRight(os.Getenv("AUTHZEN_URL"), "/")
	if authzenURL == "" {
		log.Fatal("AUTHZEN_URL is required (e.g. http://authzen-adapter:8080)")
	}

	srv := &server{
		authzenURL:    authzenURL,
		authzenAPIKey: os.Getenv("AUTHZEN_API_KEY"),
		httpc: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				// same posture as the Kong plugin's ssl_verify=false (demo only)
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	lis, err := net.Listen("tcp", ":"+port) // dual-stack (Railway private networking is IPv6-only)
	if err != nil {
		log.Fatalf("listen :%s: %v", port, err)
	}
	gs := grpc.NewServer()
	authv3.RegisterAuthorizationServer(gs, srv)
	healthpb.RegisterHealthServer(gs, health.NewServer())
	log.Printf("authzen-extauthz (Envoy ext_authz -> AuthZEN PDP bridge) listening on :%s, PDP at %s", port, authzenURL)
	if err := gs.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
