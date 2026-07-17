package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/joho/godotenv"
)

// Structures updated to conform to the specification

// Subject represents the "subject" object.
// Note: The "id" field may be omitted in Subject Search requests
// and, if present, is ignored by the PDP for the Subject Search API.
type Subject struct {
	Type       string                 `json:"type"`       // Required
	ID         string                 `json:"identity"`   // Required
	Properties map[string]interface{} `json:"properties"` // Optional
}

// UnmarshalJSON accepts the subject id under EITHER key.
//
// AuthZEN 1.0 names it `id`; this adapter has always read `identity`, which is what the
// demo's own PEP sends (demo/coaz-pep .. "identity": agent). That was invisible while the
// PEP was the only caller, but it means a spec-conformant AuthZEN client is rejected by an
// AuthZEN PDP: its subject id lands nowhere, and the "subject, resource, and action are
// required" check fails. The Grant Management API is such a client.
//
// Both are accepted rather than migrating the PEP, because the two must interoperate during
// any migration anyway. `identity` wins when both are present: it is what the existing
// callers send, so no in-flight request changes meaning. The marshal side is untouched.
func (s *Subject) UnmarshalJSON(b []byte) error {
	var raw struct {
		Type       string                 `json:"type"`
		ID         string                 `json:"id"`
		Identity   string                 `json:"identity"`
		Properties map[string]interface{} `json:"properties"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	s.Type = raw.Type
	s.Properties = raw.Properties
	s.ID = raw.Identity
	if s.ID == "" {
		s.ID = raw.ID
	}
	return nil
}

// Resource represents the "resource" object.
// Note: The "id" field may be omitted in Resource Search requests
// and, if present, is ignored by the PDP for the Resource Search API.
type Resource struct {
	Type       string                 `json:"type"`       // Required
	ID         string                 `json:"id"`         // Required
	Properties map[string]interface{} `json:"properties"` // Optional
}

type Action struct {
	Name       string                 `json:"name"`       // Required
	Properties map[string]interface{} `json:"properties"` // Optional
}

// Page can be included in requests/responses to support pagination.
type Page struct {
	NextToken string `json:"next_token,omitempty"`
}

type Context map[string]interface{}

type EvaluationRequest struct {
	Subject     Subject       `json:"subject"`           // Required
	Action      Action        `json:"action"`            // Required
	Resource    Resource      `json:"resource"`          // Required
	Context     *Context      `json:"context,omitempty"` // Optional
	Evaluations *[]Evaluation `json:"evaluations,omitempty"`
}

type SearchRequest struct {
	Subject  Subject  `json:"subject"`  // Required
	Action   Action   `json:"action"`   // Required
	Resource Resource `json:"resource"` // Required
	Context  Context  `json:"context"`  // Optional
}

type Evaluation struct {
	Resource Resource `json:"resource"`
	Action   Action   `json:"action"`
	Subject  Subject  `json:"subject"`
	Context  Context  `json:"context"`
}

type EvaluationResponse struct {
	Decision bool     `json:"decision"`          // Required
	Context  *Context `json:"context,omitempty"` // Optional
	// RawPDP is the verbatim governance-engine response body from PingAuthorize —
	// the same JSON record the product writes to its policy-decision log (id,
	// deploymentPackageId, decision, statements/advice, status). Surfaced to the
	// UI's PDP-decisions panel as proof; never sent on the AuthZEN wire.
	RawPDP string `json:"-"`
}

type PdpPayload struct {
	Domain     string                 `json:"domain"`
	Service    string                 `json:"service"`
	Action     string                 `json:"action"`
	Attributes map[string]interface{} `json:"attributes"`
}

// ------------------------------
// Ping Authorize Query API
// ------------------------------

type QueryRequest struct {
	Query   []QueryItem    `json:"query"`
	Context map[string]any `json:"context,omitempty"`
}

// QueryItem represents each item in the "query" array.
type QueryItem struct {
	Attribute string   `json:"attribute"`
	Values    []string `json:"values,omitempty"`
}

// ------------------------------
// Subject Search API
// ------------------------------

// SubjectSearchRequest defines the 3-tuple (plus optional page)
// used to search for all subjects that match a given action+resource.
type SubjectSearchRequest struct {
	Subject  Subject  `json:"subject"`  // REQUIRED
	Action   Action   `json:"action"`   // REQUIRED
	Resource Resource `json:"resource"` // REQUIRED
	Page     *Page    `json:"page,omitempty"`
}

// SubjectSearchResponse is a paged array of Subjects that match the search.
type SubjectSearchResponse struct {
	Results []Subject `json:"results"`
	Page    Page      `json:"page"`
}

// ------------------------------
// Resource Search API
// ------------------------------

// ResourceSearchRequest defines the 3-tuple (plus optional page)
// used to search for all resources that match a given subject+action.
type ResourceSearchRequest struct {
	Subject  Subject  `json:"subject"`  // REQUIRED
	Action   Action   `json:"action"`   // REQUIRED
	Resource Resource `json:"resource"` // REQUIRED
	Page     *Page    `json:"page,omitempty"`
}

// ResourceSearchResponse is a paged array of Resources that match the search.
type ResourceSearchResponse struct {
	Results []Resource `json:"results"`
	Page    Page       `json:"page"`
}

func init() {
	log.SetOutput(os.Stdout)                     // Ensure logs go to standard output
	log.SetFlags(log.LstdFlags | log.Lshortfile) // Include timestamps and file line numbers in logs
}

// handleSubjectSearchRequest handles HTTP requests for searching subjects.
// It decodes the incoming JSON request payload into a SubjectSearchRequest struct,
// builds a subject search query request, and encodes the response as JSON.
//
// If the request payload is invalid, it responds with a "400 Bad Request" status.
// If there is an error building the subject search query request, it responds with a "500 Internal Server Error" status.
// If there is an error encoding the response, it responds with a "500 Internal Server Error" status.
//
// Parameters:
//   - w: http.ResponseWriter to write the HTTP response.
//   - r: *http.Request containing the HTTP request.
func handleSubjectSearchRequest(w http.ResponseWriter, r *http.Request) {

	expectedAPIKey := os.Getenv("API_KEY")
	if expectedAPIKey == "" {
		log.Println("API key not set in environment")
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized: Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}
	providedAPIKey := strings.TrimPrefix(authHeader, "Bearer ")
	if providedAPIKey != expectedAPIKey {
		http.Error(w, "Unauthorized: Invalid API key", http.StatusUnauthorized)
		return
	}

	var subjectSearchRequest SubjectSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&subjectSearchRequest); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	queryRequest, err := buildSubjectSearchQueryRequest(subjectSearchRequest)
	if err != nil {
		http.Error(w, "Error building subject search query request", http.StatusInternalServerError)
		return
	}

	// now do makeQueryRequest and return the payload from the PDP
	queryItems, err := makeQueryRequest(queryRequest)
	if err != nil {
		http.Error(w, "Error making query request", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(queryItems); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}

}

// handleResourceSearchRequest handles HTTP requests for searching resources.
// It decodes the incoming JSON request payload into a ResourceSearchRequest struct,
// builds a resource search query request, and encodes the response as JSON.
//
// If the request payload is invalid, it responds with a "400 Bad Request" status.
// If there is an error building the resource search query request, it responds with a "500 Internal Server Error" status.
// If there is an error encoding the response, it responds with a "500 Internal Server Error" status.
//
// Parameters:
//   - w: http.ResponseWriter to write the HTTP response.
//   - r: *http.Request containing the HTTP request.
func handleResourceSearchRequest(w http.ResponseWriter, r *http.Request) {
	expectedAPIKey := os.Getenv("API_KEY")
	if expectedAPIKey == "" {
		log.Println("API key not set in environment")
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized: Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}
	providedAPIKey := strings.TrimPrefix(authHeader, "Bearer ")
	if providedAPIKey != expectedAPIKey {
		http.Error(w, "Unauthorized: Invalid API key", http.StatusUnauthorized)
		return
	}

	var resourceSearchRequest ResourceSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&resourceSearchRequest); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	queryRequest, err := buildResourceSearchQueryRequest(resourceSearchRequest)
	if err != nil {
		http.Error(w, "Error building resource search query request", http.StatusInternalServerError)
		return
	}

	// now do makeQueryRequest and return the payload from the PDP
	queryItems, err := makeQueryRequest(queryRequest)
	if err != nil {
		http.Error(w, "Error making query request", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(queryItems); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// buildSubjectSearchQueryRequest constructs a QueryRequest based on the provided SubjectSearchRequest.
// It retrieves the PDP_ATTRIBUTE_PREFIX environment variable to determine the attribute prefix.
// If the prefix is not set, it defaults to "subject". Otherwise, it uses the prefix followed by ".subject".
// The function creates a QueryItem with the attribute and the subject type from the SubjectSearchRequest,
// and then wraps it in a QueryRequest.
//
// Parameters:
//   - subjectSearchRequest: The SubjectSearchRequest containing the subject information.
//
// Returns:
//   - *QueryRequest: A pointer to the constructed QueryRequest.
//   - error: An error if any issues occur during the construction of the QueryRequest.
func buildSubjectSearchQueryRequest(subjectSearchRequest SubjectSearchRequest) (*QueryRequest, error) {

	pdpAttributePrefix := os.Getenv("PDP_ATTRIBUTE_PREFIX")

	// create a new query item from the SubjectSearchRequest - if there is no attribute prefix do not use the . before the subject name
	attribute := pdpAttributePrefix
	if attribute == "" {
		attribute = "subject"
	} else {
		attribute = fmt.Sprintf("%s.subject", pdpAttributePrefix)
	}

	subjectItem := QueryItem{
		Attribute: attribute,
		Values:    []string{fmt.Sprintf(`{"type":"%s"}`, subjectSearchRequest.Subject.Type)},
	}

	actionItem := QueryItem{
		Attribute: "action",
	}

	resourceAttribute := pdpAttributePrefix
	if resourceAttribute == "" {
		resourceAttribute = "resource"
	} else {
		resourceAttribute = fmt.Sprintf("%s.resource", pdpAttributePrefix)
	}

	resourceItem := QueryItem{
		Attribute: resourceAttribute,
		Values:    []string{fmt.Sprintf(`{"type":"%s","id":"%s"}`, subjectSearchRequest.Resource.Type, subjectSearchRequest.Resource.ID)},
	}

	// Add the items to the queryRequest
	queryRequest := QueryRequest{
		Query: []QueryItem{subjectItem, actionItem, resourceItem},
	}

	return &queryRequest, nil
}

// buildResourceSearchQueryRequest constructs a QueryRequest based on the provided ResourceSearchRequest.
// It retrieves the PDP_ATTRIBUTE_PREFIX environment variable to determine the attribute prefix.
// If the prefix is empty, it defaults to "resource". Otherwise, it uses the prefix followed by ".resource".
// The function creates a QueryItem with the attribute and the resource type from the ResourceSearchRequest,
// and then includes this QueryItem in the QueryRequest.
//
// Parameters:
//   - resourceSearchRequest: The ResourceSearchRequest containing the resource type.
//
// Returns:
//   - *QueryRequest: A pointer to the constructed QueryRequest.
//   - error: An error if any occurs during the construction of the QueryRequest.
func buildResourceSearchQueryRequest(resourceSearchRequest ResourceSearchRequest) (*QueryRequest, error) {
	pdpAttributePrefix := os.Getenv("PDP_ATTRIBUTE_PREFIX")

	// create a new query item from the ResourceSearchRequest - if there is no subAttribute prefix do not use the . before the resource name
	subAttribute := pdpAttributePrefix
	if subAttribute == "" {
		subAttribute = "subject"
	} else {
		subAttribute = fmt.Sprintf("%s.subject", pdpAttributePrefix)
	}

	subjectItem := QueryItem{
		Attribute: subAttribute,
		Values:    []string{fmt.Sprintf(`{"type":"%s", "id":"%s"}`, resourceSearchRequest.Subject.Type, resourceSearchRequest.Subject.ID)},
	}

	actionItem := QueryItem{
		Attribute: "action",
	}

	resourceAttribute := pdpAttributePrefix
	if resourceAttribute == "" {
		resourceAttribute = "resource"
	} else {
		resourceAttribute = fmt.Sprintf("%s.resource", pdpAttributePrefix)
	}

	resourceItem := QueryItem{
		Attribute: resourceAttribute,
		Values:    []string{fmt.Sprintf(`{"type":"%s"}`, resourceSearchRequest.Resource.Type)},
	}

	// Add the items to the queryRequest
	queryRequest := QueryRequest{
		Query: []QueryItem{subjectItem, actionItem, resourceItem},
	}

	return &queryRequest, nil
}

// proofingGate is the runtime ON/OFF switch for the mDL identity-proofing gate on account
// origination. OFF (default) → the adapter reports identity_proofing_present=true for
// open_account, so the PDP origination deny-rule is a no-op and origination flows normally.
// ON → the adapter does the real proofing-directory lookup, so origination is gated on a
// verified mDL. Flipped live at /admin/proofing-gate; initial value from PROOFING_GATE_ENABLED.
var proofingGate atomic.Bool

func proofingGateEnabled() bool { return proofingGate.Load() }

// proofingPresent asks the proofing directory whether the given subject (the customer
// being onboarded) has an ACTIVE identity-proofing activity — a verified mDL presentation
// — FOR the specific account being originated. Account-scoped: a proofing performed for a
// savings origination does not satisfy a cheque origination. Used only for account
// origination. Fails CLOSED (returns false) when the directory is unset or unreachable:
// an un-proofed origination must never slip through the gate.
func proofingPresent(subject, account string) bool {
	base := strings.TrimRight(os.Getenv("PROOFING_DIRECTORY_URL"), "/")
	if base == "" || subject == "" {
		return false
	}
	u := fmt.Sprintf("%s/proofing?active=true&subject=%s", base, url.QueryEscape(subject))
	if account != "" {
		u += "&account=" + url.QueryEscape(account)
	}
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		log.Printf("proofing directory lookup failed for %q: %v", subject, err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var out struct {
		TotalResults int `json:"totalResults"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false
	}
	return out.TotalResults > 0
}

// Build PDP decision payload for single evaluation
func buildPdpDecisionPayload(evalRequest EvaluationRequest) (*PdpPayload, error) {
	log.Println("Starting buildPdpDecisionPayload")

	pdpDomainPrefix := os.Getenv("PDP_DOMAIN_PREFIX")
	pdpAttributePrefix := os.Getenv("PDP_ATTRIBUTE_PREFIX")
	service := os.Getenv("PDP_SERVICE")
	action := os.Getenv("PDP_ACTION")

	log.Printf("Environment variables - PDP_DOMAIN_PREFIX: %s, PDP_ATTRIBUTE_PREFIX: %s, PDP_SERVICE: %s, PDP_ACTION: %s\n",
		pdpDomainPrefix, pdpAttributePrefix, service, action)
	log.Printf("EvaluationRequest: %+v\n", evalRequest)

	if evalRequest.Subject.ID == "" ||
		evalRequest.Action.Name == "" || evalRequest.Resource.Type == "" || evalRequest.Resource.ID == "" {
		log.Println("Error: subject, resource, and action are requiredX")
		return nil, errors.New("subject, resource, and action are required")
	}

	domainValue := pdpDomainPrefix
	pdpPayload := &PdpPayload{
		Domain:     domainValue,
		Service:    service,
		Action:     action,
		Attributes: make(map[string]interface{}),
	}

	log.Println("Building subject object")
	subject := map[string]interface{}{
		"type": evalRequest.Subject.Type,
		"id":   evalRequest.Subject.ID,
	}
	if evalRequest.Subject.Properties != nil {
		subject["properties"] = evalRequest.Subject.Properties
	}

	log.Println("Building resource object")
	resource := map[string]interface{}{
		"type": evalRequest.Resource.Type,
		"id":   evalRequest.Resource.ID,
	}
	if evalRequest.Resource.Properties != nil {
		resource["properties"] = evalRequest.Resource.Properties
	}

	log.Println("Building action object")
	actionObj := map[string]interface{}{
		"name": evalRequest.Action.Name,
	}
	if evalRequest.Action.Properties != nil {
		actionObj["properties"] = evalRequest.Action.Properties
	}

	if evalRequest.Context != nil {
		log.Println("Marshaling context object")
		contextJSON, err := json.Marshal(evalRequest.Context)
		if err != nil {
			log.Printf("Error marshaling context: %v\n", err)
			return nil, fmt.Errorf("failed to marshal context: %v", err)
		}
		contextKey := fmt.Sprintf("%s.context", pdpAttributePrefix)
		pdpPayload.Attributes[contextKey] = string(contextJSON)
	}

	subjectJSON, _ := json.Marshal(subject)
	pdpPayload.Attributes[fmt.Sprintf("%s.subject", pdpAttributePrefix)] = string(subjectJSON)

	resourceJSON, _ := json.Marshal(resource)
	pdpPayload.Attributes[fmt.Sprintf("%s.resource", pdpAttributePrefix)] = string(resourceJSON)

	actionJSON, _ := json.Marshal(actionObj)
	pdpPayload.Attributes[fmt.Sprintf("%s.action", pdpAttributePrefix)] = string(actionJSON)

	// Flat scalar attributes (in addition to the JSON-string attributes above)
	// so PingAuthorize policies can read them directly via a "request" resolver
	// keyed on the attribute name. Keys are dot-free -> 1:1 Trust Framework attrs.
	pdpPayload.Attributes["actionName"] = evalRequest.Action.Name
	pdpPayload.Attributes["resourceType"] = evalRequest.Resource.Type
	pdpPayload.Attributes["resourceId"] = evalRequest.Resource.ID
	pdpPayload.Attributes["agentId"] = evalRequest.Subject.ID
	// The payment's destination account — the policy compares it to the consented
	// creditorAccount in the RAR (authorization_details) for a fine-grained match.
	if evalRequest.Resource.Properties != nil {
		if v, ok := evalRequest.Resource.Properties["to_account"]; ok {
			pdpPayload.Attributes["to_account"] = fmt.Sprintf("%v", v)
		}
	}
	if evalRequest.Subject.Properties != nil {
		if v, ok := evalRequest.Subject.Properties["on_behalf_of"]; ok {
			pdpPayload.Attributes["onBehalfOf"] = fmt.Sprintf("%v", v)
		}
		if v, ok := evalRequest.Subject.Properties["agent_type"]; ok {
			pdpPayload.Attributes["agentType"] = fmt.Sprintf("%v", v)
		}
	}
	if evalRequest.Context != nil {
		ctx := *evalRequest.Context
		if v, ok := ctx["amount"]; ok {
			pdpPayload.Attributes["amount"] = fmt.Sprintf("%v", v)
		}
		if v, ok := ctx["currency"]; ok {
			pdpPayload.Attributes["currency"] = fmt.Sprintf("%v", v)
		}
		if v, ok := ctx["channel"]; ok {
			pdpPayload.Attributes["channel"] = fmt.Sprintf("%v", v)
		}
		// The logged-in user's (Alice's) consented scopes, forwarded by the gateway.
		// The banking policy reads this to decide whether a large payment already has
		// step-up approval (banking:payments:transfer).
		if v, ok := ctx["user_scope"]; ok {
			pdpPayload.Attributes["user_scope"] = fmt.Sprintf("%v", v)
		}
		// The fine-grained RAR (RFC 9396 authorization_details) Alice consented to, from her
		// rich JWT. Passed as a JSON string so the policy can verify THIS payment is within a
		// consented authorization_details entry (amount/account), not just the coarse scope.
		if v, ok := ctx["authorization_details"]; ok && v != nil {
			if b, err := json.Marshal(v); err == nil {
				pdpPayload.Attributes["authorization_details"] = string(b)
			}
		}
		// Pre-extracted consented cap + destination from the RAR (the gateway parsed the
		// payment_initiation entry) so the policy matches with plain comparisons.
		if v, ok := ctx["consented_amount"]; ok {
			pdpPayload.Attributes["consented_amount"] = fmt.Sprintf("%v", v)
		}
		if v, ok := ctx["consented_creditor"]; ok {
			pdpPayload.Attributes["consented_creditor"] = fmt.Sprintf("%v", v)
		}
		// The presented token's audience (RFC 8707 / FAPI 2.0). The policy verifies the
		// token was minted for this resource (audience-restricted), not a bearer token
		// replayable anywhere. Forwarded from the gateway, which decoded the token.
		if v, ok := ctx["token_aud"]; ok {
			pdpPayload.Attributes["token_aud"] = fmt.Sprintf("%v", v)
		}
		// How the user token was authenticated (acr). The step-up rule admits the autonomous
		// demo's staff-approval channel (Bob, the agent owner, authorizing out-of-band; acr
		// urn:northwind:loa:staff-approval) as an alternative to the in-token RAR match,
		// which an ROPC/CIBA-minted token cannot carry.
		if v, ok := ctx["user_acr"]; ok {
			pdpPayload.Attributes["user_acr"] = fmt.Sprintf("%v", v)
		}
	}

	// Fine-grained RFC 9396 RAR coverage, pre-computed as booleans. The embedded PDP
	// (PingAuthorize 11.0.0.2) cannot compare two attributes to each other, so we do the
	// amount/account match here and hand the policy plain booleans it compares to a constant:
	//   rar_amount_ok   — this payment's amount is within a consented cap (cap>0 && amount<=cap)
	//   rar_creditor_ok — this payment's destination matches the consented creditor account
	// Both false when there is no consent, so an uncovered payment steps up.
	attrStr := func(k string) string {
		if v, ok := pdpPayload.Attributes[k]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
	amtOK := false
	if amt, err1 := strconv.ParseFloat(attrStr("amount"), 64); err1 == nil {
		if cap, err2 := strconv.ParseFloat(attrStr("consented_amount"), 64); err2 == nil {
			amtOK = cap > 0 && amt <= cap
		}
	}
	toAcct, cred := attrStr("to_account"), attrStr("consented_creditor")
	credOK := cred != "" && toAcct == cred
	pdpPayload.Attributes["rar_amount_ok"] = strconv.FormatBool(amtOK)
	pdpPayload.Attributes["rar_creditor_ok"] = strconv.FormatBool(credOK)

	// mDL identity-proofing gate for account origination: an account may only be opened
	// once the customer (the delegated principal) has a verified identity-proofing activity
	// — an mDL presentation — recorded in the proofing directory. We resolve it to a plain
	// boolean here (the embedded PDP can't call out to the directory), mirroring the
	// rar_*_ok precompute above. Always set (false when not an origination) so the policy
	// never sees a missing attribute. No directory call is made unless this is open_account.
	// Default true: for non-origination actions, and whenever the gate SWITCH is OFF, we
	// report identity_proofing_present=true so the PDP origination deny-rule is a no-op.
	// Only when the switch is ON do we do the real directory lookup for open_account — so a
	// customer without a verified mDL is denied and challenged to present one.
	proofed := true
	actLower := strings.ToLower(attrStr("actionName"))
	resLower := strings.ToLower(attrStr("resourceId"))
	if proofingGateEnabled() &&
		(strings.Contains(actLower, "open_account") || strings.Contains(resLower, "open_account")) {
		subj := attrStr("onBehalfOf")
		if subj == "" {
			subj = evalRequest.Subject.ID
		}
		// The account being originated: the COAZ mapping carries it both as the
		// account_type resource property and encoded in the resource id ("new:<type>").
		account := strings.ToLower(attrStr("account_type"))
		if account == "" && strings.HasPrefix(resLower, "new:") {
			account = strings.TrimPrefix(resLower, "new:")
		}
		proofed = proofingPresent(subj, account)
	}
	pdpPayload.Attributes["identity_proofing_present"] = strconv.FormatBool(proofed)

	log.Println("Successfully built PdpPayload")
	log.Printf("PdpPayload: %+v\n", pdpPayload)

	return pdpPayload, nil
}

func makeQueryRequest(queryRequest *QueryRequest) ([]QueryItem, error) {
	pdpUrl := os.Getenv("QUERY_URL")
	if pdpUrl == "" {
		pdpUrl = "https://localhost:8443/governance-engine/query"
	}
	pdpSecretHeader := os.Getenv("PDP_SECRET_HEADER")
	if pdpSecretHeader == "" {
		pdpSecretHeader = "CLIENT_TOKEN"
	}
	pdpSecret := os.Getenv("PDP_SECRET")
	if pdpSecret == "" {
		pdpSecret = "2FederateM)re"
	}

	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	payloadBytes, err := json.Marshal(queryRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal queryRequest: %v", err)
	}
	payloadString := string(payloadBytes)
	req, err := http.NewRequest("POST", pdpUrl, strings.NewReader(string(payloadBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(pdpSecretHeader, pdpSecret)

	curlCommand := fmt.Sprintf("curl -X -k POST '%s' \\\n -H 'Content-Type: application/json' \\\n -H '%s: %s' \\\n -d '%s'",
		pdpUrl, pdpSecretHeader, pdpSecret, payloadString)
	log.Printf("Equivalent curl command:\n%s", curlCommand)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make query request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var responsePayload map[string]interface{}
	if err := json.Unmarshal(body, &responsePayload); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	queryItems, ok := responsePayload["query"].([]QueryItem)
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'query' field in response")
	}

	return queryItems, nil
}

// Make authorization decision request
func makeAuthorizationDecisionRequest(pdpPayload *PdpPayload) ([]EvaluationResponse, error) {
	pdpUrl := os.Getenv("PDP_URL")
	if pdpUrl == "" {
		pdpUrl = "https://localhost:8443/governance-engine"
	}
	pdpSecretHeader := os.Getenv("PDP_SECRET_HEADER")
	if pdpSecretHeader == "" {
		pdpSecretHeader = "CLIENT-TOKEN"
	}
	pdpSecret := os.Getenv("PDP_SECRET")
	if pdpSecret == "" {
		pdpSecret = "Password1"
	}

	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	payloadBytes, err := json.Marshal(pdpPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pdpPayload: %v", err)
	}
	payloadString := string(payloadBytes)
	req, err := http.NewRequest("POST", pdpUrl, strings.NewReader(string(payloadBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to create new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(pdpSecretHeader, pdpSecret)

	curlCommand := fmt.Sprintf("curl -X -k POST '%s' \\\n -H 'Content-Type: application/json' \\\n -H '%s: %s' \\\n -d '%s'",
		pdpUrl, pdpSecretHeader, pdpSecret, payloadString)
	log.Printf("Equivalent curl command:\n%s", curlCommand)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make authorization request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Log the raw PDP response so misconfigurations are diagnosable
	log.Printf("DEBUG: PDP response status=%d body=%s", resp.StatusCode, string(body))

	var responsePayload map[string]interface{}
	if err := json.Unmarshal(body, &responsePayload); err != nil {
		return nil, fmt.Errorf("failed to decode response (status %d): %v; body: %.300s",
			resp.StatusCode, err, string(body))
	}

	// Accept the legacy custom {"authorised": bool} shape as well as the
	// standard PingAuthorize JSON PDP API shapes:
	//   {"authorized": bool} and {"decision": "PERMIT"|"DENY"}.
	authorized, ok := responsePayload["authorised"].(bool)
	if !ok {
		authorized, ok = responsePayload["authorized"].(bool)
	}
	if !ok {
		if decisionStr, ok2 := responsePayload["decision"].(string); ok2 {
			authorized = strings.EqualFold(decisionStr, "PERMIT")
			ok = true
		}
	}
	if !ok {
		return nil, fmt.Errorf("no authorised/authorized/decision field in PDP response (status %d): %.300s",
			resp.StatusCode, string(body))
	}

	var evalResponse EvaluationResponse
	evalResponse.Decision = authorized
	evalResponse.RawPDP = string(body) // verbatim PingAuthorize decision record

	// Build the response context. First scan policy statements for the step-up advice
	// (code "step-up-required"): its JSON payload carries {step_up, scope, message}. When
	// present, surface step_up_required + step_up_scope so the gateway issues an RFC 9470
	// step-up (insufficient_scope) challenge instead of a flat 403. Otherwise fall back to
	// a plain reason (explicit "reason", else the first statement payload) — how
	// PingAuthorize policies communicate advice back to the caller.
	ctx := Context{}
	if stmts, ok := responsePayload["statements"].([]interface{}); ok {
		for _, s := range stmts {
			st, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			if code, _ := st["code"].(string); code == "step-up-required" {
				ctx["step_up_required"] = true
				var pj map[string]interface{}
				if payload, _ := st["payload"].(string); json.Unmarshal([]byte(payload), &pj) == nil {
					if sc, ok := pj["scope"].(string); ok {
						ctx["step_up_scope"] = sc
					}
					if msg, ok := pj["message"].(string); ok {
						ctx["reason"] = msg
					}
				}
			}
			// Account origination requires an mDL identity-proofing activity that isn't
			// present yet (code "identity-proofing-required"): surface identity_proofing_required
			// (+ doctype) so the gateway/BFF drives an OID4VP mDL presentation and then resumes,
			// mirroring the step-up-required challenge above.
			if code, _ := st["code"].(string); code == "identity-proofing-required" {
				ctx["identity_proofing_required"] = true
				var pj map[string]interface{}
				if payload, _ := st["payload"].(string); json.Unmarshal([]byte(payload), &pj) == nil {
					if dt, ok := pj["doctype"].(string); ok {
						ctx["identity_proofing_doctype"] = dt
					}
					if msg, ok := pj["message"].(string); ok {
						ctx["reason"] = msg
					}
				}
			}
		}
	}
	if _, hasReason := ctx["reason"]; !hasReason {
		if reason, exists := responsePayload["reason"]; exists {
			ctx["reason"] = reason
		} else if stmts, ok := responsePayload["statements"].([]interface{}); ok && len(stmts) > 0 {
			if st, ok := stmts[0].(map[string]interface{}); ok {
				if p, ok := st["payload"].(string); ok && p != "" {
					ctx["reason"] = p
				}
			}
		}
	}
	if len(ctx) > 0 {
		evalResponse.Context = &ctx
	}

	return []EvaluationResponse{evalResponse}, nil
}

func handleEvaluationRequest(w http.ResponseWriter, r *http.Request) {
	log.Println("DEBUG: Received evaluation request")

	expectedAPIKey := os.Getenv("API_KEY")
	if expectedAPIKey == "" {
		log.Println("ERROR: API key not set in environment")
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	// Log incoming request headers for debugging
	log.Println("DEBUG: Request Headers:")
	for key, values := range r.Header {
		log.Printf("DEBUG: %s: %s\n", key, strings.Join(values, ", "))
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		log.Println("ERROR: Missing or invalid Authorization header")
		http.Error(w, "Unauthorized: Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	providedAPIKey := strings.TrimPrefix(authHeader, "Bearer ")
	if providedAPIKey != expectedAPIKey {
		log.Println("ERROR: Unauthorized request - Invalid API key")
		http.Error(w, "Unauthorized: Invalid API key", http.StatusUnauthorized)
		return
	}

	// Log that authorization passed
	log.Println("DEBUG: API key authentication successful")

	// Decode JSON request body
	var evalRequest EvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&evalRequest); err != nil {
		log.Printf("ERROR: Failed to decode request body: %v\n", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Log received evaluation request JSON
	evalRequestJSON, _ := json.MarshalIndent(evalRequest, "", "  ")
	log.Printf("DEBUG: Parsed Evaluation Request:\n%s\n", evalRequestJSON)
	log.Printf("DEBUG: Evaluations: %v\n", evalRequest.Evaluations)

	if evalRequest.Evaluations != nil && len(*evalRequest.Evaluations) > 0 {
		log.Printf("DEBUG: Processing batch evaluation with %d requests\n", len(*evalRequest.Evaluations))

		batchRequests := make([]EvaluationRequest, len(*evalRequest.Evaluations))

		for i, eval := range *evalRequest.Evaluations {
			action := eval.Action
			if action.Name == "" {
				action = evalRequest.Action
			}

			resource := eval.Resource
			if resource.Type == "" || resource.ID == "" {
				resource = evalRequest.Resource
			}

			subject := evalRequest.Subject
			if eval.Subject.ID != "" || eval.Subject.Type != "" {
				subject = eval.Subject
			}

			context := eval.Context
			if context == nil {
				context = *evalRequest.Context
			}

			batchRequests[i] = EvaluationRequest{
				Subject:  subject,
				Action:   action,
				Resource: resource,
				Context:  &context,
			}

			// Log each constructed batch request
			batchRequestJSON, _ := json.MarshalIndent(batchRequests[i], "", "  ")
			log.Printf("DEBUG: Constructed Batch Request %d:\n%s\n", i+1, batchRequestJSON)
		}

		// Handle batch evaluation
		results, err := handleEvaluationBatchRequests(batchRequests)
		if err != nil {
			log.Printf("ERROR: Batch authorization request failed: %v\n", err)
			http.Error(w, "Error making batch authorization decision request", http.StatusInternalServerError)
			return
		}

		// Log evaluation results
		resultsJSON, _ := json.MarshalIndent(map[string]interface{}{"evaluations": results}, "", "  ")
		log.Printf("DEBUG: Batch Evaluation Response:\n%s\n", resultsJSON)

		// Send response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"evaluations": results}); err != nil {
			log.Printf("ERROR: Failed to encode batch response: %v\n", err)
			http.Error(w, "Failed to encode batch response", http.StatusInternalServerError)
		}
		return
	}
	log.Println("DEBUG: Processing single evaluation request")

	pdpPayload, err := buildPdpDecisionPayload(evalRequest)
	if err != nil {
		log.Printf("ERROR: Failed to build PDP Payload: %v\n", err)
		http.Error(w, "Error building PDP payload", http.StatusInternalServerError)
		return
	}

	// Log PDP Payload
	pdpPayloadJSON, _ := json.MarshalIndent(pdpPayload, "", "  ")
	log.Printf("DEBUG: PDP Payload:\n%s\n", pdpPayloadJSON)

	decision, err := makeAuthorizationDecisionRequest(pdpPayload)
	if err != nil {
		log.Printf("ERROR: Authorization request failed: %v\n", err)
		http.Error(w, "Error making authorization decision request", http.StatusInternalServerError)
		return
	}

	// Log Decision Response
	decisionJSON, _ := json.MarshalIndent(decision, "", "  ")
	log.Printf("DEBUG: Authorization Decision Response:\n%s\n", decisionJSON)

	// Feed the live PDP-decisions sidebar (best-effort, never blocks).
	if len(decision) > 0 {
		feed.publish(pdpEventFrom(pdpPayload, decision[0]))
	}

	// Send Response. The AuthZEN single-evaluation endpoint returns a single
	// decision OBJECT ({"decision":bool,"context":{...}}) — NOT an array — so
	// callers (e.g. the Kong PEP) can read `.decision` directly.
	var single EvaluationResponse
	if len(decision) > 0 {
		single = decision[0]
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(single); err != nil {
		log.Printf("ERROR: Failed to encode response: %v\n", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}

}

// handleEvaluationBatchRequests processes a batch of evaluation requests and returns their corresponding evaluation responses.
// It iterates over each evaluation request, builds the PDP (Policy Decision Point) payload, and makes an authorization decision request.
// If any error occurs during the process, it returns the error.
//
// Parameters:
//
//	evalRequests []EvaluationRequest - A slice of evaluation requests to be processed.
//
// Returns:
//
//	[]EvaluationResponse - A slice of evaluation responses corresponding to the input requests.
//	error - An error if any occurs during the processing of the requests.
func handleEvaluationBatchRequests(evalRequests []EvaluationRequest) ([]EvaluationResponse, error) {
	log.Println("DEBUG: Starting batch evaluation request processing")
	log.Printf("DEBUG: Received %d evaluation requests\n", len(evalRequests))

	var results []EvaluationResponse

	for i, evalReq := range evalRequests {
		log.Printf("DEBUG: Processing request %d: %+v\n", i+1, evalReq)

		// Build PDP Payload
		pdpPayload, err := buildPdpDecisionPayload(evalReq)
		if err != nil {
			log.Printf("ERROR: Failed to build PDP Payload for request %d: %v\n", i+1, err)
			return nil, fmt.Errorf("error building PDP Payload: %v", err)
		}

		// Log PDP Payload (JSON formatted for readability)
		pdpPayloadJSON, _ := json.MarshalIndent(pdpPayload, "", "  ")
		log.Printf("DEBUG: PDP Payload for request %d:\n%s\n", i+1, pdpPayloadJSON)

		// Make Authorization Decision Request
		decision, err := makeAuthorizationDecisionRequest(pdpPayload)
		if err != nil {
			log.Printf("ERROR: Authorization decision request failed for request %d: %v\n", i+1, err)
			return nil, fmt.Errorf("error making authorization decision request: %v", err)
		}

		// Log Decision Response (JSON formatted)
		decisionJSON, _ := json.MarshalIndent(decision, "", "  ")
		log.Printf("DEBUG: Authorization Decision Response for request %d:\n%s\n", i+1, decisionJSON)

		// Feed the live PDP-decisions sidebar (best-effort, never blocks).
		for _, d := range decision {
			feed.publish(pdpEventFrom(pdpPayload, d))
		}

		results = append(results, decision...)
	}

	log.Println("DEBUG: Completed batch evaluation processing successfully")
	return results, nil
}

// handleProofingGate exposes the mDL identity-proofing SWITCH. GET returns the current
// state; POST {"enabled":true|false} flips it live (no redeploy) so the demo can toggle
// whether account origination requires a verified mDL. Open (no auth) — demo control plane.
func handleProofingGate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		proofingGate.Store(body.Enabled)
		log.Printf("mDL proofing gate switched enabled=%v", body.Enabled)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": proofingGate.Load()})
}

func main() {
	godotenv.Load()
	if strings.EqualFold(os.Getenv("PROOFING_GATE_ENABLED"), "true") {
		proofingGate.Store(true)
	}
	http.HandleFunc("/access/v1/evaluation", handleEvaluationRequest)
	http.HandleFunc("/access/v1/evaluations", handleEvaluationRequest)
	http.HandleFunc("/access/v1/subjectsearch", handleSubjectSearchRequest)
	http.HandleFunc("/access/v1/resourcesearch", handleResourceSearchRequest)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})
	// Live decision feed for the demo UI's PDP sidebar.
	http.HandleFunc("/pdp/events", handlePdpEvents)
	http.HandleFunc("/pdp/recent", handlePdpRecent)
	// The mDL identity-proofing gate switch (GET state, POST {enabled} to flip live).
	http.HandleFunc("/admin/proofing-gate", handleProofingGate)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	address := fmt.Sprintf(":%s", port)
	log.Printf("Starting proxy service on port %s", address)
	if err := http.ListenAndServe(address, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
