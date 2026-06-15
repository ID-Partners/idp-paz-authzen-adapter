package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// ------------------------------
// AuthZEN MCP Profile + Default Mappings
// ------------------------------
//
// Based on the "Default AuthZEN Mappings for MCP JSON-RPC Messages"
// (MCP Specification 2025-11-25). Each MCP JSON-RPC method maps onto the
// AuthZEN Subject-Action-Resource-Context (SARC) model so that an MCP
// server/gateway acting as a Policy Enforcement Point (PEP) can externalize
// authorization to an AuthZEN PDP.
//
// Resource types reflect the MCP primitive being accessed.
const (
	ResourceTypeTool      = "tool"
	ResourceTypeResource  = "resource"
	ResourceTypePrompt    = "prompt"
	ResourceTypeTask      = "task"
	ResourceTypeMCPServer = "mcp_server"
)

// MCP discovery/list methods. In the default mapping these are scoped to the
// MCP server (resource.type = mcp_server, resource.id = the JWT aud claim)
// rather than to a specific instance.
const (
	ActionToolsList             = "tools/list"
	ActionResourcesList         = "resources/list"
	ActionResourceTemplatesList = "resources/templates/list"
	ActionPromptsList           = "prompts/list"
	ActionTasksList             = "tasks/list"
	ActionRootsList             = "roots/list"
)

// isMCPResourceType reports whether the resource type is one defined by the
// AuthZEN default mappings for MCP.
func isMCPResourceType(t string) bool {
	switch t {
	case ResourceTypeTool, ResourceTypeResource, ResourceTypePrompt,
		ResourceTypeTask, ResourceTypeMCPServer:
		return true
	default:
		return false
	}
}

// isMCPListAction reports whether the action is an MCP discovery/list method.
// List operations enumerate items a subject may access; when a PEP omits a
// resource id for them the adapter does not require one.
func isMCPListAction(name string) bool {
	switch name {
	case ActionToolsList, ActionResourcesList, ActionResourceTemplatesList,
		ActionPromptsList, ActionTasksList, ActionRootsList:
		return true
	default:
		return false
	}
}

// Structures updated to conform to the specification

// Subject represents the "subject" object.
// Note: The "id" field may be omitted in Subject Search requests
// and, if present, is ignored by the PDP for the Subject Search API.
type Subject struct {
	Type       string                 `json:"type"`       // Required
	ID         string                 `json:"identity"`   // Required
	Properties map[string]interface{} `json:"properties"` // Optional
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

// requireAPIKey validates the Bearer API key on a request. It writes the
// appropriate error response and returns false when the request is not
// authorized, otherwise it returns true.
func requireAPIKey(w http.ResponseWriter, r *http.Request) bool {
	expectedAPIKey := os.Getenv("API_KEY")
	if expectedAPIKey == "" {
		log.Println("API key not set in environment")
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return false
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized: Missing or invalid Authorization header", http.StatusUnauthorized)
		return false
	}
	if strings.TrimPrefix(authHeader, "Bearer ") != expectedAPIKey {
		http.Error(w, "Unauthorized: Invalid API key", http.StatusUnauthorized)
		return false
	}
	return true
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

	if !requireAPIKey(w, r) {
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
	if !requireAPIKey(w, r) {
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

	// MCP discovery/list operations (tools/list, resources/list, prompts/list)
	// enumerate accessible resources and so are not bound to a specific
	// resource id. For every other request a resource id remains required.
	requireResourceID := !isMCPListAction(evalRequest.Action.Name)

	if evalRequest.Subject.ID == "" ||
		evalRequest.Action.Name == "" || evalRequest.Resource.Type == "" ||
		(requireResourceID && evalRequest.Resource.ID == "") {
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
	}
	// Omit the id for MCP list operations, which do not target a specific resource.
	if evalRequest.Resource.ID != "" {
		resource["id"] = evalRequest.Resource.ID
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

	var responsePayload map[string]interface{}
	if err := json.Unmarshal(body, &responsePayload); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// Generate EvaluationResponse from response
	authorized, ok := responsePayload["authorised"].(bool)
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'authorised' field in response")
	}

	var evalResponse EvaluationResponse
	evalResponse.Decision = authorized

	// Optionally add context if there is a reason for the decision
	if reason, exists := responsePayload["reason"]; exists {
		context := Context{"reason": reason}
		evalResponse.Context = &context
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

	// Send Response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(decision); err != nil {
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

		results = append(results, decision...)
	}

	log.Println("DEBUG: Completed batch evaluation processing successfully")
	return results, nil
}

// ------------------------------
// AuthZEN MCP Profile: coazMapping resolution
// ------------------------------
//
// The COAZ profile lets an MCP tool declare an "x-coaz-mapping" (a.k.a.
// coazMapping) object inside its inputSchema. The mapping describes how to
// project a tool invocation onto the AuthZEN Subject-Action-Resource-Context
// model, using JSONPath-style references:
//
//   $.properties[...]  -> the tool-call arguments (inputSchema properties)
//   $.token[...]       -> claims from the caller's (JWT) OAuth access token
//
// This endpoint resolves such a mapping against a concrete set of arguments
// and token claims, producing a ready-to-send AuthZEN evaluation request. When
// "evaluate" is set it additionally forwards the request to the PDP and
// returns the decision, so an MCP gateway can perform parameter-level
// authorization in a single call.

// CoazResolveRequest is the payload accepted by the coazMapping resolver.
type CoazResolveRequest struct {
	Mapping    map[string]interface{} `json:"mapping"`              // the tool's x-coaz-mapping object (REQUIRED)
	Tool       string                 `json:"tool,omitempty"`       // tool name; default action.name when the mapping omits one
	Properties map[string]interface{} `json:"properties,omitempty"` // resolved tool-call arguments ($.properties)
	Token      map[string]interface{} `json:"token,omitempty"`      // decoded OAuth/JWT claims ($.token)
	Action     string                 `json:"action,omitempty"`     // optional MCP method override for action.name
	Evaluate   bool                   `json:"evaluate,omitempty"`   // if true, forward to the PDP and include the decision
}

// CoazResolveResponse returns the resolved AuthZEN request and, optionally, the
// PDP decision.
type CoazResolveResponse struct {
	EvaluationRequest map[string]interface{} `json:"evaluation_request"`
	Decision          *bool                  `json:"decision,omitempty"`
	Context           *Context               `json:"context,omitempty"`
}

// resolveCoazValue walks an arbitrary mapping value, replacing any string that
// begins with "$." with the value referenced from sources. Objects and arrays
// are resolved recursively; all other values pass through unchanged.
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

// tokenizeCoazPath splits a "$.root.a['b'][0]" reference into its path
// segments (e.g. ["root", "a", "b", "0"]). It supports dot notation,
// quoted/unquoted bracket notation, and numeric array indices.
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

// resolveCoazRef resolves a single "$..." reference against sources. The first
// path segment selects the source ("properties" or "token"); the remaining
// segments traverse nested objects and arrays.
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

// toStringValue coerces a resolved JSON value into a string for the typed
// fields of an EvaluationRequest.
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
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// evaluationRequestFromResolved converts a resolved AuthZEN request (generic
// map) into the typed EvaluationRequest used to build the PDP payload.
func evaluationRequestFromResolved(resolved map[string]interface{}) EvaluationRequest {
	var er EvaluationRequest

	if s, ok := resolved["subject"].(map[string]interface{}); ok {
		er.Subject.Type = toStringValue(s["type"])
		if v, ok := s["id"]; ok {
			er.Subject.ID = toStringValue(v)
		} else {
			er.Subject.ID = toStringValue(s["identity"])
		}
		if p, ok := s["properties"].(map[string]interface{}); ok {
			er.Subject.Properties = p
		}
	}

	if res, ok := resolved["resource"].(map[string]interface{}); ok {
		er.Resource.Type = toStringValue(res["type"])
		er.Resource.ID = toStringValue(res["id"])
		if p, ok := res["properties"].(map[string]interface{}); ok {
			er.Resource.Properties = p
		}
	}

	if a, ok := resolved["action"].(map[string]interface{}); ok {
		er.Action.Name = toStringValue(a["name"])
		if p, ok := a["properties"].(map[string]interface{}); ok {
			er.Action.Properties = p
		}
	}

	if c, ok := resolved["context"].(map[string]interface{}); ok {
		ctx := Context(c)
		er.Context = &ctx
	}

	return er
}

// handleCoazResolveRequest resolves an MCP tool's x-coaz-mapping into an
// AuthZEN evaluation request, optionally evaluating it against the PDP.
func handleCoazResolveRequest(w http.ResponseWriter, r *http.Request) {
	if !requireAPIKey(w, r) {
		return
	}

	var req CoazResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	if req.Mapping == nil {
		http.Error(w, "Missing required 'mapping' (x-coaz-mapping) object", http.StatusBadRequest)
		return
	}

	sources := map[string]interface{}{
		"properties": coalesceMap(req.Properties),
		"token":      coalesceMap(req.Token),
	}

	resolvedAny, err := resolveCoazValue(req.Mapping, sources)
	if err != nil {
		log.Printf("ERROR: failed to resolve coaz mapping: %v", err)
		http.Error(w, fmt.Sprintf("Failed to resolve coaz mapping: %v", err), http.StatusBadRequest)
		return
	}
	resolved, ok := resolvedAny.(map[string]interface{})
	if !ok {
		http.Error(w, "Resolved coaz mapping is not an object", http.StatusBadRequest)
		return
	}

	// action.name: an explicit override wins; otherwise the mapping's value is
	// kept; otherwise it defaults to the tool name (per the COAZ profile).
	if req.Action != "" {
		setActionName(resolved, req.Action)
	} else if _, present := resolved["action"]; !present && req.Tool != "" {
		setActionName(resolved, req.Tool)
	}

	resp := CoazResolveResponse{EvaluationRequest: resolved}

	if req.Evaluate {
		evalReq := evaluationRequestFromResolved(resolved)
		pdpPayload, err := buildPdpDecisionPayload(evalReq)
		if err != nil {
			log.Printf("ERROR: failed to build PDP payload from coaz mapping: %v", err)
			http.Error(w, fmt.Sprintf("Error building PDP payload: %v", err), http.StatusBadRequest)
			return
		}
		decisions, err := makeAuthorizationDecisionRequest(pdpPayload)
		if err != nil {
			log.Printf("ERROR: coaz authorization decision request failed: %v", err)
			http.Error(w, "Error making authorization decision request", http.StatusInternalServerError)
			return
		}
		if len(decisions) > 0 {
			d := decisions[0].Decision
			resp.Decision = &d
			resp.Context = decisions[0].Context
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("ERROR: failed to encode coaz response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// coalesceMap returns a non-nil map so reference resolution never dereferences nil.
func coalesceMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return map[string]interface{}{}
	}
	return m
}

// setActionName sets action.name on a resolved request, creating the action
// object if it is missing.
func setActionName(resolved map[string]interface{}, name string) {
	if a, ok := resolved["action"].(map[string]interface{}); ok {
		a["name"] = name
		return
	}
	resolved["action"] = map[string]interface{}{"name": name}
}

// ------------------------------
// AuthZEN Default Mappings for MCP JSON-RPC Messages
// ------------------------------

// JSONRPCMessage is the subset of an MCP JSON-RPC message used for mapping.
type JSONRPCMessage struct {
	JSONRPC string                 `json:"jsonrpc,omitempty"`
	ID      interface{}            `json:"id,omitempty"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params,omitempty"`
}

// MCPEvaluateRequest maps an MCP JSON-RPC message onto an AuthZEN request.
// Either an embedded "message" or explicit "method"/"params" may be supplied.
type MCPEvaluateRequest struct {
	Message     *JSONRPCMessage        `json:"message,omitempty"`      // the MCP JSON-RPC message
	Method      string                 `json:"method,omitempty"`       // method override / alternative to message
	Params      map[string]interface{} `json:"params,omitempty"`       // params override / alternative to message
	Token       map[string]interface{} `json:"token,omitempty"`        // decoded OAuth/JWT claims (sub, aud, client_id, ...)
	CoazMapping map[string]interface{} `json:"coaz_mapping,omitempty"` // x-coaz-mapping for the called tool (tools/call only)
	Evaluate    bool                   `json:"evaluate,omitempty"`     // if true, forward to the PDP and include the decision
}

// MCPEvaluateResponse returns the mapped AuthZEN request and, optionally, the PDP decision.
type MCPEvaluateResponse struct {
	EvaluationRequest map[string]interface{} `json:"evaluation_request"`
	Decision          *bool                  `json:"decision,omitempty"`
	Context           *Context               `json:"context,omitempty"`
}

// toMap returns v as a JSON object, or nil if it is not one.
func toMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

// getStr returns m[key] coerced to a string, or "" when absent.
func getStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		return toStringValue(v)
	}
	return ""
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

// buildMCPEvaluationRequest projects an MCP JSON-RPC method+params and the
// caller's token claims onto an AuthZEN evaluation request using the default
// mappings. For tools/call, a non-nil coazMapping (the tool's x-coaz-mapping)
// overrides the default subject/resource/action/context.
func buildMCPEvaluationRequest(method string, params, claims, coazMapping map[string]interface{}) (map[string]interface{}, error) {
	sub := getStr(claims, "sub")
	aud := audienceString(claims)
	agent := getStr(claims, "client_id")

	subject := map[string]interface{}{"type": "identity", "id": sub}
	context := map[string]interface{}{"agent": agent}

	// Default: scoped to the MCP server. Covers list/discovery methods,
	// lifecycle (initialize, ping), notifications, and any unrecognized method.
	req := map[string]interface{}{
		"subject":  subject,
		"action":   map[string]interface{}{"name": method},
		"resource": map[string]interface{}{"type": ResourceTypeMCPServer, "id": aud},
		"context":  context,
	}
	setAction := func(name string) { req["action"] = map[string]interface{}{"name": name} }
	setResource := func(typ, id string) { req["resource"] = map[string]interface{}{"type": typ, "id": id} }

	switch method {
	case "tools/call":
		toolName := getStr(params, "name")
		setAction(toolName)
		setResource(ResourceTypeTool, toolName)
		// Task-augmented invocation carries a task object in params.
		if task := toMap(params["task"]); task != nil {
			if v, ok := task["ttl"]; ok {
				context["task_ttl"] = v
			}
		}
		// COAZ override: the tool's x-coaz-mapping replaces the defaults.
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
		setResource(ResourceTypeResource, getStr(params, "uri"))

	case "prompts/get":
		// Per the spec's per-method mapping, prompts/get uses subject.type "user".
		subject["type"] = "user"
		setResource(ResourceTypePrompt, getStr(params, "name"))

	case "completion/complete":
		ref := toMap(params["ref"])
		refID := getStr(ref, "name")
		if refID == "" {
			refID = getStr(ref, "uri")
		}
		setResource(getStr(ref, "type"), refID)
		context["argument_name"] = getStr(toMap(params["argument"]), "name")

	case "tasks/get", "tasks/result", "tasks/cancel":
		setResource(ResourceTypeTask, getStr(params, "taskId"))

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

// handleMCPEvaluateRequest maps an MCP JSON-RPC message to an AuthZEN request
// using the default mappings, and optionally evaluates it against the PDP.
func handleMCPEvaluateRequest(w http.ResponseWriter, r *http.Request) {
	if !requireAPIKey(w, r) {
		return
	}

	var req MCPEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	method := req.Method
	params := req.Params
	if req.Message != nil {
		method = req.Message.Method
		params = req.Message.Params
	}
	if method == "" {
		http.Error(w, "Missing MCP method", http.StatusBadRequest)
		return
	}

	mapped, err := buildMCPEvaluationRequest(method, params, req.Token, req.CoazMapping)
	if err != nil {
		log.Printf("ERROR: failed to map MCP message: %v", err)
		http.Error(w, fmt.Sprintf("Failed to map MCP message: %v", err), http.StatusBadRequest)
		return
	}

	resp := MCPEvaluateResponse{EvaluationRequest: mapped}

	if req.Evaluate {
		evalReq := evaluationRequestFromResolved(mapped)
		pdpPayload, err := buildPdpDecisionPayload(evalReq)
		if err != nil {
			log.Printf("ERROR: failed to build PDP payload from MCP mapping: %v", err)
			http.Error(w, fmt.Sprintf("Error building PDP payload: %v", err), http.StatusBadRequest)
			return
		}
		decisions, err := makeAuthorizationDecisionRequest(pdpPayload)
		if err != nil {
			log.Printf("ERROR: MCP authorization decision request failed: %v", err)
			http.Error(w, "Error making authorization decision request", http.StatusInternalServerError)
			return
		}
		if len(decisions) > 0 {
			d := decisions[0].Decision
			resp.Decision = &d
			resp.Context = decisions[0].Context
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("ERROR: failed to encode MCP evaluate response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func main() {
	godotenv.Load()
	http.HandleFunc("/access/v1/evaluation", handleEvaluationRequest)
	http.HandleFunc("/access/v1/evaluations", handleEvaluationRequest)
	http.HandleFunc("/access/v1/subjectsearch", handleSubjectSearchRequest)
	http.HandleFunc("/access/v1/resourcesearch", handleResourceSearchRequest)
	http.HandleFunc("/access/v1/coaz/resolve", handleCoazResolveRequest)
	http.HandleFunc("/access/v1/mcp/evaluate", handleMCPEvaluateRequest)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})

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
