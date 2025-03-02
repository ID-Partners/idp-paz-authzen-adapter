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
	"strings"

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

func main() {
	godotenv.Load()
	http.HandleFunc("/access/v1/evaluation", handleEvaluationRequest)
	http.HandleFunc("/access/v1/evaluations", handleEvaluationRequest)
	http.HandleFunc("/access/v1/subjectsearch", handleSubjectSearchRequest)
	http.HandleFunc("/access/v1/resourcesearch", handleResourceSearchRequest)
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
