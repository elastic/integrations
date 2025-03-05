package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// Mock OAuth2 client credentials
var mockClientID = "xxxx"
var mockClientSecret = "xxxx"
var datafeedCalled bool = false

// Mock OAuth2 token
var mockAccessToken = "abcd"
var mockSessionToken = "xyz"

// Mock dataFeedURL (simulating a URL to fetch events from)
var mockDataFeedURL = "http://svc-crowdstrike-streaming:8090/events"

// Mock OAuth2 Token endpoint
func mockTokenHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: Method=%s, URL=%s", r.Method, r.URL.String())
	log.Printf("Headers: %+v", r.Header)
	// Only allow POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data (client credentials)
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	// Get client credentials from the form
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Validate client credentials
	if clientID == mockClientID && clientSecret == mockClientSecret {
		// Mock success, return an access token
		tokenResponse := map[string]string{
			"access_token": mockAccessToken,
			"token_type":   "bearer",
		}
		log.Printf("Returning auth token")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(tokenResponse)
	} else {
		// Invalid credentials
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
	}
}

// Middleware to verify OAuth2 Bearer token
func verifyOAuth2Token(r *http.Request) error {
	// Extract OAuth2 token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return fmt.Errorf("missing Bearer token")
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate the token
	if tokenString != mockAccessToken {
		return fmt.Errorf("invalid token")
	}
	return nil
}

// Returns a resource with a dataFeedURL and sessionToken
func resourceHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: Method=%s, URL=%s", r.Method, r.URL.String())
	log.Printf("Headers: %+v", r.Header)
	if datafeedCalled {
		fmt.Println("Datafeed has already been called. Exiting...")
		os.Exit(0) // Exit the program, or use return if you don't want to terminate
	}
	datafeedCalled = true
	err := verifyOAuth2Token(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	resource := map[string]interface{}{
		"resources": []map[string]interface{}{
			{
				"dataFeedURL": mockDataFeedURL,
				"sessionToken": map[string]interface{}{
					"token":      mockSessionToken,
					"expiration": "2025-11-18T09:21:31.767185156Z",
				},
				"refreshActiveSessionURL":      mockDataFeedURL,
				"refreshActiveSessionInterval": 1800,
			},
		},
	}
	log.Printf("Returning datafeed url.")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resource)
}

type streamReader struct {
	data  []string
	index int
}

func (s *streamReader) Read(p []byte) (n int, err error) {
	if s.index >= len(s.data) {
		return 0, io.EOF // No more data to stream
	}
	chunk := s.data[s.index]
	s.index++
	copy(p, chunk)
	return len(chunk), nil
}

func streamData(w http.ResponseWriter, r *http.Request) {
	// Set the response header for streaming
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked") // This will stream data in chunks

	// Prepare data to stream
	data := []string{
		`{"metadata":{"customerIDString":"abcabcabc22221","offset":8695284,"eventType":"RemoteResponseSessionStartEvent","eventCreationTime":1698932494000,"version":"1.0"},"event":{"SessionId":"1111-fffff-4bb4-99c1-74c13cfc3e5a","HostnameField":"UKCHUDL00206","UserName":"admin.rose@example.com","StartTimestamp":1698932494,"AgentIdString":"fffffffff33333"}}`,
		`{"metadata":{"customerIDString":"abcabcabc22222","offset":8695285,"eventType":"RemoteResponseSessionStartEvent","eventCreationTime":1698932494000,"version":"1.0"},"event":{"SessionId":"1111-fffff-4bb4-99c1-74c13cfc3e5a","HostnameField":"UKCHUDL00206","UserName":"admin.rose@example.com","StartTimestamp":1698932494,"AgentIdString":"fffffffff33333"}}`,
		`{"metadata":{"customerIDString":"abcabcabc22223","offset":8695286,"eventType":"RemoteResponseSessionStartEvent","eventCreationTime":1698932494000,"version":"1.0"},"event":{"SessionId":"1111-fffff-4bb4-99c1-74c13cfc3e5a","HostnameField":"UKCHUDL00206","UserName":"admin.rose@example.com","StartTimestamp":1698932494,"AgentIdString":"fffffffff33333"}}`,
	}

	// Create a custom reader for streaming data
	reader := &streamReader{
		data:  data,
		index: 0,
	}

	// Stream the data using the custom reader
	_, err := io.Copy(w, reader)
	if err != nil {
		http.Error(w, "Error while streaming data", http.StatusInternalServerError)
		return
	}

	log.Println("Data streaming completed, closing connection.")
}

func main() {
	// Setup routes
	http.HandleFunc("/oauth2/token", mockTokenHandler)                // Token endpoint
	http.HandleFunc("/sensors/entities/datafeed/v2", resourceHandler) // Resource endpoint
	http.HandleFunc("/", streamData)                                  // Event stream endpoint

	// Start the server
	port := ":8090"
	log.Printf("Starting mock OAuth2 server on %s...", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
