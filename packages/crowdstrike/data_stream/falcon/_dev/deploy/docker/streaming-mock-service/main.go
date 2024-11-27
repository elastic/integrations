package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	mockClientID     = flag.String("client_id", "", "Mock Client ID")
	mockClientSecret = flag.String("client_secret", "", "Mock Client Secret")
	mockAccessToken  = flag.String("access_token", "", "Mock Access Token")
	mockSessionToken = flag.String("session_token", "", "Mock Session Token")
	filePath         = flag.String("file", "", "Path to the input file")
	mockDataFeedURL  = flag.String("mock_datafeed_url", "", "Mock DataFeed URL")
	datafeedCalled   = flag.Bool("datafeed_called", false, "Mock Datafeed Called")
)

func main() {
	flag.Parse()
	// Setup routes
	http.HandleFunc("POST /oauth2/token", mockTokenHandler)
	http.HandleFunc("GET /sensors/entities/datafeed/v2", resourceHandler) // Resource endpoint
	http.HandleFunc("GET /", streamData)                                  // Event stream endpoint

	// Start the server
	port := ":8090"
	log.Printf("Starting mock OAuth2 server on %s...", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

// Mock OAuth2 Token endpoint
func mockTokenHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: Method=%s, URL=%s", r.Method, r.URL.String())
	log.Printf("Headers: %+v", r.Header)

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
	if clientID == *mockClientID && clientSecret == *mockClientSecret {
		// Mock success, return an access token
		tokenResponse := map[string]string{
			"access_token": *mockAccessToken,
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

// Returns a resource with a dataFeedURL and sessionToken
func resourceHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: Method=%s, URL=%s", r.Method, r.URL.String())
	log.Printf("Headers: %+v", r.Header)
	if *datafeedCalled {
		fmt.Println("Datafeed has already been called. Exiting...")
		os.Exit(0) // Exit the program, or use return if you don't want to terminate
	}
	*datafeedCalled = true
	err := verifyOAuth2Token(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	resource := map[string]interface{}{
		"resources": []map[string]interface{}{
			{
				"dataFeedURL": *mockDataFeedURL,
				"sessionToken": map[string]interface{}{
					"token":      *mockSessionToken,
					"expiration": "2025-11-18T09:21:31.767185156Z",
				},
				"refreshActiveSessionURL":      *mockDataFeedURL,
				"refreshActiveSessionInterval": 1800,
			},
		},
	}
	log.Printf("Returning datafeed url.")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resource)
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
	if tokenString != *mockAccessToken {
		return fmt.Errorf("invalid token")
	}
	return nil
}

type streamReader struct {
	data  []string
	index int
}

func streamData(w http.ResponseWriter, r *http.Request) {
	// Set the response header for streaming
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked") // This will stream data in chunks
	file, err := os.Open(*filePath)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close() // Ensure the file is closed when done

	// Initialize a slice to hold the JSON strings
	var data []string

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	// Read the file line by line
	for scanner.Scan() {
		line := scanner.Text() // Get the current line

		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		// Append the non-empty line (JSON string) to the data slice
		data = append(data, line)
	}

	// Create a custom reader for streaming data
	reader := &streamReader{
		data:  data,
		index: 0,
	}

	// Stream the data using the custom reader
	_, err = io.Copy(w, reader)
	if err != nil {
		http.Error(w, "Error while streaming data", http.StatusInternalServerError)
		return
	}

	log.Println("Data streaming completed, closing connection.")
}

func (s *streamReader) Read(p []byte) (n int, err error) {
	if s.index >= len(s.data) {
		return 0, io.EOF // No more data to stream
	}
	chunk := s.data[s.index]
	s.index++
	if len(chunk) > len(p) {
		p = append(p, make([]byte, len(chunk)-len(p))...)
	}
	copy(p, chunk)
	return len(chunk), nil
}
