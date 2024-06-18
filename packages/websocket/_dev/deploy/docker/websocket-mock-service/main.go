// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

func main() {
	http.HandleFunc("/", handleWebSocket)
	log.Fatal(http.ListenAndServe(":3000", nil))
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/testbasicauth" {
		// Check if the 'Authorization' header is set for basic authentication
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Basic dGVzdDp0ZXN0" {
			// If the header is incorrect, return an authentication error message
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Error: Authentication failed."))
			return
		}
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	var responseMessage []map[string]string

	if r.URL.Path == "/testbasicauth" {
		// Check if the 'Authorization' header is set for basic authentication
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Basic dGVzdDp0ZXN0" {
			// If the header is correct, return a success message
			responseMessage = []map[string]string{
				{
					"message": "You are now authenticated to the WebSocket server.",
				},
			}
		}
	} else if r.URL.Path == "/test" {
		// Return a success message
		responseMessage = []map[string]string{
			{
				"ts":   "2024-01-01T01:00:00.000000-00:00",
				"data": "testdata1",
				"id":   "test1234567891",
			},
			{
				"ts":   "2024-01-01T02:00:00.000000-00:00",
				"data": "testdata2",
				"id":   "test1234567890",
			},
		}
	}

	// Send a message to the client upon successful WebSocket connection
	err = conn.WriteJSON(responseMessage)
	if err != nil {
		log.Println("write:", err)
		return
	}
}
