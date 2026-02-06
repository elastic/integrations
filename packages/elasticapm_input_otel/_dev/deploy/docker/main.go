// Minimal HTTP server instrumented with Elastic APM Go agent for system tests.
// Sends APM Intake v2 data to the collector (elastic-agent:8200).
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"go.elastic.co/apm/module/apmhttp"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := apmhttp.Wrap(mux)
	server := &http.Server{Addr: ":8080", Handler: handler}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// Wait for the stack and agent to be up and listening before sending any traffic.
	// The agent can take 30–60s to enroll, apply policy, and start the collector.
	const agentReadyDelay = 60 * time.Second
	log.Printf("waiting %v for agent to be listening...", agentReadyDelay)
	time.Sleep(agentReadyDelay)

	// Generate a few transactions so the agent sends data to the collector.
	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 5; i++ {
		resp, err := client.Get("http://localhost:8080/")
		if err != nil {
			log.Printf("request %d: %v", i+1, err)
			continue
		}
		_ = resp.Body.Close()
	}

	// Keep running so the agent can receive and flush; system test will stop the container.
	time.Sleep(15 * time.Second)
	fmt.Println("apm-app done")
}
