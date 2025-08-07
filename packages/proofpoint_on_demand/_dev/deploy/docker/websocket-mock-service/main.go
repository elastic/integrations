// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	connections   = make(map[*websocket.Conn]struct{})
	connectionsMu sync.Mutex
)

func main() {
	server := &http.Server{Addr: ":8443"}

	http.HandleFunc("/", handleWebSocket)

	// Graceful shutdown goroutine
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGTERM, syscall.SIGINT)
		<-sigint

		log.Println("shutdown signal received, closing WebSocket connections...")

		// close all WebSocket connections
		connectionsMu.Lock()
		for conn := range connections {
			err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "server shutting down"))
			if err != nil {
				log.Println("error closing connection:", err)
			}
			conn.Close()
		}
		connectionsMu.Unlock()

		// shutdown server gracefully
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("server shutdown failed:%+v", err)
		}

		log.Println("server shutdown successful")
	}()

	log.Println("server started on :8443")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("ListenAndServe(): %s", err)
	}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader != "Bearer xxxx" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Error: Authentication failed."))
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	// register connection
	connectionsMu.Lock()
	connections[conn] = struct{}{}
	connectionsMu.Unlock()

	defer func() {
		// uregister connection
		connectionsMu.Lock()
		delete(connections, conn)
		connectionsMu.Unlock()
	}()

	var responseMessage string
	typeParam := r.URL.Query().Get("type")

	switch typeParam {
	case "audit":
		responseMessage = `{"audit":{"action":"login","level":"INFO","resourceType":"authorization","tags":[{"name":"eventSubCategory","value":"authorization"},{"name":"eventDetails","value":""},{"name":"login.authorization","value":"true"}],"user":{"email":"bob@example.org","id":"a7e6abcd-1234-7901-1234-abcdefc31236","ipAddress":"1.128.0.0"}},"guid":"792f514f-15cb-480d-825e-e3565d32f928","metadata":{"customerId":"c8215678-6e78-42dd-a327-abcde13f9cff","origin":{"data":{"agent":"89.160.20.128","cid":"pphosted_prodmgt_hosted","version":"1.0"},"schemaVersion":"1.0","type":"cadmin-api-gateway"}},"ts":"2023-10-30T06:13:37.162521+0000"}`
	case "maillog":
		responseMessage = `{"data":"2024-06-19T05:28:32.533564-07:00 m0000123 sendmail[17416]: 45ABSW12341234: to=<mailive@example.com>, delay=00:00:00, xdelay=00:00:00, mailer=esmtp, tls_verify=OK, tls_version=TLSv1.2, cipher=ECDHE-RSA-AES256-GCM, pri=121557, relay=test4.example.net. [216.160.83.56], dsn=2.0.0, stat=Sent (Ok: queued)","id":"NABCDefGH0/I1234slqccQ","metadata":{"customerId":"c82abcde-5678-42dd-1234-1234563f9cff","origin":{"data":{"agent":"m0000123.ppops.net","cid":"pphosted_prodmgt_hosted"},"schemaVersion":"20200420"}},"pps":{"agent":"m0000123.ppops.net","cid":"pphosted_prodmgt_hosted"},"sm":{"delay":"00:00:00","dsn":"2.0.0","mailer":"esmtp","pri":"121557","qid":"45ABSW12341234","relay":"test4.example.net. [216.160.83.56]","stat":"Sent (Ok: queued)","to":["<mailive@example.com>"],"xdelay":"00:00:00"},"tls":{"cipher":"ECDHE-RSA-AES256-GCM","verify":"OK","version":"TLSv1.2"},"ts":"2024-06-19T05:28:32.533564-0700"}`
	default:
		responseMessage = `{"connection":{"country":"**","helo":"m0000123.ppops.net","host":"localhost","ip":"127.0.0.1","protocol":"smtp:smtp","resolveStatus":"ok","sid":"3y8abcd123","tls":{"inbound":{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","cipherBits":256,"version":"TLSv1.2"}}},"envelope":{"from":"pps@m0000123.ppops.net","rcpts":["pps@m0000123.ppops.net"]},"filter":{"actions":[{"action":"accept","isFinal":true,"module":"access","rule":"system"}],"delivered":{"rcpts":["pps@m0000123.ppops.net"]},"disposition":"accept","durationSecs":0.11872,"msgSizeBytes":1127,"qid":"44ABCDm0000123","routeDirection":"outbound","routes":["allow_relay","firewallsafe"],"suborgs":{"rcpts":["0"],"sender":"0"},"verified":{"rcpts":["pps@m0000123.ppops.net"]}},"guid":"vRq4ZIFWHXbuABCDEFghij0U4VvIc71x","metadata":{"origin":{"data":{"agent":"m0000123.ppops.net","cid":"pphosted_prodmgt_hosted","version":"8.21.0.1358"}}},"msg":{"header":{"from":["\"(Cron Daemon)\" <pps@m0000123.ppops.net>"],"message-id":["<212345678910.44ABCDE1231370@m0000123.ppops.net>"],"subject":["Cron <pps@m0000123> /opt/proofpoint/resttimer.pl"],"to":["pps@m0000123.ppops.net"]},"lang":"","normalizedHeader":{"from":["\"(Cron Daemon)\" <pps@m0000123.ppops.net>"],"message-id":["212345678910.44ABCDE1231370@m0000123.ppops.net"],"subject":["Cron <pps@m0000123> /opt/proofpoint/resttimer.pl"],"to":["pps@m0000123.ppops.net"]},"parsedAddresses":{},"sizeBytes":1151},"msgParts":[],"ts":"2024-05-22T12:10:03.058340-0700"}`
	}

	if err := conn.WriteMessage(websocket.TextMessage, []byte(responseMessage)); err != nil {
		log.Println("write:", err)
		return
	}
}
