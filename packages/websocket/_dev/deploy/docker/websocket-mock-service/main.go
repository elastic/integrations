package main

import (
  "log"
  "net/http"
  "github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
  CheckOrigin: func(r *http.Request) bool {
    return true
  },
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
  conn, err := upgrader.Upgrade(w, r, nil)
  if err != nil {
    log.Println(err)
    return
  }
  defer conn.Close()

  // Send a message to the client upon successful WebSocket connection
  err = conn.WriteJSON(map[string]string{
    "message": "You are now connected to the WebSocket server.",
  })
  if err != nil {
    log.Println("write:", err)
    return
  }
}

func main() {
  http.HandleFunc("/", handleWebSocket)
  log.Fatal(http.ListenAndServe(":3000", nil))
}