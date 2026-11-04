// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Test events delivered to the consumer.
var testEvents = []string{
	`{"time":"2023-10-27T00:10:43.5547000Z","tenantId":"3adb963c-8e61-48e8-a06d-6dbb0dacea39","category":"Devices","operationName":"Devices","resultType":"None","properties":{"DeviceId":"6c4217e6-bc89-4e7f-a04c-129f04866de4","DeviceName":"CLW555TEST","UPN":"abc.123@example.com","LastContact":"2023-10-26 12:23:58.7994868","OSVersion":"10.0.22621.2428","OS":"Windows","CompliantState":"Compliant","Ownership":"Corporate","ManagedBy":"Intune","Model":"20U1A006IG","SerialNumber":"PF2C55YE","Manufacturer":"LENOVO","CreatedDate":"2023-10-20 06:55:27.6237465","DeviceState":"Managed","UserEmail":"abc.123@example.com","UserName":"CDP User IS-38411","IMEI":"","PhoneNumber":"","DeviceRegistrationState":"Registered","ReferenceId":"f18bd540-d5e4-46e0-8ddd-3d03a59e4e14","ManagedDeviceName":"cdp.38411_Windows_10/20/2023_6:55 AM","GraphDeviceIsManaged":true,"CategoryName":"","EncryptionStatusString":"True","SubscriberCarrierNetwork":"","JoinType":"Azure AD joined","SupervisedStatusString":"False","WifiMacAddress":"A87EEABC6AC9","StorageTotal":243406,"StorageFree":205247,"AndroidPatchLevel":"","MEID":"","InGracePeriodUntil":"9999-12-31 23:59:59.9999999","JailBroken":"Unknown","SkuFamily":"Enterprise","EasID":"095976316EA99845E253336F24119200","PrimaryUser":"588d7c15-8565-448e-bc2d-57f2b7c4c58a","BatchId":"fe8f2c78-580c-4405-bac7-62d85a3161b7","IntuneAccountId":"10b5ba40-b8e0-45a0-8d68-266bf9def4b5","AADTenantId":"3adb963c-8e61-48e8-a06d-6dbb0dacea39"}}`,
	`{"time":"2026-02-19T00:20:52.4792000Z","tenantId":"3adb963c-8e61-48e8-a06d-6dbb0dacea39","category":"Devices","operationName":"Devices","resultType":"None","properties":{"DeviceId":"076b58ec-2c12-470c-91b3-90a200205536","DeviceName":"C-LAB-14","UPN":"abc.hello@example.com","LastContact":"2026-02-18 19:10:29.6961667","OSVersion":"10.0.19045.6456","OS":"Windows","CompliantState":"Compliant","Ownership":"Corporate","ManagedBy":"Intune","Model":"VMware7,1","SerialNumber":"VMware-42030e5acab78dd5-5bfaa83a47fb01d9","Manufacturer":"VMware, Inc.","CreatedDate":"2025-12-21 16:52:31.7372518","DeviceState":"Managed","UserEmail":"abc.hello@example.com","UserName":"Defender User","IMEI":"","PhoneNumber":"","DeviceRegistrationState":"Registered","ReferenceId":"9e64bf4b-638d-4c80-9374-9a84c794b124","ManagedDeviceName":"abc.defender_Windows_12/21/2025_4:52 PM","GraphDeviceIsManaged":true,"CategoryName":"","EncryptionStatusString":"False","SubscriberCarrierNetwork":"","JoinType":"Azure AD joined","SupervisedStatusString":"False","WifiMacAddress":"","StorageTotal":50550,"StorageFree":22760,"AndroidPatchLevel":"","MEID":"","InGracePeriodUntil":"9999-12-31 23:59:59.9999999","JailBroken":"Unknown","SkuFamily":"Pro","EasID":"7B56C1D2A4B4B3681F90D24D547A9912","PrimaryUser":"588d7c15-8565-448e-bc2d-57f2b7c4c58a","BatchId":"8e4d424a-9aac-4ca0-8b09-762695b21aba","IntuneAccountId":"10b5ba40-b8e0-45a0-8d68-266bf9def4b5","AADTenantId":"3adb963c-8e61-48e8-a06d-6dbb0dacea39"}}`,
}

func main() {
	store := newBlobStore()

	// Blob storage on port 10000.
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/", store.handle)
		log.Printf("blob storage listening on :10000")
		if err := http.ListenAndServe(":10000", mux); err != nil {
			log.Fatalf("blob server: %v", err)
		}
	}()

	// WebSocket listener on port 443 (TLS with auto-generated cert).
	go func() {
		cert, err := generateTLSCert()
		if err != nil {
			log.Fatalf("generate TLS cert: %v", err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/", handleWebSocket)
		srv := &http.Server{
			Addr:    ":443",
			Handler: mux,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		}
		log.Printf("WebSocket (TLS) listening on :443")
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("websocket server: %v", err)
		}
	}()

	// AMQP on port 5672.
	ln, err := net.Listen("tcp", ":5672")
	if err != nil {
		log.Fatalf("listen amqp: %v", err)
	}
	log.Printf("AMQP listening on :5672")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

// generateTLSCert creates a TLS server certificate. If an external CA is
// available at /app/ca-cert.pem and /app/ca-key.pem (the elastic-package
// CA mounted by the test script), the server cert is signed by that CA so
// the elastic-agent trusts it. Otherwise the cert is self-signed.
func generateTLSCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "fake-azure-eh"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "fake-azure-eh", "svc-azure-eh"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	issuer := tmpl
	var signer crypto.Signer = key
	if ca, caKey, err := loadCA("/app/ca-cert.pem", "/app/ca-key.pem"); err == nil {
		issuer = ca
		signer = caKey
		log.Printf("signing server cert with CA (CN=%s)", ca.Subject.CommonName)
	} else {
		log.Printf("no external CA (%v), using self-signed cert", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, signer)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func loadCA(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block in %s", keyPath)
	}
	if ecKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return cert, ecKey, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA key: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not a crypto.Signer")
	}
	return cert, signer, nil
}

// ---- WebSocket ----

// handleWebSocket upgrades an HTTP connection to WebSocket with the "amqp"
// subprotocol, then runs the AMQP handler over the WebSocket connection.
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
		return
	}

	// Validate Sec-WebSocket-Key.
	wsKey := r.Header.Get("Sec-WebSocket-Key")
	if wsKey == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	// Compute accept key per RFC 6455 §4.2.2.
	const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(wsKey + wsGUID))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Hijack the connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "server does not support hijacking", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write the 101 response.
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n" +
		"Sec-WebSocket-Protocol: amqp\r\n" +
		"\r\n"
	if _, err := buf.WriteString(resp); err != nil {
		conn.Close()
		return
	}
	if err := buf.Flush(); err != nil {
		conn.Close()
		return
	}

	log.Printf("WebSocket upgrade complete for %s", r.RemoteAddr)

	// Wrap the raw connection in a WebSocket frame adapter and
	// run the AMQP handler over it.
	ws := &wsConn{conn: conn}
	handleConn(ws)
}

// wsConn adapts a raw TCP connection carrying WebSocket frames into a
// net.Conn that reads/writes raw payloads. Each Write produces one
// WebSocket binary message; each Read consumes from the current message,
// advancing to the next when exhausted.
type wsConn struct {
	conn    net.Conn
	readBuf []byte
}

func (w *wsConn) Read(p []byte) (int, error) {
	for len(w.readBuf) == 0 {
		payload, err := wsReadMessage(w.conn)
		if err != nil {
			return 0, err
		}
		if payload == nil {
			continue // control frame, skip
		}
		w.readBuf = payload
	}
	n := copy(p, w.readBuf)
	w.readBuf = w.readBuf[n:]
	return n, nil
}

func (w *wsConn) Write(p []byte) (int, error) {
	return wsWriteBinary(w.conn, p)
}

func (w *wsConn) Close() error                       { return w.conn.Close() }
func (w *wsConn) LocalAddr() net.Addr                { return w.conn.LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr               { return w.conn.RemoteAddr() }
func (w *wsConn) SetDeadline(t time.Time) error      { return w.conn.SetDeadline(t) }
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.conn.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }

// wsReadMessage reads one WebSocket frame. It handles CLOSE and PING
// control frames internally, returning nil payload for them. Returns the
// payload for binary/text data frames.
func wsReadMessage(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	opcode := hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7F)

	switch {
	case length == 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case length == 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return nil, err
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	switch opcode {
	case 0x8: // Close
		return nil, io.EOF
	case 0x9: // Ping — respond with Pong
		wsWriteFrame(r.(net.Conn), 0x0A, payload)
		return nil, nil
	case 0x1, 0x2: // Text, Binary
		return payload, nil
	default:
		return nil, nil
	}
}

// wsWriteBinary writes a WebSocket binary frame (server→client, unmasked).
func wsWriteBinary(w io.Writer, payload []byte) (int, error) {
	return wsWriteFrame(w, 0x02, payload)
}

func wsWriteFrame(w io.Writer, opcode byte, payload []byte) (int, error) {
	n := len(payload)
	var hdr []byte
	switch {
	case n <= 125:
		hdr = []byte{0x80 | opcode, byte(n)}
	case n <= 65535:
		hdr = []byte{0x80 | opcode, 126, byte(n >> 8), byte(n)}
	default:
		hdr = []byte{0x80 | opcode, 127,
			byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
		}
	}
	frame := make([]byte, len(hdr)+n)
	copy(frame, hdr)
	copy(frame[len(hdr):], payload)
	_, err := w.Write(frame)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ---- Blob Storage ----

type blobItem struct {
	data         []byte
	metadata     map[string]string
	etag         string
	lastModified time.Time
}

type blobStore struct {
	mu         sync.Mutex
	containers map[string]map[string]*blobItem
}

func newBlobStore() *blobStore {
	return &blobStore{containers: make(map[string]map[string]*blobItem)}
}

func (s *blobStore) handle(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 3)
	if len(parts) < 2 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// parts[0] = account, parts[1] = container, parts[2:] = blob path
	container := parts[1]
	blob := ""
	if len(parts) > 2 {
		blob = parts[2]
	}
	switch {
	case r.URL.Query().Get("restype") == "container" && r.URL.Query().Get("comp") == "list":
		s.listBlobs(w, container, r.URL.Query().Get("prefix"))
		return
	case r.URL.Query().Get("restype") == "container":
		switch r.Method {
		case http.MethodPut:
			s.createContainer(w, container)
		case http.MethodGet, http.MethodHead:
			s.getContainer(w, container)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	case r.URL.Query().Get("comp") == "metadata":
		s.setMetadata(w, r, container, blob)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.getBlob(w, container, blob)
	case http.MethodPut:
		s.putBlob(w, r, container, blob)
	case http.MethodDelete:
		s.deleteBlob(w, container, blob)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *blobStore) getContainer(w http.ResponseWriter, container string) {
	s.mu.Lock()
	_, ok := s.containers[container]
	s.mu.Unlock()
	if !ok {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		w.Write(xmlErr("ContainerNotFound", "The specified container does not exist."))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *blobStore) createContainer(w http.ResponseWriter, container string) {
	s.mu.Lock()
	if s.containers[container] == nil {
		s.containers[container] = make(map[string]*blobItem)
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
}

func (s *blobStore) deleteBlob(w http.ResponseWriter, container, blob string) {
	s.mu.Lock()
	if blobs := s.containers[container]; blobs != nil {
		delete(blobs, blob)
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func (s *blobStore) listBlobs(w http.ResponseWriter, container, prefix string) {
	s.mu.Lock()
	blobs := s.containers[container]
	type xmlMeta struct {
		XMLName xml.Name
		Value   string `xml:",chardata"`
	}
	type xmlProps struct {
		LastModified string `xml:"Last-Modified"`
		Etag         string `xml:"Etag"`
	}
	type xmlBlob struct {
		Name       string    `xml:"Name"`
		Properties xmlProps  `xml:"Properties"`
		Metadata   []xmlMeta `xml:"Metadata"`
	}
	var items []xmlBlob
	for name, item := range blobs {
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		b := xmlBlob{
			Name: name,
			Properties: xmlProps{
				LastModified: item.lastModified.UTC().Format(http.TimeFormat),
				Etag:         item.etag,
			},
		}
		for k, v := range item.metadata {
			b.Metadata = append(b.Metadata, xmlMeta{XMLName: xml.Name{Local: k}, Value: v})
		}
		items = append(items, b)
	}
	s.mu.Unlock()

	type result struct {
		XMLName xml.Name  `xml:"EnumerationResults"`
		Blobs   []xmlBlob `xml:"Blobs>Blob"`
	}
	w.Header().Set("Content-Type", "application/xml")
	xml.NewEncoder(w).Encode(result{Blobs: items})
}

func (s *blobStore) putBlob(w http.ResponseWriter, r *http.Request, container, blob string) {
	body, _ := io.ReadAll(r.Body)
	meta := extractMeta(r)
	s.mu.Lock()
	if s.containers[container] == nil {
		s.containers[container] = make(map[string]*blobItem)
	}
	// Conditional write: honour If-None-Match for ownership claims.
	if inm := r.Header.Get("If-None-Match"); inm == "*" {
		if s.containers[container][blob] != nil {
			s.mu.Unlock()
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusConflict)
			w.Write(xmlErr("BlobAlreadyExists", "The specified blob already exists."))
			return
		}
	}
	now := time.Now()
	etag := fmt.Sprintf(`"etag-%d"`, now.UnixNano())
	s.containers[container][blob] = &blobItem{data: body, metadata: meta, etag: etag, lastModified: now}
	s.mu.Unlock()

	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", now.UTC().Format(http.TimeFormat))
	w.WriteHeader(http.StatusCreated)
}

func (s *blobStore) setMetadata(w http.ResponseWriter, r *http.Request, container, blob string) {
	meta := extractMeta(r)
	s.mu.Lock()
	blobs := s.containers[container]
	if blobs == nil {
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		w.Write(xmlErr("BlobNotFound", "The specified blob does not exist."))
		return
	}
	item := blobs[blob]
	if item == nil {
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		w.Write(xmlErr("BlobNotFound", "The specified blob does not exist."))
		return
	}
	now := time.Now()
	etag := fmt.Sprintf(`"etag-%d"`, now.UnixNano())
	item.metadata = meta
	item.etag = etag
	item.lastModified = now
	s.mu.Unlock()

	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", now.UTC().Format(http.TimeFormat))
	w.WriteHeader(http.StatusOK)
}

func (s *blobStore) getBlob(w http.ResponseWriter, container, blob string) {
	s.mu.Lock()
	blobs := s.containers[container]
	var item *blobItem
	if blobs != nil {
		item = blobs[blob]
	}
	s.mu.Unlock()

	if item == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	for k, v := range item.metadata {
		w.Header().Set("x-ms-meta-"+k, v)
	}
	w.Header().Set("ETag", `"mock-etag"`)
	w.WriteHeader(http.StatusOK)
	w.Write(item.data)
}

func extractMeta(r *http.Request) map[string]string {
	meta := make(map[string]string)
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if key, ok := strings.CutPrefix(lk, "x-ms-meta-"); ok {
			meta[key] = v[0]
		}
	}
	return meta
}

func xmlErr(code, msg string) []byte {
	type errResp struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}
	b, _ := xml.Marshal(errResp{Code: code, Message: msg})
	return b
}

// ---- AMQP server ----

type linkInfo struct {
	handle       uint32
	name         string
	isSender     bool // from server's perspective
	address      string
	replyAddress string
	startOnce    sync.Once
}

type connState struct {
	conn           net.Conn
	mu             sync.Mutex
	links          map[uint32]*linkInfo
	linksByName    map[string]*linkInfo
	nextDeliveryID atomic.Uint32
	channel        uint16
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	if err := saslExchange(conn); err != nil {
		log.Printf("sasl: %v", err)
		return
	}

	amqpMagic := []byte("AMQP\x00\x01\x00\x00")
	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Printf("amqp magic read: %v", err)
		return
	}
	if _, err := conn.Write(amqpMagic); err != nil {
		log.Printf("amqp magic write: %v", err)
		return
	}

	cs := &connState{
		conn:        conn,
		links:       make(map[uint32]*linkInfo),
		linksByName: make(map[string]*linkInfo),
	}
	cs.readLoop()
}

func (cs *connState) readLoop() {
	for {
		frame, payload, err := readFrame(cs.conn)
		if err != nil {
			log.Printf("readFrame: %v", err)
			return
		}
		if err := cs.handleFrame(frame, payload); err != nil {
			log.Printf("handleFrame: %v", err)
			return
		}
	}
}

type frameHeader struct {
	size    uint32
	doff    uint8
	ftype   uint8
	channel uint16
}

func readFrame(r io.Reader) (frameHeader, []byte, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return frameHeader{}, nil, err
	}
	fh := frameHeader{
		size:    binary.BigEndian.Uint32(hdr[0:4]),
		doff:    hdr[4],
		ftype:   hdr[5],
		channel: binary.BigEndian.Uint16(hdr[6:8]),
	}
	bodyLen := int(fh.size) - 8
	if bodyLen < 0 {
		return fh, nil, fmt.Errorf("invalid frame size %d", fh.size)
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return fh, nil, err
	}
	return fh, body, nil
}

var codeNames = map[byte]string{
	0x10: "Open", 0x11: "Begin", 0x12: "Attach", 0x13: "Flow",
	0x14: "Transfer", 0x15: "Disposition", 0x16: "Detach", 0x17: "End", 0x18: "Close",
}

func (cs *connState) handleFrame(fh frameHeader, payload []byte) error {
	if len(payload) < 3 {
		return nil
	}
	if payload[0] != 0x00 || payload[1] != 0x53 {
		return nil
	}
	code := payload[2]
	body := payload[3:]

	if name := codeNames[code]; name != "" {
		log.Printf("rx ch=%d %s", fh.channel, name)
	}

	switch code {
	case 0x10:
		return cs.handleOpen(body)
	case 0x11:
		cs.channel = fh.channel
		return cs.handleBegin(body)
	case 0x12:
		return cs.handleAttach(fh.channel, body)
	case 0x13:
		return cs.handleFlow(fh.channel, body)
	case 0x14:
		return cs.handleTransfer(fh.channel, payload)
	case 0x15:
		return nil
	case 0x16:
		return cs.handleDetach(fh.channel, body)
	case 0x17:
		return cs.sendFrame(fh.channel, buildPerformative(0x17, encodeList8(nil)))
	case 0x18:
		if fields, _ := parseList(body); len(fields) > 0 && fields[0] != nil {
			log.Printf("rx Close with error: %v", fields[0])
		}
		cs.sendFrame(fh.channel, buildPerformative(0x18, encodeList8(nil)))
		return fmt.Errorf("connection closed")
	}
	return nil
}

func (cs *connState) handleOpen(body []byte) error {
	openList := encodeList8([][]byte{
		encodeStr8("fake-azure-eh"),
	})
	return cs.sendFrame(0, buildPerformative(0x10, openList))
}

func (cs *connState) handleBegin(body []byte) error {
	beginList := encodeList32([][]byte{
		encodeUshort(cs.channel),
		encodeUint(0),
		encodeUint(65535),
		encodeUint(65535),
	})
	return cs.sendFrame(cs.channel, buildPerformative(0x11, beginList))
}

func (cs *connState) handleAttach(channel uint16, body []byte) error {
	fields, _ := parseList(body)
	if len(fields) < 3 {
		return nil
	}

	name, _ := fields[0].(string)
	handle := toUint32(fields[1])
	clientIsSender := false
	if len(fields) > 2 {
		if b, ok := fields[2].(bool); ok {
			clientIsSender = !b
		}
	}

	sndSettleMode := []byte{0x40}
	rcvSettleMode := []byte{0x40}
	if len(fields) > 3 && fields[3] != nil {
		if v, ok := fields[3].(uint8); ok {
			sndSettleMode = []byte{0x50, v}
		}
	}
	if len(fields) > 4 && fields[4] != nil {
		if v, ok := fields[4].(uint8); ok {
			rcvSettleMode = []byte{0x50, v}
		}
	}

	sourceAddr := ""
	targetAddr := ""
	if len(fields) > 5 {
		sourceAddr = extractAddress(fields[5])
	}
	if len(fields) > 6 {
		targetAddr = extractAddress(fields[6])
	}

	li := &linkInfo{
		handle:   handle,
		name:     name,
		isSender: !clientIsSender,
	}
	if clientIsSender {
		li.address = targetAddr
	} else {
		li.address = sourceAddr
		li.replyAddress = targetAddr
	}

	cs.mu.Lock()
	cs.links[handle] = li
	cs.linksByName[name] = li
	cs.mu.Unlock()

	serverRole := clientIsSender
	var roleByte []byte
	if serverRole {
		roleByte = []byte{0x41}
	} else {
		roleByte = []byte{0x42}
	}

	var sourceBytes, targetBytes []byte
	if clientIsSender {
		sourceBytes = []byte{0x40}
		targetBytes = encodeDescribed(0x29, encodeList8([][]byte{encodeStr8(targetAddr)}))
	} else {
		sourceBytes = encodeDescribed(0x28, encodeList8([][]byte{encodeStr8(sourceAddr)}))
		targetBytes = []byte{0x40}
	}

	var attachFields [][]byte
	attachFields = append(attachFields,
		encodeStr8(name),
		encodeUint(handle),
		roleByte,
		sndSettleMode,
		rcvSettleMode,
		sourceBytes,
		targetBytes,
	)
	if !serverRole {
		attachFields = append(attachFields, []byte{0x40}, []byte{0x40}, encodeUint(0))
	}

	log.Printf("attach ch=%d name=%q handle=%d isSender=%v addr=%q", channel, name, handle, !clientIsSender, li.address)
	attachList := encodeList32(attachFields)
	if err := cs.sendFrame(channel, buildPerformative(0x12, attachList)); err != nil {
		return err
	}
	if clientIsSender {
		flowList := encodeList32([][]byte{
			encodeUint(0),
			encodeUint(65535),
			encodeUint(0),
			encodeUint(65535),
			encodeUint(handle),
			encodeUint(0),
			encodeUint(64),
		})
		return cs.sendFrame(channel, buildPerformative(0x13, flowList))
	}
	return nil
}

func (cs *connState) handleFlow(channel uint16, body []byte) error {
	fields, _ := parseList(body)
	if len(fields) < 5 {
		return nil
	}
	handle := toUint32(fields[4])

	cs.mu.Lock()
	li := cs.links[handle]
	cs.mu.Unlock()

	if li == nil || !li.isSender {
		return nil
	}
	if strings.Contains(li.address, "/Partitions/") {
		go li.startOnce.Do(func() { cs.deliverEvents(channel, li) })
	}
	return nil
}

func (cs *connState) deliverEvents(channel uint16, li *linkInfo) {
	for i, event := range testEvents {
		deliveryID := cs.nextDeliveryID.Add(1)
		tag := []byte{byte(deliveryID >> 24), byte(deliveryID >> 16), byte(deliveryID >> 8), byte(deliveryID)}

		msg := buildEventMessage([]byte(event), int64(i))

		transferList := encodeList32([][]byte{
			encodeUint(li.handle),
			encodeUint(uint32(deliveryID)),
			encodeBytes8(tag),
			encodeUint(0),
			{0x41},
		})
		transferFrame := buildPerformative(0x14, transferList)
		frame := append(transferFrame, msg...)

		if err := cs.sendFrame(channel, frame); err != nil {
			log.Printf("deliver event %d: %v", i, err)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (cs *connState) handleTransfer(channel uint16, payload []byte) error {
	if len(payload) < 3 {
		return nil
	}
	pos := 3

	fields, listEnd, err := parseListAt(payload, pos)
	if err != nil {
		return nil
	}
	msgPayload := payload[listEnd:]

	if len(fields) < 1 {
		return nil
	}
	handle := toUint32(fields[0])
	deliveryID := uint32(0)
	if len(fields) > 1 {
		deliveryID = toUint32(fields[1])
	}

	cs.mu.Lock()
	li := cs.links[handle]
	cs.mu.Unlock()

	if li == nil {
		return nil
	}

	dispList := encodeList32([][]byte{
		{0x41},
		encodeUint(deliveryID),
		encodeUint(deliveryID),
		{0x41},
		encodeDescribed(0x24, []byte{0x45}),
	})
	if err := cs.sendFrame(channel, buildPerformative(0x15, dispList)); err != nil {
		return err
	}

	msgID, replyTo := parseMessageProperties(msgPayload)
	log.Printf("transfer on link %q (addr=%q) msgID=%q replyTo=%q", li.name, li.address, msgID, replyTo)

	replyLink := cs.findReplyLink(li.address, replyTo)
	if replyLink == nil {
		log.Printf("no reply link for addr=%q replyTo=%q; known links: %v", li.address, replyTo, cs.linkNames())
		return nil
	}
	return cs.sendResponse(channel, replyLink, li.address, msgID)
}

func (cs *connState) linkNames() []string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	var names []string
	for _, li := range cs.links {
		names = append(names, fmt.Sprintf("%q(addr=%q)", li.name, li.address))
	}
	return names
}

func (cs *connState) findReplyLink(senderAddr, replyTo string) *linkInfo {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if replyTo != "" {
		if li := cs.linksByName[replyTo]; li != nil {
			return li
		}
		for _, li := range cs.links {
			if li.address == replyTo || li.name == replyTo || li.replyAddress == replyTo {
				return li
			}
		}
	}

	if senderAddr == "$cbs" {
		for _, li := range cs.links {
			if strings.HasPrefix(li.name, "cbs-reply-to-") || strings.HasPrefix(li.address, "cbs-reply-to-") {
				return li
			}
		}
	}
	if senderAddr == "$management" {
		for _, li := range cs.links {
			if strings.HasPrefix(li.name, "management-reply-to-") || strings.HasPrefix(li.address, "management-reply-to-") {
				return li
			}
		}
	}
	return nil
}

func (cs *connState) sendResponse(channel uint16, replyLink *linkInfo, senderAddr, msgID string) error {
	deliveryID := cs.nextDeliveryID.Add(1)
	tag := []byte{byte(deliveryID), 0, 0, 0}

	var msgBody []byte
	if senderAddr == "$management" {
		msgBody = buildManagementResponse(msgID)
	} else {
		msgBody = buildCBSResponse(msgID)
	}

	transferList := encodeList32([][]byte{
		encodeUint(replyLink.handle),
		encodeUint(uint32(deliveryID)),
		encodeBytes8(tag),
		encodeUint(0),
		{0x41},
	})
	transferFrame := buildPerformative(0x14, transferList)
	frame := append(transferFrame, msgBody...)
	return cs.sendFrame(channel, frame)
}

func (cs *connState) handleDetach(channel uint16, body []byte) error {
	fields, _ := parseList(body)
	handle := uint32(0)
	if len(fields) > 0 {
		handle = toUint32(fields[0])
	}
	closed := false
	if len(fields) > 1 {
		if b, ok := fields[1].(bool); ok {
			closed = b
		}
	}
	errField := any(nil)
	if len(fields) > 2 {
		errField = fields[2]
	}
	log.Printf("detach ch=%d handle=%d closed=%v err=%v", channel, handle, closed, errField)
	cs.mu.Lock()
	li := cs.links[handle]
	if li != nil {
		delete(cs.links, handle)
		delete(cs.linksByName, li.name)
	}
	cs.mu.Unlock()

	detachList := encodeList32([][]byte{encodeUint(handle)})
	return cs.sendFrame(channel, buildPerformative(0x16, detachList))
}

// sendFrame writes a complete AMQP frame as a single Write call.
// This is required for WebSocket transport where each Write becomes
// one WebSocket message.
func (cs *connState) sendFrame(channel uint16, payload []byte) error {
	size := uint32(8 + len(payload))
	frame := make([]byte, size)
	binary.BigEndian.PutUint32(frame[0:4], size)
	frame[4] = 0x02 // DOFF
	frame[5] = 0x00 // type AMQP
	binary.BigEndian.PutUint16(frame[6:8], channel)
	copy(frame[8:], payload)

	cs.mu.Lock()
	defer cs.mu.Unlock()
	_, err := cs.conn.Write(frame)
	return err
}

// ---- SASL ----

func saslExchange(conn net.Conn) error {
	saslMagic := []byte("AMQP\x03\x01\x00\x00")
	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if _, err := conn.Write(saslMagic); err != nil {
		return err
	}

	anonBytes := []byte("ANONYMOUS")
	arrayBody := append([]byte{0xA3, byte(len(anonBytes))}, anonBytes...)
	arrayData := append([]byte{0xE0, byte(1 + len(arrayBody)), 0x01}, arrayBody...)

	mechList := encodeList8([][]byte{arrayData})
	mechsPerf := buildSASLPerformative(0x40, mechList)
	if err := sendSASLFrame(conn, mechsPerf); err != nil {
		return err
	}

	_, _, err := readFrame(conn)
	if err != nil {
		return err
	}

	outcomeList := encodeList8([][]byte{{0x50, 0x00}})
	outcomePerf := buildSASLPerformative(0x44, outcomeList)
	return sendSASLFrame(conn, outcomePerf)
}

// sendSASLFrame writes a complete SASL frame as a single Write call.
func sendSASLFrame(conn net.Conn, payload []byte) error {
	size := uint32(8 + len(payload))
	frame := make([]byte, size)
	binary.BigEndian.PutUint32(frame[0:4], size)
	frame[4] = 0x02 // DOFF
	frame[5] = 0x01 // type SASL
	frame[6] = 0x00 // channel 0
	frame[7] = 0x00
	copy(frame[8:], payload)

	_, err := conn.Write(frame)
	return err
}

func buildSASLPerformative(code byte, listBody []byte) []byte {
	return append([]byte{0x00, 0x53, code}, listBody...)
}

func buildPerformative(code byte, listBody []byte) []byte {
	return append([]byte{0x00, 0x53, code}, listBody...)
}

// ---- AMQP encoding ----

func encodeStr8(s string) []byte {
	b := []byte(s)
	if len(b) > 255 {
		out := make([]byte, 5+len(b))
		out[0] = 0xB1
		binary.BigEndian.PutUint32(out[1:], uint32(len(b)))
		copy(out[5:], b)
		return out
	}
	return append([]byte{0xA1, byte(len(b))}, b...)
}

func encodeBytes8(b []byte) []byte {
	if len(b) > 255 {
		out := make([]byte, 5+len(b))
		out[0] = 0xB0
		binary.BigEndian.PutUint32(out[1:], uint32(len(b)))
		copy(out[5:], b)
		return out
	}
	return append([]byte{0xA0, byte(len(b))}, b...)
}

func encodeSym8(s string) []byte {
	b := []byte(s)
	return append([]byte{0xA3, byte(len(b))}, b...)
}

func encodeUint(v uint32) []byte {
	if v == 0 {
		return []byte{0x43}
	}
	if v <= 255 {
		return []byte{0x52, byte(v)}
	}
	return []byte{0x70, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func encodeUshort(v uint16) []byte {
	return []byte{0x60, byte(v >> 8), byte(v)}
}

func encodeInt32(v int32) []byte {
	if v >= -128 && v <= 127 {
		return []byte{0x54, byte(v)}
	}
	return []byte{0x71, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func encodeLong(v int64) []byte {
	if v >= -128 && v <= 127 {
		return []byte{0x55, byte(v)}
	}
	return []byte{0x81,
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

func encodeTimestamp(t time.Time) []byte {
	ms := t.UnixMilli()
	return []byte{0x83,
		byte(ms >> 56), byte(ms >> 48), byte(ms >> 40), byte(ms >> 32),
		byte(ms >> 24), byte(ms >> 16), byte(ms >> 8), byte(ms),
	}
}

func encodeDescribed(code byte, value []byte) []byte {
	return append([]byte{0x00, 0x53, code}, value...)
}

func encodeList8(items [][]byte) []byte {
	if len(items) == 0 {
		return []byte{0x45}
	}
	var body []byte
	for _, item := range items {
		body = append(body, item...)
	}
	count := byte(len(items))
	size := byte(1 + len(body))
	return append([]byte{0xC0, size, count}, body...)
}

func encodeList32(items [][]byte) []byte {
	var body []byte
	for _, item := range items {
		body = append(body, item...)
	}
	count := uint32(len(items))
	size := uint32(4 + len(body))
	out := make([]byte, 9+len(body))
	out[0] = 0xD0
	binary.BigEndian.PutUint32(out[1:], size)
	binary.BigEndian.PutUint32(out[5:], count)
	copy(out[9:], body)
	return out
}

func encodeMap32(kvPairs [][]byte) []byte {
	var body []byte
	for _, kv := range kvPairs {
		body = append(body, kv...)
	}
	count := uint32(len(kvPairs))
	size := uint32(4 + len(body))
	out := make([]byte, 9+len(body))
	out[0] = 0xD1
	binary.BigEndian.PutUint32(out[1:], size)
	binary.BigEndian.PutUint32(out[5:], count)
	copy(out[9:], body)
	return out
}

// ---- Message construction ----

func buildEventMessage(data []byte, seqNum int64) []byte {
	now := time.Now().UTC()
	annotationsMap := encodeMap32([][]byte{
		encodeSym8("x-opt-enqueued-time"),
		encodeTimestamp(now),
		encodeSym8("x-opt-sequence-number"),
		encodeLong(seqNum),
		encodeSym8("x-opt-offset"),
		encodeStr8("0"),
	})
	annotationsSection := encodeDescribed(0x72, annotationsMap)
	dataSection := encodeDescribed(0x75, encodeBytes8(data))
	return append(annotationsSection, dataSection...)
}

func buildCBSResponse(correlationID string) []byte {
	propFields := [][]byte{
		{0x40},
		{0x40},
		{0x40},
		{0x40},
		{0x40},
		encodeStr8(correlationID),
	}
	propsSection := encodeDescribed(0x73, encodeList32(propFields))

	appPropsMap := encodeMap32([][]byte{
		encodeSym8("status-code"),
		encodeInt32(200),
		encodeSym8("status-description"),
		encodeStr8("OK"),
	})
	appPropsSection := encodeDescribed(0x74, appPropsMap)

	return append(propsSection, appPropsSection...)
}

func buildManagementResponse(correlationID string) []byte {
	propFields := [][]byte{
		{0x40},
		{0x40},
		{0x40},
		{0x40},
		{0x40},
		encodeStr8(correlationID),
	}
	propsSection := encodeDescribed(0x73, encodeList32(propFields))

	appPropsMap := encodeMap32([][]byte{
		encodeSym8("status-code"),
		encodeInt32(200),
		encodeSym8("status-description"),
		encodeStr8("OK"),
	})
	appPropsSection := encodeDescribed(0x74, appPropsMap)

	partIDArrayBody := []byte{0xA1, 0x01, '0'}
	partIDArray := append([]byte{0xE0, byte(1 + len(partIDArrayBody)), 0x01}, partIDArrayBody...)

	epoch := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	hubMap := encodeMap32([][]byte{
		encodeSym8("name"),
		encodeStr8("m365-defender-test"),
		encodeSym8("created_at"),
		encodeTimestamp(epoch),
		encodeSym8("partition_ids"),
		partIDArray,
		encodeSym8("georeplication_factor"),
		encodeInt32(1),
	})
	valueSection := encodeDescribed(0x77, hubMap)

	msg := append(propsSection, appPropsSection...)
	msg = append(msg, valueSection...)
	return msg
}

// ---- AMQP parsing ----

func parseList(data []byte) ([]any, error) {
	fields, _, err := parseListAt(data, 0)
	return fields, err
}

func parseListAt(data []byte, pos int) ([]any, int, error) {
	if pos >= len(data) {
		return nil, pos, nil
	}
	t := data[pos]
	switch t {
	case 0x45:
		return nil, pos + 1, nil
	case 0xC0:
		if pos+2 >= len(data) {
			return nil, pos, fmt.Errorf("list8 truncated")
		}
		size := int(data[pos+1])
		count := int(data[pos+2])
		end := min(pos+2+size, len(data))
		items, err := parseItems(data[pos+3:end], count)
		return items, end, err
	case 0xD0:
		if pos+8 >= len(data) {
			return nil, pos, fmt.Errorf("list32 truncated")
		}
		size := int(binary.BigEndian.Uint32(data[pos+1:]))
		count := int(binary.BigEndian.Uint32(data[pos+5:]))
		end := min(pos+5+size, len(data))
		items, err := parseItems(data[pos+9:end], count)
		return items, end, err
	}
	return nil, pos, fmt.Errorf("not a list: 0x%02x", t)
}

func parseItems(data []byte, count int) ([]any, error) {
	var items []any
	pos := 0
	for i := 0; i < count && pos < len(data); i++ {
		val, next, err := parseValue(data, pos)
		if err != nil {
			return items, err
		}
		items = append(items, val)
		pos = next
	}
	return items, nil
}

func parseValue(data []byte, pos int) (any, int, error) {
	if pos >= len(data) {
		return nil, pos, fmt.Errorf("truncated")
	}
	t := data[pos]
	switch t {
	case 0x00: // described
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("described truncated")
		}
		_, pos2, err := parseValue(data, pos+1)
		if err != nil {
			return nil, pos, err
		}
		val, pos3, err := parseValue(data, pos2)
		return val, pos3, err
	case 0x40:
		return nil, pos + 1, nil
	case 0x41:
		return true, pos + 1, nil
	case 0x42:
		return false, pos + 1, nil
	case 0x43:
		return uint32(0), pos + 1, nil
	case 0x44:
		return uint64(0), pos + 1, nil
	case 0x45:
		return []any{}, pos + 1, nil
	case 0x50:
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("ubyte truncated")
		}
		return uint8(data[pos+1]), pos + 2, nil
	case 0x52:
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("uint small truncated")
		}
		return uint32(data[pos+1]), pos + 2, nil
	case 0x53:
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("ulong small truncated")
		}
		return uint64(data[pos+1]), pos + 2, nil
	case 0x54:
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("int small truncated")
		}
		return int32(int8(data[pos+1])), pos + 2, nil
	case 0x70:
		if pos+4 >= len(data) {
			return nil, pos, fmt.Errorf("uint32 truncated")
		}
		return binary.BigEndian.Uint32(data[pos+1:]), pos + 5, nil
	case 0x71:
		if pos+4 >= len(data) {
			return nil, pos, fmt.Errorf("int32 truncated")
		}
		return int32(binary.BigEndian.Uint32(data[pos+1:])), pos + 5, nil
	case 0x80:
		if pos+8 >= len(data) {
			return nil, pos, fmt.Errorf("ulong truncated")
		}
		return binary.BigEndian.Uint64(data[pos+1:]), pos + 9, nil
	case 0x83:
		if pos+8 >= len(data) {
			return nil, pos, fmt.Errorf("timestamp truncated")
		}
		ms := int64(binary.BigEndian.Uint64(data[pos+1:]))
		return time.UnixMilli(ms), pos + 9, nil
	case 0xA0:
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("binary8 truncated")
		}
		n := int(data[pos+1])
		end := pos + 2 + n
		if end > len(data) {
			return nil, pos, fmt.Errorf("binary8 data truncated")
		}
		return data[pos+2 : end], end, nil
	case 0xA1:
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("str8 truncated")
		}
		n := int(data[pos+1])
		end := pos + 2 + n
		if end > len(data) {
			return nil, pos, fmt.Errorf("str8 data truncated")
		}
		return string(data[pos+2 : end]), end, nil
	case 0xA3:
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("sym8 truncated")
		}
		n := int(data[pos+1])
		end := pos + 2 + n
		if end > len(data) {
			return nil, pos, fmt.Errorf("sym8 data truncated")
		}
		return string(data[pos+2 : end]), end, nil
	case 0xB0:
		if pos+4 >= len(data) {
			return nil, pos, fmt.Errorf("binary32 truncated")
		}
		n := int(binary.BigEndian.Uint32(data[pos+1:]))
		end := pos + 5 + n
		if end > len(data) {
			return nil, pos, fmt.Errorf("binary32 data truncated")
		}
		return data[pos+5 : end], end, nil
	case 0xB1:
		if pos+4 >= len(data) {
			return nil, pos, fmt.Errorf("str32 truncated")
		}
		n := int(binary.BigEndian.Uint32(data[pos+1:]))
		end := pos + 5 + n
		if end > len(data) {
			return nil, pos, fmt.Errorf("str32 data truncated")
		}
		return string(data[pos+5 : end]), end, nil
	case 0xB3:
		if pos+4 >= len(data) {
			return nil, pos, fmt.Errorf("sym32 truncated")
		}
		n := int(binary.BigEndian.Uint32(data[pos+1:]))
		end := pos + 5 + n
		if end > len(data) {
			return nil, pos, fmt.Errorf("sym32 data truncated")
		}
		return string(data[pos+5 : end]), end, nil
	case 0xC0:
		items, end, err := parseListAt(data, pos)
		return items, end, err
	case 0xD0:
		items, end, err := parseListAt(data, pos)
		return items, end, err
	case 0xD1:
		if pos+8 >= len(data) {
			return nil, pos, fmt.Errorf("map32 truncated")
		}
		size := int(binary.BigEndian.Uint32(data[pos+1:]))
		count := int(binary.BigEndian.Uint32(data[pos+5:]))
		end := min(pos+5+size, len(data))
		items, err := parseItems(data[pos+9:end], count)
		return items, end, err
	case 0xE0:
		if pos+2 >= len(data) {
			return nil, pos, fmt.Errorf("array8 truncated")
		}
		size := int(data[pos+1])
		end := min(pos+2+size, len(data))
		return data[pos:end], end, nil
	default:
		return nil, pos + 1, fmt.Errorf("unknown type 0x%02x", t)
	}
}

func parseMessageProperties(msg []byte) (msgID, replyTo string) {
	pos := 0
	for pos < len(msg) {
		if pos+2 >= len(msg) {
			break
		}
		if msg[pos] != 0x00 {
			break
		}
		_, descEnd, err := parseValue(msg, pos+1)
		if err != nil {
			break
		}
		sectionCode := byte(0)
		if pos+1 < len(msg) && msg[pos+1] == 0x53 && pos+2 < len(msg) {
			sectionCode = msg[pos+2]
		}

		val, valEnd, err := parseValue(msg, descEnd)
		if err != nil {
			break
		}
		pos = valEnd

		if sectionCode == 0x73 {
			fields, ok := val.([]any)
			if !ok {
				continue
			}
			if len(fields) > 0 {
				if s, ok := fields[0].(string); ok {
					msgID = s
				}
			}
			if len(fields) > 4 {
				if s, ok := fields[4].(string); ok {
					replyTo = s
				}
			}
		}
	}
	return msgID, replyTo
}

func extractAddress(v any) string {
	if v == nil {
		return ""
	}
	fields, ok := v.([]any)
	if !ok {
		return ""
	}
	if len(fields) == 0 {
		return ""
	}
	if s, ok := fields[0].(string); ok {
		return s
	}
	return ""
}

func toUint32(v any) uint32 {
	switch x := v.(type) {
	case uint32:
		return x
	case uint64:
		return uint32(x)
	case uint8:
		return uint32(x)
	case int32:
		return uint32(x)
	}
	return 0
}
