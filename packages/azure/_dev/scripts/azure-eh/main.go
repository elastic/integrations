// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Test events delivered to the consumer.
var testEvents = []string{
	`{"category":"Administrative"}`,
	`{"category":"ApplicationGatewayFirewallLog"}`,
	`{"category":"AuditLogs"}`,
	`{"category":"AzureFirewallApplicationRule"}`,
	`{"category":"MicrosoftGraphActivityLogs"}`,
	`{"category":"RiskyUsers"}`,
	`{"category":"ProvisioningLogs"}`,
	`{"Category":"SignInLogs"}`,
	`{"category":"ApplicationConsole"}`,
	`{"Category":"AzureADGraphActivityLogs"}`,
	`{"category":"AppServiceHTTPLogs","time":"2024-01-01T00:00:00Z","resourceId":"/subscriptions/test/resourceGroups/rg/providers/Microsoft.Web/sites/myapp"}`,
}

func main() {
	store := newBlobStore()

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
	path := strings.TrimPrefix(r.URL.Path, "/devstoreaccount1/")
	parts := strings.SplitN(path, "/", 2)
	container := parts[0]
	blob := ""
	if len(parts) == 2 {
		blob = parts[1]
	}

	restype := r.URL.Query().Get("restype")
	comp := r.URL.Query().Get("comp")

	switch {
	case blob == "" && restype == "container" && r.Method == http.MethodGet && comp == "":
		s.containerExists(w, container)
	case blob == "" && restype == "container" && r.Method == http.MethodPut:
		s.createContainer(w, container)
	case blob == "" && restype == "container" && r.Method == http.MethodGet && comp == "list":
		s.listBlobs(w, r, container)
	case blob != "" && r.Method == http.MethodPut && comp == "metadata":
		s.setMetadata(w, r, container, blob)
	case blob != "" && r.Method == http.MethodPut:
		s.putBlob(w, r, container, blob)
	case blob != "" && r.Method == http.MethodGet:
		s.getBlob(w, container, blob)
	case blob != "" && r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusAccepted)
	default:
		log.Printf("blob unhandled: %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusNotFound)
	}
}

func xmlErr(code, msg string) []byte {
	return fmt.Appendf(nil, `<?xml version="1.0" encoding="utf-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, msg)
}

func (s *blobStore) containerExists(w http.ResponseWriter, container string) {
	s.mu.Lock()
	_, ok := s.containers[container]
	s.mu.Unlock()
	if !ok {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		w.Write(xmlErr("ContainerNotFound", "The specified container does not exist."))
		return
	}
	w.Header().Set("x-ms-request-id", "fake-req-id")
	w.Header().Set("ETag", `"mock-etag"`)
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

func (s *blobStore) listBlobs(w http.ResponseWriter, r *http.Request, container string) {
	prefix := r.URL.Query().Get("prefix")
	s.mu.Lock()
	blobs := s.containers[container]
	s.mu.Unlock()

	// The azblob SDK parses BlobItem.Metadata via a custom UnmarshalXML that
	// reads child elements of <Metadata> as key-value pairs. The Properties
	// block must include Last-Modified (for LastModifiedTime) and Etag (for ETag)
	// since copyOwnershipPropsFromBlob dereferences both without nil checks.
	var buf strings.Builder
	buf.WriteString(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs>`)
	for name, item := range blobs {
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		buf.WriteString("<Blob><Name>")
		xml.EscapeText(&buf, []byte(name))
		buf.WriteString("</Name><Properties><Last-Modified>")
		buf.WriteString(item.lastModified.UTC().Format(http.TimeFormat))
		buf.WriteString("</Last-Modified><Etag>")
		xml.EscapeText(&buf, []byte(item.etag))
		buf.WriteString("</Etag></Properties><Metadata>")
		for k, v := range item.metadata {
			buf.WriteString("<")
			xml.EscapeText(&buf, []byte(k))
			buf.WriteString(">")
			xml.EscapeText(&buf, []byte(v))
			buf.WriteString("</")
			xml.EscapeText(&buf, []byte(k))
			buf.WriteString(">")
		}
		buf.WriteString("</Metadata></Blob>")
	}
	buf.WriteString(`</Blobs><NextMarker/></EnumerationResults>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, buf.String())
}

func (s *blobStore) putBlob(w http.ResponseWriter, r *http.Request, container, blob string) {
	body, _ := io.ReadAll(r.Body)
	meta := extractMeta(r)

	s.mu.Lock()
	if s.containers[container] == nil {
		s.containers[container] = make(map[string]*blobItem)
	}
	if r.Header.Get("If-None-Match") == "*" {
		if _, exists := s.containers[container][blob]; exists {
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

// ---- AMQP server ----

type linkInfo struct {
	handle       uint32
	name         string
	isSender     bool // from server's perspective
	address      string
	replyAddress string // target address from client's receiver Attach (for CBS/mgmt reply routing)
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

	// SASL exchange
	if err := saslExchange(conn); err != nil {
		log.Printf("sasl: %v", err)
		return
	}

	// AMQP exchange
	amqpMagic := []byte("AMQP\x00\x01\x00\x00")
	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Printf("amqp magic read: %v", err)
		return
	}
	if err := writeAll(conn, amqpMagic); err != nil {
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
	// Expect described type: 0x00 0x53 [code]
	if payload[0] != 0x00 || payload[1] != 0x53 {
		return nil
	}
	code := payload[2]
	body := payload[3:]

	if name := codeNames[code]; name != "" {
		log.Printf("rx ch=%d %s", fh.channel, name)
	}

	switch code {
	case 0x10: // Open
		return cs.handleOpen(body)
	case 0x11: // Begin
		cs.channel = fh.channel
		return cs.handleBegin(body)
	case 0x12: // Attach
		return cs.handleAttach(fh.channel, body)
	case 0x13: // Flow
		return cs.handleFlow(fh.channel, body)
	case 0x14: // Transfer
		return cs.handleTransfer(fh.channel, payload)
	case 0x15: // Disposition
		return nil
	case 0x16: // Detach
		return cs.handleDetach(fh.channel, body)
	case 0x17: // End
		return cs.sendFrame(fh.channel, buildPerformative(0x17, encodeList8(nil)))
	case 0x18: // Close
		if fields, _ := parseList(body); len(fields) > 0 && fields[0] != nil {
			log.Printf("rx Close with error: %v", fields[0])
		}
		cs.sendFrame(fh.channel, buildPerformative(0x18, encodeList8(nil)))
		return fmt.Errorf("connection closed")
	}
	return nil
}

func (cs *connState) handleOpen(body []byte) error {
	fields, _ := parseList(body)
	containerID := "fake-azure-eh"
	if len(fields) > 0 {
		if s, ok := fields[0].(string); ok {
			_ = s
		}
	}
	// Send Open response
	openList := encodeList8([][]byte{
		encodeStr8(containerID),
	})
	return cs.sendFrame(0, buildPerformative(0x10, openList))
}

func (cs *connState) handleBegin(body []byte) error {
	fields, _ := parseList(body)
	_ = fields
	// Begin response: [remote-channel, next-outgoing-id, incoming-window, outgoing-window]
	beginList := encodeList32([][]byte{
		encodeUshort(cs.channel), // remote-channel: the channel the peer used
		encodeUint(0),            // next-outgoing-id
		encodeUint(65535),        // incoming-window
		encodeUint(65535),        // outgoing-window
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
	// role field[2]: false=sender, true=receiver (from client's perspective)
	clientIsSender := false
	if len(fields) > 2 {
		if b, ok := fields[2].(bool); ok {
			clientIsSender = !b // client is sender if role=false
		}
	}

	// Echo settle modes (fields[3] and [4]) from the client's Attach.
	// go-amqp validates that the server's Attach response echoes back the
	// requested snd-settle-mode; a mismatch causes it to send Detach immediately.
	sndSettleMode := []byte{0x40} // null
	rcvSettleMode := []byte{0x40} // null
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

	// Extract source address (field[5]) and target address (field[6])
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

	// Build Attach response - server inverts role
	serverRole := clientIsSender // if client is sender, server is receiver (role=true)

	var roleByte []byte
	if serverRole {
		roleByte = []byte{0x41} // true
	} else {
		roleByte = []byte{0x42} // false
	}

	// Build source and target for response
	var sourceBytes, targetBytes []byte
	if clientIsSender {
		// client sends to target, server is receiver
		// server's source is null, target echoes client's target
		sourceBytes = []byte{0x40} // null
		targetBytes = encodeDescribed(0x29, encodeList8([][]byte{encodeStr8(targetAddr)}))
	} else {
		// client is receiver, server is sender
		// server's source echoes client's source, target is null
		sourceBytes = encodeDescribed(0x28, encodeList8([][]byte{encodeStr8(sourceAddr)}))
		targetBytes = []byte{0x40} // null
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
		// server is sender: initial-delivery-count is mandatory (field index 9).
		// Fields 7 (unsettled) and 8 (incomplete-unsettled) must be present as null.
		attachFields = append(attachFields, []byte{0x40}, []byte{0x40}, encodeUint(0))
	}

	log.Printf("attach ch=%d name=%q handle=%d isSender=%v addr=%q", channel, name, handle, !clientIsSender, li.address)
	attachList := encodeList32(attachFields)
	if err := cs.sendFrame(channel, buildPerformative(0x12, attachList)); err != nil {
		return err
	}
	// Server is the receiver: grant link credit so the client sender can transmit.
	if clientIsSender {
		flowList := encodeList32([][]byte{
			encodeUint(0),      // next-incoming-id
			encodeUint(65535),  // incoming-window
			encodeUint(0),      // next-outgoing-id
			encodeUint(65535),  // outgoing-window
			encodeUint(handle), // handle
			encodeUint(0),      // delivery-count (sender starts at 0)
			encodeUint(64),     // link-credit
		})
		return cs.sendFrame(channel, buildPerformative(0x13, flowList))
	}
	return nil
}

func (cs *connState) handleFlow(channel uint16, body []byte) error {
	fields, _ := parseList(body)
	// fields[4] = handle, fields[5] = delivery-count, fields[6] = link-credit
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

	// Check if this is a partition link.
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

		// Transfer: [handle, delivery-id, delivery-tag, msg-format=0, settled=true]
		transferList := encodeList32([][]byte{
			encodeUint(li.handle),
			encodeUint(uint32(deliveryID)),
			encodeBytes8(tag),
			encodeUint(0), // msg-format
			{0x41},        // settled=true
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
	// payload = 0x00 0x53 0x14 [list body] [message]
	// Skip past the performative to find the message
	if len(payload) < 3 {
		return nil
	}
	pos := 3 // after 0x00 0x53 0x14

	// Parse the list to get transfer fields
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

	// Send Disposition: acknowledge the transfer
	dispList := encodeList32([][]byte{
		{0x41},                              // role=true (receiver)
		encodeUint(deliveryID),              // first
		encodeUint(deliveryID),              // last
		{0x41},                              // settled=true
		encodeDescribed(0x24, []byte{0x45}), // state=Accepted (list0)
	})
	if err := cs.sendFrame(channel, buildPerformative(0x15, dispList)); err != nil {
		return err
	}

	// Parse message to find Properties section
	msgID, replyTo := parseMessageProperties(msgPayload)

	log.Printf("transfer on link %q (addr=%q) msgID=%q replyTo=%q", li.name, li.address, msgID, replyTo)

	// Find the reply-to link
	replyLink := cs.findReplyLink(li.address, replyTo)
	if replyLink == nil {
		log.Printf("no reply link for addr=%q replyTo=%q; known links: %v", li.address, replyTo, cs.linkNames())
		return nil
	}

	// Build and send response
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

	// Infer reply link from sender address
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
		encodeUint(0), // msg-format
		{0x41},        // settled=true
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

func (cs *connState) sendFrame(channel uint16, payload []byte) error {
	size := uint32(8 + len(payload))
	hdr := []byte{
		byte(size >> 24), byte(size >> 16), byte(size >> 8), byte(size),
		0x02, // DOFF
		0x00, // type AMQP
		byte(channel >> 8), byte(channel),
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if _, err := cs.conn.Write(hdr); err != nil {
		return err
	}
	if _, err := cs.conn.Write(payload); err != nil {
		return err
	}
	return nil
}

// ---- SASL ----

func saslExchange(conn net.Conn) error {
	saslMagic := []byte("AMQP\x03\x01\x00\x00")
	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if err := writeAll(conn, saslMagic); err != nil {
		return err
	}

	// Send SASLMechanisms: descriptor 0x40, list containing array8 of sym8 ["ANONYMOUS"]
	// array8 of sym8 ["ANONYMOUS"]:
	// 0xE0 [size] [count=1] [ctor=0xA3] [len=9] ANONYMOUS
	anonBytes := []byte("ANONYMOUS")
	arrayBody := append([]byte{0xA3, byte(len(anonBytes))}, anonBytes...)
	// size_field = 1(count) + len(ctor+elements) = 1 + len(arrayBody)
	arrayData := append([]byte{0xE0, byte(1 + len(arrayBody)), 0x01}, arrayBody...)

	mechList := encodeList8([][]byte{arrayData})
	mechsPerf := buildSASLPerformative(0x40, mechList)
	if err := sendSASLFrame(conn, mechsPerf); err != nil {
		return err
	}

	// Read SASLInit
	_, initPayload, err := readFrame(conn)
	if err != nil {
		return err
	}
	_ = initPayload

	// Send SASLOutcome: code=0 (success)
	// ubyte(0) encoded as 0x50 0x00
	outcomeList := encodeList8([][]byte{{0x50, 0x00}})
	outcomePerf := buildSASLPerformative(0x44, outcomeList)
	return sendSASLFrame(conn, outcomePerf)
}

func sendSASLFrame(conn net.Conn, payload []byte) error {
	size := uint32(8 + len(payload))
	hdr := []byte{
		byte(size >> 24), byte(size >> 16), byte(size >> 8), byte(size),
		0x02,       // DOFF
		0x01,       // type SASL
		0x00, 0x00, // channel 0
	}
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(payload)
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
	// Message annotations (0x72): x-opt-enqueued-time, x-opt-sequence-number, x-opt-offset.
	// Without x-opt-enqueued-time the SDK leaves EnqueuedTime nil, and the
	// filebeat debug encoder panics dereferencing a nil *time.Time.
	annotationsMap := encodeMap32([][]byte{
		encodeSym8("x-opt-enqueued-time"),
		encodeTimestamp(now),
		encodeSym8("x-opt-sequence-number"),
		encodeLong(seqNum),
		encodeSym8("x-opt-offset"),
		encodeStr8("0"),
	})
	annotationsSection := encodeDescribed(0x72, annotationsMap)

	// Data section: 0x00 0x53 0x75 binary8/32
	dataSection := encodeDescribed(0x75, encodeBytes8(data))
	return append(annotationsSection, dataSection...)
}

func buildCBSResponse(correlationID string) []byte {
	// Properties section (0x73): list with correlation-id at [5]
	propFields := [][]byte{
		{0x40},                    // message-id: null
		{0x40},                    // user-id: null
		{0x40},                    // to: null
		{0x40},                    // subject: null
		{0x40},                    // reply-to: null
		encodeStr8(correlationID), // correlation-id at [5]
	}
	propsSection := encodeDescribed(0x73, encodeList32(propFields))

	// ApplicationProperties section (0x74): map32 with status-code=200, status-description="OK"
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
	// Properties section
	propFields := [][]byte{
		{0x40},                    // message-id: null
		{0x40},                    // user-id: null
		{0x40},                    // to: null
		{0x40},                    // subject: null
		{0x40},                    // reply-to: null
		encodeStr8(correlationID), // correlation-id at [5]
	}
	propsSection := encodeDescribed(0x73, encodeList32(propFields))

	// ApplicationProperties section
	appPropsMap := encodeMap32([][]byte{
		encodeSym8("status-code"),
		encodeInt32(200),
		encodeSym8("status-description"),
		encodeStr8("OK"),
	})
	appPropsSection := encodeDescribed(0x74, appPropsMap)

	// AmqpValue section (0x77) with hub properties map
	// partition_ids: array8 of str8 ["0"]
	// 0xE0 [size] [count=1] [ctor=0xA1] [len=1] "0"
	partIDArrayBody := []byte{0xA1, 0x01, '0'}
	partIDArray := append([]byte{0xE0, byte(1 + len(partIDArrayBody)), 0x01}, partIDArrayBody...)

	epoch := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	hubMap := encodeMap32([][]byte{
		encodeSym8("name"),
		encodeStr8("azure-routing-test"),
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
	case 0x45: // list0
		return nil, pos + 1, nil
	case 0xC0: // list8
		if pos+2 >= len(data) {
			return nil, pos, fmt.Errorf("list8 truncated")
		}
		size := int(data[pos+1])
		count := int(data[pos+2])
		end := min(pos+2+size, len(data))
		items, err := parseItems(data[pos+3:end], count)
		return items, end, err
	case 0xD0: // list32
		if pos+8 >= len(data) {
			return nil, pos, fmt.Errorf("list32 truncated")
		}
		size := int(binary.BigEndian.Uint32(data[pos+1:]))
		count := int(binary.BigEndian.Uint32(data[pos+5:]))
		// end = pos + 1(tag) + 4(size_field) + size = pos + 5 + size
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
		_, pos2, err := parseValue(data, pos+1) // descriptor
		if err != nil {
			return nil, pos, err
		}
		val, pos3, err := parseValue(data, pos2) // value
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
	case 0x50: // ubyte
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("ubyte truncated")
		}
		return uint8(data[pos+1]), pos + 2, nil
	case 0x52: // uint small
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("uint small truncated")
		}
		return uint32(data[pos+1]), pos + 2, nil
	case 0x53: // ulong small
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("ulong small truncated")
		}
		return uint64(data[pos+1]), pos + 2, nil
	case 0x54: // int small
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("int small truncated")
		}
		return int32(int8(data[pos+1])), pos + 2, nil
	case 0x70: // uint32
		if pos+4 >= len(data) {
			return nil, pos, fmt.Errorf("uint32 truncated")
		}
		return binary.BigEndian.Uint32(data[pos+1:]), pos + 5, nil
	case 0x71: // int32
		if pos+4 >= len(data) {
			return nil, pos, fmt.Errorf("int32 truncated")
		}
		v := int32(binary.BigEndian.Uint32(data[pos+1:]))
		return v, pos + 5, nil
	case 0x80: // ulong
		if pos+8 >= len(data) {
			return nil, pos, fmt.Errorf("ulong truncated")
		}
		return binary.BigEndian.Uint64(data[pos+1:]), pos + 9, nil
	case 0x83: // timestamp
		if pos+8 >= len(data) {
			return nil, pos, fmt.Errorf("timestamp truncated")
		}
		ms := int64(binary.BigEndian.Uint64(data[pos+1:]))
		return time.UnixMilli(ms), pos + 9, nil
	case 0xA0: // binary8
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("binary8 truncated")
		}
		n := int(data[pos+1])
		end := pos + 2 + n
		if end > len(data) {
			return nil, pos, fmt.Errorf("binary8 data truncated")
		}
		return data[pos+2 : end], end, nil
	case 0xA1: // str8
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("str8 truncated")
		}
		n := int(data[pos+1])
		end := pos + 2 + n
		if end > len(data) {
			return nil, pos, fmt.Errorf("str8 data truncated")
		}
		return string(data[pos+2 : end]), end, nil
	case 0xA3: // sym8
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("sym8 truncated")
		}
		n := int(data[pos+1])
		end := pos + 2 + n
		if end > len(data) {
			return nil, pos, fmt.Errorf("sym8 data truncated")
		}
		return string(data[pos+2 : end]), end, nil
	case 0xB0: // binary32
		if pos+4 >= len(data) {
			return nil, pos, fmt.Errorf("binary32 truncated")
		}
		n := int(binary.BigEndian.Uint32(data[pos+1:]))
		end := pos + 5 + n
		if end > len(data) {
			return nil, pos, fmt.Errorf("binary32 data truncated")
		}
		return data[pos+5 : end], end, nil
	case 0xB1: // str32
		if pos+4 >= len(data) {
			return nil, pos, fmt.Errorf("str32 truncated")
		}
		n := int(binary.BigEndian.Uint32(data[pos+1:]))
		end := pos + 5 + n
		if end > len(data) {
			return nil, pos, fmt.Errorf("str32 data truncated")
		}
		return string(data[pos+5 : end]), end, nil
	case 0xB3: // sym32
		if pos+4 >= len(data) {
			return nil, pos, fmt.Errorf("sym32 truncated")
		}
		n := int(binary.BigEndian.Uint32(data[pos+1:]))
		end := pos + 5 + n
		if end > len(data) {
			return nil, pos, fmt.Errorf("sym32 data truncated")
		}
		return string(data[pos+5 : end]), end, nil
	case 0xC0: // list8
		items, end, err := parseListAt(data, pos)
		return items, end, err
	case 0xD0: // list32
		items, end, err := parseListAt(data, pos)
		return items, end, err
	case 0xD1: // map32
		if pos+8 >= len(data) {
			return nil, pos, fmt.Errorf("map32 truncated")
		}
		size := int(binary.BigEndian.Uint32(data[pos+1:]))
		count := int(binary.BigEndian.Uint32(data[pos+5:]))
		// end = pos + 1(tag) + 4(size_field) + size = pos + 5 + size
		end := min(pos+5+size, len(data))
		items, err := parseItems(data[pos+9:end], count)
		return items, end, err
	case 0xE0: // array8
		if pos+2 >= len(data) {
			return nil, pos, fmt.Errorf("array8 truncated")
		}
		size := int(data[pos+1])
		end := min(pos+2+size, len(data))
		return data[pos:end], end, nil
	default:
		// Unknown type - skip it by returning nil and advancing 1
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
		// described type
		_, descEnd, err := parseValue(msg, pos+1) // descriptor
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
			// Properties section
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

func writeAll(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}
