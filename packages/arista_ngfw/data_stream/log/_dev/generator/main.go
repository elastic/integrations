package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"
)

type AdminLoginEvent struct {
	Timestamp     string `json:"timeStamp"`
	Login         string `json:"login"`
	ClientAddress string `json:"clientAddress"`
	Class         string `json:"class"`
	Local         bool   `json:"local"`
	Succeeded     bool   `json:"succeeded"`
}

type FirewallEvent struct {
	Timestamp string `json:"timeStamp"`
	Flagged   bool   `json:"flagged"`
	Blocked   bool   `json:"blocked"`
	SessionID int64  `json:"sessionId"`
	RuleID    int    `json:"ruleId"`
	Class     string `json:"class"`
}

type HttpRequestEvent struct {
	Timestamp     string `json:"timeStamp"`
	Method        string `json:"method"`
	RequestID     int64  `json:"requestId"`
	Domain        string `json:"domain"`
	Host          string `json:"host"`
	ContentLength int    `json:"contentLength"`
	RequestURI    string `json:"requestUri"`
	Class         string `json:"class"`
}

type HttpResponseEvent struct {
	Timestamp        string           `json:"timeStamp"`
	ContentLength    int              `json:"contentLength"`
	RequestLine      string           `json:"requestLine"`
	ContentType      string           `json:"contentType"`
	Class            string           `json:"class"`
	HttpRequestEvent HttpRequestEvent `json:"httpRequestEvent"`
}

type InterfaceStatEvent struct {
	Timestamp   string  `json:"timeStamp"`
	RxBytes     int     `json:"rxBytes"`
	TxBytes     int     `json:"txBytes"`
	TxRate      float64 `json:"txRate"`
	InterfaceID int     `json:"interfaceId"`
	RxRate      float64 `json:"rxRate"`
	Class       string  `json:"class"`
}

type IntrusionPreventionLogEvent struct {
	Msg           string `json:"msg"`
	IpDestination string `json:"ipDestination"`
	IpSource      string `json:"ipSource"`
	Classtype     string `json:"classtype"`
	SignatureID   int    `json:"signatureId"`
	SportItype    int    `json:"sportItype"`
	Timestamp     string `json:"timeStamp"`
	GeneratorID   int    `json:"generatorId"`
	Protocol      string `json:"protocol"`
	Blocked       bool   `json:"blocked"`
	Category      string `json:"category"`
	RuleID        string `json:"ruleId"`
	Class         string `json:"class"`
	DportIcode    int    `json:"dportIcode"`
}

type SessionEvent struct {
	Entitled        bool    `json:"entitled"`
	Protocol        int     `json:"protocol"`
	Hostname        string  `json:"hostname"`
	CServerPort     int     `json:"CServerPort"`
	ProtocolName    string  `json:"protocolName"`
	ServerLatitude  float64 `json:"serverLatitude"`
	LocalAddr       string  `json:"localAddr"`
	Class           string  `json:"class"`
	SServerAddr     string  `json:"SServerAddr"`
	RemoteAddr      string  `json:"remoteAddr"`
	ServerIntf      int     `json:"serverIntf"`
	CClientAddr     string  `json:"CClientAddr"`
	ServerCountry   string  `json:"serverCountry"`
	SessionID       int64   `json:"sessionId"`
	SClientAddr     string  `json:"SClientAddr"`
	ClientCountry   string  `json:"clientCountry"`
	PolicyRuleID    int     `json:"policyRuleId"`
	Timestamp       string  `json:"timeStamp"`
	ServerLongitude float64 `json:"serverLongitude"`
	ClientIntf      int     `json:"clientIntf"`
	PolicyID        int     `json:"policyId"`
	SClientPort     int     `json:"SClientPort"`
	Bypassed        bool    `json:"bypassed"`
	SServerPort     int     `json:"SServerPort"`
	CServerAddr     string  `json:"CServerAddr"`
	TagsString      string  `json:"tagsString"`
}

type SessionStatsEvent struct {
	Timestamp    string       `json:"timeStamp"`
	S2pBytes     int          `json:"s2pBytes"`
	P2sBytes     int          `json:"p2sBytes"`
	EndTime      int64        `json:"endTime"`
	SessionID    int64        `json:"sessionId"`
	Class        string       `json:"class"`
	SessionEvent SessionEvent `json:"sessionEvent"`
	C2pBytes     int          `json:"c2pBytes"`
	P2cBytes     int          `json:"p2cBytes"`
}

type SystemStatEvent struct {
	DiskFreePercent float64 `json:"diskFreePercent"`
	CpuSystem       float64 `json:"cpuSystem"`
	DiskUsedPercent float64 `json:"diskUsedPercent"`
	DiskTotal       int64   `json:"diskTotal"`
	DiskFree        int64   `json:"diskFree"`
	CpuUser         float64 `json:"cpuUser"`
	MemUsedPercent  float64 `json:"memUsedPercent"`
	DiskUsed        int64   `json:"diskUsed"`
	Class           string  `json:"class"`
	Load15          float64 `json:"load15"`
	SwapUsedPercent float64 `json:"swapUsedPercent"`
	SwapFree        int64   `json:"swapFree"`
	MemFree         int64   `json:"memFree"`
	MemTotal        int64   `json:"memTotal"`
	SwapTotal       int64   `json:"swapTotal"`
	Load5           float64 `json:"load5"`
	MemBuffers      int64   `json:"memBuffers"`
	ActiveHosts     int     `json:"activeHosts"`
	Load1           float64 `json:"load1"`
	Timestamp       string  `json:"timeStamp"`
	SwapUsed        int64   `json:"swapUsed"`
	SwapFreePercent float64 `json:"swapFreePercent"`
	MemUsed         int64   `json:"memUsed"`
	MemFreePercent  float64 `json:"memFreePercent"`
	MemCache        int64   `json:"memCache"`
}

type WebFilterEvent struct {
	Reason       string       `json:"reason"`
	AppName      string       `json:"appName"`
	RequestLine  string       `json:"requestLine"`
	SessionEvent SessionEvent `json:"sessionEvent"`
	Timestamp    string       `json:"timeStamp"`
	Flagged      bool         `json:"flagged"`
	Blocked      bool         `json:"blocked"`
	Category     string       `json:"category"`
	RuleID       int          `json:"ruleId"`
	Class        string       `json:"class"`
	CategoryID   int          `json:"categoryId"`
}

func generateRandomAdminLoginEvent() AdminLoginEvent {
	return AdminLoginEvent{
		Timestamp:     time.Now().Format("2006-01-02 15:04:05.000"),
		Login:         "admin",
		ClientAddress: fmt.Sprintf("10.0.1.%d", rand.Intn(255)),
		Class:         "class com.untangle.uvm.event.AdminLoginEvent",
		Local:         rand.Intn(2) == 0,
		Succeeded:     rand.Intn(2) == 0,
	}
}

func generateRandomFirewallEvent() FirewallEvent {
	return FirewallEvent{
		Timestamp: time.Now().Format("2006-01-02 15:04:05.000"),
		Flagged:   rand.Intn(2) == 0,
		Blocked:   rand.Intn(2) == 0,
		SessionID: rand.Int63(),
		RuleID:    rand.Intn(100),
		Class:     "class com.untangle.app.firewall.FirewallEvent",
	}
}

func generateRandomHttpRequestEvent() HttpRequestEvent {
	return HttpRequestEvent{
		Timestamp:     time.Now().Format("2006-01-02 15:04:05.000"),
		Method:        "GET",
		RequestID:     rand.Int63(),
		Domain:        "example.com",
		Host:          "example.com",
		ContentLength: rand.Intn(1000),
		RequestURI:    "/path",
		Class:         "class com.untangle.app.http.HttpRequestEvent",
	}
}

func generateRandomHttpResponseEvent() HttpResponseEvent {
	return HttpResponseEvent{
		Timestamp:        time.Now().Format("2006-01-02 15:04:05.000"),
		ContentLength:    rand.Intn(1000),
		RequestLine:      "GET /path",
		ContentType:      "text/plain",
		Class:            "class com.untangle.app.http.HttpResponseEvent",
		HttpRequestEvent: generateRandomHttpRequestEvent(),
	}
}

func generateRandomInterfaceStatEvent() InterfaceStatEvent {
	return InterfaceStatEvent{
		Timestamp:   time.Now().Format("2006-01-02 15:04:05.000"),
		RxBytes:     rand.Intn(1e6),
		TxBytes:     rand.Intn(1e6),
		TxRate:      rand.Float64() * 1000,
		InterfaceID: rand.Intn(10),
		RxRate:      rand.Float64() * 1000,
		Class:       "class com.untangle.uvm.logging.InterfaceStatEvent",
	}
}

func generateRandomIntrusionPreventionLogEvent() IntrusionPreventionLogEvent {
	return IntrusionPreventionLogEvent{
		Msg:           "ET CINS Active Threat Intelligence Poor Reputation IP group 35",
		IpDestination: fmt.Sprintf("1.128.0.%d", rand.Intn(255)),
		IpSource:      fmt.Sprintf("216.160.83.%d", rand.Intn(255)),
		Classtype:     "misc-attack",
		SignatureID:   rand.Intn(1000000),
		SportItype:    rand.Intn(65535),
		Timestamp:     time.Now().Format("2006-01-02 15:04:05.000"),
		GeneratorID:   rand.Intn(100),
		Protocol:      "ip",
		Blocked:       rand.Intn(2) == 0,
		Category:      "ciarmy",
		RuleID:        "reserved_classification__2",
		Class:         "class com.untangle.app.intrusion_prevention.IntrusionPreventionLogEvent",
		DportIcode:    rand.Intn(65535),
	}
}

func generateRandomSessionEvent() SessionEvent {
	return SessionEvent{
		Entitled:        rand.Intn(2) == 0,
		Protocol:        rand.Intn(256),
		Hostname:        "Host1",
		CServerPort:     rand.Intn(65535),
		ProtocolName:    "UDP",
		ServerLatitude:  rand.Float64()*180 - 90,
		LocalAddr:       fmt.Sprintf("10.0.0.%d", rand.Intn(255)),
		Class:           "class com.untangle.uvm.app.SessionEvent",
		SServerAddr:     fmt.Sprintf("216.160.83.%d", rand.Intn(255)),
		RemoteAddr:      fmt.Sprintf("216.160.83.%d", rand.Intn(255)),
		ServerIntf:      rand.Intn(10),
		CClientAddr:     fmt.Sprintf("10.0.0.%d", rand.Intn(255)),
		ServerCountry:   "US",
		SessionID:       rand.Int63(),
		SClientAddr:     fmt.Sprintf("1.128.0.%d", rand.Intn(255)),
		ClientCountry:   "XL",
		PolicyRuleID:    rand.Intn(100),
		Timestamp:       time.Now().Format("2006-01-02 15:04:05.000"),
		ServerLongitude: rand.Float64()*360 - 180,
		ClientIntf:      rand.Intn(10),
		PolicyID:        rand.Intn(100),
		SClientPort:     rand.Intn(65535),
		Bypassed:        rand.Intn(2) == 0,
		SServerPort:     rand.Intn(65535),
		CServerAddr:     fmt.Sprintf("216.160.83.%d", rand.Intn(255)),
		TagsString:      "",
	}
}

func generateRandomSessionStatsEvent() SessionStatsEvent {
	return SessionStatsEvent{
		Timestamp:    time.Now().Format("2006-01-02 15:04:05.000"),
		S2pBytes:     rand.Intn(1e6),
		P2sBytes:     rand.Intn(1e6),
		EndTime:      time.Now().UnixNano() / int64(time.Millisecond),
		SessionID:    rand.Int63(),
		Class:        "class com.untangle.uvm.app.SessionStatsEvent",
		SessionEvent: generateRandomSessionEvent(),
		C2pBytes:     rand.Intn(1e6),
		P2cBytes:     rand.Intn(1e6),
	}
}

func generateRandomSystemStatEvent() SystemStatEvent {
	return SystemStatEvent{
		DiskFreePercent: rand.Float64(),
		CpuSystem:       rand.Float64(),
		DiskUsedPercent: rand.Float64(),
		DiskTotal:       rand.Int63(),
		DiskFree:        rand.Int63(),
		CpuUser:         rand.Float64(),
		MemUsedPercent:  rand.Float64(),
		DiskUsed:        rand.Int63(),
		Class:           "class com.untangle.uvm.logging.SystemStatEvent",
		Load15:          rand.Float64(),
		SwapUsedPercent: rand.Float64(),
		SwapFree:        rand.Int63(),
		MemFree:         rand.Int63(),
		MemTotal:        rand.Int63(),
		SwapTotal:       rand.Int63(),
		Load5:           rand.Float64(),
		MemBuffers:      rand.Int63(),
		ActiveHosts:     rand.Intn(100),
		Load1:           rand.Float64(),
		Timestamp:       time.Now().Format("2006-01-02 15:04:05.000"),
		SwapUsed:        rand.Int63(),
		SwapFreePercent: rand.Float64(),
		MemUsed:         rand.Int63(),
		MemFreePercent:  rand.Float64(),
		MemCache:        rand.Int63(),
	}
}

func generateRandomWebFilterEvent() WebFilterEvent {
	return WebFilterEvent{
		Reason:       "DEFAULT",
		AppName:      "web_filter",
		RequestLine:  "GET http://example.com/",
		SessionEvent: generateRandomSessionEvent(),
		Timestamp:    time.Now().Format("2006-01-02 15:04:05.000"),
		Flagged:      rand.Intn(2) == 0,
		Blocked:      rand.Intn(2) == 0,
		Category:     "Computer and Internet Security",
		RuleID:       rand.Intn(100),
		Class:        "class com.untangle.app.web_filter.WebFilterEvent",
		CategoryID:   rand.Intn(100),
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())

	logs := []interface{}{
		generateRandomAdminLoginEvent(),
		generateRandomFirewallEvent(),
		generateRandomHttpRequestEvent(),
		generateRandomHttpResponseEvent(),
		generateRandomInterfaceStatEvent(),
		generateRandomIntrusionPreventionLogEvent(),
		generateRandomSessionEvent(),
		generateRandomSessionStatsEvent(),
		generateRandomSystemStatEvent(),
		generateRandomWebFilterEvent(),
	}

	logCountStr := os.Getenv("LOG_COUNT")
	logCount, err := strconv.ParseInt(logCountStr, 10, 64)
	if err != nil {
		logCount = 1000000
	}

	for i := 0; i < int(logCount); i++ {
		log := logs[rand.Intn(len(logs))]
		logJSON, err := json.Marshal(log)
		if err != nil {
			fmt.Println("Error marshalling log:", err)
			continue
		}
		fmt.Printf("<174>%s INFO  uvm[0]:  %s\n", time.Now().Format("Jan 02 15:04:05"), string(logJSON))
	}
}
