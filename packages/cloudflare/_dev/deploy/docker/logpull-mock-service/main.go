// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

var (
	responses_iter_0 = []string{
		`{"CacheCacheStatus":"unknown","CacheResponseBytes":0,"CacheResponseStatus":0,"CacheTieredFill":false,"ClientASN":15169,"ClientCountry":"us","ClientDeviceType":"desktop","ClientIP":"35.232.161.245","ClientIPClass":"noRecord","ClientRequestBytes":2577,"ClientRequestHost":"cf-analytics.com","ClientRequestMethod":"POST","ClientRequestPath":"/wp-cron.php","ClientRequestProtocol":"HTTP/1.1","ClientRequestReferer":"https://cf-analytics.com/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000","ClientRequestURI":"/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000","ClientRequestUserAgent":"WordPress/5.2.2;https://cf-analytics.com","ClientSSLCipher":"ECDHE-ECDSA-AES128-GCM-SHA256","ClientSSLProtocol":"TLSv1.2","ClientSrcPort":55028,"EdgeColoID":14,"EdgeEndTimestamp":"2019-08-02T15:29:08Z","EdgePathingOp":"wl","EdgePathingSrc":"filter_based_firewall","EdgePathingStatus":"captchaNew","EdgeRateLimitAction":"","EdgeRateLimitID":0,"EdgeRequestHost":"","EdgeResponseBytes":2848,"EdgeResponseCompressionRatio":2.64,"EdgeResponseContentType":"text/html","EdgeResponseStatus":403,"EdgeServerIP":"","EdgeStartTimestamp":"2019-08-02T15:29:08Z","FirewallMatchesActions":["simulate","challenge"],"FirewallMatchesSources":["firewallRules","firewallRules"],"FirewallMatchesRuleIDs":["094b71fea25d4860a61fa0c6fbbd8d8b","e454fd4a0ce546b3a9a462536613692c"],"OriginIP":"","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":0,"OriginResponseTime":0,"OriginSSLProtocol":"unknown","ParentRayID":"00","RayID":"500115ec386354d8","SecurityLevel":"med","WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"ZoneID":155978002}`,
		`{"CacheCacheStatus":"hit","CacheResponseBytes":26888,"CacheResponseStatus":200,"CacheTieredFill":true,"ClientASN":1136,"ClientCountry":"nl","ClientDeviceType":"desktop","ClientIP":"222.97.65.242","ClientIPClass":"noRecord","ClientRequestBytes":5324,"ClientRequestHost":"eqlplayground.io","ClientRequestMethod":"GET","ClientRequestPath":"/40865/bundles/plugin/securitySolution/8.0.0/securitySolution.chunk.9.js","ClientRequestProtocol":"HTTP/1.1","ClientRequestReferer":"https://eqlplayground.io/s/eqldemo/app/security/timelines/default?sourcerer=(default:!(.siem-signals-eqldemo))&timerange=(global:(linkTo:!(),timerange:(from:%272021-03-03T19:55:15.519Z%27,fromStr:now-24h,kind:relative,to:%272021-03-04T19:55:15.519Z%27,toStr:now)),timeline:(linkTo:!(),timerange:(from:%272020-03-04T19:55:28.684Z%27,fromStr:now-1y,kind:relative,to:%272021-03-04T19:55:28.692Z%27,toStr:now)))&timeline=(activeTab:eql,graphEventId:%27%27,id:%2769f93840-7d23-11eb-866c-79a0609409ba%27,isOpen:!t)","ClientRequestURI":"/40865/bundles/plugin/securitySolution/8.0.0/securitySolution.chunk.9.js","ClientRequestUserAgent":"Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/91.0.4472.124Safari/537.36","ClientSSLCipher":"NONE","ClientSSLProtocol":"none","ClientSrcPort":0,"ClientXRequestedWith":"","EdgeColoCode":"33.147.138.217","EdgeColoID":20,"EdgeEndTimestamp":1625752958875000000,"EdgePathingOp":"wl","EdgePathingSrc":"macro","EdgePathingStatus":"nr","EdgeRateLimitAction":"","EdgeRateLimitID":0,"EdgeRequestHost":"eqlplayground.io","EdgeResponseBytes":24743,"EdgeResponseCompressionRatio":0,"EdgeResponseContentType":"application/javascript","EdgeResponseStatus":200,"EdgeServerIP":"","EdgeStartTimestamp":1625752958812000000,"FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":0,"OriginResponseTime":0,"OriginSSLProtocol":"unknown","ParentRayID":"66b9d9f88b5b4c4f","RayID":"66b9d9f890ae4c4f","SecurityLevel":"off","WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":true,"WorkerSubrequestCount":0,"ZoneID":393347122}`,
		`{"CacheCacheStatus":"unknown","CacheResponseBytes":0,"CacheResponseStatus":0,"CacheTieredFill":false,"ClientASN":1136,"ClientCountry":"nl","ClientDeviceType":"desktop","ClientIP":"149.175.108.201","ClientIPClass":"noRecord","ClientRequestBytes":2520,"ClientRequestHost":"eqlplayground.io","ClientRequestMethod":"GET","ClientRequestPath":"/s/eqldemo/security/account","ClientRequestProtocol":"HTTP/2","ClientRequestReferer":"","ClientRequestURI":"/s/eqldemo/security/account","ClientRequestUserAgent":"Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/91.0.4472.124Safari/537.36","ClientSSLCipher":"AEAD-AES128-GCM-SHA256","ClientSSLProtocol":"TLSv1.3","ClientSrcPort":61593,"ClientXRequestedWith":"","EdgeColoCode":"AMS","EdgeColoID":20,"EdgeEndTimestamp":1625754264684000000,"EdgePathingOp":"ban","EdgePathingSrc":"filter_based_firewall","EdgePathingStatus":"nr","EdgeRateLimitAction":"","EdgeRateLimitID":0,"EdgeRequestHost":"183.53.30.34","EdgeResponseBytes":2066,"EdgeResponseCompressionRatio":2.45,"EdgeResponseContentType":"text/html","EdgeResponseStatus":403,"EdgeServerIP":"","EdgeStartTimestamp":1625754264676000000,"FirewallMatchesActions":["block"],"FirewallMatchesRuleIDs":["391eb601201e4f2a81038910f2b63f6d"],"FirewallMatchesSources":["firewallRules"],"OriginIP":"","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":0,"OriginResponseTime":0,"OriginSSLProtocol":"unknown","ParentRayID":"00","RayID":"66b9f9da396e4c01","SecurityLevel":"unk","WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"ZoneID":393347122}`,
	}
	responses_iter_1 = []string{
		`{"CacheCacheStatus":"success","CacheResponseBytes":2048,"CacheResponseStatus":200,"CacheTieredFill":true,"ClientASN":12345,"ClientCountry":"ca","ClientDeviceType":"mobile","ClientIP":"192.168.1.1","ClientIPClass":"private","ClientRequestBytes":4096,"ClientRequestHost":"example.com","ClientRequestMethod":"GET","ClientRequestPath":"/page","ClientRequestProtocol":"HTTP/2.0","ClientRequestReferer":"https://referrer.com/page","ClientRequestURI":"/page","ClientRequestUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36","ClientSSLCipher":"AES256-GCM-SHA384","ClientSSLProtocol":"TLSv1.3","ClientSrcPort":12345,"EdgeColoID":42,"EdgeEndTimestamp":"2023-10-10T12:00:00Z","EdgePathingOp":"bypass","EdgePathingSrc":"direct","EdgePathingStatus":"allowed","EdgeRateLimitAction":"allow","EdgeRateLimitID":1,"EdgeRequestHost":"example.com","EdgeResponseBytes":8192,"EdgeResponseCompressionRatio":3.2,"EdgeResponseContentType":"application/json","EdgeResponseStatus":404,"EdgeServerIP":"203.0.113.1","EdgeStartTimestamp":"2023-10-10T11:45:00Z","FirewallMatchesActions":["block"],"FirewallMatchesSources":["firewallRules"],"FirewallMatchesRuleIDs":["abc123"],"OriginIP":"192.168.0.1","OriginResponseBytes":1024,"OriginResponseHTTPExpires":"Wed, 11 Oct 2023 12:00:00 GMT","OriginResponseHTTPLastModified":"Wed, 11 Oct 2023 10:00:00 GMT","OriginResponseStatus":200,"OriginResponseTime":150,"OriginSSLProtocol":"TLSv1.2","ParentRayID":"123","RayID":"456789abcdef","SecurityLevel":"high","WAFAction":"block","WAFFlags":"1","WAFMatchedVar":"user-agent","WAFProfile":"custom","WAFRuleID":"789","WAFRuleMessage":"Access denied","WorkerCPUTime":10,"WorkerStatus":"active","WorkerSubrequest":true,"WorkerSubrequestCount":5,"ZoneID":987654321}`,
		`{"CacheCacheStatus":"miss","CacheResponseBytes":3072,"CacheResponseStatus":404,"CacheTieredFill":false,"ClientASN":54321,"ClientCountry":"uk","ClientDeviceType":"tablet","ClientIP":"10.0.0.1","ClientIPClass":"private","ClientRequestBytes":8192,"ClientRequestHost":"example.org","ClientRequestMethod":"PUT","ClientRequestPath":"/api","ClientRequestProtocol":"HTTP/1.1","ClientRequestReferer":"https://referrer.org/api","ClientRequestURI":"/api","ClientRequestUserAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15","ClientSSLCipher":"AES128-GCM-SHA256","ClientSSLProtocol":"TLSv1.2","ClientSrcPort":54321,"EdgeColoID":7,"EdgeEndTimestamp":"2023-10-10T13:30:00Z","EdgePathingOp":"rate_limiting","EdgePathingSrc":"waf_firewall","EdgePathingStatus":"blocked","EdgeRateLimitAction":"block","EdgeRateLimitID":2,"EdgeRequestHost":"example.org","EdgeResponseBytes":10240,"EdgeResponseCompressionRatio":4.0,"EdgeResponseContentType":"application/json","EdgeResponseStatus":429,"EdgeServerIP":"198.51.100.2","EdgeStartTimestamp":"2023-10-10T13:15:00Z","FirewallMatchesActions":["block"],"FirewallMatchesSources":["waf_rules"],"FirewallMatchesRuleIDs":["def456"],"OriginIP":"192.168.0.2","OriginResponseBytes":2048,"OriginResponseHTTPExpires":"Wed, 11 Oct 2023 13:30:00 GMT","OriginResponseHTTPLastModified":"Wed, 11 Oct 2023 11:30:00 GMT","OriginResponseStatus":200,"OriginResponseTime":200,"OriginSSLProtocol":"TLSv1.3","ParentRayID":"456","RayID":"789abcdef012","SecurityLevel":"low","WAFAction":"simulate","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":5,"WorkerStatus":"inactive","WorkerSubrequest":false,"WorkerSubrequestCount":0,"ZoneID":123456789}`,
		`{"CacheCacheStatus":"unknown","CacheResponseBytes":5120,"CacheResponseStatus":503,"CacheTieredFill":true,"ClientASN":98765,"ClientCountry":"de","ClientDeviceType":"mobile","ClientIP":"172.16.0.1","ClientIPClass":"private","ClientRequestBytes":10240,"ClientRequestHost":"example.net","ClientRequestMethod":"GET","ClientRequestPath":"/home","ClientRequestProtocol":"HTTP/2.0","ClientRequestReferer":"https://referrer.net/home","ClientRequestURI":"/home","ClientRequestUserAgent":"Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36","ClientSSLCipher":"ECDHE-RSA-AES256-GCM-SHA384","ClientSSLProtocol":"TLSv1.3","ClientSrcPort":98765,"EdgeColoID":21,"EdgeEndTimestamp":"2023-10-10T14:45:00Z","EdgePathingOp":"none","EdgePathingSrc":"direct","EdgePathingStatus":"allowed","EdgeRateLimitAction":"none","EdgeRateLimitID":0,"EdgeRequestHost":"example.net","EdgeResponseBytes":2048,"EdgeResponseCompressionRatio":1.0,"EdgeResponseContentType":"text/html","EdgeResponseStatus":200,"EdgeServerIP":"203.0.113.3","EdgeStartTimestamp":"2023-10-10T14:30:00Z","FirewallMatchesActions":[],"FirewallMatchesSources":[],"FirewallMatchesRuleIDs":[],"OriginIP":"172.16.0.2","OriginResponseBytes":4096,"OriginResponseHTTPExpires":"Wed, 11 Oct 2023 14:45:00 GMT","OriginResponseHTTPLastModified":"Wed, 11 Oct 2023 12:45:00 GMT","OriginResponseStatus":200,"OriginResponseTime":100,"OriginSSLProtocol":"TLSv1.2","ParentRayID":"789","RayID":"abcdef012345","SecurityLevel":"medium","WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":2,"WorkerStatus":"active","WorkerSubrequest":true,"WorkerSubrequestCount":3,"ZoneID":9876543210}`,
	}
	iteration           int
	previousIterEndTime string
)

// Ref: https://developers.cloudflare.com/logs/logpull/requesting-logs/
func main() {
	router := mux.NewRouter()
	router.Path("/client/v4/zones/aaabbbccc/logs/received").HandlerFunc(logpullHandler).Methods("GET").Schemes("http")

	port := 3000
	log.Printf("Server listening on port %d...\n", port)
	h := handlers.CombinedLoggingHandler(os.Stderr, router)
	http.ListenAndServe(fmt.Sprintf(":%d", port), h)
}

func logpullHandler(w http.ResponseWriter, r *http.Request) {
	// Set response headers to indicate rolling response
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	email := r.Header.Get("x-auth-email")
	key := r.Header.Get("x-auth-key")

	if email == "" || key == "" {
		httpError(w, r, `{"message": "Missing authentication credentials"}`, http.StatusUnauthorized)
		return
	}
	if email != "user@example.com" && key != "xxxxxxxxxx" {
		httpError(w, r, `{"message": "Invalid authentication credentials"}`, http.StatusUnauthorized)
		return
	}

	// Get the timestamp value from the URL query parameter
	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")

	// Check if the timestamp parameter is empty
	if start == "" || end == "" {
		httpError(w, r, `{"message": "Timestamp parameter is missing"}`, http.StatusBadRequest)
		return
	}

	// this constraint is specific to iteration 1 as it allows us to simulate an use case where the start time of the next request is the same as the end time of the previous request
	if iteration == 1 && start != previousIterEndTime {
		httpError(w, r, `{"message":"constraint failed: start == previousIterEndTime for iteration 1"}`, http.StatusBadRequest)
		return
	}
	startTimestamp, _ := time.Parse(time.RFC3339, start)
	endTimestamp, _ := time.Parse(time.RFC3339, end)

	// Check if the timestamp falls within a valid Unix timestamp range
	if startTimestamp.Unix() < 0 || startTimestamp.Unix() > 1<<63-1 {
		httpError(w, r, `{"message":"Invalid Unix timestamp value"}`, http.StatusBadRequest)
		return
	}

	// Check if the timestamp falls within a valid Unix timestamp range
	if endTimestamp.Unix() < 0 || endTimestamp.Unix() > 1<<63-1 {
		httpError(w, r, `{"message":"Invalid Unix timestamp value"}`, http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()

	if now.Sub(startTimestamp) > 168*time.Hour {
		httpError(w, r, `{"message":"constraint failed: now - start <= 168h"}`, http.StatusBadRequest)
		return
	}
	if now.Sub(endTimestamp) <= 1*time.Minute {
		httpError(w, r, `{"message":"constraint failed: now - end > 1m"}`, http.StatusBadRequest)
		return
	}
	if startTimestamp.Sub(endTimestamp) >= 0 {
		httpError(w, r, `{"message":"constraint failed: start < end"}`, http.StatusBadRequest)
		return
	}
	if endTimestamp.Sub(startTimestamp) > 1*time.Hour {
		httpError(w, r, `{"message":"constraint failed: end - start <= 1h"}`, http.StatusBadRequest)
		return
	}

	// Simulate rolling responses every 2 second
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	logsWritten := 0
	var responses []string

	switch iteration {
	case 0:
		responses = responses_iter_0
	case 1:
		responses = responses_iter_1
	default:
		httpError(w, r, `{"message":"No more responses to send"}`, http.StatusInternalServerError)
		return
	}

	for {
		select {
		case <-r.Context().Done():
			log.Println("Client disconnected.")
			return
		case <-ticker.C:
			w.Write([]byte(responses[logsWritten]))
			w.(http.Flusher).Flush()
			logsWritten++
			if logsWritten >= len(responses) {
				log.Printf("%s - Stopping rolling updates after sending %d events for iteration %d.", r.RemoteAddr, logsWritten, iteration)
				// save end time for comparing with start time in next request
				previousIterEndTime = end
				// increment iteration count for next request
				iteration++
				return
			}
		}
	}
}

func httpError(w http.ResponseWriter, r *http.Request, error string, code int) {
	log.Printf("%s - WARN Returning %d: %s", r.RemoteAddr, code, error)
	http.Error(w, error, code)
}
