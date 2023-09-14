package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()
	router.Path("/client/v4/zones/aaabbbccc/logs/received").HandlerFunc(logpullHandler).Methods("GET").Schemes("http")

	port := 3000
	log.Printf("Server listening on port %d...\n", port)
	router.Use(mux.CORSMethodMiddleware(router))
	http.ListenAndServe(fmt.Sprintf(":%d", port), router)
}

// logpullHandler is a mock http handler that simulates the Cloudflare Logpull API.
func logpullHandler(w http.ResponseWriter, r *http.Request) {
	// set response headers to indicate rolling response
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	email := r.Header.Get("x-auth-email")
	key := r.Header.Get("x-auth-key")
	if email == "" || key == "" {
		http.Error(w, `{"message": "missing authentication credentials"}`, http.StatusUnauthorized)
		return
	}
	if email != "user@example.com" && key != "xxxxxxxxxx" {
		http.Error(w, `{"message": "invalid authentication credentials"}`, http.StatusUnauthorized)
		return
	}

	// get the timestamp value from the URL query parameter
	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")

	// check if the timestamp parameter is empty
	if start == "" || end == "" {
		http.Error(w, `{"message": "timestamp parameter is missing"}`, http.StatusBadRequest)
		return
	}

	startTimestamp, err := time.Parse(time.RFC3339, start)
	if err != nil {
		log.Println("error parsing start timestamp: ", err)
		http.Error(w, fmt.Sprintf(`{"message":"error parsing start timestamp: %v"}`, err), http.StatusBadRequest)
		return
	}
	endTimestamp, err := time.Parse(time.RFC3339, end)
	if err != nil {
		log.Println("error parsing end timestamp: ", err)
		http.Error(w, fmt.Sprintf(`{"message":"error parsing end timestamp: %v"}`, err), http.StatusBadRequest)
		return
	}

	// check if the timestamp falls within a valid Unix timestamp range
	if startTimestamp.Unix() < 0 || startTimestamp.Unix() > 1<<63-1 {
		log.Println("error validating start timestamp: ", startTimestamp)
		http.Error(w, `{"message":"invalid Unix timestamp value"}`, http.StatusBadRequest)
		return
	}

	// check if the timestamp falls within a valid Unix timestamp range
	if endTimestamp.Unix() < 0 || endTimestamp.Unix() > 1<<63-1 {
		log.Println("error validating end timestamp: ", endTimestamp)
		http.Error(w, `{"message":"invalid Unix timestamp value"}`, http.StatusBadRequest)
		return
	}

	// apply constraints on the timestamp values
	now := time.Now().UTC()
	if now.Sub(startTimestamp) > 168*time.Hour {
		http.Error(w, `{"message":"constraint failed: now - start <= 168h"}`, http.StatusBadRequest)
		return
	}
	if now.Sub(endTimestamp) <= 1*time.Minute {
		http.Error(w, `{"message":"constraint failed: now - end > 1m"}`, http.StatusBadRequest)
		return
	}
	if startTimestamp.Sub(endTimestamp) >= 0 {
		http.Error(w, `{"message":"constraint failed: start < end"}`, http.StatusBadRequest)
		return
	}
	if endTimestamp.Sub(startTimestamp) > 1*time.Hour {
		http.Error(w, `{"message":"constraint failed: end - start <= 1h"}`, http.StatusBadRequest)
		return
	}

	// we have a valid timestamp range, now return a rolling response
	responses := []string{
		`{"CacheCacheStatus":"unknown","CacheResponseBytes":0,"CacheResponseStatus":0,"CacheTieredFill":false,"ClientASN":15169,"ClientCountry":"us","ClientDeviceType":"desktop","ClientIP":"35.232.161.245","ClientIPClass":"noRecord","ClientRequestBytes":2577,"ClientRequestHost":"cf-analytics.com","ClientRequestMethod":"POST","ClientRequestPath":"/wp-cron.php","ClientRequestProtocol":"HTTP/1.1","ClientRequestReferer":"https://cf-analytics.com/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000","ClientRequestURI":"/wp-cron.php?doing_wp_cron=1564759748.3962020874023437500000","ClientRequestUserAgent":"WordPress/5.2.2;https://cf-analytics.com","ClientSSLCipher":"ECDHE-ECDSA-AES128-GCM-SHA256","ClientSSLProtocol":"TLSv1.2","ClientSrcPort":55028,"EdgeColoID":14,"EdgeEndTimestamp":"2019-08-02T15:29:08Z","EdgePathingOp":"wl","EdgePathingSrc":"filter_based_firewall","EdgePathingStatus":"captchaNew","EdgeRateLimitAction":"","EdgeRateLimitID":0,"EdgeRequestHost":"","EdgeResponseBytes":2848,"EdgeResponseCompressionRatio":2.64,"EdgeResponseContentType":"text/html","EdgeResponseStatus":403,"EdgeServerIP":"","EdgeStartTimestamp":"2019-08-02T15:29:08Z","FirewallMatchesActions":["simulate","challenge"],"FirewallMatchesSources":["firewallRules","firewallRules"],"FirewallMatchesRuleIDs":["094b71fea25d4860a61fa0c6fbbd8d8b","e454fd4a0ce546b3a9a462536613692c"],"OriginIP":"","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":0,"OriginResponseTime":0,"OriginSSLProtocol":"unknown","ParentRayID":"00","RayID":"500115ec386354d8","SecurityLevel":"med","WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"ZoneID":155978002}`,
		`{"CacheCacheStatus":"hit","CacheResponseBytes":26888,"CacheResponseStatus":200,"CacheTieredFill":true,"ClientASN":1136,"ClientCountry":"nl","ClientDeviceType":"desktop","ClientIP":"222.97.65.242","ClientIPClass":"noRecord","ClientRequestBytes":5324,"ClientRequestHost":"eqlplayground.io","ClientRequestMethod":"GET","ClientRequestPath":"/40865/bundles/plugin/securitySolution/8.0.0/securitySolution.chunk.9.js","ClientRequestProtocol":"HTTP/1.1","ClientRequestReferer":"https://eqlplayground.io/s/eqldemo/app/security/timelines/default?sourcerer=(default:!(.siem-signals-eqldemo))&timerange=(global:(linkTo:!(),timerange:(from:%272021-03-03T19:55:15.519Z%27,fromStr:now-24h,kind:relative,to:%272021-03-04T19:55:15.519Z%27,toStr:now)),timeline:(linkTo:!(),timerange:(from:%272020-03-04T19:55:28.684Z%27,fromStr:now-1y,kind:relative,to:%272021-03-04T19:55:28.692Z%27,toStr:now)))&timeline=(activeTab:eql,graphEventId:%27%27,id:%2769f93840-7d23-11eb-866c-79a0609409ba%27,isOpen:!t)","ClientRequestURI":"/40865/bundles/plugin/securitySolution/8.0.0/securitySolution.chunk.9.js","ClientRequestUserAgent":"Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/91.0.4472.124Safari/537.36","ClientSSLCipher":"NONE","ClientSSLProtocol":"none","ClientSrcPort":0,"ClientXRequestedWith":"","EdgeColoCode":"33.147.138.217","EdgeColoID":20,"EdgeEndTimestamp":1625752958875000000,"EdgePathingOp":"wl","EdgePathingSrc":"macro","EdgePathingStatus":"nr","EdgeRateLimitAction":"","EdgeRateLimitID":0,"EdgeRequestHost":"eqlplayground.io","EdgeResponseBytes":24743,"EdgeResponseCompressionRatio":0,"EdgeResponseContentType":"application/javascript","EdgeResponseStatus":200,"EdgeServerIP":"","EdgeStartTimestamp":1625752958812000000,"FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":0,"OriginResponseTime":0,"OriginSSLProtocol":"unknown","ParentRayID":"66b9d9f88b5b4c4f","RayID":"66b9d9f890ae4c4f","SecurityLevel":"off","WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":true,"WorkerSubrequestCount":0,"ZoneID":393347122}`,
		`{"CacheCacheStatus":"unknown","CacheResponseBytes":0,"CacheResponseStatus":0,"CacheTieredFill":false,"ClientASN":1136,"ClientCountry":"nl","ClientDeviceType":"desktop","ClientIP":"149.175.108.201","ClientIPClass":"noRecord","ClientRequestBytes":2520,"ClientRequestHost":"eqlplayground.io","ClientRequestMethod":"GET","ClientRequestPath":"/s/eqldemo/security/account","ClientRequestProtocol":"HTTP/2","ClientRequestReferer":"","ClientRequestURI":"/s/eqldemo/security/account","ClientRequestUserAgent":"Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/91.0.4472.124Safari/537.36","ClientSSLCipher":"AEAD-AES128-GCM-SHA256","ClientSSLProtocol":"TLSv1.3","ClientSrcPort":61593,"ClientXRequestedWith":"","EdgeColoCode":"AMS","EdgeColoID":20,"EdgeEndTimestamp":1625754264684000000,"EdgePathingOp":"ban","EdgePathingSrc":"filter_based_firewall","EdgePathingStatus":"nr","EdgeRateLimitAction":"","EdgeRateLimitID":0,"EdgeRequestHost":"183.53.30.34","EdgeResponseBytes":2066,"EdgeResponseCompressionRatio":2.45,"EdgeResponseContentType":"text/html","EdgeResponseStatus":403,"EdgeServerIP":"","EdgeStartTimestamp":1625754264676000000,"FirewallMatchesActions":["block"],"FirewallMatchesRuleIDs":["391eb601201e4f2a81038910f2b63f6d"],"FirewallMatchesSources":["firewallRules"],"OriginIP":"","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":0,"OriginResponseTime":0,"OriginSSLProtocol":"unknown","ParentRayID":"00","RayID":"66b9f9da396e4c01","SecurityLevel":"unk","WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"ZoneID":393347122}`,
	}

	// simulate rolling responses every second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	requestCount := 0

	// we only want to send 3 responses since we assert hit_count for 3 requests
	for {
		select {
		case <-r.Context().Done():
			log.Println("client disconnected.")
			return
		case <-ticker.C:
			if requestCount <= 2 {
				fmt.Fprintf(w, responses[requestCount])
				w.(http.Flusher).Flush()
				requestCount++
			} else {
				log.Printf("stopping rolling updates at request_count: %d", requestCount)
				return
			}
		}
	}
}
