package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// API response data types and helpers
////////////////////////////////////////////////////////////////////////////////

type tokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	ExtExpiresIn int64  `json:"ext_expires_in"`
	AccessToken  string `json:"access_token"`
}

type refreshTokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
}

func subscriptionEnabledResponse(contentType string) map[string]any {
	return map[string]any{
		"contentType": contentType,
		"status":      "enabled",
	}
}

var subscriptionAlreadyEnabledResponse = map[string]any{
	"error": map[string]any{
		"code":    "AF20024",
		"message": "The subscription is already enabled. No property change.",
	},
}

type listItem struct {
	ContentType       string    `json:"contentType"`
	ContentId         string    `json:"contentId"`
	ContentUri        string    `json:"contentUri"`
	ContentCreated    time.Time `json:"contentCreated"`
	ContentExpiration time.Time `json:"contentExpiration"`
}

type fetchItem map[string]any

func makeListItems(cfg *config, run *run, contentType string, minN, maxN int, minTime, maxTime string) []listItem {
	numMaybe := maxN - minN
	numItems := minN + run.randomSource.Intn(numMaybe+1)

	maxTimeDuration, err := time.ParseDuration(maxTime)
	if err != nil {
		panic(err)
	}
	minTimeDuration, err := time.ParseDuration(minTime)
	if err != nil {
		panic(err)
	}
	possibleRange := maxTimeDuration - minTimeDuration

	result := make([]listItem, numItems)
	for i := range numItems {
		timeOffset := minTimeDuration + time.Duration(run.randomSource.Int63n(int64(possibleRange)+1))
		result[i] = makeListItem(cfg, run, contentType, timeOffset.String(), "")
	}
	return result
}

func makeListItem(cfg *config, run *run, contentType, timeOffset string, expirationOverride string) listItem {
	timeOffsetDuration, err := time.ParseDuration(timeOffset)
	if err != nil {
		panic(err)
	}

	contentCreated := run.startTime.Add(timeOffsetDuration)
	contentExpiration := contentCreated.Add(time.Hour * 24 * 7)

	if expirationOverride != "" {
		expirationOverrideDuration, err := time.ParseDuration(expirationOverride)
		if err != nil {
			panic(err)
		}
		contentExpiration = run.startTime.Add(expirationOverrideDuration)
	}

	contentId := randomString(run, 12)
	contentUri := fmt.Sprintf("http://%s/api/v1.0/%s/activity/feed/audit/%s", cfg.addr, cfg.tenantId, contentId)

	return listItem{
		contentType,
		contentId,
		contentUri,
		contentCreated,
		contentExpiration,
	}
}

func makeFetchItems(cfg *config, run *run) []fetchItem {
	numMaybe := cfg.scenario.maxFetchItems - cfg.scenario.minFetchItems
	numItems := cfg.scenario.minFetchItems + run.randomSource.Intn(numMaybe+1)
	result := make([]fetchItem, numItems)
	for i := range numItems {
		if cfg.scenario.fullFetchItemsFromPool {
			result[i] = cfg.fetchItemPool[run.fetchItemPoolIndex]
			run.fetchItemPoolIndex = (run.fetchItemPoolIndex + 1) % len(cfg.fetchItemPool)
		} else {
			result[i] = fetchItem{}
		}
		result[i]["CreationTime"] = randomTime(run, 8*24*time.Hour).Format("2006-01-02T15:04:05")
		result[i]["Id"] = randomString(run, 12)
	}
	if cfg.scenario.duplicateItemInEachFetch {
		return slices.Concat(result, []fetchItem{result[len(result)-1]})
	}
	return result
}

////////////////////////////////////////////////////////////////////////////////
// Fetch item pool - Real data that can be cycled through for responses.
//                   (CreationTime and Id will be overridden with random values)
////////////////////////////////////////////////////////////////////////////////

var fetchItemPool = []fetchItem{
	{
		"ClientIP":         "213.97.47.133",
		"CorrelationId":    "622b339f-4000-a000-f25f-92b3478c7a25",
		"CreationTime":     "2020-02-07T16:43:53",
		"CustomUniqueId":   true,
		"EventSource":      "SharePoint",
		"Id":               "99d005e6-a4c6-46fd-117c-08d7abeceab5",
		"ItemType":         "Page",
		"ListItemUniqueId": "59a8433d-9bb8-cfef-6edc-4c0fc8b86875",
		"ObjectId":         "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/_layouts/15/onedrive.aspx",
		"Operation":        "PageViewed",
		"OrganizationId":   "b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd",
		"RecordType":       4,
		"Site":             "d5180cfc-3479-44d6-b410-8c985ac894e3",
		"UserAgent":        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0",
		"UserId":           "asr@testsiem.onmicrosoft.com",
		"UserKey":          "i:0h.f|membership|1003200096971f55@live.com",
		"UserType":         0,
		"Version":          1,
		"WebId":            "8c5c94bb-8396-470c-87d7-8999f440cd30",
		"Workload":         "OneDrive",
	},
	{
		"ClientIP":         "213.97.47.133",
		"CorrelationId":    "622b339f-4000-a000-f25f-92b3478c7a25",
		"CreationTime":     "2020-02-07T16:43:53",
		"CustomUniqueId":   true,
		"EventSource":      "SharePoint",
		"Id":               "99d005e6-a4c6-46fd-117c-08d7abeceab5",
		"ItemType":         "Page",
		"ListItemUniqueId": "59a8433d-9bb8-cfef-6edc-4c0fc8b86875",
		"ObjectId":         "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/_layouts/15/onedrive.aspx",
		"Operation":        "PageViewed",
		"OrganizationId":   "b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd",
		"RecordType":       4,
		"Site":             "d5180cfc-3479-44d6-b410-8c985ac894e3",
		"UserAgent":        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0",
		"UserId":           "asr@testsiem.onmicrosoft.com",
		"UserKey":          "i:0h.f|membership|1003200096971f55@live.com",
		"UserType":         0,
		"Version":          1,
		"WebId":            "8c5c94bb-8396-470c-87d7-8999f440cd30",
		"Workload":         "OneDrive",
	},
	{
		"ClientIP":            "213.97.47.133",
		"CorrelationId":       "692b339f-902e-a000-f25f-95def5f17903",
		"CreationTime":        "2020-02-07T16:44:23",
		"EventSource":         "SharePoint",
		"Id":                  "5b02fadb-8eac-4aff-af87-08d7abecfca3",
		"ItemType":            "File",
		"ListId":              "2b6ad2bd-0fd7-4556-9c89-a97847085b85",
		"ListItemUniqueId":    "7f06ab3a-bd98-41d3-a0b2-ad270d71e4d8",
		"ObjectId":            "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/Documents/Screenshot.png",
		"Operation":           "FileModified",
		"OrganizationId":      "b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd",
		"RecordType":          6,
		"Site":                "d5180cfc-3479-44d6-b410-8c985ac894e3",
		"SiteUrl":             "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/",
		"SourceFileExtension": "png",
		"SourceFileName":      "Screenshot.png",
		"SourceRelativeUrl":   "Documents",
		"UserAgent":           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0",
		"UserId":              "asr@testsiem.onmicrosoft.com",
		"UserKey":             "i:0h.f|membership|1003200096971f55@live.com",
		"UserType":            0,
		"Version":             1,
		"WebId":               "8c5c94bb-8396-470c-87d7-8999f440cd30",
		"Workload":            "OneDrive",
	},
	{
		"ClientIP":            "213.97.47.133",
		"CorrelationId":       "652b339f-908c-a000-f25f-91423da7dd9b",
		"CreationTime":        "2020-02-07T16:44:07",
		"EventSource":         "SharePoint",
		"Id":                  "ec04aa09-0a43-4879-cdc8-08d7abecf327",
		"ItemType":            "File",
		"ListId":              "2b6ad2bd-0fd7-4556-9c89-a97847085b85",
		"ListItemUniqueId":    "4803608a-df7d-4f63-aa73-67aa33bb576e",
		"ObjectId":            "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/Documents/Screenshot 2020-01-27 at 11.30.48.png",
		"Operation":           "FileDeleted",
		"OrganizationId":      "b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd",
		"RecordType":          6,
		"Site":                "d5180cfc-3479-44d6-b410-8c985ac894e3",
		"SiteUrl":             "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/",
		"SourceFileExtension": "png",
		"SourceFileName":      "Screenshot 2020-01-27 at 11.30.48.png",
		"SourceRelativeUrl":   "Documents",
		"UserAgent":           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0",
		"UserId":              "asr@testsiem.onmicrosoft.com",
		"UserKey":             "i:0h.f|membership|1003200096971f55@live.com",
		"UserType":            0,
		"Version":             1,
		"WebId":               "8c5c94bb-8396-470c-87d7-8999f440cd30",
		"Workload":            "OneDrive",
	},
	{
		"ClientIP":              "79.159.10.151",
		"CorrelationId":         "fe71359f-005f-9000-7cb1-ccf5124703db",
		"CreationTime":          "2020-02-14T18:25:44",
		"EventData":             "<Permissions granted>System.LimitedEdit</Permissions granted>",
		"EventSource":           "SharePoint",
		"Id":                    "98633e47-3540-4e8a-bcfc-08d7b17b4e48",
		"ItemType":              "File",
		"ListId":                "2b6ad2bd-0fd7-4556-9c89-a97847085b85",
		"ListItemUniqueId":      "7f06ab3a-bd98-41d3-a0b2-ad270d71e4d8",
		"ObjectId":              "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/Documents/Screenshot.png",
		"Operation":             "SharingSet",
		"OrganizationId":        "b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd",
		"RecordType":            14,
		"Site":                  "d5180cfc-3479-44d6-b410-8c985ac894e3",
		"SiteUrl":               "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com",
		"SourceFileExtension":   "png",
		"SourceFileName":        "Screenshot.png",
		"SourceRelativeUrl":     "Documents/Screenshot.png",
		"TargetUserOrGroupName": "4da1e7f54501bb99b6e0ab2ff8749842152ac02ff8c0c8017b0e40e6b67fecdd",
		"TargetUserOrGroupType": "SecurityGroup",
		"UserAgent":             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:73.0) Gecko/20100101 Firefox/73.0",
		"UserId":                "asr@testsiem.onmicrosoft.com",
		"UserKey":               "i:0h.f|membership|1003200096971f55@live.com",
		"UserType":              0,
		"Version":               1,
		"WebId":                 "8c5c94bb-8396-470c-87d7-8999f440cd30",
		"Workload":              "OneDrive",
	},
	{
		"ClientIP":            "213.97.47.133",
		"CorrelationId":       "652b339f-908c-a000-f25f-91423da7dd9b",
		"CreationTime":        "2020-02-07T16:44:07",
		"EventSource":         "SharePoint",
		"Id":                  "dc04ab19-0b43-4g79-cdc8-08d7abecf317",
		"ItemType":            "File",
		"ListId":              "2b6ad2be-0ed7-4556-9c89-a97847085b85",
		"ListItemUniqueId":    "4803608a-df7d-4f63-aa73-67aa33bb576e",
		"ObjectId":            "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/Documents/Screenshot 2020-01-27 at 12.30.48.png",
		"Operation":           "FileDeleted",
		"OrganizationId":      "b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd",
		"RecordType":          6,
		"Site":                "d5180cfc-3479-44d6-b410-8c985ac894e3",
		"SiteUrl":             "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/",
		"SourceFileExtension": "png",
		"SourceFileName":      "Screenshot 2020-01-27 at 112.30.48.png",
		"SourceRelativeUrl":   "Documents",
		"UserAgent":           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0",
		"UserId":              "asr@testsiem.onmicrosoft.com",
		"UserKey":             "i:0h.f|membership|1003200096971f55@live.com",
		"UserType":            0,
		"Version":             1,
		"WebId":               "8c5c94bb-8396-470c-87d7-8999f440cd30",
		"Workload":            "OneDrive",
	},
	{
		"ClientIP":              "79.159.10.151",
		"CorrelationId":         "fe71359f-005f-9000-7cb1-ccf5124703db",
		"CreationTime":          "2020-02-14T18:25:44",
		"EventData":             "<Permissions granted>System.LimitedEdit</Permissions granted>",
		"EventSource":           "SharePoint",
		"Id":                    "90633f47-25f0-4e8a-bcfc-08d7b17b4e60",
		"ItemType":              "File",
		"ListId":                "2b6ad2bd-0fd7-4556-9c89-a97847085b85",
		"ListItemUniqueId":      "7f06ab3a-bd98-41d3-a0b2-ad270d71e4d8",
		"ObjectId":              "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com/Documents/Screenshot1234.png",
		"Operation":             "SharingSet",
		"OrganizationId":        "b86ab9d4-fcf1-4b11-8a06-7a8f91b47fbd",
		"RecordType":            14,
		"Site":                  "d5180cfc-3479-44d6-b410-8c985ac894e3",
		"SiteUrl":               "https://testsiem-my.sharepoint.com/personal/asr_testsiem_onmicrosoft_com",
		"SourceFileExtension":   "png",
		"SourceFileName":        "Screenshot1234.png",
		"SourceRelativeUrl":     "Documents/Screenshot1234.png",
		"TargetUserOrGroupName": "4da1e7f54501bb99b6e0ab2ff8749842152ac02ff8c0c8017b0e40e6b67fecdd",
		"TargetUserOrGroupType": "SecurityGroup",
		"UserAgent":             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:73.0) Gecko/20100101 Firefox/73.0",
		"UserId":                "asr@testsiem.onmicrosoft.com",
		"UserKey":               "i:0h.f|membership|1003200096971f55@live.com",
		"UserType":              0,
		"Version":               1,
		"WebId":                 "8c5c94bb-8396-470c-87d7-8999f440cd30",
		"Workload":              "OneDrive",
	},
	{
		"ActorUserId":       "alice@testsiem2.onmicrosoft.com",
		"ActorYammerUserId": 36787265537,
		"ClientIP":          "79.159.10.151:12345",
		"CreationTime":      "2020-02-28T09:42:45",
		"GroupName":         "Sales",
		"Id":                "2af7bbf1-d5d8-5cb0-8aca-f4ad8a087594",
		"ObjectId":          "Sales",
		"Operation":         "GroupCreation",
		"OrganizationId":    "0e1dddce-163e-4b0b-9e33-87ba56ac4655",
		"RecordType":        22,
		"ResultStatus":      "TRUE",
		"UserId":            "alice@testsiem2.onmicrosoft.com",
		"UserKey":           "100320009d6edf94",
		"UserType":          0,
		"Version":           1,
		"Workload":          "Yammer",
		"YammerNetworkId":   5846122497,
	},
	{
		"ActorUserId":       "asr@testsiem2.onmicrosoft.com",
		"ActorYammerUserId": 36085768193,
		"ClientIP":          "[fdfd::555]:12346",
		"CreationTime":      "2020-02-28T09:39:20",
		"GroupName":         "Company group",
		"Id":                "3f3e7f1c-84c1-55fc-9bb2-c8b8563eae06",
		"ObjectId":          "Company group",
		"Operation":         "GroupCreation",
		"OrganizationId":    "0e1dddce-163e-4b0b-9e33-87ba56ac4655",
		"RecordType":        22,
		"ResultStatus":      "TRUE",
		"UserId":            "asr@testsiem2.onmicrosoft.com",
		"UserKey":           "100320009d292e16",
		"UserType":          0,
		"Version":           1,
		"Workload":          "Yammer",
		"YammerNetworkId":   5846122497,
	},
}

////////////////////////////////////////////////////////////////////////////////
// Config types
////////////////////////////////////////////////////////////////////////////////

type config struct {
	addr                        string
	tenantId                    string
	clientId                    string
	clientSecret                string
	refreshToken                string
	accessToken                 string
	fetchItemPool               []fetchItem
	scenario                    scenario
	genericRequstLogging        bool
	maxGap                      time.Duration
	maxListingRange             time.Duration
	checkTenantId               bool
	checkCredentials            bool
	checkAccessToken            bool
	checkSubscribedBeforeListed bool
}

type scenario struct {
	itemsByType              map[string][]listItem
	unauthorizedType         string
	pageLimit                int
	shuffleInPages           bool
	minFetchItems            int
	maxFetchItems            int
	fullFetchItemsFromPool   bool
	duplicateItemInEachFetch bool
}

////////////////////////////////////////////////////////////////////////////////
// Run state type
////////////////////////////////////////////////////////////////////////////////

type run struct {
	startTime                       time.Time
	randomSource                    *rand.Rand
	servedListItemsFetchCount       map[string]int
	servedFetchItemsCount           int
	servedUniqueFetchItemsCount     int
	servedItemsExpiry               map[string]time.Time
	servedNextPageQueryRequestCount map[string]int
	minStartByType                  map[string]time.Time
	maxEndByType                    map[string]time.Time
	maxContentCreatedByType         map[string]time.Time
	subscriptionsByType             map[string]int
	fetchItemPoolIndex              int
}

////////////////////////////////////////////////////////////////////////////////
// Main - Initialize the run state and config, start the server.
//        Scenarios are defined here. The requested one is added to the config.
////////////////////////////////////////////////////////////////////////////////

func main() {
	log := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)

	if len(os.Args) < 2 {
		log.Printf("Usage: go run o365mock.go SCENARIONAME [SEED]")
		os.Exit(1)
	}

	var run = run{
		startTime:                       time.Now().UTC(),
		servedListItemsFetchCount:       map[string]int{},
		servedItemsExpiry:               map[string]time.Time{},
		servedNextPageQueryRequestCount: map[string]int{},
		minStartByType:                  map[string]time.Time{},
		maxEndByType:                    map[string]time.Time{},
		maxContentCreatedByType:         map[string]time.Time{},
		subscriptionsByType:             map[string]int{},
	}

	var seed int64
	if len(os.Args) == 3 {
		var err error
		seed, err = strconv.ParseInt(os.Args[2], 10, 64)
		if err != nil {
			log.Printf("ERROR: Couldn't parse seed value '%s'!", os.Args[2])
			os.Exit(1)
		}
	}
	if seed == 0 {
		seed = run.startTime.UnixNano()
	}
	run.randomSource = rand.New(rand.NewSource(seed))

	port := "9999"
	envPort := os.Getenv("PORT")
	if envPort != "" {
		port = envPort
	}

	cfg := config{
		addr:                        "0.0.0.0:" + port,
		tenantId:                    "test-cel-tenant-id",
		clientId:                    "test-cel-client-id",
		clientSecret:                "test-cel-client-secret",
		refreshToken:                "refresh_token_123",
		accessToken:                 "someaccesstoken",
		fetchItemPool:               fetchItemPool,
		genericRequstLogging:        false,
		maxGap:                      0 * time.Millisecond,
		maxListingRange:             time.Hour + time.Millisecond,
		checkTenantId:               true,
		checkCredentials:            true,
		checkAccessToken:            true,
		checkSubscribedBeforeListed: true,
	}
	scenarios := map[string]scenario{
		"cel-bad-creds": {
			itemsByType: map[string][]listItem{
				"Audit.General": []listItem{
					makeListItem(&cfg, &run, "Audit.AzureActiveDirectory", "-1h", ""),
				},
			},
			unauthorizedType:       "Audit.TypeRequiringAdditionalPermissions",
			fullFetchItemsFromPool: true,
			pageLimit:              3,
			minFetchItems:          1,
			maxFetchItems:          1,
		},
		"cel": {
			itemsByType: map[string][]listItem{
				"Audit.SharePoint": sortListItems(
					makeListItems(&cfg, &run, "Audit.SharePoint", 5, 5, "-11h", "0h"),
				),
				"Audit.General": sortListItems(
					makeListItems(&cfg, &run, "Audit.General", 5, 5, "-11h", "0h"),
				),
			},
			fullFetchItemsFromPool:   true,
			duplicateItemInEachFetch: true,
			shuffleInPages:           true,
			pageLimit:                3,
			minFetchItems:            3,
			maxFetchItems:            3,
		},
		"bit_of_recent_data": {
			itemsByType: map[string][]listItem{
				"Audit.AzureActiveDirectory": sortListItems([]listItem{
					makeListItem(&cfg, &run, "Audit.AzureActiveDirectory", "-007h55m", ""),
					makeListItem(&cfg, &run, "Audit.AzureActiveDirectory", "-007h35m", ""),
					makeListItem(&cfg, &run, "Audit.AzureActiveDirectory", "-004h35m", ""),
					makeListItem(&cfg, &run, "Audit.AzureActiveDirectory", "-004h55m", ""),
				}),
			},
			unauthorizedType:         "Audit.NoPermissions",
			fullFetchItemsFromPool:   false,
			duplicateItemInEachFetch: false,
			shuffleInPages:           false,
			pageLimit:                math.MaxInt,
			minFetchItems:            1,
			maxFetchItems:            5,
		},
		"2_types_random_250_to_500_last_12h_pages_of_20": {
			itemsByType: map[string][]listItem{
				"Audit.AzureActiveDirectory": sortListItems(
					makeListItems(&cfg, &run, "Audit.AzureActiveDirectory", 250, 500, "-12h", "0h"),
				),
				"Audit.Exchange": sortListItems(
					makeListItems(&cfg, &run, "Audit.Exchange", 250, 500, "-12h", "0h"),
				),
			},
			fullFetchItemsFromPool:   true,
			duplicateItemInEachFetch: false,
			shuffleInPages:           false,
			pageLimit:                20,
			minFetchItems:            1,
			maxFetchItems:            5,
		},
		"chunks_with_gaps_and_1_expired": {
			itemsByType: map[string][]listItem{
				"Audit.AzureActiveDirectory": sortListItems(slices.Concat(
					makeListItems(&cfg, &run, "Audit.AzureActiveDirectory", 100, 200, "-11h", "-9h"),
					makeListItems(&cfg, &run, "Audit.AzureActiveDirectory", 100, 200, "-4h", "-2h"),
					[]listItem{makeListItem(&cfg, &run, "Audit.AzureActiveDirectory", "-1h15m", "-1h")}, // expired 15 mins after creation
					makeListItems(&cfg, &run, "Audit.AzureActiveDirectory", 100, 200, "-55m", "-30m"),
				)),
				"Audit.Exchange": sortListItems(slices.Concat(
					makeListItems(&cfg, &run, "Audit.Exchange", 100, 200, "-10h", "-5h55m"),
					makeListItems(&cfg, &run, "Audit.Exchange", 100, 200, "-5h30m", "-4h"),
					makeListItems(&cfg, &run, "Audit.Exchange", 100, 200, "-1h55m", "-1h5m"),
				)),
			},
			fullFetchItemsFromPool:   true,
			duplicateItemInEachFetch: true,
			shuffleInPages:           true,
			pageLimit:                20,
			minFetchItems:            1,
			maxFetchItems:            5,
		},
	}

	scenarioName := os.Args[1]
	if _, ok := scenarios[scenarioName]; !ok {
		names := make([]string, 0, len(scenarios))
		for name := range scenarios {
			names = append(names, name)
		}
		log.Printf("ERROR: Scenario '%s' not found! Available scenarios: %s", scenarioName, strings.Join(names, ", "))
		os.Exit(1)
	}
	cfg.scenario = scenarios[scenarioName]

	rerunCmd := "PORT=" + port + " go run o365mock.go " + scenarioName + " " + strconv.FormatInt(seed, 10)
	log.Printf("RunStart StartTime=%s, scenarioName=%s, seed=%d, Addr=%s, rerun: '%s'",
		run.startTime.Format(time.RFC3339Nano),
		scenarioName,
		seed,
		cfg.addr,
		rerunCmd,
	)

	s := newServer(&cfg, &run, log)
	s.doRun()
}

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous helpers
////////////////////////////////////////////////////////////////////////////////

func sortListItems(slice []listItem) []listItem {
	slices.SortFunc(slice, func(a, b listItem) int {
		return int(a.ContentCreated.Sub(b.ContentCreated))
	})
	return slice
}

func shuffleListItems(run *run, slice []listItem) []listItem {
	run.randomSource.Shuffle(len(slice), func(i, j int) {
		slice[i], slice[j] = slice[j], slice[i]
	})
	return slice
}

func randomString(run *run, n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[run.randomSource.Intn(len(letters))]
	}
	return string(b)
}

func randomTime(run *run, inLast time.Duration) time.Time {
	randNanos := run.randomSource.Int63n(int64(inLast.Nanoseconds()))
	return run.startTime.Add(-time.Duration(randNanos))
}

////////////////////////////////////////////////////////////////////////////////
// Server
////////////////////////////////////////////////////////////////////////////////

type server struct {
	mux    *http.ServeMux
	log    *log.Logger
	addr   string
	server *http.Server
	cfg    *config
	run    *run
}

func newServer(cfg *config, run *run, logger *log.Logger) *server {
	if logger == nil {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}
	mux := http.NewServeMux()
	s := &server{
		mux:  mux,
		log:  logger,
		addr: cfg.addr,
		run:  run,
		cfg:  cfg,
	}
	s.routes()
	s.server = &http.Server{
		Addr:         cfg.addr,
		Handler:      s.logRequests(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s
}

func (s *server) doRun() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		err := s.server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			errCh <- nil
			return
		}
		errCh <- err
	}()

	select {
	case sig := <-sigCh:
		s.log.Printf("received signal %v, shutting down", sig)
	case err := <-errCh:
		s.log.Printf("server error: %v", err)
	}

	_ = s.server.Shutdown(context.Background())
	s.shutdownReport()
}

func (s *server) routes() {
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("POST /{tenantId}/oauth2/v2.0/token", s.handleToken)
	s.mux.HandleFunc("POST /api/v1.0/{tenantId}/activity/feed/subscriptions/start", s.handleSubscribe)
	s.mux.HandleFunc("GET /api/v1.0/{tenantId}/activity/feed/subscriptions/content", s.handleList)
	s.mux.HandleFunc("GET /api/v1.0/{tenantId}/activity/feed/audit/{contentId}", s.handleFetch)
}

func (s *server) shutdownReport() {
	s.log.Printf("RunStop %s", time.Now().UTC().Format(time.RFC3339Nano))

	// subscribing
	for contentType := range s.cfg.scenario.itemsByType {
		s.log.Printf("Report subscriptions for content type %s: %d",
			contentType,
			s.run.subscriptionsByType[contentType],
		)
	}

	// requesting ranges (based on initial page of each range)
	for contentType := range s.cfg.scenario.itemsByType {
		s.log.Printf("Report requested range spans [%s--%s] for %s",
			s.run.minStartByType[contentType].Format(time.RFC3339Nano),
			s.run.maxEndByType[contentType].Format(time.RFC3339Nano),
			contentType,
		)
	}

	// served max times
	for contentType := range s.cfg.scenario.itemsByType {
		s.log.Printf("Report max contentCreated value %s for %s",
			s.run.maxContentCreatedByType[contentType].Format(time.RFC3339Nano),
			contentType,
		)
	}

	// requesting next pages
	var nextPageRequestedOnce, nextPageRequestedRepeatedly, nextPageRequestedNever int
	for _, count := range s.run.servedNextPageQueryRequestCount {
		switch count {
		case 0:
			nextPageRequestedNever++
		case 1:
			nextPageRequestedOnce++
		default:
			nextPageRequestedRepeatedly++
		}
	}
	s.log.Printf("Report served NextPageUri requested never: %d", nextPageRequestedNever)
	s.log.Printf("Report served NextPageUri requested once: %d", nextPageRequestedOnce)
	s.log.Printf("Report served NextPageUri requested repeatedly: %d", nextPageRequestedRepeatedly)

	// fetching content
	var fetchedOnce, fetchedRepeatedly, fetchedNever int
	for _, count := range s.run.servedListItemsFetchCount {
		switch count {
		case 0:
			fetchedNever++
		case 1:
			fetchedOnce++
		default:
			fetchedRepeatedly++
		}
	}
	s.log.Printf("Report served and fetched never %d (e.g. if already expired)", fetchedNever)
	s.log.Printf("Report served and fetched once: %d", fetchedOnce)
	s.log.Printf("Report served and fetched repeatedly: %d", fetchedRepeatedly)

	s.log.Printf("Report served fetch items (events): %d", s.run.servedFetchItemsCount)
	s.log.Printf("Report served unique fetch items (events): %d", s.run.servedUniqueFetchItemsCount)
}

func (s *server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.genericRequstLogging {
			s.log.Printf("Request %s %s", r.Method, r.URL)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	tenantId := r.PathValue("tenantId")
	authorization := r.Header.Get("Authorization")
	contentType := r.Header.Get("Content-Type")

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	scope := r.FormValue("scope")
	refreshToken := r.FormValue("refresh_token")

	s.log.Printf("Token tenantId=%s, Authorization=%s, Content-Type=%s, grant_type=%s, scope=%s, refresh_token=%s",
		tenantId,
		authorization,
		contentType,
		grantType,
		scope,
		refreshToken,
	)
	if s.cfg.checkTenantId && tenantId != s.cfg.tenantId {
		s.log.Printf("ERROR received tenantId %s does not match expected %s", tenantId, s.cfg.tenantId)
	}
	if s.cfg.checkCredentials {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authorization, "Basic "))
		if err != nil {
			s.log.Printf("ERROR could not decode Authorization header value '%s'", authorization)
			http.Error(w, "bad authorization header value", http.StatusBadRequest)
			return
		}
		if string(decoded) != s.cfg.clientId+":"+s.cfg.clientSecret {
			s.log.Printf("ERROR Incorrect Authorization header value for token request")
			http.Error(w, "bad credentials in authorization header", http.StatusBadRequest)
			return
		}
		if grantType == "refresh_token" && refreshToken != s.cfg.refreshToken {
			s.log.Printf("ERROR Incorrect refresh token value for token request")
			http.Error(w, "bad refresh token value for grant type refresh_token", http.StatusBadRequest)
			return
		}
	}
	if grantType == "refresh_token" {
		s.writeJSON(w, http.StatusOK, refreshTokenResponse{
			TokenType:    "Bearer",
			ExpiresIn:    3599,
			AccessToken:  s.cfg.accessToken,
			Scope:        scope,
			RefreshToken: "somerefreshtokenvalue...",
			IdToken:      "someidtokenvalue...",
		})
		return
	}
	s.writeJSON(w, http.StatusOK, tokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3599,
		ExtExpiresIn: 3599,
		AccessToken:  s.cfg.accessToken,
	})
}

func (s *server) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	tenantId := r.PathValue("tenantId")
	q := r.URL.Query()
	contentType := q.Get("contentType")
	var respStatus int
	var respBody map[string]any
	if s.run.randomSource.Intn(2) == 0 {
		respStatus = http.StatusOK
		respBody = subscriptionEnabledResponse(contentType)
	} else {
		respStatus = http.StatusBadRequest
		respBody = subscriptionAlreadyEnabledResponse
	}

	if s.cfg.scenario.unauthorizedType != "" && contentType == s.cfg.scenario.unauthorizedType {
		respStatus = http.StatusUnauthorized
		w.WriteHeader(respStatus)
		s.log.Printf("Subscribe %s, result %d (that type was configured as unauthorized in the scenario)", contentType, respStatus)
		return
	}
	if _, ok := s.cfg.scenario.itemsByType[contentType]; !ok {
		s.log.Printf("ERROR attempted to subscribe to unknown content type %s", contentType)
		http.NotFound(w, r)
		return
	}
	s.run.subscriptionsByType[contentType]++

	s.log.Printf("Subscribe %s, result %d",
		contentType,
		respStatus,
	)
	if s.cfg.checkTenantId && tenantId != s.cfg.tenantId {
		s.log.Printf("ERROR received tenantId %s does not match expected %s", tenantId, s.cfg.tenantId)
	}
	if authorization := r.Header.Get("Authorization"); s.cfg.checkAccessToken && authorization != "Bearer "+s.cfg.accessToken {
		s.log.Printf("ERROR received Authorization header '%s' does not match expected '%s'",
			authorization,
			"Bearer "+s.cfg.accessToken,
		)
	}
	s.writeJSON(w, respStatus, respBody)
}

func (s *server) handleList(w http.ResponseWriter, r *http.Request) {
	tenantId := r.PathValue("tenantId")
	q := r.URL.Query()
	publisherIdentifier := q.Get("PublisherIdentifier")
	contentType := q.Get("contentType")
	startTime, err := time.Parse(time.RFC3339Nano, q.Get("startTime"))
	if err != nil {
		panic(err)
	}
	endTimeStr := q.Get("endTime")
	if endTimeStr == "" {
		endTimeStr = q.Get("endtime")
	}
	endTime, err := time.Parse(time.RFC3339Nano, endTimeStr)
	if err != nil {
		panic(err)
	}
	nextPage := q.Get("nextPage")
	numSeen, err := strconv.Atoi(nextPage)
	if err != nil {
		numSeen = 0
	}

	items, ok := s.cfg.scenario.itemsByType[contentType]
	if !ok {
		s.log.Printf("ERROR requested unknown content type %s", contentType)
		s.writeJSON(w, http.StatusNotFound, nil)
		return
	}

	inRange := []listItem{}
	for _, item := range items {
		if (item.ContentCreated.Equal(startTime) || item.ContentCreated.After(startTime)) &&
			item.ContentCreated.Before(endTime) && item.ContentCreated.Before(time.Now().UTC()) {
			inRange = append(inRange, item)
		}
	}

	skip := min(numSeen, len(inRange))
	n := min(s.cfg.scenario.pageLimit, len(inRange)-skip)
	newNumSeen := skip + n
	inPage := inRange[skip:newNumSeen]
	numRest := len(inRange) - skip - n

	if s.cfg.scenario.shuffleInPages {
		shuffleListItems(s.run, inPage)
	}

	s.log.Printf("List %s [%s--%s] (%s) nextPage=%s, returning %d, remaining %d",
		contentType,
		startTime.Format(time.RFC3339Nano),
		endTime.Format(time.RFC3339Nano),
		(endTime.Sub(startTime)).String(),
		nextPage,
		len(inPage),
		numRest,
	)

	if nextPage != "" {
		// asking for a next page
		qEncoded := q.Encode()
		if _, ok := s.run.servedNextPageQueryRequestCount[qEncoded]; !ok {
			s.log.Printf("ERROR asked for an unknown next page: %s", qEncoded)
		} else {
			s.run.servedNextPageQueryRequestCount[qEncoded]++
		}
	}

	// make NextPageUri if necessary
	if numRest > 0 {
		nextPageURL := *r.URL
		nextPageQ := nextPageURL.Query()
		nextPageQ.Set("nextPage", strconv.Itoa(newNumSeen))
		// randomly downcase endTime param
		if s.run.randomSource.Intn(2) == 0 {
			endTime := nextPageQ.Get("endTime")
			if endTime != "" {
				nextPageQ.Set("endtime", nextPageQ.Get("endTime"))
				nextPageQ.Del("endTime")
			}
		}
		nextPageURL.RawQuery = nextPageQ.Encode()
		nextPageURLFull := "http://" + r.Host + nextPageURL.RequestURI()
		// force the non-canonical header name by avoiding http.Header.Set()
		w.Header()["NextPageUri"] = []string{nextPageURLFull}
		if _, ok := s.run.servedNextPageQueryRequestCount[nextPageURL.RawQuery]; ok {
			s.log.Printf("ERROR already served NextPageUri: %s", nextPageURL.RawQuery)
		} else {
			s.run.servedNextPageQueryRequestCount[nextPageURL.RawQuery] = 0
		}
	}
	// make sure the host/port matches the incoming request
	for i := range inPage {
		inPage[i].ContentUri = strings.Replace(inPage[i].ContentUri, s.cfg.addr, r.Host, 1)
	}

	// check it's not asking for too much
	listingRange := endTime.Sub(startTime)
	if listingRange > s.cfg.maxListingRange {
		s.log.Printf("ERROR listing range of %s exceeds max of %s", listingRange, s.cfg.maxListingRange.String())

	}

	// check new request range against previous range
	if _, ok := s.run.maxEndByType[contentType]; ok && nextPage == "" {
		// not-initial request, initial page
		requestGap := startTime.Sub(s.run.maxEndByType[contentType])
		if requestGap > s.cfg.maxGap {
			s.log.Printf("ERROR gap between listing ranges is %s, exceeding max of %s", requestGap.String(), s.cfg.maxGap.String())
		} else if requestGap < 0*time.Second {
			s.log.Printf("WARNING overlap between listing ranges of %s", (-requestGap).String())
		}
	}
	// update requested/served range
	minStart := s.run.minStartByType[contentType]
	if minStart.IsZero() || startTime.Before(minStart) {
		s.run.minStartByType[contentType] = startTime
	}
	if endTime.After(s.run.maxEndByType[contentType]) {
		s.run.maxEndByType[contentType] = endTime
	}
	if len(inPage) > 0 {
		var maxContentCreatedByType time.Time
		for _, item := range inPage {
			if item.ContentCreated.After(maxContentCreatedByType) {
				maxContentCreatedByType = item.ContentCreated
			}
		}
		if _, ok := s.run.maxContentCreatedByType[contentType]; !ok {
			s.run.maxContentCreatedByType[contentType] = maxContentCreatedByType
		} else if maxContentCreatedByType.After(s.run.maxContentCreatedByType[contentType]) {
			s.run.maxContentCreatedByType[contentType] = maxContentCreatedByType
		}
	}
	for _, item := range inPage {
		// check for multiple listings
		if _, ok := s.run.servedListItemsFetchCount[item.ContentId]; ok {
			s.log.Printf("ERROR already listed item contentId=%s contentCreated=%s", item.ContentId, item.ContentCreated.Format(time.RFC3339Nano))
		} else {
			s.run.servedListItemsFetchCount[item.ContentId] = 0
		}
		// keep track of expiry times
		s.run.servedItemsExpiry[item.ContentId] = item.ContentExpiration
	}
	// other checks
	if s.run.subscriptionsByType[contentType] == 0 {
		s.log.Printf("ERROR listing unsubscribed content type '%s'", contentType)
	}
	if s.cfg.checkTenantId && tenantId != s.cfg.tenantId {
		s.log.Printf("ERROR received tenantId '%s' does not match expected '%s'", tenantId, s.cfg.tenantId)
	}
	if s.cfg.checkTenantId && publisherIdentifier != s.cfg.tenantId {
		s.log.Printf("ERROR received PublisherIdentifier '%s' does not match expected '%s'", publisherIdentifier, s.cfg.tenantId)
	}
	if authorization := r.Header.Get("Authorization"); s.cfg.checkAccessToken && authorization != "Bearer "+s.cfg.accessToken {
		s.log.Printf("ERROR received Authorization header '%s' does not match expected '%s'",
			authorization,
			"Bearer "+s.cfg.accessToken,
		)
	}
	// write response
	s.writeJSON(w, http.StatusOK, inPage)
}
func (s *server) handleFetch(w http.ResponseWriter, r *http.Request) {
	tenantId := r.PathValue("tenantId")
	contentId := r.PathValue("contentId")
	reqTime := time.Now()

	if _, ok := s.run.servedListItemsFetchCount[contentId]; !ok {
		s.log.Printf("ERROR fetching unknown item contentId=%s", contentId)
	} else {
		s.run.servedListItemsFetchCount[contentId] += 1
	}

	expiry := s.run.servedItemsExpiry[contentId]
	if !reqTime.Before(expiry) {
		s.log.Printf("ERROR requested expired item contentId=%s contentExpiration=%s", contentId, expiry.UTC().String())
		s.writeJSON(w, http.StatusNotFound, nil)
	} else {
		resp := makeFetchItems(s.cfg, s.run)

		// keep track of served events
		s.run.servedFetchItemsCount += len(resp)
		s.run.servedUniqueFetchItemsCount += len(resp)
		if s.cfg.scenario.duplicateItemInEachFetch {
			s.run.servedUniqueFetchItemsCount--
		}

		s.log.Printf("Fetch %s, length %d",
			contentId,
			len(resp),
		)
		s.writeJSON(w, http.StatusOK, resp)
	}

	if s.cfg.checkTenantId && tenantId != s.cfg.tenantId {
		s.log.Printf("ERROR received tenantId %s does not match expected %s", tenantId, s.cfg.tenantId)
	}

	if authorization := r.Header.Get("Authorization"); s.cfg.checkAccessToken && authorization != "Bearer "+s.cfg.accessToken {
		s.log.Printf("ERROR received Authorization header '%s' does not match expected '%s'",
			authorization,
			"Bearer "+s.cfg.accessToken,
		)
	}
}

func (s *server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
