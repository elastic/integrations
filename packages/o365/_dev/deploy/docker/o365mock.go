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

type TokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	ExtExpiresIn int64  `json:"ext_expires_in"`
	AccessToken  string `json:"access_token"`
}

type RefreshTokenResponse struct {
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

type ListItem struct {
	ContentType       string    `json:"contentType"`
	ContentId         string    `json:"contentId"`
	ContentUri        string    `json:"contentUri"`
	ContentCreated    time.Time `json:"contentCreated"`
	ContentExpiration time.Time `json:"contentExpiration"`
}

type FetchItem map[string]any

func MakeListItems(cfg *Config, run *Run, contentType string, minN, maxN int, minTime, maxTime string) []ListItem {
	numMaybe := maxN - minN
	numItems := minN + run.RandomSource.Intn(numMaybe+1)

	maxTimeDuration, err := time.ParseDuration(maxTime)
	if err != nil {
		panic(err)
	}
	minTimeDuration, err := time.ParseDuration(minTime)
	if err != nil {
		panic(err)
	}
	possibleRange := maxTimeDuration - minTimeDuration

	result := make([]ListItem, numItems)
	for i := range numItems {
		timeOffset := minTimeDuration + time.Duration(run.RandomSource.Int63n(int64(possibleRange)+1))
		result[i] = MakeListItem(cfg, run, contentType, timeOffset.String(), "")
	}
	return result
}

func MakeListItem(cfg *Config, run *Run, contentType, timeOffset string, expirationOverride string) ListItem {
	timeOffsetDuration, err := time.ParseDuration(timeOffset)
	if err != nil {
		panic(err)
	}

	contentCreated := run.StartTime.Add(timeOffsetDuration)
	contentExpiration := contentCreated.Add(time.Hour * 24 * 7)

	if expirationOverride != "" {
		expirationOverrideDuration, err := time.ParseDuration(expirationOverride)
		if err != nil {
			panic(err)
		}
		contentExpiration = run.StartTime.Add(expirationOverrideDuration)
	}

	contentId := RandomString(run, 12)
	contentUri := fmt.Sprintf("http://%s/api/v1.0/%s/activity/feed/audit/%s", cfg.Addr, cfg.TenantId, contentId)

	return ListItem{
		contentType,
		contentId,
		contentUri,
		contentCreated,
		contentExpiration,
	}
}

func MakeFetchItems(cfg *Config, run *Run) []FetchItem {
	numMaybe := cfg.Scenario.MaxFetchItems - cfg.Scenario.MinFetchItems
	numItems := cfg.Scenario.MinFetchItems + run.RandomSource.Intn(numMaybe+1)
	result := make([]FetchItem, numItems)
	for i := range numItems {
		if cfg.Scenario.FullFetchItemsFromPool {
			result[i] = cfg.FetchItemPool[run.FetchItemPoolIndex]
			run.FetchItemPoolIndex = (run.FetchItemPoolIndex + 1) % len(cfg.FetchItemPool)
		} else {
			result[i] = FetchItem{}
		}
		result[i]["CreationTime"] = RandomTime(run, 8*24*time.Hour).Format("2006-01-02T15:04:05")
		result[i]["Id"] = RandomString(run, 12)
	}
	if cfg.Scenario.DuplicateItemInEachFetch {
		return slices.Concat(result, []FetchItem{result[len(result)-1]})
	}
	return result
}

////////////////////////////////////////////////////////////////////////////////
// Fetch item pool - Real data that can be cycled through for responses.
//                   (CreationTime and Id will be overridden with random values)
////////////////////////////////////////////////////////////////////////////////

var fetchItemPool = []FetchItem{
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

type Config struct {
	Addr                        string
	TenantId                    string
	ClientId                    string
	ClientSecret                string
	RefreshToken                string
	AccessToken                 string
	FetchItemPool               []FetchItem
	Scenario                    Scenario
	GenericRequstLogging        bool
	MaxGap                      time.Duration
	MaxListingRange             time.Duration
	CheckTenantId               bool
	CheckCredentials            bool
	CheckAccessToken            bool
	CheckSubscribedBeforeListed bool
}

type Scenario struct {
	ItemsByType              map[string][]ListItem
	UnauthorizedType         string
	PageLimit                int
	ShuffleInPages           bool
	MinFetchItems            int
	MaxFetchItems            int
	FullFetchItemsFromPool   bool
	DuplicateItemInEachFetch bool
}

////////////////////////////////////////////////////////////////////////////////
// Run state type
////////////////////////////////////////////////////////////////////////////////

type Run struct {
	StartTime                       time.Time
	RandomSource                    *rand.Rand
	ServedListItemsFetchCount       map[string]int
	ServedFetchItemsCount           int
	ServedUniqueFetchItemsCount     int
	ServedItemsExpiry               map[string]time.Time
	ServedNextPageQueryRequestCount map[string]int
	MinStartByType                  map[string]time.Time
	MaxEndByType                    map[string]time.Time
	MaxContentCreatedByType         map[string]time.Time
	SubscriptionsByType             map[string]int
	FetchItemPoolIndex              int
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

	var run = Run{
		StartTime:                       time.Now().UTC(),
		ServedListItemsFetchCount:       map[string]int{},
		ServedItemsExpiry:               map[string]time.Time{},
		ServedNextPageQueryRequestCount: map[string]int{},
		MinStartByType:                  map[string]time.Time{},
		MaxEndByType:                    map[string]time.Time{},
		MaxContentCreatedByType:         map[string]time.Time{},
		SubscriptionsByType:             map[string]int{},
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
		seed = run.StartTime.UnixNano()
	}
	run.RandomSource = rand.New(rand.NewSource(seed))

	port := "9999"
	envPort := os.Getenv("PORT")
	if envPort != "" {
		port = envPort
	}

	cfg := Config{
		Addr:                        "0.0.0.0:" + port,
		TenantId:                    "test-cel-tenant-id",
		ClientId:                    "test-cel-client-id",
		ClientSecret:                "test-cel-client-secret",
		RefreshToken:                "refresh_token_123",
		AccessToken:                 "someaccesstoken",
		FetchItemPool:               fetchItemPool,
		GenericRequstLogging:        false,
		MaxGap:                      0 * time.Millisecond,
		MaxListingRange:             time.Hour + time.Millisecond,
		CheckTenantId:               true,
		CheckCredentials:            true,
		CheckAccessToken:            true,
		CheckSubscribedBeforeListed: true,
	}
	scenarios := map[string]Scenario{
		"cel-bad-creds": {
			ItemsByType: map[string][]ListItem{
				"Audit.General": []ListItem{
					MakeListItem(&cfg, &run, "Audit.AzureActiveDirectory", "-1h", ""),
				},
			},
			UnauthorizedType:       "Audit.TypeRequiringAdditionalPermissions",
			FullFetchItemsFromPool: true,
			PageLimit:              3,
			MinFetchItems:          1,
			MaxFetchItems:          1,
		},
		"cel": {
			ItemsByType: map[string][]ListItem{
				"Audit.SharePoint": SortListItems(
					MakeListItems(&cfg, &run, "Audit.SharePoint", 5, 5, "-11h", "0h"),
				),
				"Audit.General": SortListItems(
					MakeListItems(&cfg, &run, "Audit.General", 5, 5, "-11h", "0h"),
				),
			},
			FullFetchItemsFromPool:   true,
			DuplicateItemInEachFetch: true,
			ShuffleInPages:           true,
			PageLimit:                3,
			MinFetchItems:            3,
			MaxFetchItems:            3,
		},
		"bit_of_recent_data": {
			ItemsByType: map[string][]ListItem{
				"Audit.AzureActiveDirectory": SortListItems([]ListItem{
					MakeListItem(&cfg, &run, "Audit.AzureActiveDirectory", "-007h55m", ""),
					MakeListItem(&cfg, &run, "Audit.AzureActiveDirectory", "-007h35m", ""),
					MakeListItem(&cfg, &run, "Audit.AzureActiveDirectory", "-004h35m", ""),
					MakeListItem(&cfg, &run, "Audit.AzureActiveDirectory", "-004h55m", ""),
				}),
			},
			UnauthorizedType:         "Audit.NoPermissions",
			FullFetchItemsFromPool:   false,
			DuplicateItemInEachFetch: false,
			ShuffleInPages:           false,
			PageLimit:                math.MaxInt,
			MinFetchItems:            1,
			MaxFetchItems:            5,
		},
		"2_types_random_250_to_500_last_12h_pages_of_20": {
			ItemsByType: map[string][]ListItem{
				"Audit.AzureActiveDirectory": SortListItems(
					MakeListItems(&cfg, &run, "Audit.AzureActiveDirectory", 250, 500, "-12h", "0h"),
				),
				"Audit.Exchange": SortListItems(
					MakeListItems(&cfg, &run, "Audit.Exchange", 250, 500, "-12h", "0h"),
				),
			},
			FullFetchItemsFromPool:   true,
			DuplicateItemInEachFetch: false,
			ShuffleInPages:           false,
			PageLimit:                20,
			MinFetchItems:            1,
			MaxFetchItems:            5,
		},
		"chunks_with_gaps_and_1_expired": {
			ItemsByType: map[string][]ListItem{
				"Audit.AzureActiveDirectory": SortListItems(slices.Concat(
					MakeListItems(&cfg, &run, "Audit.AzureActiveDirectory", 100, 200, "-11h", "-9h"),
					MakeListItems(&cfg, &run, "Audit.AzureActiveDirectory", 100, 200, "-4h", "-2h"),
					[]ListItem{MakeListItem(&cfg, &run, "Audit.AzureActiveDirectory", "-1h15m", "-1h")}, // expired 15 mins after creation
					MakeListItems(&cfg, &run, "Audit.AzureActiveDirectory", 100, 200, "-55m", "-30m"),
				)),
				"Audit.Exchange": SortListItems(slices.Concat(
					MakeListItems(&cfg, &run, "Audit.Exchange", 100, 200, "-10h", "-5h55m"),
					MakeListItems(&cfg, &run, "Audit.Exchange", 100, 200, "-5h30m", "-4h"),
					MakeListItems(&cfg, &run, "Audit.Exchange", 100, 200, "-1h55m", "-1h5m"),
				)),
			},
			FullFetchItemsFromPool:   true,
			DuplicateItemInEachFetch: true,
			ShuffleInPages:           true,
			PageLimit:                20,
			MinFetchItems:            1,
			MaxFetchItems:            5,
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
	cfg.Scenario = scenarios[scenarioName]

	rerunCmd := "PORT=" + port + " go run o365mock.go " + scenarioName + " " + strconv.FormatInt(seed, 10)
	log.Printf("RunStart StartTime=%s, scenarioName=%s, seed=%d, Addr=%s, rerun: '%s'",
		run.StartTime.Format(time.RFC3339Nano),
		scenarioName,
		seed,
		cfg.Addr,
		rerunCmd,
	)

	s := NewServer(&cfg, &run, log)
	s.Run()
}

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous helpers
////////////////////////////////////////////////////////////////////////////////

func SortListItems(slice []ListItem) []ListItem {
	slices.SortFunc(slice, func(a, b ListItem) int {
		return int(a.ContentCreated.Sub(b.ContentCreated))
	})
	return slice
}

func ShuffleListItems(run *Run, slice []ListItem) []ListItem {
	run.RandomSource.Shuffle(len(slice), func(i, j int) {
		slice[i], slice[j] = slice[j], slice[i]
	})
	return slice
}

func RandomString(run *Run, n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[run.RandomSource.Intn(len(letters))]
	}
	return string(b)
}

func RandomTime(run *Run, inLast time.Duration) time.Time {
	randNanos := run.RandomSource.Int63n(int64(inLast.Nanoseconds()))
	return run.StartTime.Add(-time.Duration(randNanos))
}

////////////////////////////////////////////////////////////////////////////////
// Server
////////////////////////////////////////////////////////////////////////////////

type Server struct {
	mux    *http.ServeMux
	log    *log.Logger
	addr   string
	server *http.Server
	cfg    *Config
	run    *Run
}

func NewServer(cfg *Config, run *Run, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}
	mux := http.NewServeMux()
	s := &Server{
		mux:  mux,
		log:  logger,
		addr: cfg.Addr,
		run:  run,
		cfg:  cfg,
	}
	s.routes()
	s.server = &http.Server{
		Addr:         cfg.Addr,
		Handler:      s.logRequests(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s
}

func (s *Server) Run() {
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

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("POST /{tenantId}/oauth2/v2.0/token", s.handleToken)
	s.mux.HandleFunc("POST /api/v1.0/{tenantId}/activity/feed/subscriptions/start", s.handleSubscribe)
	s.mux.HandleFunc("GET /api/v1.0/{tenantId}/activity/feed/subscriptions/content", s.handleList)
	s.mux.HandleFunc("GET /api/v1.0/{tenantId}/activity/feed/audit/{contentId}", s.handleFetch)
}

func (s *Server) shutdownReport() {
	s.log.Printf("RunStop %s", time.Now().UTC().Format(time.RFC3339Nano))

	// subscribing
	for contentType := range s.cfg.Scenario.ItemsByType {
		s.log.Printf("Report subscriptions for content type %s: %d",
			contentType,
			s.run.SubscriptionsByType[contentType],
		)
	}

	// requesting ranges (based on initial page of each range)
	for contentType := range s.cfg.Scenario.ItemsByType {
		s.log.Printf("Report requested range spans [%s--%s] for %s",
			s.run.MinStartByType[contentType].Format(time.RFC3339Nano),
			s.run.MaxEndByType[contentType].Format(time.RFC3339Nano),
			contentType,
		)
	}

	// served max times
	for contentType := range s.cfg.Scenario.ItemsByType {
		s.log.Printf("Report max contentCreated value %s for %s",
			s.run.MaxContentCreatedByType[contentType].Format(time.RFC3339Nano),
			contentType,
		)
	}

	// requesting next pages
	var nextPageRequestedOnce, nextPageRequestedRepeatedly, nextPageRequestedNever int
	for _, count := range s.run.ServedNextPageQueryRequestCount {
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
	for _, count := range s.run.ServedListItemsFetchCount {
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

	s.log.Printf("Report served fetch items (events): %d", s.run.ServedFetchItemsCount)
	s.log.Printf("Report served unique fetch items (events): %d", s.run.ServedUniqueFetchItemsCount)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.GenericRequstLogging {
			s.log.Printf("Request %s %s", r.Method, r.URL)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
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
	if s.cfg.CheckTenantId && tenantId != s.cfg.TenantId {
		s.log.Printf("ERROR received tenantId %s does not match expected %s", tenantId, s.cfg.TenantId)
	}
	if s.cfg.CheckCredentials {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authorization, "Basic "))
		if err != nil {
			s.log.Printf("ERROR could not decode Authorization header value '%s'", authorization)
			http.Error(w, "bad authorization header value", http.StatusBadRequest)
			return
		}
		if string(decoded) != s.cfg.ClientId+":"+s.cfg.ClientSecret {
			s.log.Printf("ERROR Incorrect Authorization header value for token request")
			http.Error(w, "bad credentials in authorization header", http.StatusBadRequest)
			return
		}
		if grantType == "refresh_token" && refreshToken != s.cfg.RefreshToken {
			s.log.Printf("ERROR Incorrect refresh token value for token request")
			http.Error(w, "bad refresh token value for grant type refresh_token", http.StatusBadRequest)
			return
		}
	}
	if grantType == "refresh_token" {
		s.writeJSON(w, http.StatusOK, RefreshTokenResponse{
			TokenType:    "Bearer",
			ExpiresIn:    3599,
			AccessToken:  s.cfg.AccessToken,
			Scope:        scope,
			RefreshToken: "somerefreshtokenvalue...",
			IdToken:      "someidtokenvalue...",
		})
		return
	}
	s.writeJSON(w, http.StatusOK, TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    3599,
		ExtExpiresIn: 3599,
		AccessToken:  s.cfg.AccessToken,
	})
}

func (s *Server) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	tenantId := r.PathValue("tenantId")
	q := r.URL.Query()
	contentType := q.Get("contentType")
	var respStatus int
	var respBody map[string]any
	if s.run.RandomSource.Intn(2) == 0 {
		respStatus = http.StatusOK
		respBody = subscriptionEnabledResponse(contentType)
	} else {
		respStatus = http.StatusBadRequest
		respBody = subscriptionAlreadyEnabledResponse
	}

	if s.cfg.Scenario.UnauthorizedType != "" && contentType == s.cfg.Scenario.UnauthorizedType {
		respStatus = http.StatusUnauthorized
		w.WriteHeader(respStatus)
		s.log.Printf("Subscribe %s, result %d (that type was configured as unauthorized in the scenario)", contentType, respStatus)
		return
	}
	if _, ok := s.cfg.Scenario.ItemsByType[contentType]; !ok {
		s.log.Printf("ERROR attempted to subscribe to unknown content type %s", contentType)
		http.NotFound(w, r)
		return
	}
	s.run.SubscriptionsByType[contentType]++

	s.log.Printf("Subscribe %s, result %d",
		contentType,
		respStatus,
	)
	if s.cfg.CheckTenantId && tenantId != s.cfg.TenantId {
		s.log.Printf("ERROR received tenantId %s does not match expected %s", tenantId, s.cfg.TenantId)
	}
	if authorization := r.Header.Get("Authorization"); s.cfg.CheckAccessToken && authorization != "Bearer "+s.cfg.AccessToken {
		s.log.Printf("ERROR received Authorization header '%s' does not match expected '%s'",
			authorization,
			"Bearer "+s.cfg.AccessToken,
		)
	}
	s.writeJSON(w, respStatus, respBody)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
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

	items, ok := s.cfg.Scenario.ItemsByType[contentType]
	if !ok {
		s.log.Printf("ERROR requested unknown content type %s", contentType)
		s.writeJSON(w, http.StatusNotFound, nil)
		return
	}

	inRange := []ListItem{}
	for _, item := range items {
		if (item.ContentCreated.Equal(startTime) || item.ContentCreated.After(startTime)) &&
			item.ContentCreated.Before(endTime) && item.ContentCreated.Before(time.Now().UTC()) {
			inRange = append(inRange, item)
		}
	}

	skip := min(numSeen, len(inRange))
	n := min(s.cfg.Scenario.PageLimit, len(inRange)-skip)
	newNumSeen := skip + n
	inPage := inRange[skip:newNumSeen]
	numRest := len(inRange) - skip - n

	if s.cfg.Scenario.ShuffleInPages {
		ShuffleListItems(s.run, inPage)
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
		if _, ok := s.run.ServedNextPageQueryRequestCount[qEncoded]; !ok {
			s.log.Printf("ERROR asked for an unknown next page: %s", qEncoded)
		} else {
			s.run.ServedNextPageQueryRequestCount[qEncoded]++
		}
	}

	// make NextPageUri if necessary
	if numRest > 0 {
		nextPageURL := *r.URL
		nextPageQ := nextPageURL.Query()
		nextPageQ.Set("nextPage", strconv.Itoa(newNumSeen))
		// randomly downcase endTime param
		if s.run.RandomSource.Intn(2) == 0 {
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
		if _, ok := s.run.ServedNextPageQueryRequestCount[nextPageURL.RawQuery]; ok {
			s.log.Printf("ERROR already served NextPageUri: %s", nextPageURL.RawQuery)
		} else {
			s.run.ServedNextPageQueryRequestCount[nextPageURL.RawQuery] = 0
		}
	}
	// make sure the host/port matches the incoming request
	for i := range inPage {
		inPage[i].ContentUri = strings.Replace(inPage[i].ContentUri, s.cfg.Addr, r.Host, 1)
	}

	// check it's not asking for too much
	listingRange := endTime.Sub(startTime)
	if listingRange > s.cfg.MaxListingRange {
		s.log.Printf("ERROR listing range of %s exceeds max of %s", listingRange, s.cfg.MaxListingRange.String())

	}

	// check new request range against previous range
	if _, ok := s.run.MaxEndByType[contentType]; ok && nextPage == "" {
		// not-initial request, initial page
		requestGap := startTime.Sub(s.run.MaxEndByType[contentType])
		if requestGap > s.cfg.MaxGap {
			s.log.Printf("ERROR gap between listing ranges is %s, exceeding max of %s", requestGap.String(), s.cfg.MaxGap.String())
		} else if requestGap < 0*time.Second {
			s.log.Printf("WARNING overlap between listing ranges of %s", (-requestGap).String())
		}
	}
	// update requested/served range
	minStart := s.run.MinStartByType[contentType]
	if minStart.IsZero() || startTime.Before(minStart) {
		s.run.MinStartByType[contentType] = startTime
	}
	if endTime.After(s.run.MaxEndByType[contentType]) {
		s.run.MaxEndByType[contentType] = endTime
	}
	if len(inPage) > 0 {
		var maxContentCreatedByType time.Time
		for _, item := range inPage {
			if item.ContentCreated.After(maxContentCreatedByType) {
				maxContentCreatedByType = item.ContentCreated
			}
		}
		if _, ok := s.run.MaxContentCreatedByType[contentType]; !ok {
			s.run.MaxContentCreatedByType[contentType] = maxContentCreatedByType
		} else if maxContentCreatedByType.After(s.run.MaxContentCreatedByType[contentType]) {
			s.run.MaxContentCreatedByType[contentType] = maxContentCreatedByType
		}
	}
	for _, item := range inPage {
		// check for multiple listings
		if _, ok := s.run.ServedListItemsFetchCount[item.ContentId]; ok {
			s.log.Printf("ERROR already listed item contentId=%s contentCreated=%s", item.ContentId, item.ContentCreated.Format(time.RFC3339Nano))
		} else {
			s.run.ServedListItemsFetchCount[item.ContentId] = 0
		}
		// keep track of expiry times
		s.run.ServedItemsExpiry[item.ContentId] = item.ContentExpiration
	}
	// other checks
	if s.run.SubscriptionsByType[contentType] == 0 {
		s.log.Printf("ERROR listing unsubscribed content type '%s'", contentType)
	}
	if s.cfg.CheckTenantId && tenantId != s.cfg.TenantId {
		s.log.Printf("ERROR received tenantId '%s' does not match expected '%s'", tenantId, s.cfg.TenantId)
	}
	if s.cfg.CheckTenantId && publisherIdentifier != s.cfg.TenantId {
		s.log.Printf("ERROR received PublisherIdentifier '%s' does not match expected '%s'", publisherIdentifier, s.cfg.TenantId)
	}
	if authorization := r.Header.Get("Authorization"); s.cfg.CheckAccessToken && authorization != "Bearer "+s.cfg.AccessToken {
		s.log.Printf("ERROR received Authorization header '%s' does not match expected '%s'",
			authorization,
			"Bearer "+s.cfg.AccessToken,
		)
	}
	// write response
	s.writeJSON(w, http.StatusOK, inPage)
}
func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	tenantId := r.PathValue("tenantId")
	contentId := r.PathValue("contentId")
	reqTime := time.Now()

	if _, ok := s.run.ServedListItemsFetchCount[contentId]; !ok {
		s.log.Printf("ERROR fetching unknown item contentId=%s", contentId)
	} else {
		s.run.ServedListItemsFetchCount[contentId] += 1
	}

	expiry := s.run.ServedItemsExpiry[contentId]
	if !reqTime.Before(expiry) {
		s.log.Printf("ERROR requested expired item contentId=%s contentExpiration=%s", contentId, expiry.UTC().String())
		s.writeJSON(w, http.StatusNotFound, nil)
	} else {
		resp := MakeFetchItems(s.cfg, s.run)

		// keep track of served events
		s.run.ServedFetchItemsCount += len(resp)
		s.run.ServedUniqueFetchItemsCount += len(resp)
		if s.cfg.Scenario.DuplicateItemInEachFetch {
			s.run.ServedUniqueFetchItemsCount--
		}

		s.log.Printf("Fetch %s, length %d",
			contentId,
			len(resp),
		)
		s.writeJSON(w, http.StatusOK, resp)
	}

	if s.cfg.CheckTenantId && tenantId != s.cfg.TenantId {
		s.log.Printf("ERROR received tenantId %s does not match expected %s", tenantId, s.cfg.TenantId)
	}

	if authorization := r.Header.Get("Authorization"); s.cfg.CheckAccessToken && authorization != "Bearer "+s.cfg.AccessToken {
		s.log.Printf("ERROR received Authorization header '%s' does not match expected '%s'",
			authorization,
			"Bearer "+s.cfg.AccessToken,
		)
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
