package main

import (
	"compress/gzip"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Replace these values with your desired username and password
const (
	username = "admin"
	password = "MongoDB@123"
)

func generateDigest(username, realm, password, method, uri, nonce, nc, cnonce, qop string) string {
	ha1 := md5.New()
	fmt.Fprintf(ha1, "%s:%s:%s", username, realm, password)
	ha1Hex := fmt.Sprintf("%x", ha1.Sum(nil))

	ha2 := md5.New()
	fmt.Fprintf(ha2, "%s:%s", method, uri)
	ha2Hex := fmt.Sprintf("%x", ha2.Sum(nil))

	response := md5.New()
	fmt.Fprintf(response, "%s:%s:%s:%s:%s:%s", ha1Hex, nonce, nc, cnonce, qop, ha2Hex)
	return fmt.Sprintf("%x", response.Sum(nil))
}

func digestAuth(w http.ResponseWriter, r *http.Request, realm, nonce, qop string) bool {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="%s", qop="%s", nonce="%s"`, realm, qop, nonce))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Digest" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return false
	}

	params := make(map[string]string)
	for _, param := range strings.Split(parts[1], ",") {
		kv := strings.SplitN(strings.TrimSpace(param), "=", 2)
		if len(kv) != 2 {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return false
		}
		params[kv[0]] = strings.Trim(kv[1], `"`)
	}

	calculatedResponse := generateDigest(params["username"], realm, password, r.Method, r.RequestURI, nonce, params["nc"], params["cnonce"], params["qop"])

	if calculatedResponse != params["response"] {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	return true
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	// Digest Authentication
	realm := "MyRealm"
	nonce := "123456"
	qop := "auth"

	authorized := digestAuth(w, r, realm, nonce, qop)
	if !authorized {
		return
	}

	fileName := strings.TrimPrefix(r.URL.Path, "/api/atlas/v2/groups/mongodb-group1/clusters/hostname1/logs/")
	// Replace "path/to/your/log/file.log" with the actual path to your log file
	var logFilePath string
	if fileName == "mongodb.gz" {
		logFilePath = "mongod_database_data.log"
	} else {
		logFilePath = "mongod_audit_data.log"
	}

	// Open the log file
	logFile, err := os.Open(logFilePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error opening log file: %v", err), http.StatusInternalServerError)
		return
	}
	defer logFile.Close()

	// Create a gzip writer for the response
	w.Header().Set("Content-Type", "application/vnd.atlas.2023-02-01+gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="mongodb-log.gz"`)

	gzipWriter := gzip.NewWriter(w)
	defer gzipWriter.Close()

	// Copy the log file content to the gzip writer
	_, err = io.Copy(gzipWriter, logFile)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading log file: %v", err), http.StatusInternalServerError)
		return
	}
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {

	realm := "MyRealm"
	nonce := "123456"
	qop := "auth"

	authorized := digestAuth(w, r, realm, nonce, qop)
	if !authorized {
		return
	}

	type DataPoint struct {
		Timestamp string `json:"timestamp"`
		Value     int    `json:"value"`
	}

	type Link struct {
		Href string `json:"href"`
		Rel  string `json:"rel"`
	}

	type Measurement struct {
		DataPoints []DataPoint `json:"dataPoints"`
		Name       string      `json:"name"`
		Units      string      `json:"units"`
	}

	type Response struct {
		End          string        `json:"end"`
		Granularity  string        `json:"granularity"`
		GroupId      string        `json:"groupId"`
		HostId       string        `json:"hostId"`
		Links        []Link        `json:"links"`
		Measurements []Measurement `json:"measurements"`
		ProcessId    string        `json:"processId"`
		Start        string        `json:"start"`
	}

	// Create the response
	response := Response{
		End:         "2024-04-08T12:04:15Z",
		Granularity: "PT5M",
		GroupId:     "mongodb-group1",
		HostId:      "hostname1",
		Links: []Link{
			{Href: "http://localhost:7780/api/atlas/v2/groups/mongodb-group1/clusters/hostname1/measurements?granularity=PT5M&period=PT5m", Rel: "self"},
		},
		Measurements: []Measurement{
			{
				DataPoints: []DataPoint{
					{Timestamp: "2024-04-08T12:04:15Z", Value: 0},
				},
				Name:  "ASSERT_REGULAR",
				Units: "SCALAR_PER_SECOND",
			},
		},
		ProcessId: "hostname1",
		Start:     "2024-04-08T12:04:05Z",
	}

	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/vnd.atlas.2023-02-01+json")

	// Encode and send the response
	encoder := json.NewEncoder(w)
	if encoder == nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err := encoder.Encode(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func hardwareMetrics(w http.ResponseWriter, r *http.Request) {

	realm := "MyRealm"
	nonce := "123456"
	qop := "auth"

	authorized := digestAuth(w, r, realm, nonce, qop)
	if !authorized {
		return
	}

	type DataPoint struct {
		Timestamp string  `json:"timestamp"`
		Value     float64 `json:"value"`
	}

	type Link struct {
		Href string `json:"href"`
		Rel  string `json:"rel"`
	}

	type Measurement struct {
		DataPoints []DataPoint `json:"dataPoints"`
		Name       string      `json:"name"`
		Units      string      `json:"units"`
	}

	type Response struct {
		End                  string        `json:"end"`
		Granularity          string        `json:"granularity"`
		GroupId              string        `json:"groupId"`
		Links                []Link        `json:"links"`
		HardwareMeasurements []Measurement `json:"hardwareMeasurements"`
		StatusMeasurements   []Measurement `json:"statusMeasurements"`
		ProcessId            string        `json:"processId"`
		Start                string        `json:"start"`
	}

	// Create the response
	response := Response{
		End:         "2024-04-08T12:04:15Z",
		Granularity: "PT5M",
		GroupId:     "mongodb-group1",
		Links: []Link{
			{Href: "http://localhost:7780/api/atlas/v2/groups/mongodb-group1/clusters/hostname1/measurements?granularity=PT5M&period=PT5m", Rel: "self"},
		},
		HardwareMeasurements: []Measurement{
			{
				DataPoints: []DataPoint{
					{Timestamp: "2024-04-08T12:04:15Z", Value: 175143048.53333333},
				},
				Name:  "FTS_DISK_USAGE",
				Units: "BYTES",
			},
		},
		StatusMeasurements: []Measurement{
			{
				DataPoints: []DataPoint{
					{Timestamp: "2024-04-08T12:04:15Z", Value: 0.16428448420436206},
				},
				Name:  "PAGE_FAULTS",
				Units: "SCALAR_PER_SECOND",
			},
		},
		ProcessId: "hostname1",
		Start:     "2024-04-08T12:04:05Z",
	}

	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/vnd.atlas.2023-02-01+json")

	// Encode and send the response
	encoder := json.NewEncoder(w)
	if encoder == nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err := encoder.Encode(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func hostHandler(w http.ResponseWriter, r *http.Request) {

	realm := "MyRealm"
	nonce := "123456"
	qop := "auth"

	authorized := digestAuth(w, r, realm, nonce, qop)
	if !authorized {
		return
	}

	type Link struct {
		Rel string `json:"rel"`
	}
	type Result struct {
		Hostname string `json:"hostname"`
		ID       string `json:"id"`
	}
	type Response struct {
		Links   []Link   `json:"links"`
		Results []Result `json:"results"`
	}

	// Create the response
	response := Response{
		Links: []Link{
			{
				Rel: "self",
			},
		},
		Results: []Result{
			{
				Hostname: "hostname1",
				ID:       "hostname1",
			},
		},
	}

	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/vnd.atlas.2023-02-01+json")

	// Encode and send the response
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func diskHandler(w http.ResponseWriter, r *http.Request) {

	realm := "MyRealm"
	nonce := "123456"
	qop := "auth"

	authorized := digestAuth(w, r, realm, nonce, qop)
	if !authorized {
		return
	}

	type Link struct {
		Rel string `json:"rel"`
	}

	type Result struct {
		PartitionName string `json:"partitionName"`
	}
	type Response struct {
		Links   []Link   `json:"links"`
		Results []Result `json:"results"`
	}

	// Create the response
	response := Response{
		Links: []Link{
			{
				Rel: "self",
			},
		},
		Results: []Result{
			{
				PartitionName: "disk1",
			},
		},
	}

	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/vnd.atlas.2023-02-01+json")

	// Encode and send the response
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func diskMetrics(w http.ResponseWriter, r *http.Request) {
	realm := "MyRealm"
	nonce := "123456"
	qop := "auth"

	authorized := digestAuth(w, r, realm, nonce, qop)
	if !authorized {
		return
	}

	type DataPoint struct {
		Timestamp string  `json:"timestamp"`
		Value     float64 `json:"value"`
	}

	type Measurement struct {
		DataPoints []DataPoint `json:"dataPoints"`
		Name       string      `json:"name"`
		Units      string      `json:"units"`
	}

	type Response struct {
		End           string        `json:"end"`
		Granularity   string        `json:"granularity"`
		GroupId       string        `json:"groupId"`
		HostId        string        `json:"hostId"`
		Measurements  []Measurement `json:"measurements"`
		PartitionName string        `json:"partitionName"`
		ProcessId     string        `json:"processId"`
		Start         string        `json:"start"`
	}

	// Create the response
	response := Response{
		End:         "2024-07-11T05:17:44Z",
		Granularity: "PT5M",
		GroupId:     "mongodb-group1",
		HostId:      "hostname1",
		Measurements: []Measurement{
			{
				DataPoints: []DataPoint{
					{Timestamp: "2024-07-11T05:17:44", Value: 0.9994005994005996},
				},
				Name:  "DISK_PARTITION_IOPS_READ",
				Units: "SCALAR_PER_SECOND",
			},
			{
				DataPoints: []DataPoint{
					{Timestamp: "2024-07-11T05:17:44", Value: 4.25004682136163},
				},
				Name:  "DISK_PARTITION_IOPS_WRITE",
				Units: "SCALAR_PER_SECOND",
			},
			{
				DataPoints: []DataPoint{
					{Timestamp: "2024-07-11T11:05:45", Value: 7.90646784e9},
				},
				Name:  "DISK_PARTITION_SPACE_FREE",
				Units: "BYTES",
			},
		},
		PartitionName: "data",
		ProcessId:     "hostname1:7780",
		Start:         "2024-07-11T05:17:44Z",
	}

	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/vnd.atlas.2023-02-01+json")

	// Encode and send the response
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func databaseHandler(w http.ResponseWriter, r *http.Request) {

	realm := "MyRealm"
	nonce := "123456"
	qop := "auth"

	authorized := digestAuth(w, r, realm, nonce, qop)
	if !authorized {
		return
	}

	type Link struct {
		Rel string `json:"rel"`
	}

	type Result struct {
		DatabaseName string `json:"databaseName"`
	}
	type Response struct {
		Links   []Link   `json:"links"`
		Results []Result `json:"results"`
	}

	// Create the response
	response := Response{
		Links: []Link{
			{
				Rel: "self",
			},
		},
		Results: []Result{
			{
				DatabaseName: "config",
			},
		},
	}

	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/vnd.atlas.2023-02-01+json")

	// Encode and send the response
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func databaseMetrics(w http.ResponseWriter, r *http.Request) {
	realm := "MyRealm"
	nonce := "123456"
	qop := "auth"

	authorized := digestAuth(w, r, realm, nonce, qop)
	if !authorized {
		return
	}

	type DataPoint struct {
		Timestamp string  `json:"timestamp"`
		Value     float64 `json:"value"`
	}

	type Measurement struct {
		DataPoints []DataPoint `json:"dataPoints"`
		Name       string      `json:"name"`
		Units      string      `json:"units"`
	}

	type Response struct {
		Granularity  string        `json:"granularity"`
		GroupId      string        `json:"groupId"`
		HostId       string        `json:"hostId"`
		Measurements []Measurement `json:"measurements"`
		DatabaseName string        `json:"databaseName"`
		ProcessId    string        `json:"processId"`
	}

	// Create the response
	response := Response{
		Granularity: "PT5M",
		GroupId:     "mongodb-group1",
		HostId:      "hostname1",
		Measurements: []Measurement{
			{
				DataPoints: []DataPoint{
					{Timestamp: "2024-07-11T05:17:44", Value: 0.9994005994005996},
				},
				Name:  "DATABASE_COLLECTION_COUNT",
				Units: "SCALAR_PER_SECOND",
			},
			{
				DataPoints: []DataPoint{
					{Timestamp: "2024-07-11T05:17:44", Value: 4.25004682136163},
				},
				Name:  "DATABASE_AVERAGE_OBJECT_SIZE",
				Units: "BYTES",
			},
			{
				DataPoints: []DataPoint{
					{Timestamp: "2024-07-11T11:05:45", Value: 7.90646784e9},
				},
				Name:  "DATABASE_DATA_SIZE",
				Units: "BYTES",
			},
		},
		DatabaseName: "config",
		ProcessId:    "hostname1:7780",
	}

	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/vnd.atlas.2023-02-01+json")

	// Encode and send the response
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func organizationHandler(w http.ResponseWriter, r *http.Request) {
	realm := "MyRealm"
	nonce := "123456"
	qop := "auth"

	authorized := digestAuth(w, r, realm, nonce, qop)
	if !authorized {
		return
	}

	type Link struct {
		Rel string `json:"rel"`
	}

	type CurrentValue struct {
		Number int    `json:"number"`
		Units  string `json:"units"`
	}

	type Raw struct {
		Type            string   `json:"_t"`
		Cid             string   `json:"cid"`
		Cre             string   `json:"cre"`
		Description     string   `json:"description"`
		GroupName       string   `json:"gn"`
		OrgName         string   `json:"orgName"`
		Severity        string   `json:"severity"`
		Source          string   `json:"source"`
		TagsAdded       []string `json:"tagsAdded"`
		TagsRemoved     []string `json:"tagsRemoved"`
		Username        string   `json:"un"`
		UpdatedTagsList []string `json:"updatedTagsList"`
		UpdateType      string   `json:"ut"`
	}

	type Result struct {
		Created         string       `json:"created"`
		EventTypeName   string       `json:"eventTypeName"`
		GroupId         string       `json:"groupId"`
		ID              string       `json:"id"`
		IsGlobalAdmin   bool         `json:"isGlobalAdmin"`
		OrgId           string       `json:"orgId"`
		Raw             Raw          `json:"raw"`
		RemoteAddress   string       `json:"remoteAddress"`
		TargetUsername  string       `json:"targetUsername"`
		UserId          string       `json:"userId"`
		Username        string       `json:"username"`
		Port            int          `json:"port"`
		WhiteListEntry  string       `json:"whitelistEntry"`
		AlertConfigId   string       `json:"alertConfigId"`
		AlertId         string       `json:"alertId"`
		ApiKeyId        string       `json:"apiKeyId"`
		ClusterId       string       `json:"clusterId"`
		ClusterName     string       `json:"clusterName"`
		Collection      string       `json:"collection"`
		CurrentValue    CurrentValue `json:"currentValue"`
		Database        string       `json:"database"`
		HostId          string       `json:"hostId"`
		Hostname        string       `json:"hostname"`
		InvoiceId       string       `json:"invoiceId"`
		MetricName      string       `json:"metricName"`
		OpType          string       `json:"opType"`
		PaymentId       string       `json:"paymentId"`
		PublicKey       string       `json:"publicKey"`
		ReplicaSetName  string       `json:"replicaSetName"`
		ShardName       string       `json:"shardName"`
		TargetPublicKey string       `json:"targetPublicKey"`
		TeamId          string       `json:"teamId"`
	}

	type ApiResponse struct {
		Links   []Link   `json:"links"`
		Results []Result `json:"results"`
	}

	response := ApiResponse{
		Links: []Link{{Rel: "self"}},
		Results: []Result{{
			Created:       "2024-04-30T06:17:35Z",
			EventTypeName: "GROUP_TAGS_MODIFIED",
			GroupId:       "663087fcc4818d301a53af06",
			ID:            "66308cff73a61b3c0633ad96",
			IsGlobalAdmin: false,
			OrgId:         "646f418c72f24c07d430aaca",
			Raw: Raw{
				Type:            "RESOURCE_AUDIT",
				Cid:             "663087fcc4818d301a53af06",
				Cre:             "2024-04-30T06:17:35Z",
				Description:     "Tag(s) were added or modified on project",
				GroupName:       "test_project_org",
				OrgName:         "Integrations - 2023-05-25",
				Severity:        "INFO",
				Source:          "USER",
				TagsAdded:       []string{"{key=test_123, value=test_123}"},
				TagsRemoved:     []string{},
				Username:        "sample1.user@example.com",
				UpdatedTagsList: []string{"{key=application, value=mongo_test}", "{key=test_123, value=test_123}"},
				UpdateType:      "LOCAL",
			},
			RemoteAddress:  "0.0.0.0",
			TargetUsername: "sample.user@example.com",
			UserId:         "sample_user_id",
			Username:       "sample1.user@example.com",
			Port:           80,
			WhiteListEntry: "sample.user@example.com",
			AlertConfigId:  "sample_alert_config_id",
			AlertId:        "sample_alert_id",
			ApiKeyId:       "sample_api_key_id",
			ClusterId:      "sample_cluster_id",
			ClusterName:    "sample_cluster",
			Collection:     "sample_collection",
			CurrentValue: CurrentValue{
				Number: 50,
				Units:  "RAW",
			},
			Database:        "sample_db",
			HostId:          "sample_host_id",
			Hostname:        "sample_hostname",
			InvoiceId:       "sample_invoice_id",
			MetricName:      "sample_metric",
			OpType:          "update",
			PaymentId:       "sample_payment_id",
			PublicKey:       "sample_public_key",
			ReplicaSetName:  "sample_replica_set",
			ShardName:       "sample_shard",
			TargetPublicKey: "sample_target_public_key",
			TeamId:          "sample_team_id",
		}},
	}

	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/vnd.atlas.2023-02-01+json")

	// Encode and send the response
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func projectHandler(w http.ResponseWriter, r *http.Request) {
	realm := "MyRealm"
	nonce := "123456"
	qop := "auth"

	authorized := digestAuth(w, r, realm, nonce, qop)
	if !authorized {
		return
	}

	type Link struct {
		Rel string `json:"rel"`
	}

	type CurrentValue struct {
		Number int    `json:"number"`
		Units  string `json:"units"`
	}

	type Raw struct {
		T              string   `json:"_t"`
		CID            string   `json:"cid"`
		Cre            string   `json:"cre"`
		Description    string   `json:"description"`
		Et             string   `json:"et"`
		Hidden         bool     `json:"hidden"`
		ID             string   `json:"id"`
		IsMmsAdmin     bool     `json:"isMmsAdmin"`
		NewRoles       []string `json:"newRoles"`
		OrgId          *string  `json:"orgId"`
		RemoteAddr     string   `json:"remoteAddr"`
		Severity       string   `json:"severity"`
		Source         string   `json:"source"`
		TargetUsername string   `json:"targetUsername"`
		Un             string   `json:"un"`
		UserId         string   `json:"userId"`
		Ut             string   `json:"ut"`
	}

	type Result struct {
		Created                       string       `json:"created"`
		EventTypeName                 string       `json:"eventTypeName"`
		GroupId                       string       `json:"groupId"`
		ID                            string       `json:"id"`
		IsGlobalAdmin                 bool         `json:"isGlobalAdmin"`
		Raw                           Raw          `json:"raw"`
		RemoteAddress                 string       `json:"remoteAddress"`
		TargetUsername                string       `json:"targetUsername"`
		UserId                        string       `json:"userId"`
		Username                      string       `json:"username"`
		OrgId                         string       `json:"orgId"`
		Port                          int          `json:"port"`
		WhiteListEntry                string       `json:"whitelistEntry"`
		AlertConfigId                 string       `json:"alertConfigId"`
		AlertId                       string       `json:"alertId"`
		ApiKeyId                      string       `json:"apiKeyId"`
		ClusterId                     string       `json:"clusterId"`
		ClusterName                   string       `json:"clusterName"`
		Collection                    string       `json:"collection"`
		CurrentValue                  CurrentValue `json:"currentValue"`
		Database                      string       `json:"database"`
		HostId                        string       `json:"hostId"`
		Hostname                      string       `json:"hostname"`
		InvoiceId                     string       `json:"invoiceId"`
		MetricName                    string       `json:"metricName"`
		OpType                        string       `json:"opType"`
		PaymentId                     string       `json:"paymentId"`
		PublicKey                     string       `json:"publicKey"`
		ReplicaSetName                string       `json:"replicaSetName"`
		ShardName                     string       `json:"shardName"`
		TargetPublicKey               string       `json:"targetPublicKey"`
		TeamId                        string       `json:"teamId"`
		FrequencyType                 string       `json:"frequencyType"`
		SnapshotScheduledCreationDate string       `json:"snapshotScheduledCreationDate"`
		SnapshotCompletionDate        string       `json:"snapshotCompletionDate"`
		ApplicationId                 string       `json:"applicationId"`
		ApplicationName               string       `json:"applicationName"`
		DbUserUsername                string       `json:"dbUserUsername"`
		EndpointId                    string       `json:"endpointId"`
		ProviderEndpointId            string       `json:"providerEndpointId"`
		InstanceName                  string       `json:"instanceName"`
		ProcessorErrorMsg             string       `json:"processorErrorMsg"`
		ProcessorName                 string       `json:"processorName"`
		ProcessorState                string       `json:"processorState"`
		ResourceId                    string       `json:"resourceId"`
		ResourceType                  string       `json:"resourceType"`
	}

	type ApiResponse struct {
		Links   []Link   `json:"links"`
		Results []Result `json:"results"`
	}

	response := ApiResponse{
		Links: []Link{{Rel: "self"}},
		Results: []Result{{
			Created:       "2024-02-21T10:00:29Z",
			EventTypeName: "INVITED_TO_GROUP",
			GroupId:       "646f4379c47da356740d14ad",
			ID:            "65d5c9bd2c86e3377aa5e5e4",
			IsGlobalAdmin: false,
			Raw: Raw{
				T:              "USER_AUDIT",
				CID:            "646f4379c47da356740d14ad",
				Cre:            "2024-02-21T10:00:29Z",
				Description:    "User was invited to project",
				Et:             "INVITED_TO_GROUP",
				Hidden:         false,
				ID:             "65d5c9bd2c86e3377aa5e5e4",
				IsMmsAdmin:     false,
				NewRoles:       []string{},
				OrgId:          nil,
				RemoteAddr:     "0.0.0.0",
				Severity:       "INFO",
				Source:         "USER",
				TargetUsername: "sample.user@example.com",
				Un:             "sample1.user@example.com",
				UserId:         "sample_user_id",
				Ut:             "LOCAL",
			},
			RemoteAddress:  "0.0.0.0",
			TargetUsername: "sample.user@example.com",
			UserId:         "sample_user_id",
			Username:       "sample1.user@example.com",
			OrgId:          "sample_org_id",
			Port:           80,
			WhiteListEntry: "sample.user@example.com",
			AlertConfigId:  "sample_alert_config_id",
			AlertId:        "sample_alert_id",
			ApiKeyId:       "sample_api_key_id",
			ClusterId:      "sample_cluster_id",
			ClusterName:    "sample_cluster",
			Collection:     "sample_collection",
			CurrentValue: CurrentValue{
				Number: 50,
				Units:  "RAW",
			},
			Database:                      "sample_db",
			HostId:                        "sample_host_id",
			Hostname:                      "sample_hostname",
			InvoiceId:                     "sample_invoice_id",
			MetricName:                    "sample_metric",
			OpType:                        "update",
			PaymentId:                     "sample_payment_id",
			PublicKey:                     "sample_public_key",
			ReplicaSetName:                "sample_replica_set",
			ShardName:                     "sample_shard",
			TargetPublicKey:               "sample_target_public_key",
			TeamId:                        "sample_team_id",
			FrequencyType:                 "HOURLY",
			SnapshotScheduledCreationDate: "2024-06-18T05:47:05Z",
			SnapshotCompletionDate:        "2024-06-18T05:51:05Z",
			ApplicationId:                 "647ef2c43a8a03710fbceda1",
			ApplicationName:               "Application-0",
			DbUserUsername:                "atlas-sample-dataset-load-646f4e082084495b64d07ead",
			EndpointId:                    "123e4567-e89b-12d3-a456-426614174000",
			ProviderEndpointId:            "456f7890-f12a-34d5-b678-567890123456",
			InstanceName:                  "mongo-instance-01",
			ProcessorErrorMsg:             "Failed to connect to database instance due to timeout.",
			ProcessorName:                 "eventProcessorService",
			ProcessorState:                "active",
			ResourceId:                    "789g1011-h12i-34j5-k678-890123456789",
			ResourceType:                  "database",
		}},
	}

	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/vnd.atlas.2023-02-01+json")

	// Encode and send the response
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func alertHandler(w http.ResponseWriter, r *http.Request) {
	realm := "MyRealm"
	nonce := "123456"
	qop := "auth"

	authorized := digestAuth(w, r, realm, nonce, qop)
	if !authorized {
		return
	}

	type CurrentValue struct {
		Number float64 `json:"number"`
		Units  string  `json:"units"`
	}

	type Link struct {
		Rel string `json:"rel"`
	}

	type Result struct {
		AlertConfigId          string       `json:"alertConfigId"`
		ClusterName            string       `json:"clusterName"`
		Created                string       `json:"created"`
		CurrentValue           CurrentValue `json:"currentValue"`
		EventTypeName          string       `json:"eventTypeName"`
		GroupId                string       `json:"groupId"`
		HostnameAndPort        string       `json:"hostnameAndPort"`
		ID                     string       `json:"id"`
		LastNotified           string       `json:"lastNotified"`
		MetricName             string       `json:"metricName"`
		OrgId                  string       `json:"orgId"`
		ReplicaSetName         string       `json:"replicaSetName"`
		Resolved               string       `json:"resolved"`
		Status                 string       `json:"status"`
		Updated                string       `json:"updated"`
		UserAlias              string       `json:"userAlias"`
		AcknowledgedUntil      string       `json:"acknowledgedUntil"`
		AcknowledgementComment string       `json:"acknowledgementComment"`
		AcknowledgingUsername  string       `json:"acknowledgingUsername"`
		ParentClusterId        string       `json:"parentClusterId"`
		ClusterId              string       `json:"clusterId"`
		NonRunningHostIds      []string     `json:"nonRunningHostIds"`
		HostId                 string       `json:"hostId"`
		SourceTypeName         string       `json:"sourceTypeName"`
		InstanceName           string       `json:"instanceName"`
		ProcessorErrorMsg      string       `json:"processorErrorMsg"`
		ProcessorName          string       `json:"processorName"`
		ProcessorState         string       `json:"processorState"`
		Tags                   []string     `json:"tags"`
	}

	type AlertData struct {
		Links   []Link   `json:"links"`
		Results []Result `json:"results"`
	}

	response := AlertData{
		Links: []Link{{Rel: "self"}},
		Results: []Result{{
			AlertConfigId: "6683cb42d12516670f38a3ef",
			ClusterName:   "IntegrationsDevBuildCluster",
			Created:       "2024-07-02T09:55:24Z",
			CurrentValue: CurrentValue{
				Number: 1.2666666666666666,
				Units:  "RAW",
			},
			EventTypeName:          "OUTSIDE_METRIC_THRESHOLD",
			GroupId:                "646f4379c47da356740d14ad",
			HostnameAndPort:        "atlas-ccx4uc-shard-00-01.q5ljb.mongodb.net:27017",
			ID:                     "6683ce8c9558e8655626e1ed",
			LastNotified:           "2024-07-02T10:03:21Z",
			MetricName:             "FTS_PROCESS_CPU_USER",
			OrgId:                  "",
			ReplicaSetName:         "atlas-ccx4uc-shard-0",
			Resolved:               "2024-07-02T10:03:21Z",
			Status:                 "CLOSED",
			Updated:                "2024-07-02T10:03:21Z",
			UserAlias:              "integrationsdevbuildclu-shard-00-01.q5ljb.mongodb.net",
			AcknowledgedUntil:      "2024-07-05T00:00:00Z",
			AcknowledgementComment: "Issue acknowledged and being worked on",
			AcknowledgingUsername:  "devOpsUser",
			ParentClusterId:        "exampleParentClusterId123",
			ClusterId:              "exampleClusterId456",
			NonRunningHostIds:      []string{"hostId1", "hostId2"},
			HostId:                 "exampleHostId789",
			SourceTypeName:         "ATLAS_MONITORING_AGENT",
			InstanceName:           "instance123",
			ProcessorErrorMsg:      "No errors",
			ProcessorName:          "Processor1",
			ProcessorState:         "Running",
			Tags:                   []string{"critical", "cpu", "threshold"},
		}},
	}

	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/vnd.atlas.2023-02-01+json")

	// Encode and send the response
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
		return
	}
}

func main() {

	// Logs Handler for serving the mongod audit logs
	http.HandleFunc("/api/atlas/v2/groups/mongodb-group1/clusters/hostname1/logs/mongodb-audit-log.gz", logsHandler)

	// Logs Handler for serving the mongod database logs
	http.HandleFunc("/api/atlas/v2/groups/mongodb-group1/clusters/hostname1/logs/mongodb.gz", logsHandler)

	// Metrics Handler for serving the process metrics response
	http.HandleFunc("/api/atlas/v2/groups/mongodb-group1/processes/hostname1/measurements", metricsHandler)

	// Metrics Handler for serving the hardware metrics response
	http.HandleFunc("/api/atlas/v2/groups/mongodb-group1/hosts/hostname1/fts/metrics/measurements", hardwareMetrics)

	// New handler for returning the list of disks
	http.HandleFunc("/api/atlas/v2/groups/mongodb-group1/processes/hostname1/disks/", diskHandler)
	http.HandleFunc("/api/atlas/v2/groups/mongodb-group1/processes/hostname1/disks/disk1/measurements", diskMetrics)

	// New handler for returning the list of database
	http.HandleFunc("/api/atlas/v2/groups/mongodb-group1/processes/hostname1/databases/", databaseHandler)
	http.HandleFunc("/api/atlas/v2/groups/mongodb-group1/processes/hostname1/databases/config/measurements", databaseMetrics)

	// New handler for returning the hostname
	http.HandleFunc("/api/atlas/v2/groups/mongodb-group1/processes", hostHandler)

	// Organization Handler for collecting organization events
	http.HandleFunc("/api/atlas/v2/orgs/org-1/events", organizationHandler)

	// Project Handler for collecting project events
	http.HandleFunc("/api/atlas/v2/groups/mongodb-group1/events", projectHandler)

	// Alert Handler for collecting Alert logs
	http.HandleFunc("/api/atlas/v2/groups/mongodb-group1/alerts", alertHandler)
	// Start the server
	http.ListenAndServe(":7780", nil)
}
