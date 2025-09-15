// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// ObjectData stores the raw data and its content type.
type ObjectData struct {
	Data        []byte
	ContentType string
}

// The in-memory store to hold ObjectData structs.
var inMemoryStore = make(map[string]map[string]ObjectData)

// GCSListResponse mimics the structure of a real GCS object list response.
type GCSListResponse struct {
	Kind  string      `json:"kind"`
	Items []GCSObject `json:"items"`
}

// GCSObject mimics the structure of a GCS object resource with ContentType.
type GCSObject struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Bucket      string `json:"bucket"`
	Size        string `json:"size"`
	ContentType string `json:"contentType"`
}

func handleRequests(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	log.Printf("Received request: %s %s", r.Method, path)

	switch r.Method {
	case "GET":
		if strings.HasPrefix(path, "/health") {
			healthHandler(w, r)
			return
		}
		if strings.HasPrefix(path, "/storage/v1/b/") && strings.HasSuffix(path, "/o") {
			handleListObjects(w, r)
			return
		}
		// route for getting an object (either path-style or API-style)
		handleGetObject(w, r)
	case "POST":
		// route for creating a bucket: /storage/v1/b
		if path == "/storage/v1/b" {
			handleCreateBucket(w, r)
			return
		}
		// route for uploading an object: /upload/storage/v1/b/{bucket}/o
		if strings.HasPrefix(path, "/upload/storage/v1/b/") {
			handleUploadObject(w, r)
			return
		}
	default:
		http.NotFound(w, r)
	}
}

// healthHandler responds with a simple "OK" message.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

// handleCreateBucket creates a new, empty bucket.
func handleCreateBucket(w http.ResponseWriter, r *http.Request) {
	var bucketInfo struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&bucketInfo); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	bucketName := bucketInfo.Name
	if _, exists := inMemoryStore[bucketName]; exists {
		http.Error(w, "bucket already exists", http.StatusConflict)
		return
	}
	inMemoryStore[bucketName] = make(map[string]ObjectData)
	log.Printf("created bucket: %s", bucketName)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(bucketInfo)
}

// handleUploadObject uploads a new file to a bucket.
func handleUploadObject(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 5 {
		http.Error(w, "invalid upload URL", http.StatusBadRequest)
		return
	}
	bucketName := pathParts[4]
	objectName := r.URL.Query().Get("name")
	if objectName == "" {
		http.Error(w, "missing 'name' query parameter", http.StatusBadRequest)
		return
	}

	if _, ok := inMemoryStore[bucketName]; !ok {
		http.Error(w, "bucket not found", http.StatusNotFound)
		return
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	inMemoryStore[bucketName][objectName] = ObjectData{
		Data:        data,
		ContentType: contentType,
	}
	log.Printf("uploaded object '%s' to bucket '%s' with Content-Type '%s'", objectName, bucketName, contentType)

	response := GCSObject{
		Kind:        "storage#object",
		Name:        objectName,
		Bucket:      bucketName,
		Size:        strconv.Itoa(len(data)),
		ContentType: contentType,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGetObject is for retrieving an object from a bucket.
func handleGetObject(w http.ResponseWriter, r *http.Request) {
	var bucketName, objectName string
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")

	if strings.HasPrefix(path, "storage/v1/b/") {
		// api style: /storage/v1/b/{bucket}/o/{object}
		if len(parts) >= 6 {
			bucketName, objectName = parts[3], parts[5]
		}
	} else {
		// path style: /{bucket}/{object}
		if len(parts) >= 2 {
			bucketName, objectName = parts[0], parts[1]
		}
	}

	if bucketName == "" || objectName == "" {
		http.Error(w, "not found: invalid URL format", http.StatusNotFound)
		return
	}

	if bucket, ok := inMemoryStore[bucketName]; ok {
		if object, ok := bucket[objectName]; ok {
			w.Header().Set("Content-Type", object.ContentType)
			w.Write(object.Data)
			return
		}
	}
	http.Error(w, "not found", http.StatusNotFound)
}

// handleListObjects lists all objects in a bucket.
func handleListObjects(w http.ResponseWriter, r *http.Request) {
	bucketName := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[3]

	if bucket, ok := inMemoryStore[bucketName]; ok {
		response := GCSListResponse{
			Kind:  "storage#objects",
			Items: []GCSObject{},
		}
		for name, object := range bucket {
			item := GCSObject{
				Kind:        "storage#object",
				Name:        name,
				Bucket:      bucketName,
				Size:        strconv.Itoa(len(object.Data)),
				ContentType: object.ContentType,
			}
			response.Items = append(response.Items, item)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func main() {
	host := flag.String("host", "localhost", "host to listen on")
	port := flag.String("port", "4443", "port to listen on")
	flag.Parse()

	addr := fmt.Sprintf("%s:%s", *host, *port)

	fmt.Printf("Starting mock GCS server on http://%s\n", addr)
	fmt.Println("Store is empty. Create buckets and objects via API calls.")

	http.HandleFunc("/", handleRequests)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
