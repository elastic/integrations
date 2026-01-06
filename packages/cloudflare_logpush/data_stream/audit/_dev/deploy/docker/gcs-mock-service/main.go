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
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func main() {
	host := flag.String("host", "0.0.0.0", "host to listen on")
	port := flag.String("port", "4443", "port to listen on")
	manifest := flag.String("manifest", "", "path to YAML manifest file for preloading buckets and objects")
	flag.Parse()

	addr := fmt.Sprintf("%s:%s", *host, *port)

	fmt.Printf("Starting mock GCS server on http://%s\n", addr)
	if *manifest != "" {
		m, err := readManifest(*manifest)
		if err != nil {
			log.Fatalf("error reading manifest: %v", err)
		}
		if err := processManifest(m); err != nil {
			log.Fatalf("error processing manifest: %v", err)
		}
	} else {
		fmt.Println("Store is empty. Create buckets and objects via API calls.")
	}

	// setup HTTP handlers
	mux := http.NewServeMux()
	// health check
	mux.HandleFunc("/health", healthHandler)
	// standard gcs api calls
	mux.HandleFunc("GET /storage/v1/b/{bucket}/o", handleListObjects)
	mux.HandleFunc("GET /storage/v1/b/{bucket}/o/{object...}", handleGetObject)
	mux.HandleFunc("POST /storage/v1/b", handleCreateBucket)
	mux.HandleFunc("POST /upload/storage/v1/b/{bucket}/o", handleUploadObject)
	mux.HandleFunc("POST /upload/storage/v1/b/{bucket}/o/{object...}", handleUploadObject)
	// direct path-style gcs sdk calls
	mux.HandleFunc("GET /{bucket}/o/{object...}", handleGetObject)
	mux.HandleFunc("GET /{bucket}/{object...}", handleGetObject)
	// debug: log all requests
	loggedMux := loggingMiddleware(mux)

	if err := http.ListenAndServe(addr, loggedMux); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}

// loggingMiddleware logs incoming HTTP requests.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s\n", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// readManifest reads and parses the YAML manifest file.
func readManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &manifest, nil
}

// processManifest creates buckets and uploads objects as specified in the manifest.
func processManifest(manifest *Manifest) error {
	for bucketName, bucket := range manifest.Buckets {
		for _, file := range bucket.Files {
			fmt.Printf("preloading data for bucket: %s | path: %s | content-type: %s...\n",
				bucketName, file.Path, file.ContentType)

			if err := createBucket(bucketName); err != nil {
				return fmt.Errorf("failed to create bucket '%s': %w", bucketName, err)
			}
			data, err := os.ReadFile(file.Path)
			if err != nil {
				return fmt.Errorf("failed to read bucket data file '%s': %w", file.Path, err)
			}
			pathParts := strings.Split(file.Path, "/")
			if _, err := uploadObject(bucketName, pathParts[len(pathParts)-1], data, file.ContentType); err != nil {
				return fmt.Errorf("failed to create object '%s' in bucket '%s': %w", file.Path, bucketName, err)
			}
		}
	}
	return nil
}

// healthHandler responds with a simple "OK" message for health checks.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

// handleListObjects lists all objects in the specified bucket.
func handleListObjects(w http.ResponseWriter, r *http.Request) {
	bucketName := r.PathValue("bucket")

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

// handleGetObject retrieves a specific object from a bucket.
func handleGetObject(w http.ResponseWriter, r *http.Request) {
	bucketName := r.PathValue("bucket")
	objectName := r.PathValue("object")

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

// handleCreateBucket creates a new bucket.
func handleCreateBucket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	var bucketInfo struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&bucketInfo); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if bucketInfo.Name == "" {
		http.Error(w, "bucket name is required", http.StatusBadRequest)
		return
	}

	if err := createBucket(bucketInfo.Name); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(bucketInfo)
}

// handleUploadObject uploads an object to a specified bucket.
func handleUploadObject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	bucketName := r.PathValue("bucket")
	objectName := r.URL.Query().Get("name")
	if objectName == "" {
		objectName = r.PathValue("object")
	}

	if bucketName == "" || objectName == "" {
		http.Error(w, "missing bucket or object name", http.StatusBadRequest)
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

	response, err := uploadObject(bucketName, objectName, data, contentType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func createBucket(bucketName string) error {
	if _, exists := inMemoryStore[bucketName]; exists {
		return fmt.Errorf("bucket already exists")
	}
	inMemoryStore[bucketName] = make(map[string]ObjectData)
	log.Printf("created bucket: %s", bucketName)
	return nil
}

func uploadObject(bucketName, objectName string, data []byte, contentType string) (*GCSObject, error) {
	if _, ok := inMemoryStore[bucketName]; !ok {
		return nil, fmt.Errorf("bucket not found")
	}

	inMemoryStore[bucketName][objectName] = ObjectData{
		Data:        data,
		ContentType: contentType,
	}
	log.Printf("created object '%s' in bucket '%s' with Content-Type '%s'",
		objectName, bucketName, contentType)

	return &GCSObject{
		Kind:        "storage#object",
		Name:        objectName,
		Bucket:      bucketName,
		Size:        strconv.Itoa(len(data)),
		ContentType: contentType,
	}, nil
}

// The in-memory store to hold ObjectData structs.
var inMemoryStore = make(map[string]map[string]ObjectData)

// ObjectData stores the raw data and its content type.
type ObjectData struct {
	Data        []byte
	ContentType string
}

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

// Manifest represents the top-level structure of the YAML file
type Manifest struct {
	Buckets map[string]Bucket `yaml:"buckets"`
}

// Bucket represents each bucket and its files
type Bucket struct {
	Files []File `yaml:"files"`
}

// File represents each file entry inside a bucket
type File struct {
	Path        string `yaml:"path"`
	ContentType string `yaml:"content-type"`
}
