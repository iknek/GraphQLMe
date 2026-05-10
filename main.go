package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"graphqlme/scanner"
	"io"
	"net/http"
	"os"
	"strings"
)

//go:embed index.html style.css js
var staticFiles embed.FS

const schemaFile = "schema.json"
const maxBodySize = 100 << 20 // 100 MB

var scanManager = scanner.NewManager()

func main() {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(staticFiles)))
	mux.HandleFunc("/api/proxy", handleProxy)
	mux.HandleFunc("/api/schema", handleSchema)
	mux.HandleFunc("/api/security/scan", handleScan)
	mux.HandleFunc("/api/security/scan/", handleScanResult)

	fmt.Println("GraphQL Tool running at http://localhost:8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// handleProxy forwards a GraphQL request to the target endpoint.
// This avoids CORS issues when querying third-party GraphQL APIs.
// NOTE: This is intended for local development use only.
func handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL     string            `json:"url"`
		Body    json.RawMessage   `json:"body"`
		Headers map[string]string `json:"headers"`
	}

	limited := http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := json.NewDecoder(limited).Decode(&req); err != nil {
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	httpReq, err := http.NewRequest(http.MethodPost, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusBadRequest)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleSchema manages the saved schema file.
//
//	GET  → return the saved schema
//	POST → save the schema to disk
func handleSchema(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(schemaFile)
		if err != nil {
			http.Error(w, "No saved schema found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)

	case http.MethodPost:
		limited := http.MaxBytesReader(w, r.Body, maxBodySize)
		data, err := io.ReadAll(limited)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		var pretty bytes.Buffer
		if err := json.Indent(&pretty, data, "", "  "); err == nil {
			data = pretty.Bytes()
		}

		if err := os.WriteFile(schemaFile, data, 0600); err != nil {
			http.Error(w, "Failed to save schema", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"saved"}`))

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleScan starts a new security scan.
// POST → start scan, returns scan ID.
func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req scanner.ScanRequest
	limited := http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := json.NewDecoder(limited).Decode(&req); err != nil {
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}
	if len(req.Operations) == 0 {
		http.Error(w, "At least one operation is required", http.StatusBadRequest)
		return
	}
	if len(req.Categories) == 0 {
		http.Error(w, "At least one category is required", http.StatusBadRequest)
		return
	}

	id := scanManager.StartScan(req)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

// handleScanResult returns scan status/results or a markdown report.
// GET /api/security/scan/{id} → scan status + findings.
// GET /api/security/scan/{id}/report → markdown report.
func handleScanResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/security/scan/")
	isReport := false
	if strings.HasSuffix(path, "/report") {
		path = strings.TrimSuffix(path, "/report")
		isReport = true
	}

	if path == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	job, ok := scanManager.GetJob(path)
	if !ok {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	if isReport {
		report := scanner.GenerateMarkdownReport(job)
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=scan-%s.md", job.ID))
		w.Write([]byte(report))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}
