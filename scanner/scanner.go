package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Manager keeps track of all scan jobs.
type Manager struct {
	mu   sync.RWMutex
	jobs map[string]*ScanJob
}

// NewManager creates a new scan manager.
func NewManager() *Manager {
	return &Manager{jobs: make(map[string]*ScanJob)}
}

// GetJob returns a scan job by ID.
func (m *Manager) GetJob(id string) (*ScanJob, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, false
	}
	// Return a snapshot to avoid races.
	snapshot := *j
	snapshot.Findings = make([]Finding, len(j.Findings))
	copy(snapshot.Findings, j.Findings)
	return &snapshot, true
}

// StartScan launches a new scan job in the background and returns its ID.
func (m *Manager) StartScan(req ScanRequest) string {
	id := fmt.Sprintf("%d", time.Now().UnixNano())

	job := &ScanJob{
		ID:        id,
		Status:    StatusRunning,
		StartedAt: time.Now(),
		Findings:  []Finding{},
	}

	m.mu.Lock()
	m.jobs[id] = job
	m.mu.Unlock()

	go m.runScan(job, req)
	return id
}

func (m *Manager) runScan(job *ScanJob, req ScanRequest) {
	defer func() {
		m.mu.Lock()
		now := time.Now()
		job.FinishedAt = &now
		if job.Status == StatusRunning {
			job.Status = StatusComplete
		}
		m.mu.Unlock()
	}()

	// Build the full list of test cases.
	type testCase struct {
		op       OperationTarget
		arg      Arg
		category Category
		payload  string
	}

	var cases []testCase
	for _, op := range req.Operations {
		for _, arg := range op.Args {
			// Only inject into string-like arguments.
			if !isInjectable(arg.TypeName) {
				continue
			}
			for _, cat := range req.Categories {
				payloads := Payloads[cat]
				// Append custom payloads if any.
				if custom, ok := req.CustomPayloads[cat]; ok {
					payloads = append(payloads, custom...)
				}
				for _, p := range payloads {
					cases = append(cases, testCase{op: op, arg: arg, category: cat, payload: p})
				}
			}
		}
	}

	m.mu.Lock()
	job.Progress.Total = len(cases)
	m.mu.Unlock()

	if len(cases) == 0 {
		return
	}

	// Semaphore for concurrency control (2 concurrent requests).
	sem := make(chan struct{}, 2)
	var completed atomic.Int64
	var findingID atomic.Int64

	// Baseline cache: operation name → response body.
	baselineCache := &sync.Map{}

	var wg sync.WaitGroup

	for _, tc := range cases {
		wg.Add(1)
		sem <- struct{}{}

		// Rate limiting
		if req.RateLimit > 0 {
			time.Sleep(time.Duration(req.RateLimit) * time.Millisecond)
		}

		go func(tc testCase) {
			defer wg.Done()
			defer func() { <-sem }()

			// Get or fetch baseline.
			baselineBody := m.getBaseline(baselineCache, tc.op, req)

			// Build injected query.
			injectedQuery := injectPayload(tc.op.Query, tc.arg.Name, tc.payload)

			// Send injected request.
			respBody, statusCode, err := sendGraphQL(req.URL, req.Headers, injectedQuery)
			if err != nil || statusCode == 406 {
				done := completed.Add(1)
				m.mu.Lock()
				job.Progress.Completed = int(done)
				m.mu.Unlock()
				return
			}

			// Detect vulnerabilities.
			var evidence, description string

			// XSS-specific detection: check if payload is reflected.
			if tc.category == CategoryXSSReflected || tc.category == CategoryXSSStored {
				if xssEvidence := DetectXSSReflection(tc.payload, respBody); xssEvidence != "" {
					meta := CategoryMeta[tc.category]
					evidence = xssEvidence
					description = fmt.Sprintf("%s detected. %s", meta.Name, xssEvidence)
				}
			}

			// 1. Error-based detection.
			if evidence == "" {
				if sig := DetectErrorBased(tc.category, respBody); sig != "" {
					meta := CategoryMeta[tc.category]
					evidence = sig
					description = fmt.Sprintf("%s detected via error-based analysis. "+
						"The response contains '%s' which indicates the injected payload "+
						"was interpreted by the backend.", meta.Name, sig)
				}
			}

			// 2. Response diff detection (only if error-based didn't match).
			if evidence == "" {
				if diff := DetectResponseDiff(baselineBody, respBody); diff != "" {
					meta := CategoryMeta[tc.category]
					evidence = diff
					description = fmt.Sprintf("Potential %s detected via response diff. %s",
						meta.Name, diff)
				}
			}

			if evidence != "" {
				fid := findingID.Add(1)
				meta := CategoryMeta[tc.category]
				finding := Finding{
					ID:           fmt.Sprintf("F-%d", fid),
					Category:     tc.category,
					Severity:     meta.Severity,
					Operation:    tc.op.Name,
					Argument:     tc.arg.Name,
					Payload:      tc.payload,
					Evidence:     evidence,
					Description:  description,
					BaselineBody: truncate(baselineBody, 2000),
					InjectedBody: truncate(respBody, 2000),
					StatusCode:   statusCode,
				}

				m.mu.Lock()
				job.Findings = append(job.Findings, finding)
				m.mu.Unlock()
			}

			done := completed.Add(1)
			m.mu.Lock()
			job.Progress.Completed = int(done)
			m.mu.Unlock()
		}(tc)
	}

	wg.Wait()

	// Run CSRF tests if the CSRF category is selected.
	for _, cat := range req.Categories {
		if cat == CategoryCSRF {
			var mutations []OperationTarget
			for _, op := range req.Operations {
				if !op.IsQuery {
					mutations = append(mutations, op)
				}
			}
			csrfFindings := RunCSRFTests(req.URL, req.Headers, mutations)
			m.mu.Lock()
			job.Findings = append(job.Findings, csrfFindings...)
			m.mu.Unlock()
			break
		}
	}
}

// getBaseline fetches or returns cached baseline response for an operation.
func (m *Manager) getBaseline(cache *sync.Map, op OperationTarget, req ScanRequest) string {
	if v, ok := cache.Load(op.Name); ok {
		return v.(string)
	}
	body, _, _ := sendGraphQL(req.URL, req.Headers, op.Query)
	cache.Store(op.Name, body)
	return body
}

// sendGraphQL sends a GraphQL query to the target URL and returns the response body and status.
func sendGraphQL(targetURL string, headers map[string]string, query string) (string, int, error) {
	payload := map[string]string{"query": query}
	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return "", 0, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(jsonBody))
	if err != nil {
		return "", 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return "", resp.StatusCode, err
	}

	return string(respBytes), resp.StatusCode, nil
}

// injectPayload replaces the value of a named argument in a GraphQL query string.
func injectPayload(query, argName, payload string) string {
	// Look for patterns like:  argName: "value"  or  argName: value
	// and replace the value with the payload.

	// Try quoted value first: argName: "..."
	patterns := []struct {
		prefix string
		quoted bool
	}{
		{argName + `: "`, true},
		{argName + `: `, false},
	}

	for _, p := range patterns {
		idx := strings.Index(query, p.prefix)
		if idx < 0 {
			continue
		}
		start := idx + len(p.prefix)
		if p.quoted {
			// Find the closing quote.
			end := strings.Index(query[start:], `"`)
			if end < 0 {
				continue
			}
			escaped := strings.ReplaceAll(payload, `"`, `\"`)
			return query[:start] + escaped + query[start+end:]
		}
		// Unquoted: find the next comma, paren, or newline.
		end := strings.IndexAny(query[start:], ",)\n ")
		if end < 0 {
			end = len(query) - start
		}
		// Wrap payload in quotes for string injection.
		escaped := strings.ReplaceAll(payload, `"`, `\"`)
		return query[:idx] + argName + `: "` + escaped + `"` + query[start+end:]
	}

	// Fallback: couldn't find the argument, return original with payload appended as comment.
	return query
}

// isInjectable returns true if the GraphQL type is suitable for injection.
func isInjectable(typeName string) bool {
	t := strings.ToLower(strings.TrimRight(typeName, "![]"))
	switch t {
	case "string", "id":
		return true
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... (truncated)"
}
