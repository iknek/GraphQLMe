package scanner

import (
	"fmt"
	"strings"
)

// XSS testing categories.
const (
	CategoryXSSReflected Category = "XSS_REFLECTED"
	CategoryXSSStored    Category = "XSS_STORED"
)

func init() {
	CategoryMeta[CategoryXSSReflected] = struct {
		Name     string
		Severity Severity
	}{"Reflected XSS", SeverityHigh}

	CategoryMeta[CategoryXSSStored] = struct {
		Name     string
		Severity Severity
	}{"Stored XSS", SeverityHigh}

	// Add XSS payloads to the global payloads map.
	Payloads[CategoryXSSReflected] = xssPayloads
	Payloads[CategoryXSSStored] = xssPayloads
}

var xssPayloads = []string{
	`<script>alert(1)</script>`,
	`"><script>alert(1)</script>`,
	`'><script>alert(1)</script>`,
	`<img src=x onerror=alert(1)>`,
	`"><img src=x onerror=alert(1)>`,
	`<svg onload=alert(1)>`,
	`"><svg onload=alert(1)>`,
	`javascript:alert(1)`,
	`<body onload=alert(1)>`,
	`<iframe src="javascript:alert(1)">`,
	`<details open ontoggle=alert(1)>`,
	`<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">`,
	`'-alert(1)-'`,
	`\"-alert(1)-\"`,
}

// DetectXSSReflection checks if any XSS payload appears unescaped in the response.
// This detects both reflected XSS (in error messages) and stored XSS (in query results).
func DetectXSSReflection(payload, responseBody string) string {
	if strings.Contains(responseBody, payload) {
		return fmt.Sprintf("XSS payload reflected unescaped in response: %s", truncate(payload, 80))
	}

	// Check common partial reflections
	// The payload might be partially reflected (e.g., without angle brackets but with event handler)
	dangerousFragments := []string{
		"onerror=alert",
		"onload=alert",
		"ontoggle=alert",
		"<script>",
		"javascript:",
	}
	for _, frag := range dangerousFragments {
		if strings.Contains(payload, frag) && strings.Contains(responseBody, frag) {
			return fmt.Sprintf("Dangerous XSS fragment reflected: %s", frag)
		}
	}

	return ""
}

// XSSStoredCheck tests for stored XSS by:
// 1. Sending a mutation with an XSS payload
// 2. Then querying the same data back to check if the payload is stored unescaped.
// Returns a Finding if the payload is found in the query response.
func XSSStoredCheck(targetURL string, headers map[string]string,
	mutation OperationTarget, queryBack string, payload string) *Finding {

	// Step 1: Send the mutation with the XSS payload
	injectedMutation := injectPayloadAllArgs(mutation.Query, mutation.Args, payload)
	_, _, err := sendGraphQL(targetURL, headers, injectedMutation)
	if err != nil {
		return nil
	}

	// Step 2: Query the data back
	if queryBack == "" {
		return nil
	}
	respBody, statusCode, err := sendGraphQL(targetURL, headers, queryBack)
	if err != nil {
		return nil
	}

	// Step 3: Check if the payload is reflected
	evidence := DetectXSSReflection(payload, respBody)
	if evidence == "" {
		return nil
	}

	return &Finding{
		Category:    CategoryXSSStored,
		Severity:    SeverityHigh,
		Operation:   mutation.Name,
		Argument:    "(stored)",
		Payload:     payload,
		Evidence:    evidence,
		Description: "A stored XSS vulnerability was detected. The XSS payload was sent via a mutation and appeared unescaped when the data was queried back. An attacker could use this to execute JavaScript in other users' browsers.",
		InjectedBody: truncate(respBody, 2000),
		StatusCode:  statusCode,
	}
}

// injectPayloadAllArgs replaces all injectable argument values with the payload.
func injectPayloadAllArgs(query string, args []Arg, payload string) string {
	result := query
	for _, arg := range args {
		if isInjectable(arg.TypeName) {
			result = injectPayload(result, arg.Name, payload)
		}
	}
	return result
}
