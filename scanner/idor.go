package scanner

import (
	"fmt"
	"strings"
	"time"
)

// IDOR testing category.
const CategoryIDOR Category = "IDOR"

func init() {
	CategoryMeta[CategoryIDOR] = struct {
		Name     string
		Severity Severity
	}{"Insecure Direct Object Reference", SeverityHigh}
}

// idorArgPatterns are argument name patterns that suggest ID-based access control.
var idorArgPatterns = []string{
	"id", "userid", "user_id", "accountid", "account_id",
	"orderid", "order_id", "customerid", "customer_id",
	"profileid", "profile_id", "orgid", "org_id",
	"teamid", "team_id", "projectid", "project_id",
}

// idorProbeValues are ID values to test for IDOR.
var idorProbeValues = []string{
	"0",
	"1",
	"2",
	"999999",
	"-1",
	"null",
	"undefined",
}

// RunIDORTests tests for IDOR by querying with different ID values and comparing responses.
// It looks for operations with ID/Int arguments that match IDOR patterns.
func RunIDORTests(targetURL string, headers map[string]string, operations []OperationTarget, rateLimit int) []Finding {
	var findings []Finding
	findingID := 0

	for _, op := range operations {
		for _, arg := range op.Args {
			if !isIDORCandidate(arg) {
				continue
			}

			// Get baseline response with normal value
			baselineQuery := injectPayload(op.Query, arg.Name, "1")
			baselineBody, baselineStatus, err := sendGraphQL(targetURL, headers, baselineQuery)
			if err != nil || baselineStatus == 406 {
				continue
			}

			// Try each probe value
			for _, probeVal := range idorProbeValues {
				if rateLimit > 0 {
					sleepMs(rateLimit)
				}

				probeQuery := injectPayload(op.Query, arg.Name, probeVal)
				probeBody, probeStatus, err := sendGraphQL(targetURL, headers, probeQuery)
				if err != nil || probeStatus == 406 {
					continue
				}

				// Analyze the response for IDOR indicators
				evidence := analyzeIDORResponse(baselineBody, probeBody, baselineStatus, probeStatus, probeVal)
				if evidence != "" {
					findingID++
					findings = append(findings, Finding{
						ID:       fmt.Sprintf("IDOR-%d", findingID),
						Category: CategoryIDOR,
						Severity: SeverityHigh,
						Operation: op.Name,
						Argument: arg.Name,
						Payload:  probeVal,
						Evidence: evidence,
						Description: fmt.Sprintf("Potential IDOR detected on %s.%s. "+
							"Changing the %s argument to '%s' returned different data, "+
							"which may indicate access to another user's resources. "+
							"Manual verification is recommended.", op.Name, arg.Name, arg.Name, probeVal),
						BaselineBody: truncate(baselineBody, 2000),
						InjectedBody: truncate(probeBody, 2000),
						StatusCode:   probeStatus,
					})
				}
			}
		}
	}

	return findings
}

// isIDORCandidate checks if an argument is a likely IDOR target.
func isIDORCandidate(arg Arg) bool {
	lower := strings.ToLower(arg.Name)
	typeLower := strings.ToLower(strings.TrimRight(arg.TypeName, "![]"))

	// Must be ID, Int, or String type
	if typeLower != "id" && typeLower != "int" && typeLower != "string" {
		return false
	}

	// Check if the name matches IDOR patterns
	for _, pattern := range idorArgPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Also match if the arg is simply named "id"
	if lower == "id" {
		return true
	}

	return false
}

// analyzeIDORResponse compares baseline and probe responses to detect IDOR.
func analyzeIDORResponse(baseline, probe string, baselineStatus, probeStatus int, probeVal string) string {
	// Both returned errors — not interesting
	if strings.Contains(baseline, `"errors"`) && strings.Contains(probe, `"errors"`) {
		return ""
	}

	// Both returned the same data — not interesting
	if baseline == probe {
		return ""
	}

	// Probe returned data where baseline had an error
	if strings.Contains(baseline, `"errors"`) && !strings.Contains(probe, `"errors"`) {
		return fmt.Sprintf("Probe ID '%s' returned data where baseline had errors — possible unauthorized access", probeVal)
	}

	// Both returned different valid data — the most interesting case
	if !strings.Contains(baseline, `"errors"`) && !strings.Contains(probe, `"errors"`) {
		// Check if the data content is meaningfully different
		if baseline != probe && len(probe) > 10 {
			return fmt.Sprintf("Probe ID '%s' returned different data (%d bytes vs %d bytes baseline) — possible access to another user's data",
				probeVal, len(probe), len(baseline))
		}
	}

	// Probe succeeded (200) while baseline was forbidden
	if baselineStatus != 200 && probeStatus == 200 {
		return fmt.Sprintf("Probe ID '%s' returned HTTP %d while baseline returned %d — possible authorization bypass",
			probeVal, probeStatus, baselineStatus)
	}

	return ""
}

func sleepMs(ms int) {
	if ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}
