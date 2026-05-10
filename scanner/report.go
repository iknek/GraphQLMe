package scanner

import (
	"fmt"
	"strings"
	"time"
)

// GenerateMarkdownReport produces a Markdown report from a completed scan.
func GenerateMarkdownReport(job *ScanJob) string {
	var b strings.Builder

	b.WriteString("# GraphQLMe Auditor — Security Scan Report\n\n")
	b.WriteString(fmt.Sprintf("**Scan ID:** %s  \n", job.ID))
	b.WriteString(fmt.Sprintf("**Started:** %s  \n", job.StartedAt.Format(time.RFC3339)))
	if job.FinishedAt != nil {
		b.WriteString(fmt.Sprintf("**Finished:** %s  \n", job.FinishedAt.Format(time.RFC3339)))
		b.WriteString(fmt.Sprintf("**Duration:** %s  \n", job.FinishedAt.Sub(job.StartedAt).Round(time.Millisecond)))
	}
	b.WriteString(fmt.Sprintf("**Status:** %s  \n", job.Status))
	b.WriteString(fmt.Sprintf("**Tests Run:** %d  \n", job.Progress.Total))
	b.WriteString(fmt.Sprintf("**Findings:** %d  \n\n", len(job.Findings)))

	// Summary table
	if len(job.Findings) == 0 {
		b.WriteString("## No vulnerabilities detected\n\n")
		b.WriteString("The scan completed without finding any injection vulnerabilities.\n")
		return b.String()
	}

	// Count by severity
	counts := map[Severity]int{}
	for _, f := range job.Findings {
		counts[f.Severity]++
	}

	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|-------|\n")
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		if c, ok := counts[sev]; ok {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", sev, c))
		}
	}
	b.WriteString("\n")

	// Findings
	b.WriteString("## Findings\n\n")

	for i, f := range job.Findings {
		meta := CategoryMeta[f.Category]
		b.WriteString(fmt.Sprintf("### %d. [%s] %s — `%s.%s`\n\n", i+1, f.Severity, meta.Name, f.Operation, f.Argument))
		b.WriteString(fmt.Sprintf("**Category:** %s  \n", meta.Name))
		b.WriteString(fmt.Sprintf("**Operation:** %s  \n", f.Operation))
		b.WriteString(fmt.Sprintf("**Argument:** %s  \n", f.Argument))
		b.WriteString(fmt.Sprintf("**HTTP Status:** %d  \n\n", f.StatusCode))
		b.WriteString(fmt.Sprintf("**Description:** %s\n\n", f.Description))

		b.WriteString("**Payload:**\n```\n")
		b.WriteString(f.Payload)
		b.WriteString("\n```\n\n")

		b.WriteString("**Evidence:**\n```\n")
		b.WriteString(f.Evidence)
		b.WriteString("\n```\n\n")

		if f.BaselineBody != "" {
			b.WriteString("<details><summary>Baseline Response</summary>\n\n```json\n")
			b.WriteString(f.BaselineBody)
			b.WriteString("\n```\n</details>\n\n")
		}

		if f.InjectedBody != "" {
			b.WriteString("<details><summary>Injected Response</summary>\n\n```json\n")
			b.WriteString(f.InjectedBody)
			b.WriteString("\n```\n</details>\n\n")
		}

		b.WriteString("---\n\n")
	}

	return b.String()
}
