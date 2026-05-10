package scanner

import "time"

// Severity levels for findings.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Category of injection test.
type Category string

const (
	CategorySQLi          Category = "SQL_INJECTION"
	CategoryNoSQLi        Category = "NOSQL_INJECTION"
	CategorySSTI          Category = "SSTI"
	CategoryCommandInject Category = "COMMAND_INJECTION"
	CategoryPathTraversal Category = "PATH_TRAVERSAL"
)

// CategoryMeta maps category to display name and auto-severity.
var CategoryMeta = map[Category]struct {
	Name     string
	Severity Severity
}{
	CategorySQLi:          {"SQL Injection", SeverityCritical},
	CategoryNoSQLi:        {"NoSQL Injection", SeverityCritical},
	CategorySSTI:          {"Server-Side Template Injection", SeverityCritical},
	CategoryCommandInject: {"OS Command Injection", SeverityCritical},
	CategoryPathTraversal: {"Path Traversal", SeverityHigh},
}

// ScanStatus represents the state of a scan job.
type ScanStatus string

const (
	StatusRunning  ScanStatus = "running"
	StatusComplete ScanStatus = "complete"
	StatusFailed   ScanStatus = "failed"
)

// ScanRequest is sent by the frontend to start a scan.
type ScanRequest struct {
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	Operations []OperationTarget `json:"operations"`
	Categories []Category        `json:"categories"`
	// CustomPayloads maps category → list of extra payloads to try.
	CustomPayloads map[Category][]string `json:"customPayloads,omitempty"`
	// RateLimit is the delay in milliseconds between requests.
	RateLimit int `json:"rateLimit,omitempty"`
}

// OperationTarget identifies a query or mutation to test.
type OperationTarget struct {
	Name     string `json:"name"`
	IsQuery  bool   `json:"isQuery"`
	Query    string `json:"query"`    // the full GraphQL query string
	Args     []Arg  `json:"args"`     // arguments with their types
}

// Arg describes a GraphQL argument to inject into.
type Arg struct {
	Name     string `json:"name"`
	TypeName string `json:"typeName"` // e.g. "String", "ID", "Int"
}

// Finding represents a single detected vulnerability.
type Finding struct {
	ID            string   `json:"id"`
	Category      Category `json:"category"`
	Severity      Severity `json:"severity"`
	Operation     string   `json:"operation"`
	Argument      string   `json:"argument"`
	Payload       string   `json:"payload"`
	Evidence      string   `json:"evidence"`
	Description   string   `json:"description"`
	BaselineBody  string   `json:"baselineBody"`
	InjectedBody  string   `json:"injectedBody"`
	StatusCode    int      `json:"statusCode"`
}

// ScanJob holds the state of an in-progress or completed scan.
type ScanJob struct {
	ID         string     `json:"id"`
	Status     ScanStatus `json:"status"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	Findings   []Finding  `json:"findings"`
	Progress   Progress   `json:"progress"`
	Error      string     `json:"error,omitempty"`
}

// Progress tracks how far along the scan is.
type Progress struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
}
