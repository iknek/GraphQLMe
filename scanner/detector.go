package scanner

import (
	"strings"
)

// errorSignatures maps categories to strings that indicate a successful injection
// when found in the HTTP response body.
var errorSignatures = map[Category][]string{
	CategorySQLi: {
		// MySQL
		"you have an error in your sql syntax",
		"warning: mysql_",
		"unclosed quotation mark",
		"mysql_fetch",
		"mysql_num_rows",
		"mysql_query",
		// PostgreSQL
		"pg_query",
		"pg_exec",
		"psqlexception",
		"unterminated quoted string",
		"syntax error at or near",
		// MSSQL
		"microsoft ole db provider",
		"unclosed quotation mark after the character string",
		"microsoft sql native client error",
		"mssql_query",
		"odbc sql server driver",
		// SQLite
		"sqlite3.operationalerror",
		"sqlite_error",
		"unrecognized token",
		"near \".\"",
		// Oracle
		"ora-01756",
		"ora-00933",
		"oracle error",
		"quoted string not properly terminated",
		// Generic
		"sql syntax",
		"sql error",
		"syntax error",
		"invalid query",
		"database error",
	},
	CategoryNoSQLi: {
		"$where",
		"$gt",
		"$ne",
		"mongoclient",
		"mongoerror",
		"bson",
		"objectid",
		"json_decode",
		"unexpected token",
		"illegal operator",
	},
	CategorySSTI: {
		"49",          // 7*7 result
		"jinja2",
		"mako",
		"smarty",
		"twig",
		"freemarker",
		"velocity",
		"thymeleaf",
		"template error",
		"templatenotfound",
		"templatesyntaxerror",
		"undefined variable",
	},
	CategoryCommandInject: {
		"uid=",           // id command output
		"root:",          // /etc/passwd content
		"bin/bash",
		"bin/sh",
		"/usr/sbin",
		"www-data",
		"daemon",
		"nobody",
		"command not found",
		"sh:",
		"bash:",
		"[fonts]",        // win.ini content
		"for 16-bit app support",
	},
	CategoryPathTraversal: {
		"root:x:",          // /etc/passwd
		"root:*:",
		"bin/bash",
		"bin/sh",
		"daemon:",
		"[fonts]",          // win.ini
		"for 16-bit app support",
		"[extensions]",
		"/usr/sbin/nologin",
		"proc/self",
	},
}

// DetectErrorBased checks if the response body contains error signatures
// that indicate a successful injection for the given category.
// Returns the matched evidence string, or empty if no match.
func DetectErrorBased(category Category, responseBody string) string {
	lower := strings.ToLower(responseBody)
	sigs, ok := errorSignatures[category]
	if !ok {
		return ""
	}
	for _, sig := range sigs {
		if strings.Contains(lower, sig) {
			return sig
		}
	}
	return ""
}

// DetectResponseDiff compares a baseline response with an injected response.
// Returns a description of the difference if significant, or empty if similar.
func DetectResponseDiff(baseline, injected string) string {
	// Significant size change (>30% or large absolute change)
	baseLen := len(baseline)
	injLen := len(injected)

	if baseLen == 0 && injLen == 0 {
		return ""
	}

	absDiff := injLen - baseLen
	if absDiff < 0 {
		absDiff = -absDiff
	}

	// If the responses are identical, no finding.
	if baseline == injected {
		return ""
	}

	// Small responses: any significant structural change matters
	if baseLen < 100 && injLen < 100 {
		// Check if error structure changed
		baseHasErrors := strings.Contains(baseline, `"errors"`)
		injHasErrors := strings.Contains(injected, `"errors"`)
		if !baseHasErrors && injHasErrors {
			return "Injection caused new error response"
		}
		if baseHasErrors && !injHasErrors {
			return "Injection bypassed error response — possible injection"
		}
	}

	// Size-based anomaly
	if baseLen > 0 {
		ratio := float64(absDiff) / float64(baseLen)
		if ratio > 0.3 && absDiff > 50 {
			if injLen > baseLen {
				return "Response significantly larger (+%d bytes) — possible data leak"
			}
			return "Response significantly smaller (-%d bytes) — possible bypass"
		}
	}

	// Check if injected response has data where baseline had errors
	baseHasErrors := strings.Contains(baseline, `"errors"`)
	injHasData := strings.Contains(injected, `"data"`) && !strings.Contains(injected, `"data":null`)
	if baseHasErrors && injHasData {
		return "Injection produced data where baseline had errors — likely injection"
	}

	return ""
}
