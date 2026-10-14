package intercept

import (
	"regexp"
	"strings"
)

// Finding is one passive-scan observation about a flow.
type Finding struct {
	Rule     string `json:"rule"`     // short stable id, e.g. "secret.aws-key"
	Title    string `json:"title"`    // human label
	Severity string `json:"severity"` // high | medium | low | info
	Where    string `json:"where"`    // where it was seen
	Detail   string `json:"detail"`   // short, redacted explanation
}

type secretPat struct {
	rule  string
	title string
	sev   string
	re    *regexp.Regexp
}

// Secret / token patterns checked in request + response bodies and headers.
var secretPats = []secretPat{
	{"secret.aws-key", "AWS access key id", "high", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"secret.aws-secret", "Possible AWS secret key", "high", regexp.MustCompile(`(?i)aws_secret_access_key["'\s:=]+[A-Za-z0-9/+]{40}`)},
	{"secret.gcp-key", "Google API key", "high", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"secret.github-pat", "GitHub token", "high", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`)},
	{"secret.slack", "Slack token", "high", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,}`)},
	{"secret.stripe", "Stripe secret key", "high", regexp.MustCompile(`sk_live_[0-9A-Za-z]{16,}`)},
	{"secret.openai", "OpenAI/API key", "high", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)},
	{"secret.private-key", "Private key block", "high", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"secret.jwt", "JSON Web Token", "medium", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	{"secret.generic", "Possible credential in parameter", "medium", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token)["'\s]*[:=]["'\s]*[A-Za-z0-9/+_\-]{8,}`)},
}

// scanFlow runs all passive checks and returns the findings (most severe first
// implied by append order; the API re-ranks). reqBody/respBody may be nil.
func scanFlow(f *Flow, reqBody, respBody []byte) []Finding {
	var out []Finding
	seen := map[string]bool{}
	add := func(fd Finding) {
		k := fd.Rule + "|" + fd.Where
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, fd)
	}

	reqHdr := joinHeaders(f.ReqHeaders)
	respHdr := joinHeaders(f.RespHeaders)

	// 1. secrets in headers and bodies
	scanSecrets := func(where, text string) {
		if text == "" {
			return
		}
		for _, p := range secretPats {
			if p.re.MatchString(text) {
				add(Finding{Rule: p.rule, Title: p.title, Severity: p.sev, Where: where,
					Detail: p.title + " pattern matched in " + where + "."})
			}
		}
	}
	scanSecrets("request headers", reqHdr)
	scanSecrets("request body", string(reqBody))
	scanSecrets("response headers", respHdr)
	scanSecrets("response body", string(respBody))

	// credentials/secrets sent over plain HTTP (no TLS) are worse
	if !f.TLS {
		if hasAuth(f.ReqHeaders) || secretPats[9].re.MatchString(string(reqBody)) || strings.Contains(strings.ToLower(f.URL), "password=") {
			add(Finding{Rule: "transport.cleartext-secret", Title: "Credentials sent over plain HTTP", Severity: "high",
				Where: "request", Detail: "An Authorization header, credential parameter or token is sent without TLS; it can be read on the wire."})
		}
	}

	// 2. cookies
	for _, h := range f.RespHeaders {
		if !strings.EqualFold(h[0], "Set-Cookie") {
			continue
		}
		lc := strings.ToLower(h[1])
		name := cookieName(h[1])
		if f.TLS && !strings.Contains(lc, "secure") {
			add(Finding{Rule: "cookie.no-secure", Title: "Cookie without Secure flag", Severity: "low",
				Where: "Set-Cookie " + name, Detail: "Cookie " + name + " is set over HTTPS without the Secure flag, so it may leak over HTTP."})
		}
		if !strings.Contains(lc, "httponly") {
			add(Finding{Rule: "cookie.no-httponly", Title: "Cookie without HttpOnly", Severity: "low",
				Where: "Set-Cookie " + name, Detail: "Cookie " + name + " is readable from JavaScript (no HttpOnly), widening XSS impact."})
		}
		if !strings.Contains(lc, "samesite") {
			add(Finding{Rule: "cookie.no-samesite", Title: "Cookie without SameSite", Severity: "info",
				Where: "Set-Cookie " + name, Detail: "Cookie " + name + " has no SameSite attribute (CSRF hardening)."})
		}
	}

	// 3. security headers on HTML/text responses
	ct := strings.ToLower(f.ContentType)
	isDoc := strings.Contains(ct, "text/html") || (ct == "" && f.Status >= 200 && f.Status < 400 && len(respBody) > 0)
	if isDoc && f.Status >= 200 && f.Status < 400 {
		miss := func(name, rule, detail string) {
			if getHeader(f.RespHeaders, name) == "" {
				add(Finding{Rule: rule, Title: "Missing " + name, Severity: "low", Where: "response headers", Detail: detail})
			}
		}
		if getHeader(f.RespHeaders, "Content-Security-Policy") == "" {
			add(Finding{Rule: "header.no-csp", Title: "Missing Content-Security-Policy", Severity: "low",
				Where: "response headers", Detail: "No CSP: the page has no first line of defence against injected scripts."})
		}
		if f.TLS {
			miss("Strict-Transport-Security", "header.no-hsts", "No HSTS: browsers may still try this site over plain HTTP.")
		}
		miss("X-Content-Type-Options", "header.no-nosniff", "No X-Content-Type-Options: browsers may MIME-sniff responses.")
		miss("X-Frame-Options", "header.no-xfo", "No X-Frame-Options and no frame-ancestors CSP: possible clickjacking.")
	}

	// 4. CORS wildcard with credentials
	if acao := getHeader(f.RespHeaders, "Access-Control-Allow-Origin"); acao == "*" {
		if strings.EqualFold(getHeader(f.RespHeaders, "Access-Control-Allow-Credentials"), "true") {
			add(Finding{Rule: "cors.wildcard-creds", Title: "CORS: wildcard origin with credentials", Severity: "medium",
				Where: "response headers", Detail: "Access-Control-Allow-Origin: * together with credentials exposes authenticated data cross-origin."})
		} else {
			add(Finding{Rule: "cors.wildcard", Title: "CORS: wildcard Access-Control-Allow-Origin", Severity: "info",
				Where: "response headers", Detail: "Any site can read this response."})
		}
	}

	// 5. version / tech disclosure
	if srv := getHeader(f.RespHeaders, "Server"); srv != "" && strings.ContainsAny(srv, "0123456789") {
		add(Finding{Rule: "disclosure.server", Title: "Server version disclosed", Severity: "info",
			Where: "Server header", Detail: "Server: " + srv})
	}
	if xp := getHeader(f.RespHeaders, "X-Powered-By"); xp != "" {
		add(Finding{Rule: "disclosure.powered-by", Title: "Technology disclosed (X-Powered-By)", Severity: "info",
			Where: "X-Powered-By header", Detail: "X-Powered-By: " + xp})
	}

	// 6. mixed content: HTTPS doc referencing http:// resources
	if f.TLS && isDoc && len(respBody) > 0 {
		if mixedRe.Match(respBody) {
			add(Finding{Rule: "mixed-content", Title: "Mixed content (http:// resource on HTTPS page)", Severity: "low",
				Where: "response body", Detail: "The HTTPS page references resources over plain http://, which browsers may block or downgrade security."})
		}
	}

	return out
}

var mixedRe = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']http://`)

func joinHeaders(hs []Header) string {
	var b strings.Builder
	for _, h := range hs {
		b.WriteString(h[0])
		b.WriteString(": ")
		b.WriteString(h[1])
		b.WriteByte('\n')
	}
	return b.String()
}

func getHeader(hs []Header, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

func hasAuth(hs []Header) bool {
	for _, h := range hs {
		if strings.EqualFold(h[0], "Authorization") || strings.EqualFold(h[0], "Proxy-Authorization") {
			return true
		}
		if strings.EqualFold(h[0], "Cookie") && h[1] != "" {
			return true
		}
	}
	return false
}

// capBody limits the bytes the regex scanners look at, keeping scanning cheap
// for large bodies while still catching secrets near the top.
func capBody(b []byte) []byte {
	const max = 256 << 10
	if len(b) > max {
		return b[:max]
	}
	return b
}

func cookieName(setCookie string) string {
	if i := strings.IndexByte(setCookie, '='); i > 0 {
		return strings.TrimSpace(setCookie[:i])
	}
	return "cookie"
}
