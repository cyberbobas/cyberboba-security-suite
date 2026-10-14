package intercept

import "testing"

func hasRule(fs []Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestScanSecretsAndHeaders(t *testing.T) {
	f := &Flow{
		TLS: true, Status: 200, ContentType: "text/html",
		ReqHeaders: []Header{{"Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij"}},
		RespHeaders: []Header{
			{"Server", "nginx/1.18.0"},
			{"Set-Cookie", "sid=abc123; Path=/"},
			{"Access-Control-Allow-Origin", "*"},
			{"Access-Control-Allow-Credentials", "true"},
		},
	}
	fs := scanFlow(f, []byte(`{"aws":"AKIAIOSFODNN7EXAMPLE"}`), []byte(`<html><body>ok</body></html>`))
	for _, want := range []string{"secret.aws-key", "secret.jwt", "cookie.no-secure", "cookie.no-httponly",
		"cors.wildcard-creds", "disclosure.server", "header.no-csp", "header.no-hsts"} {
		if !hasRule(fs, want) {
			t.Errorf("expected finding %q, got %v", want, rulesOf(fs))
		}
	}
}

func TestScanCleartextCredentials(t *testing.T) {
	f := &Flow{TLS: false, URL: "http://x/login?password=hunter2",
		ReqHeaders: []Header{{"Authorization", "Basic dXNlcjpwYXNz"}}}
	fs := scanFlow(f, nil, nil)
	if !hasRule(fs, "transport.cleartext-secret") {
		t.Fatalf("expected cleartext-secret finding, got %v", rulesOf(fs))
	}
}

func TestScanCleanFlow(t *testing.T) {
	f := &Flow{TLS: true, Status: 200, ContentType: "application/json",
		RespHeaders: []Header{
			{"Content-Security-Policy", "default-src 'self'"},
			{"Strict-Transport-Security", "max-age=63072000"},
			{"X-Content-Type-Options", "nosniff"},
			{"X-Frame-Options", "DENY"},
		}}
	fs := scanFlow(f, []byte(`{"ok":true}`), []byte(`{"ok":true}`))
	if len(fs) != 0 {
		t.Fatalf("expected no findings on a clean JSON flow, got %v", rulesOf(fs))
	}
}

func rulesOf(fs []Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}
