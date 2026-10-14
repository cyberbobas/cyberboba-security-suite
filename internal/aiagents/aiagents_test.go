package aiagents

import "testing"

func TestMatchHost(t *testing.T) {
	cases := map[string]string{
		"api.anthropic.com":                 "claude",
		"api.openai.com":                    "codex",
		"generativelanguage.googleapis.com": "gemini",
		"api.x.ai":                          "grok",
		"foo.cursor.sh":                     "cursor",
		"example.com":                       "",
		"api.anthropic.com.evil.example":    "",
		"notcursor.sh":                      "",
	}
	for host, want := range cases {
		a, ok := MatchHost(host)
		if want == "" {
			if ok {
				t.Errorf("%s: expected no match, got %s", host, a.Key)
			}
			continue
		}
		if !ok || a.Key != want {
			t.Errorf("%s: want %s, got %q (ok=%v)", host, want, a.Key, ok)
		}
	}
}

func TestMatchProc(t *testing.T) {
	if a, ok := MatchProc("claude", "/usr/bin/claude --dangerously"); !ok || a.Key != "claude" {
		t.Errorf("claude comm: got %q ok=%v", a.Key, ok)
	}
	if a, ok := MatchProc("node", "node /home/u/.local/bin/aider --model gpt-4o"); !ok || a.Key != "aider" {
		t.Errorf("aider via node: got %q ok=%v", a.Key, ok)
	}
	if _, ok := MatchProc("bash", "grep claude foo.txt"); ok {
		t.Error("should not match grep argument 'claude'")
	}
	if _, ok := MatchProc("sshd", ""); ok {
		t.Error("unrelated process matched")
	}
}
