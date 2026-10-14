// Package aiagents holds a registry of well-known AI coding/CLI agents so the
// daemon can recognise them by process name or by the API host they talk to.
// This drives the "AI Agents" control centre: which agents are running, what
// endpoints they contact, and — most importantly — whether they are sending
// credentials (API keys, passwords, tokens) off the box.
package aiagents

import (
	"path/filepath"
	"strings"
)

// Agent is one known AI agent/tool.
type Agent struct {
	Key    string   `json:"key"`    // stable id
	Name   string   `json:"name"`   // friendly label
	Vendor string   `json:"vendor"` // model/provider behind it
	Procs  []string `json:"procs"`  // process names (comm) that identify it
	Hosts  []string `json:"hosts"`  // API host substrings it talks to
}

// Registry is the built-in set of recognised agents. Host matching is the
// reliable signal (api.anthropic.com is unambiguous); process matching is a
// best-effort "is it running" hint.
var Registry = []Agent{
	{"claude", "Claude Code", "Anthropic", []string{"claude"}, []string{"api.anthropic.com", "anthropic.com", "claude.ai", "statsig.anthropic.com"}},
	{"codex", "Codex / OpenAI CLI", "OpenAI", []string{"codex", "openai", "chatgpt"}, []string{"api.openai.com", "chatgpt.com", "openai.com"}},
	{"gemini", "Gemini CLI", "Google", []string{"gemini"}, []string{"generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com", "aiplatform.googleapis.com"}},
	{"grok", "Grok", "xAI", []string{"grok"}, []string{"api.x.ai", "x.ai"}},
	{"cursor", "Cursor", "Anysphere", []string{"cursor"}, []string{"api2.cursor.sh", "api3.cursor.sh", "cursor.sh", "cursor.com"}},
	{"copilot", "GitHub Copilot", "GitHub/OpenAI", []string{"copilot"}, []string{"api.githubcopilot.com", "copilot-proxy.githubusercontent.com", "githubcopilot.com"}},
	{"aider", "Aider", "multi", []string{"aider"}, nil},
	{"cline", "Cline", "multi", []string{"cline"}, nil},
	{"continue", "Continue", "multi", []string{"continue"}, []string{"api.continue.dev"}},
	{"goose", "Goose", "multi", []string{"goose"}, nil},
	{"interpreter", "Open Interpreter", "multi", []string{"interpreter", "open-interpreter"}, nil},
	{"cody", "Sourcegraph Cody", "Sourcegraph", []string{"cody"}, []string{"sourcegraph.com"}},
	{"windsurf", "Windsurf / Codeium", "Codeium", []string{"windsurf", "codeium"}, []string{"codeium.com", "windsurf.com", "server.codeium.com"}},
	{"ollama", "Ollama (local)", "local", []string{"ollama"}, []string{"ollama.com", "registry.ollama.ai"}},
	{"deepseek", "DeepSeek", "DeepSeek", []string{"deepseek"}, []string{"api.deepseek.com"}},
	{"mistral", "Mistral", "Mistral", []string{"mistral"}, []string{"api.mistral.ai"}},
	{"perplexity", "Perplexity", "Perplexity", []string{"pplx", "perplexity"}, []string{"api.perplexity.ai"}},
	{"qwen", "Qwen Code", "Alibaba", []string{"qwen"}, []string{"dashscope.aliyuncs.com"}},
}

// byKey indexes the registry.
var byKey = func() map[string]Agent {
	m := map[string]Agent{}
	for _, a := range Registry {
		m[a.Key] = a
	}
	return m
}()

// ByKey returns the agent with the given key.
func ByKey(key string) (Agent, bool) { a, ok := byKey[key]; return a, ok }

// interpreters whose first real argument is the script to inspect.
var interpreters = map[string]bool{
	"node": true, "nodejs": true, "bun": true, "deno": true, "python": true,
	"python3": true, "python2": true, "ruby": true, "perl": true, "uv": true, "npx": true,
}

// procTokens returns the small set of names that may identify an agent: the
// process comm, the basename of argv[0], and — only when argv[0] is a known
// interpreter — the basename of argv[1] (the script it runs). It deliberately
// does NOT scan every argument, so "grep claude foo" is not misattributed.
func procTokens(comm, cmd string) []string {
	toks := []string{}
	add := func(x string) {
		x = strings.ToLower(strings.TrimSpace(x))
		if x != "" {
			toks = append(toks, x)
		}
	}
	if comm != "" {
		add(comm)
	}
	fields := strings.Fields(cmd)
	if len(fields) > 0 {
		argv0 := strings.ToLower(filepath.Base(fields[0]))
		add(argv0)
		if interpreters[argv0] && len(fields) > 1 {
			// skip interpreter flags (e.g. python -u script)
			for _, f := range fields[1:] {
				if strings.HasPrefix(f, "-") {
					continue
				}
				add(filepath.Base(f))
				break
			}
		}
	}
	return toks
}

// MatchProc identifies an agent from a process comm and/or command line. It is
// conservative: a token must equal the agent name or be the basename
// "<name>" / "<name>.js" / "<name>-cli" of an argv element — not a loose
// substring — to avoid misattributing unrelated processes.
func MatchProc(comm, cmd string) (Agent, bool) {
	toks := procTokens(comm, cmd)
	for _, a := range Registry {
		for _, p := range a.Procs {
			for _, t := range toks {
				if t == p || t == p+".js" || t == p+"-cli" || strings.HasPrefix(t, p+".") {
					return a, true
				}
			}
		}
	}
	return Agent{}, false
}

// MatchHost identifies an agent from an API hostname it is talking to. It
// matches only on an exact host or a true dot-boundary subdomain, so a crafted
// name that merely embeds an agent host as a substring
// (e.g. "api.anthropic.com.evil.example") is NOT misattributed.
func MatchHost(host string) (Agent, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range Registry {
		for _, hs := range a.Hosts {
			if host == hs || strings.HasSuffix(host, "."+hs) {
				return a, true
			}
		}
	}
	return Agent{}, false
}

// ProcNames returns every process token across the registry (for installing
// per-app record rules covering all known agents).
func ProcNames() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, a := range Registry {
		for _, p := range a.Procs {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}
