package intercept

import (
	"regexp"
	"strings"
	"sync"

	"cyberboba/internal/config"
	"cyberboba/internal/rules"
)

// rewriter applies configured match & replace rules to flows. Used by
// authorized testers to inject headers, strip caching, patch responses, etc.
type rewriter struct {
	mu    sync.Mutex
	cache map[string]*regexp.Regexp
}

func newRewriter() *rewriter { return &rewriter{cache: map[string]*regexp.Regexp{}} }

func (r *rewriter) re(pattern string) *regexp.Regexp {
	r.mu.Lock()
	defer r.mu.Unlock()
	if re, ok := r.cache[pattern]; ok {
		return re
	}
	re, err := regexp.Compile("(?s)" + pattern)
	if err != nil {
		re = nil
	}
	if len(r.cache) > 500 {
		r.cache = map[string]*regexp.Regexp{}
	}
	r.cache[pattern] = re
	return re
}

func hostMatch(hosts []string, host string) bool {
	if len(hosts) == 0 {
		return true
	}
	host = strings.ToLower(host)
	for _, p := range hosts {
		if rules.MatchHost(strings.ToLower(strings.TrimSpace(p)), host) {
			return true
		}
	}
	return false
}

// applyRequest mutates the request side of a flow before it is forwarded.
// Returns true if anything changed. headers are modified in place on f.
func (r *rewriter) applyRequest(rw []config.Rewrite, f *Flow, body []byte) ([]byte, bool) {
	changed := false
	for i := range rw {
		w := &rw[i]
		if !w.IsEnabled() || w.Target != "request" || !hostMatch(w.Hosts, f.Host) {
			continue
		}
		switch w.Part {
		case "header":
			if r.editHeaders(&f.ReqHeaders, w) {
				changed = true
			}
		case "url":
			if nv, ok := r.editText(f.Path, w); ok {
				f.Path = nv
				f.URL = replaceLast(f.URL, f.Path)
				changed = true
			}
		case "body":
			if nb, ok := r.editBytes(body, w); ok {
				body = nb
				changed = true
			}
		}
	}
	return body, changed
}

// applyResponse mutates the response side before it is sent to the client.
func (r *rewriter) applyResponse(rw []config.Rewrite, f *Flow, body []byte) ([]byte, bool) {
	changed := false
	for i := range rw {
		w := &rw[i]
		if !w.IsEnabled() || w.Target != "response" || !hostMatch(w.Hosts, f.Host) {
			continue
		}
		switch w.Part {
		case "header":
			if r.editHeaders(&f.RespHeaders, w) {
				changed = true
			}
		case "body":
			if nb, ok := r.editBytes(body, w); ok {
				body = nb
				changed = true
			}
		}
	}
	return body, changed
}

func (r *rewriter) editHeaders(hs *[]Header, w *config.Rewrite) bool {
	name := strings.TrimSpace(w.Header)
	if name == "" {
		return false
	}
	out := (*hs)[:0]
	found := false
	changed := false
	for _, h := range *hs {
		if strings.EqualFold(h[0], name) {
			found = true
			if w.Remove {
				changed = true
				continue // drop it
			}
			if w.Match == "" {
				if h[1] != w.Replace {
					changed = true
				}
				out = append(out, Header{h[0], w.Replace})
				continue
			}
			if nv, ok := r.editText(h[1], w); ok {
				changed = true
				out = append(out, Header{h[0], nv})
				continue
			}
		}
		out = append(out, h)
	}
	*hs = out
	if !found && !w.Remove && w.Match == "" {
		*hs = append(*hs, Header{name, w.Replace})
		changed = true
	}
	return changed
}

func (r *rewriter) editText(s string, w *config.Rewrite) (string, bool) {
	if w.Match == "" {
		return s, false
	}
	re := r.re(w.Match)
	if re == nil || !re.MatchString(s) {
		return s, false
	}
	repl := w.Replace
	if w.Remove {
		repl = ""
	}
	return re.ReplaceAllString(s, repl), true
}

func (r *rewriter) editBytes(b []byte, w *config.Rewrite) ([]byte, bool) {
	if w.Match == "" || len(b) == 0 {
		return b, false
	}
	re := r.re(w.Match)
	if re == nil || !re.Match(b) {
		return b, false
	}
	repl := []byte(w.Replace)
	if w.Remove {
		repl = nil
	}
	return re.ReplaceAll(b, repl), true
}

func replaceLast(url, path string) string {
	// URL is scheme://host + path; swap the path tail.
	i := strings.Index(url, "://")
	if i < 0 {
		return url
	}
	rest := url[i+3:]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return url[:i+3] + rest + path
	}
	return url[:i+3] + rest[:slash] + path
}
