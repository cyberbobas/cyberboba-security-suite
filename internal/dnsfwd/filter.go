package dnsfwd

import (
	"bufio"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"cyberboba/internal/config"
)

// QueryEntry is one logged DNS lookup.
type QueryEntry struct {
	At      time.Time `json:"at"`
	Name    string    `json:"name"`
	Type    string    `json:"type"`
	Blocked bool      `json:"blocked"`
	Reason  string    `json:"reason,omitempty"` // "list" | "manual"
}

// FilterStats summarises the filter for the UI.
type FilterStats struct {
	Enabled     bool             `json:"enabled"`
	ListDomains int              `json:"list_domains"`
	ManualBlock int              `json:"manual_block"`
	Allowed     int              `json:"allow"`
	Total       int64            `json:"total_queries"`
	Blocked     int64            `json:"blocked_queries"`
	BlockedPct  float64          `json:"blocked_pct"`
	Lists       []string         `json:"lists"`
	Updated     time.Time        `json:"updated"`
	Updating    bool             `json:"updating"`
	TopBlocked  []map[string]any `json:"top_blocked"`
	TopQueried  []map[string]any `json:"top_queried"`
}

// Filter is the Pi-hole-style DNS blocker: it answers queries for blocked
// domains with NXDOMAIN (or 0.0.0.0) and keeps a rolling query log + counters.
type Filter struct {
	mu        sync.RWMutex
	enabled   bool
	sinkhole  string
	manual    map[string]bool // manual block domains
	allow     map[string]bool
	list      map[string]bool // domains from downloaded blocklists
	lists     []string        // the configured list URLs
	updated   time.Time
	updating  bool
	cachePath string
	logf      func(level, format string, args ...interface{})

	logMu      sync.Mutex
	log        []QueryEntry
	maxLog     int
	total      int64
	blocked    int64
	queryCount map[string]int64
	blockCount map[string]int64
	httpc      *http.Client
}

// NewFilter builds a filter persisting merged lists to cachePath.
func NewFilter(cachePath string, logf func(level, format string, args ...interface{})) *Filter {
	if logf == nil {
		logf = func(string, string, ...interface{}) {}
	}
	f := &Filter{
		manual: map[string]bool{}, allow: map[string]bool{}, list: map[string]bool{},
		cachePath: cachePath, logf: logf, maxLog: 3000,
		queryCount: map[string]int64{}, blockCount: map[string]int64{},
		httpc: &http.Client{Timeout: 25 * time.Second},
	}
	f.loadCache()
	return f
}

// Configure applies a new DNSFilter config. Manual block/allow take effect
// immediately; if the list URLs changed, a background download is kicked off.
func (f *Filter) Configure(cfg config.DNSFilter) {
	f.mu.Lock()
	f.enabled = cfg.Enabled
	f.sinkhole = cfg.Sinkhole
	f.manual = toSet(cfg.Block)
	f.allow = toSet(cfg.Allow)
	changed := !sameSlice(f.lists, cfg.Blocklists)
	f.lists = append([]string(nil), cfg.Blocklists...)
	needDownload := changed && len(cfg.Blocklists) > 0
	if len(cfg.Blocklists) == 0 {
		f.list = map[string]bool{}
	}
	f.mu.Unlock()
	if needDownload {
		go f.download()
	}
}

// Refresh forces a re-download of the configured blocklists.
func (f *Filter) Refresh() { go f.download() }

// Blocked reports whether name should be sinkholed, with a reason.
func (f *Filter) Blocked(name string) (bool, string) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if !f.enabled {
		return false, ""
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return false, ""
	}
	// allow-list wins (domain and parents)
	for _, d := range parents(name) {
		if f.allow[d] {
			return false, ""
		}
	}
	for _, d := range parents(name) {
		if f.manual[d] {
			return true, "manual"
		}
		if f.list[d] {
			return true, "list"
		}
	}
	return false, ""
}

// Sinkhole reports the configured sink response style.
func (f *Filter) Sinkhole() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.sinkhole == "zero" {
		return "zero"
	}
	return "nxdomain"
}

// Note records a query in the log and counters.
func (f *Filter) Note(name, qtype string, blocked bool, reason string) {
	f.logMu.Lock()
	f.total++
	if blocked {
		f.blocked++
		f.blockCount[name]++
	}
	f.queryCount[name]++
	f.log = append(f.log, QueryEntry{At: time.Now(), Name: name, Type: qtype, Blocked: blocked, Reason: reason})
	if len(f.log) > f.maxLog {
		f.log = f.log[len(f.log)-f.maxLog:]
	}
	// keep the count maps from growing without bound
	if len(f.queryCount) > 20000 {
		f.queryCount = topN(f.queryCount, 5000)
	}
	if len(f.blockCount) > 20000 {
		f.blockCount = topN(f.blockCount, 5000)
	}
	f.logMu.Unlock()
}

// Recent returns the last n log entries, newest first; blockedOnly filters.
func (f *Filter) Recent(n int, blockedOnly bool) []QueryEntry {
	f.logMu.Lock()
	defer f.logMu.Unlock()
	out := []QueryEntry{}
	for i := len(f.log) - 1; i >= 0 && len(out) < n; i-- {
		if blockedOnly && !f.log[i].Blocked {
			continue
		}
		out = append(out, f.log[i])
	}
	return out
}

// Stats returns a summary snapshot.
func (f *Filter) Stats() FilterStats {
	f.mu.RLock()
	st := FilterStats{Enabled: f.enabled, ListDomains: len(f.list), ManualBlock: len(f.manual),
		Allowed: len(f.allow), Lists: append([]string(nil), f.lists...), Updated: f.updated, Updating: f.updating}
	f.mu.RUnlock()
	f.logMu.Lock()
	st.Total, st.Blocked = f.total, f.blocked
	if st.Total > 0 {
		st.BlockedPct = float64(st.Blocked) / float64(st.Total) * 100
	}
	st.TopBlocked = topList(f.blockCount, 10)
	st.TopQueried = topList(f.queryCount, 10)
	f.logMu.Unlock()
	return st
}

// ResetStats clears the query log and counters (not the blocklists).
func (f *Filter) ResetStats() {
	f.logMu.Lock()
	f.log = nil
	f.total, f.blocked = 0, 0
	f.queryCount = map[string]int64{}
	f.blockCount = map[string]int64{}
	f.logMu.Unlock()
}

func (f *Filter) download() {
	f.mu.Lock()
	if f.updating {
		f.mu.Unlock()
		return
	}
	f.updating = true
	urls := append([]string(nil), f.lists...)
	f.mu.Unlock()

	merged := map[string]bool{}
	ok := 0
	for _, u := range urls {
		n, err := f.fetchInto(u, merged)
		if err != nil {
			f.logf("warn", "dns blocklist %s: %v", u, err)
			continue
		}
		ok++
		f.logf("info", "dns blocklist %s: %d domains", u, n)
	}

	f.mu.Lock()
	if ok > 0 || len(urls) == 0 {
		f.list = merged
		f.updated = time.Now()
	}
	f.updating = false
	f.mu.Unlock()
	if ok > 0 {
		f.saveCache(merged)
	}
}

func (f *Filter) fetchInto(url string, set map[string]bool) (int, error) {
	resp, err := f.httpc.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	n := 0
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if d := parseHostLine(sc.Text()); d != "" {
			set[d] = true
			n++
		}
	}
	return n, sc.Err()
}

// parseHostLine extracts a domain from a hosts-format or plain-domain line.
func parseHostLine(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	fields := strings.Fields(line)
	d := fields[0]
	if len(fields) >= 2 { // "0.0.0.0 domain" / "127.0.0.1 domain"
		if d == "0.0.0.0" || d == "127.0.0.1" || d == "::" || d == "::1" {
			d = fields[1]
		}
	}
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	if d == "" || d == "localhost" || d == "localhost.localdomain" || d == "broadcasthost" ||
		strings.ContainsAny(d, "/ ") || !strings.Contains(d, ".") {
		return ""
	}
	return d
}

func (f *Filter) saveCache(set map[string]bool) {
	if f.cachePath == "" {
		return
	}
	var b strings.Builder
	for d := range set {
		b.WriteString(d)
		b.WriteByte('\n')
	}
	tmp := f.cachePath + ".tmp"
	if os.WriteFile(tmp, []byte(b.String()), 0o644) == nil {
		_ = os.Rename(tmp, f.cachePath)
	}
}

func (f *Filter) loadCache() {
	if f.cachePath == "" {
		return
	}
	b, err := os.ReadFile(f.cachePath)
	if err != nil {
		return
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if d := strings.TrimSpace(line); d != "" {
			set[d] = true
		}
	}
	f.mu.Lock()
	f.list = set
	f.mu.Unlock()
}

// parents returns name and each parent domain, e.g.
// a.b.example.com -> [a.b.example.com, b.example.com, example.com, com].
func parents(name string) []string {
	out := []string{name}
	for {
		i := strings.IndexByte(name, '.')
		if i < 0 {
			break
		}
		name = name[i+1:]
		if name == "" {
			break
		}
		out = append(out, name)
	}
	return out
}

func toSet(ss []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range ss {
		s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
		if s != "" {
			m[s] = true
		}
	}
	return m
}

func sameSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func topN(m map[string]int64, keep int) map[string]int64 {
	type kv struct {
		k string
		v int64
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	if len(all) > keep {
		all = all[:keep]
	}
	out := make(map[string]int64, len(all))
	for _, e := range all {
		out[e.k] = e.v
	}
	return out
}

func topList(m map[string]int64, n int) []map[string]any {
	type kv struct {
		k string
		v int64
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	if len(all) > n {
		all = all[:n]
	}
	out := []map[string]any{}
	for _, e := range all {
		out = append(out, map[string]any{"name": e.k, "count": e.v})
	}
	return out
}
