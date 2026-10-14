// Package firewall is a ZoneAlarm-style application firewall layered on top of
// the routing rules. It decides WHETHER a program may reach the network, per
// zone (Trusted LAN vs Internet), prompting for unknown programs (held
// connections), remembering decisions, with an Internet Lock panic switch.
package firewall

import (
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cyberboba/internal/config"
	"cyberboba/internal/rules"
)

// How long a timed-out prompt stays answerable so a late Allow still
// remembers the program. The held connection itself is already closed.
const activityMax = 500 // firewall decision log ring size

// Activity is one noteworthy firewall decision (a block, a prompt outcome, or
// an auto-learned allow) kept in a ring so the UI/CLI can show "what the
// firewall did" — especially what it blocked.
type Activity struct {
	Time   time.Time `json:"time"`
	App    string    `json:"app"`
	Exe    string    `json:"exe,omitempty"`
	PID    int       `json:"pid,omitempty"`
	Host   string    `json:"host,omitempty"`
	IP     string    `json:"ip,omitempty"`
	Port   int       `json:"port,omitempty"`
	Zone   string    `json:"zone"`
	Allow  bool      `json:"allow"`
	Reason string    `json:"reason"`
}

const recentAskTTL = 2 * time.Minute

type recentAsk struct {
	ask   *Ask
	until time.Time
}

// Conn is the subset of a connection the firewall needs to decide.
type Conn struct {
	App, Exe, Cmd, Tag string
	IP                 netip.Addr
	Port               int
	Host               string
	PID                int
}

// Decision is the firewall verdict for one connection.
type Decision struct {
	Allow  bool
	Zone   string
	Reason string
}

// Ask is a held connection (or group of connections) from one program/zone
// awaiting a user/agent decision. Concurrent connections from the same program
// and zone coalesce onto a single Ask, so there is ONE prompt per program like
// ZoneAlarm — answering it releases every held connection of that program.
type Ask struct {
	ID      uint64    `json:"id"`
	App     string    `json:"app"`
	Exe     string    `json:"exe"`
	PID     int       `json:"pid"`
	Host    string    `json:"host"`
	IP      string    `json:"ip"`
	Port    int       `json:"port"`
	Zone    string    `json:"zone"`
	Waiting int       `json:"waiting"`
	Created time.Time `json:"created"`

	key     string
	resolve chan bool
	done    chan struct{}
	result  bool
}

// blockPat is a compiled entry of Firewall.BlockedHosts: either a host/domain
// pattern (matched against the connection's hostname) or an IP/CIDR prefix
// (matched against the destination address).
type blockPat struct {
	raw    string
	prefix netip.Prefix
	isNet  bool
}

// Engine evaluates firewall policy.
type Engine struct {
	mu         sync.Mutex
	cfg        config.Firewall
	trusted    []netip.Prefix
	blocked    []blockPat
	pending    map[uint64]*Ask
	pendingKey map[string]*Ask
	recent     []recentAsk
	activity   []Activity
	lastBlock  map[string]time.Time // per-app fw_block emit throttle
	nextID     uint64
	stats      struct{ allowed, blocked, asked atomic.Uint64 }

	emit    func(evType string, data interface{})
	persist func(func(*config.Firewall))
	hasUI   func() bool
	logf    func(level, format string, args ...interface{})
}

// New builds an engine. emit publishes events (fw_ask/fw_resolved/fw); persist
// mutates the stored firewall config (used to remember decisions).
func New(cfg config.Firewall, emit func(string, interface{}), persist func(func(*config.Firewall)), hasUI func() bool, logf func(string, string, ...interface{})) *Engine {
	if emit == nil {
		emit = func(string, interface{}) {}
	}
	if persist == nil {
		persist = func(func(*config.Firewall)) {}
	}
	if logf == nil {
		logf = func(string, string, ...interface{}) {}
	}
	if hasUI == nil {
		hasUI = func() bool { return true }
	}
	e := &Engine{pending: map[uint64]*Ask{}, pendingKey: map[string]*Ask{}, lastBlock: map[string]time.Time{}, emit: emit, persist: persist, hasUI: hasUI, logf: logf}
	e.SetConfig(cfg)
	return e
}

// SetConfig swaps the policy and recomputes the Trusted Zone prefixes.
func (e *Engine) SetConfig(cfg config.Firewall) {
	var tp []netip.Prefix
	for _, n := range cfg.TrustedNets {
		if n == "lan" {
			tp = append(tp, lanPrefixes()...)
			continue
		}
		if p, err := netip.ParsePrefix(n); err == nil {
			tp = append(tp, p)
		} else if a, err := netip.ParseAddr(n); err == nil {
			tp = append(tp, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	var bp []blockPat
	for _, h := range cfg.BlockedHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if p, err := netip.ParsePrefix(h); err == nil {
			bp = append(bp, blockPat{raw: h, prefix: p, isNet: true})
		} else if a, err := netip.ParseAddr(h); err == nil {
			bp = append(bp, blockPat{raw: h, prefix: netip.PrefixFrom(a, a.BitLen()), isNet: true})
		} else {
			bp = append(bp, blockPat{raw: strings.ToLower(h)})
		}
	}
	e.mu.Lock()
	e.cfg = cfg
	e.trusted = tp
	e.blocked = bp
	e.mu.Unlock()
}

// Enabled reports whether program control is active.
func (e *Engine) Enabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.Enabled
}

// Active reports whether the engine must inspect connections at all: either
// program control is on, or there is at least one blocked host. The proxy uses
// this to decide whether to call Check, so host blocks work even with the
// firewall otherwise off.
func (e *Engine) Active() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.Enabled || len(e.blocked) > 0
}

// hostBlock reports the matching blocklist pattern for a connection, if any.
func (e *Engine) hostBlock(host string, ip netip.Addr) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	e.mu.Lock()
	bp := e.blocked
	e.mu.Unlock()
	for _, p := range bp {
		if p.isNet {
			if ip.IsValid() && p.prefix.Contains(ip.Unmap()) {
				return p.raw, true
			}
			continue
		}
		if host != "" && rules.MatchHost(p.raw, host) {
			return p.raw, true
		}
	}
	return "", false
}

func lanPrefixes() []netip.Prefix {
	ps := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10", "100.64.0.0/10"}
	var out []netip.Prefix
	for _, s := range ps {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func inPrefixes(ip netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (e *Engine) lookup(c Conn, cfg *config.Firewall) *config.FwProgram {
	rc := rules.Conn{App: c.App, Exe: c.Exe, Cmd: c.Cmd, Tag: c.Tag, UID: -1}
	for i := range cfg.Programs {
		if cfg.Programs[i].App != "" && rules.MatchApp([]string{cfg.Programs[i].App}, rc) {
			return &cfg.Programs[i]
		}
	}
	return nil
}

// Check returns the verdict for a connection. For an unknown program in "ask"
// mode it HOLDS (blocks the calling goroutine) until a decision or timeout.
func (e *Engine) Check(c Conn) Decision {
	e.mu.Lock()
	cfg := e.cfg
	trusted := e.trusted
	e.mu.Unlock()

	if c.App == "" && c.Exe != "" {
		c.App = filepath.Base(c.Exe)
	}
	// Host blocklist applies even when program control is off, but never to
	// loopback (the control UI/API must stay reachable).
	if !(c.IP.IsValid() && c.IP.IsLoopback()) {
		if pat, ok := e.hostBlock(c.Host, c.IP); ok {
			return e.result(c, Decision{Allow: false, Zone: "blocked", Reason: "host blocked (" + pat + ")"})
		}
	}
	if !cfg.Enabled {
		return Decision{Allow: true, Reason: "firewall off"}
	}
	if c.IP.IsValid() && c.IP.IsLoopback() {
		return e.result(c, Decision{Allow: true, Zone: "trusted", Reason: "loopback"})
	}
	zone := "internet"
	if c.IP.IsValid() && inPrefixes(c.IP, trusted) {
		zone = "trusted"
	}
	prog := e.lookup(c, &cfg)

	// Internet Lock applies whenever the firewall is enabled, regardless of
	// program-control mode.
	if cfg.InternetLock {
		if prog == nil || !prog.LockPass {
			return e.result(c, Decision{Allow: false, Zone: zone, Reason: "internet lock"})
		}
	}
	if cfg.Mode == "off" {
		return e.result(c, Decision{Allow: true, Zone: zone, Reason: "program control off"})
	}

	perm := ""
	if prog != nil {
		if zone == "trusted" {
			perm = prog.Trusted
		} else {
			perm = prog.Internet
		}
	}
	if perm == "" {
		switch cfg.Mode {
		case "auto":
			perm = "autoallow"
		case "block":
			perm = "block"
		default:
			perm = "ask"
		}
	}
	switch perm {
	case "allow":
		return e.result(c, Decision{Allow: true, Zone: zone, Reason: "allowed"})
	case "block":
		return e.result(c, Decision{Allow: false, Zone: zone, Reason: "blocked"})
	case "autoallow":
		e.remember(c.App, zone, true)
		return e.result(c, Decision{Allow: true, Zone: zone, Reason: "auto-learned"})
	default: // ask
		return e.result(c, e.ask(c, zone, cfg))
	}
}

func (e *Engine) result(c Conn, d Decision) Decision {
	if d.Allow {
		e.stats.allowed.Add(1)
	} else {
		e.stats.blocked.Add(1)
	}
	e.record(c, d)
	return d
}

// record appends a noteworthy decision to the activity ring and, on a block,
// emits a live "fw_block" event. Routine allows (loopback, allowlisted apps,
// firewall off) are skipped to keep the log about what actually mattered.
func (e *Engine) record(c Conn, d Decision) {
	switch d.Reason {
	case "loopback", "firewall off", "program control off", "allowed":
		return
	}
	host := c.Host
	if host == "" && c.IP.IsValid() {
		host = c.IP.String()
	}
	a := Activity{Time: time.Now(), App: c.App, Exe: c.Exe, PID: c.PID,
		Host: host, Port: c.Port, Zone: d.Zone, Allow: d.Allow, Reason: d.Reason}
	if c.IP.IsValid() {
		a.IP = c.IP.String()
	}
	emitBlock := false
	e.mu.Lock()
	e.activity = append(e.activity, a)
	if len(e.activity) > activityMax {
		e.activity = e.activity[len(e.activity)-activityMax:]
	}
	if !d.Allow {
		// Throttle fw_block per app (fallback to ip) so a block burst (a port
		// scan, internet lock, a chatty blocked app) can't flood the SSE
		// buffer and evict pending fw_ask events.
		bk := a.App
		if bk == "" {
			bk = "ip:" + a.IP
		}
		if time.Since(e.lastBlock[bk]) > 5*time.Second {
			e.lastBlock[bk] = time.Now()
			emitBlock = true
		}
	}
	e.mu.Unlock()
	if emitBlock {
		e.emit("fw_block", a)
	}
}

// ActivityLog returns up to limit recent decisions, newest first; blockedOnly
// filters to blocks.
func (e *Engine) ActivityLog(limit int, blockedOnly bool) []Activity {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []Activity{}
	for i := len(e.activity) - 1; i >= 0; i-- {
		a := e.activity[i]
		if blockedOnly && a.Allow {
			continue
		}
		out = append(out, a)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func (e *Engine) ask(c Conn, zone string, cfg config.Firewall) Decision {
	e.stats.asked.Add(1)
	// Coalesce by program+zone. When the owning process could not be resolved
	// (App==""), key by destination IP instead so two unrelated unknown
	// programs do not share one Allow/Deny verdict.
	appKey := c.App
	if appKey == "" {
		if c.IP.IsValid() {
			appKey = "ip:" + c.IP.String()
		} else {
			appKey = "unknown"
		}
	}
	key := appKey + "\x00" + zone

	e.mu.Lock()
	if a, ok := e.pendingKey[key]; ok {
		// Coalesce: a prompt for this program+zone is already open; wait on it.
		a.Waiting++
		done := a.done
		e.mu.Unlock()
		<-done
		return e.verdict(a.result, zone)
	}
	// Short-circuit: if this program+zone was prompted and timed out recently,
	// reuse that decision instead of popping a fresh prompt for every new
	// connection (avoids the #2/#3/#4 re-ask storm).
	if dec, ok := e.recentDecisionLocked(key); ok {
		e.mu.Unlock()
		return e.verdict(dec, zone)
	}
	// Fail-open safety: if no UI is connected to answer prompts, do not hold
	// the connection (that would silently block an unattended machine, even
	// the control channel). Allow it and log instead.
	if !e.hasUI() {
		e.mu.Unlock()
		e.logf("warn", "firewall: %q -> %s:%d allowed (no UI open to prompt; %s zone)", c.App, c.Host, c.Port, zone)
		return Decision{Allow: true, Zone: zone, Reason: "allowed (no UI to prompt)"}
	}
	e.nextID++
	a := &Ask{ID: e.nextID, App: c.App, Exe: c.Exe, PID: c.PID, Host: c.Host, Port: c.Port, Zone: zone,
		Waiting: 1, Created: time.Now(), key: key, resolve: make(chan bool, 1), done: make(chan struct{})}
	if c.IP.IsValid() {
		a.IP = c.IP.String()
	}
	e.pending[a.ID] = a
	e.pendingKey[key] = a
	e.mu.Unlock()

	e.emit("fw_ask", a)
	e.logf("warn", "firewall: %q wants %s access to %s:%d — awaiting decision (ask #%d)", c.App, zone, a.hostOrIP(), c.Port, a.ID)

	to := time.Duration(cfg.AskTimeoutSec) * time.Second
	var allow bool
	timedOut := false
	if to <= 0 {
		allow = <-a.resolve
	} else {
		timer := time.NewTimer(to)
		select {
		case allow = <-a.resolve:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
			timedOut = true
			allow = cfg.AskTimeoutAction != "block"
			e.logf("warn", "firewall: ask #%d timed out, %s", a.ID, map[bool]string{true: "allowing", false: "blocking"}[allow])
		}
	}
	// resolve: release every coalesced waiter
	e.mu.Lock()
	a.result = allow
	delete(e.pending, a.ID)
	if e.pendingKey[key] == a {
		delete(e.pendingKey, key)
	}
	if timedOut {
		e.pruneRecentLocked()
		e.recent = append(e.recent, recentAsk{ask: a, until: time.Now().Add(recentAskTTL)})
	}
	close(a.done)
	n := a.Waiting
	e.mu.Unlock()
	e.emit("fw_resolved", map[string]interface{}{"id": a.ID, "allow": allow, "released": n, "timeout": timedOut})
	return e.verdict(allow, zone)
}

func (e *Engine) verdict(allow bool, zone string) Decision {
	if allow {
		return Decision{Allow: true, Zone: zone, Reason: "allowed (prompt)"}
	}
	return Decision{Allow: false, Zone: zone, Reason: "blocked (prompt)"}
}

func (a *Ask) hostOrIP() string {
	if a.Host != "" {
		return a.Host
	}
	return a.IP
}

// Pending returns a snapshot of held connections.
func (e *Engine) Pending() []Ask {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Ask, 0, len(e.pending))
	for _, a := range e.pending {
		out = append(out, *a)
	}
	return out
}

func (e *Engine) pruneRecentLocked() {
	now := time.Now()
	dst := e.recent[:0]
	for _, r := range e.recent {
		if r.until.After(now) {
			dst = append(dst, r)
		}
	}
	e.recent = dst
}

// recentDecisionLocked returns the result of a recently timed-out prompt for
// this coalescing key, if one is still within its TTL. Caller holds e.mu.
func (e *Engine) recentDecisionLocked(key string) (bool, bool) {
	e.pruneRecentLocked()
	for i := len(e.recent) - 1; i >= 0; i-- {
		if e.recent[i].ask != nil && e.recent[i].ask.key == key {
			return e.recent[i].ask.result, true
		}
	}
	return false, false
}

func (e *Engine) lookupRecentLocked(id uint64) *Ask {
	e.pruneRecentLocked()
	for _, r := range e.recent {
		if r.ask.ID == id {
			return r.ask
		}
	}
	return nil
}

// Answer resolves a held connection. remember persists an allow/block program
// entry for the app's zone. A late answer (after the prompt timed out) still
// remembers, so the next connection from that program is not asked again.
func (e *Engine) Answer(id uint64, allow, remember bool) bool {
	e.mu.Lock()
	a := e.pending[id]
	late := false
	if a == nil {
		if a = e.lookupRecentLocked(id); a != nil {
			late = true
		}
	}
	e.mu.Unlock()
	if a == nil {
		return false
	}
	if remember && a.App != "" {
		e.remember(a.App, a.Zone, allow)
	}
	if late {
		return true
	}
	select {
	case a.resolve <- allow:
	default:
	}
	return true
}

// AnswerAll resolves every pending ask with the same verdict.
func (e *Engine) AnswerAll(allow bool) int {
	e.mu.Lock()
	asks := make([]*Ask, 0, len(e.pending))
	for _, a := range e.pending {
		asks = append(asks, a)
	}
	e.mu.Unlock()
	for _, a := range asks {
		select {
		case a.resolve <- allow:
		default:
		}
	}
	return len(asks)
}

func (e *Engine) remember(app, zone string, allow bool) {
	if app == "" {
		return
	}
	perm := "block"
	if allow {
		perm = "allow"
	}
	e.persist(func(fw *config.Firewall) {
		for i := range fw.Programs {
			if fw.Programs[i].App == app {
				if zone == "trusted" {
					fw.Programs[i].Trusted = perm
				} else {
					fw.Programs[i].Internet = perm
				}
				return
			}
		}
		np := config.FwProgram{App: app}
		if zone == "trusted" {
			np.Trusted = perm
		} else {
			np.Internet = perm
		}
		fw.Programs = append(fw.Programs, np)
	})
	e.logf("info", "firewall: remembered %s=%s for %q (%s zone)", zone, perm, app, zone)
}

// Status is the live firewall summary.
func (e *Engine) Status() map[string]interface{} {
	e.mu.Lock()
	cfg := e.cfg
	np := len(e.pending)
	e.mu.Unlock()
	return map[string]interface{}{
		"enabled": cfg.Enabled, "mode": cfg.Mode, "stealth": cfg.Stealth,
		"internet_lock": cfg.InternetLock, "allow_lan_inbound": cfg.AllowLANInbound,
		"trusted_nets": cfg.TrustedNets, "programs": len(cfg.Programs),
		"blocked_hosts": cfg.BlockedHosts, "pending": np,
		"stats": map[string]uint64{
			"allowed": e.stats.allowed.Load(), "blocked": e.stats.blocked.Load(), "asked": e.stats.asked.Load(),
		},
	}
}
