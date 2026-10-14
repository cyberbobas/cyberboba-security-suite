// Package bandwidth turns the connection tracker's raw per-connection byte
// counters into a GlassWire-style per-application view: live up/down speed,
// this-session totals, and persisted per-day / rolling-30-day data usage.
//
// It samples the tracker on a fixed cadence (call Sample every second). For
// each connection it accumulates the positive delta of its byte counters into
// the owning app, so totals stay correct even after a connection is evicted
// from the tracker's history ring. Daily totals are persisted to disk so usage
// survives restarts.
package bandwidth

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"

	"cyberboba/internal/config"
	"cyberboba/internal/stats"
)

const keepDays = 31

// AppUsage is one application's bandwidth line.
type AppUsage struct {
	App        string    `json:"app"`
	RateIn     float64   `json:"rate_in"`  // bytes/sec, instantaneous (download)
	RateOut    float64   `json:"rate_out"` // bytes/sec, instantaneous (upload)
	TotalIn    int64     `json:"total_in"` // since daemon start
	TotalOut   int64     `json:"total_out"`
	TodayIn    int64     `json:"today_in"` // since local midnight (persisted)
	TodayOut   int64     `json:"today_out"`
	MonthIn    int64     `json:"month_in"` // rolling 30 days (persisted)
	MonthOut   int64     `json:"month_out"`
	Conns      int       `json:"conns"` // active connections right now
	LastActive time.Time `json:"last_active"`
}

// Snapshot is the whole meter at one instant.
type Snapshot struct {
	At            time.Time  `json:"at"`
	Apps          []AppUsage `json:"apps"`
	TotalRateIn   float64    `json:"total_rate_in"`
	TotalRateOut  float64    `json:"total_rate_out"`
	TotalTodayIn  int64      `json:"total_today_in"`
	TotalTodayOut int64      `json:"total_today_out"`
	TotalMonthIn  int64      `json:"total_month_in"`
	TotalMonthOut int64      `json:"total_month_out"`
}

type io2 struct {
	In  int64 `json:"in"`
	Out int64 `json:"out"`
}

type acc struct {
	sessIn, sessOut int64
	rateIn, rateOut float64
	conns           int
	lastActive      time.Time

	// anomaly detection: EWMA baselines, warm-up sample count, per-direction
	// sustain counters and last-alert timestamps.
	baseIn, baseOut           float64
	samples                   int
	sustainIn, sustainOut     int
	lastAlertIn, lastAlertOut time.Time
}

// Alert reports that an application's live transfer rate is abnormally high.
type Alert struct {
	App      string    `json:"app"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`     // "upload" | "download"
	Rate     float64   `json:"rate"`     // bytes/sec at trigger
	Baseline float64   `json:"baseline"` // bytes/sec recent baseline
	Factor   float64   `json:"factor"`   // rate / baseline (0 if baseline was ~0)
	Conns    int       `json:"conns"`
}

type alertCfg struct {
	enabled  bool
	floor    float64 // bytes/sec
	factor   float64
	sustain  int
	cooldown time.Duration
}

// Meter aggregates per-app bandwidth.
type Meter struct {
	mu      sync.Mutex
	seen    map[uint64]io2            // per-connection last byte counts
	apps    map[string]*acc           // session accumulators keyed by app
	daily   map[string]map[string]io2 // date "2006-01-02" -> app -> bytes
	lastAt  time.Time
	path    string
	dirtyAt time.Time
	started bool

	al      alertCfg
	alertFn func(Alert)
	alerts  []Alert // recent alert ring (newest last)
}

// New builds a meter persisting daily totals to path (may be ""). Existing
// daily history is loaded if present.
func New(path string) *Meter {
	m := &Meter{seen: map[uint64]io2{}, apps: map[string]*acc{}, daily: map[string]map[string]io2{}, path: path,
		al: alertCfg{enabled: true, floor: 800 << 10, factor: 8, sustain: 4, cooldown: 120 * time.Second}}
	m.load()
	return m
}

func today() string { return time.Now().Format("2006-01-02") }

// Sample folds one tracker snapshot into the per-app totals and recomputes
// rates. Call it about once per second with tracker.List(0, true).
func (m *Meter) Sample(conns []stats.Conn) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	dt := now.Sub(m.lastAt).Seconds()
	if !m.started {
		dt = 0
		m.started = true
	}

	present := make(map[uint64]bool, len(conns))
	deltaIn := map[string]int64{}
	deltaOut := map[string]int64{}
	connCount := map[string]int{}
	day := m.daily[today()]
	if day == nil {
		day = map[string]io2{}
		m.daily[today()] = day
	}

	for i := range conns {
		c := &conns[i]
		present[c.ID] = true
		app := c.App
		if app == "" {
			app = "unknown"
		}
		if c.State == "open" {
			connCount[app]++
		}
		prev := m.seen[c.ID]
		di := c.BytesIn - prev.In
		do := c.BytesOut - prev.Out
		if di < 0 {
			di = 0
		}
		if do < 0 {
			do = 0
		}
		m.seen[c.ID] = io2{In: c.BytesIn, Out: c.BytesOut}
		if di == 0 && do == 0 {
			continue
		}
		a := m.apps[app]
		if a == nil {
			a = &acc{}
			m.apps[app] = a
		}
		a.sessIn += di
		a.sessOut += do
		a.lastActive = now
		deltaIn[app] += di
		deltaOut[app] += do
		d := day[app]
		d.In += di
		d.Out += do
		day[app] = d
	}

	// drop byte memory for connections that vanished from the tracker
	for id := range m.seen {
		if !present[id] {
			delete(m.seen, id)
		}
	}

	// recompute rates and active-conn counts for every known app
	var fired []Alert
	for app, a := range m.apps {
		if dt > 0 {
			a.rateIn = float64(deltaIn[app]) / dt
			a.rateOut = float64(deltaOut[app]) / dt
		} else {
			a.rateIn, a.rateOut = 0, 0
		}
		a.conns = connCount[app]
		if dt > 0 {
			if al, ok := m.checkAnomaly(app, a, now); ok {
				fired = append(fired, al...)
			}
		}
	}

	m.lastAt = now

	// persist at most every 20s
	if m.path != "" && now.Sub(m.dirtyAt) > 20*time.Second {
		m.pruneLocked()
		m.saveLocked()
		m.dirtyAt = now
	}

	// Deliver alerts without holding the lock (the callback publishes events).
	if len(fired) > 0 && m.alertFn != nil {
		fn := m.alertFn
		go func(as []Alert) {
			for _, a := range as {
				fn(a)
			}
		}(fired)
	}
}

// checkAnomaly updates an app's baselines and returns any alerts that should
// fire this tick. Caller holds m.mu. It records fired alerts into the ring.
func (m *Meter) checkAnomaly(app string, a *acc, now time.Time) ([]Alert, bool) {
	// EWMA baselines over ~20s. Update with the current rate first so a lone
	// spike is compared against the pre-spike baseline.
	const alpha = 0.05
	prevIn, prevOut := a.baseIn, a.baseOut
	a.baseIn = alpha*a.rateIn + (1-alpha)*a.baseIn
	a.baseOut = alpha*a.rateOut + (1-alpha)*a.baseOut
	a.samples++
	if !m.al.enabled || a.samples < 15 {
		return nil, false
	}
	var out []Alert
	eval := func(rate, base float64, sustain *int, last *time.Time, kind string) {
		over := base <= 1 || rate > base*m.al.factor
		if rate >= m.al.floor && over {
			*sustain++
		} else {
			*sustain = 0
		}
		if *sustain >= m.al.sustain && now.Sub(*last) >= m.al.cooldown {
			*last = now
			*sustain = 0
			factor := 0.0
			if base > 1 {
				factor = rate / base
			}
			al := Alert{App: app, At: now, Kind: kind, Rate: rate, Baseline: base, Factor: factor, Conns: a.conns}
			out = append(out, al)
			m.alerts = append(m.alerts, al)
			if len(m.alerts) > 100 {
				m.alerts = m.alerts[len(m.alerts)-100:]
			}
		}
	}
	eval(a.rateOut, prevOut, &a.sustainOut, &a.lastAlertOut, "upload")
	eval(a.rateIn, prevIn, &a.sustainIn, &a.lastAlertIn, "download")
	return out, len(out) > 0
}

// SetAlert registers the callback invoked (off the meter lock) when an
// anomaly fires.
func (m *Meter) SetAlert(fn func(Alert)) {
	m.mu.Lock()
	m.alertFn = fn
	m.mu.Unlock()
}

// ConfigureAlerts applies alert tuning from config (zero fields keep sane
// defaults).
func (m *Meter) ConfigureAlerts(c config.BandwidthAlerts) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.al.enabled = c.Enabled
	m.al.floor = 800 << 10
	if c.FloorKBps > 0 {
		m.al.floor = c.FloorKBps * 1024
	}
	m.al.factor = 8
	if c.Factor > 0 {
		m.al.factor = c.Factor
	}
	m.al.sustain = 4
	if c.SustainSecs > 0 {
		m.al.sustain = c.SustainSecs
	}
	m.al.cooldown = 120 * time.Second
	if c.CooldownSecs > 0 {
		m.al.cooldown = time.Duration(c.CooldownSecs) * time.Second
	}
}

// Alerts returns the recent alert ring, newest first, plus the active config.
func (m *Meter) Alerts() ([]Alert, map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Alert, 0, len(m.alerts))
	for i := len(m.alerts) - 1; i >= 0; i-- {
		out = append(out, m.alerts[i])
	}
	cfg := map[string]interface{}{
		"enabled":       m.al.enabled,
		"floor_kbps":    m.al.floor / 1024,
		"factor":        m.al.factor,
		"sustain_secs":  m.al.sustain,
		"cooldown_secs": int(m.al.cooldown / time.Second),
	}
	return out, cfg
}

// Snapshot returns the current per-app view, sorted by live rate then session total.
func (m *Meter) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Snapshot{At: time.Now()}
	tday := m.daily[today()]
	monthFrom := time.Now().AddDate(0, 0, -30).Format("2006-01-02")
	monthByApp := map[string]io2{}
	for date, apps := range m.daily {
		if date < monthFrom {
			continue
		}
		for app, v := range apps {
			mm := monthByApp[app]
			mm.In += v.In
			mm.Out += v.Out
			monthByApp[app] = mm
		}
	}
	for app, a := range m.apps {
		u := AppUsage{App: app, RateIn: a.rateIn, RateOut: a.rateOut,
			TotalIn: a.sessIn, TotalOut: a.sessOut, Conns: a.conns, LastActive: a.lastActive}
		if tday != nil {
			u.TodayIn = tday[app].In
			u.TodayOut = tday[app].Out
		}
		u.MonthIn = monthByApp[app].In
		u.MonthOut = monthByApp[app].Out
		s.Apps = append(s.Apps, u)
		s.TotalRateIn += a.rateIn
		s.TotalRateOut += a.rateOut
		s.TotalTodayIn += u.TodayIn
		s.TotalTodayOut += u.TodayOut
		s.TotalMonthIn += u.MonthIn
		s.TotalMonthOut += u.MonthOut
	}
	sort.Slice(s.Apps, func(i, j int) bool {
		ri, rj := s.Apps[i].RateIn+s.Apps[i].RateOut, s.Apps[j].RateIn+s.Apps[j].RateOut
		if ri != rj {
			return ri > rj
		}
		return s.Apps[i].TotalIn+s.Apps[i].TotalOut > s.Apps[j].TotalIn+s.Apps[j].TotalOut
	})
	if s.Apps == nil {
		s.Apps = []AppUsage{}
	}
	return s
}

// Daily returns per-day totals for the last keepDays, newest first.
func (m *Meter) Daily() []map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	dates := make([]string, 0, len(m.daily))
	for d := range m.daily {
		dates = append(dates, d)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dates)))
	out := []map[string]interface{}{}
	for _, d := range dates {
		var in, o int64
		for _, v := range m.daily[d] {
			in += v.In
			o += v.Out
		}
		out = append(out, map[string]interface{}{"date": d, "in": in, "out": o})
	}
	return out
}

// Reset clears session and persisted history.
func (m *Meter) Reset() {
	m.mu.Lock()
	m.apps = map[string]*acc{}
	m.daily = map[string]map[string]io2{}
	m.seen = map[uint64]io2{}
	if m.path != "" {
		m.saveLocked()
	}
	m.mu.Unlock()
}

// Flush writes daily totals to disk now.
func (m *Meter) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.path != "" {
		m.pruneLocked()
		m.saveLocked()
	}
}

func (m *Meter) pruneLocked() {
	cutoff := time.Now().AddDate(0, 0, -keepDays).Format("2006-01-02")
	for d := range m.daily {
		if d < cutoff {
			delete(m.daily, d)
		}
	}
}

func (m *Meter) saveLocked() {
	b, err := json.Marshal(m.daily)
	if err != nil {
		return
	}
	tmp := m.path + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, m.path)
	}
}

func (m *Meter) load() {
	if m.path == "" {
		return
	}
	b, err := os.ReadFile(m.path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &m.daily)
	if m.daily == nil {
		m.daily = map[string]map[string]io2{}
	}
}
