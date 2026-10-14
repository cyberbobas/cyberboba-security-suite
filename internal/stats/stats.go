// Package stats keeps the live connection table, counters and an event bus
// used by the API (SSE) and the web UI.
package stats

import (
	"encoding/json"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ConnState is the lifecycle state of a tracked connection.
type ConnState string

const (
	StateOpen    ConnState = "open"
	StateClosed  ConnState = "closed"
	StateBlocked ConnState = "blocked"
	StateError   ConnState = "error"
)

// Conn is the JSON representation of a tracked connection.
type Conn struct {
	ID       uint64     `json:"id"`
	Started  time.Time  `json:"started"`
	Ended    *time.Time `json:"ended"`
	State    ConnState  `json:"state"`
	Proto    string     `json:"proto"`
	PID      int        `json:"pid"`
	App      string     `json:"app"`
	Exe      string     `json:"exe"`
	User     string     `json:"user"`
	Tag      string     `json:"tag,omitempty"`
	DstIP    string     `json:"dst_ip"`
	DstPort  int        `json:"dst_port"`
	Host     string     `json:"host"`
	Rule     string     `json:"rule"`
	Action   string     `json:"action"`
	Via      string     `json:"via"`
	VPN      string     `json:"vpn,omitempty"`
	BytesIn  int64      `json:"bytes_in"`
	BytesOut int64      `json:"bytes_out"`
	Error    string     `json:"error,omitempty"`

	in, out atomic.Int64
	closer  func()
}

// Snapshot copies the atomic counters into the JSON fields.
func (c *Conn) Snapshot() Conn {
	return Conn{ID: c.ID, Started: c.Started, Ended: c.Ended, State: c.State, Proto: c.Proto, PID: c.PID,
		App: c.App, Exe: c.Exe, User: c.User, Tag: c.Tag, DstIP: c.DstIP, DstPort: c.DstPort, Host: c.Host,
		Rule: c.Rule, Action: c.Action, Via: c.Via, VPN: c.VPN, BytesIn: c.in.Load(), BytesOut: c.out.Load(), Error: c.Error}
}

// AddIn / AddOut account transferred bytes.
func (c *Conn) AddIn(n int64)  { c.in.Add(n) }
func (c *Conn) AddOut(n int64) { c.out.Add(n) }

// SetCloser registers a function that terminates the connection.
func (c *Conn) SetCloser(f func()) { c.closer = f }

// Summary is the aggregated counters object.
type Summary struct {
	Active   int               `json:"active"`
	Total    uint64            `json:"total"`
	Blocked  uint64            `json:"blocked"`
	BytesIn  int64             `json:"bytes_in"`
	BytesOut int64             `json:"bytes_out"`
	RateIn   float64           `json:"rate_in"`
	RateOut  float64           `json:"rate_out"`
	ByAction map[string]uint64 `json:"by_action"`
}

// Event is published on the bus.
type Event struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// LogLine is a structured log record kept in memory.
type LogLine struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
}

// Tracker is the central registry.
type Tracker struct {
	mu       sync.Mutex
	nextID   uint64
	active   map[uint64]*Conn
	closed   []*Conn
	maxLog   int
	total    uint64
	blocked  uint64
	byAction map[string]uint64
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
	lastIn   int64
	lastOut  int64
	lastTick time.Time
	rateIn   float64
	rateOut  float64

	subMu sync.Mutex
	subs  map[chan Event]struct{}

	logMu   sync.Mutex
	logs    []LogLine
	maxLogs int
}

// New creates a Tracker keeping at most maxClosed finished connections.
func New(maxClosed int) *Tracker {
	if maxClosed <= 0 {
		maxClosed = 2000
	}
	return &Tracker{active: map[uint64]*Conn{}, maxLog: maxClosed, byAction: map[string]uint64{},
		subs: map[chan Event]struct{}{}, lastTick: time.Now(), maxLogs: 1000}
}

// Open registers a new connection and broadcasts it.
func (t *Tracker) Open(c *Conn) *Conn {
	t.mu.Lock()
	t.nextID++
	c.ID = t.nextID
	if c.Started.IsZero() {
		c.Started = time.Now()
	}
	if c.State == "" {
		c.State = StateOpen
	}
	t.total++
	t.byAction[c.Action]++
	if c.State == StateBlocked {
		t.blocked++
	}
	if c.State == StateOpen {
		t.active[c.ID] = c
	} else {
		t.pushClosedLocked(c)
	}
	t.mu.Unlock()
	t.Publish(Event{Type: "conn", Data: c.Snapshot()})
	return c
}

// Update re-broadcasts the connection (e.g. hostname learned).
func (t *Tracker) Update(c *Conn) { t.Publish(Event{Type: "conn", Data: c.Snapshot()}) }

// Close marks the connection finished.
func (t *Tracker) Close(c *Conn, state ConnState, errMsg string) {
	now := time.Now()
	t.mu.Lock()
	if _, ok := t.active[c.ID]; !ok {
		t.mu.Unlock()
		return
	}
	delete(t.active, c.ID)
	c.Ended = &now
	c.State = state
	c.Error = errMsg
	if state == StateBlocked {
		t.blocked++
	}
	t.pushClosedLocked(c)
	t.mu.Unlock()
	t.bytesIn.Add(c.in.Load())
	t.bytesOut.Add(c.out.Load())
	t.Publish(Event{Type: "conn", Data: c.Snapshot()})
}

func (t *Tracker) pushClosedLocked(c *Conn) {
	t.closed = append(t.closed, c)
	if len(t.closed) > t.maxLog {
		t.closed = t.closed[len(t.closed)-t.maxLog:]
	}
}

// Kill terminates an active connection by id.
func (t *Tracker) Kill(id uint64) bool {
	t.mu.Lock()
	c, ok := t.active[id]
	t.mu.Unlock()
	if !ok || c.closer == nil {
		return false
	}
	c.closer()
	return true
}

// ClearClosed drops the history.
func (t *Tracker) ClearClosed() {
	t.mu.Lock()
	t.closed = nil
	t.mu.Unlock()
}

// List returns connections, newest first.
func (t *Tracker) List(limit int, includeClosed bool) []Conn {
	t.mu.Lock()
	out := make([]Conn, 0, len(t.active)+len(t.closed))
	for _, c := range t.active {
		out = append(out, c.Snapshot())
	}
	if includeClosed {
		for _, c := range t.closed {
			out = append(out, c.Snapshot())
		}
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Summary computes the counters; call Tick periodically for rates.
func (t *Tracker) Summary() Summary {
	t.mu.Lock()
	s := Summary{Active: len(t.active), Total: t.total, Blocked: t.blocked, ByAction: map[string]uint64{}}
	for k, v := range t.byAction {
		s.ByAction[k] = v
	}
	var liveIn, liveOut int64
	for _, c := range t.active {
		liveIn += c.in.Load()
		liveOut += c.out.Load()
	}
	s.RateIn, s.RateOut = t.rateIn, t.rateOut
	t.mu.Unlock()
	s.BytesIn = t.bytesIn.Load() + liveIn
	s.BytesOut = t.bytesOut.Load() + liveOut
	return s
}

// Tick recomputes rates and publishes a stats event. Run it every second.
func (t *Tracker) Tick() {
	s := t.Summary()
	t.mu.Lock()
	now := time.Now()
	dt := now.Sub(t.lastTick).Seconds()
	if dt > 0 {
		t.rateIn = float64(s.BytesIn-t.lastIn) / dt
		t.rateOut = float64(s.BytesOut-t.lastOut) / dt
		if t.rateIn < 0 {
			t.rateIn = 0
		}
		if t.rateOut < 0 {
			t.rateOut = 0
		}
	}
	t.lastIn, t.lastOut, t.lastTick = s.BytesIn, s.BytesOut, now
	s.RateIn, s.RateOut = t.rateIn, t.rateOut
	t.mu.Unlock()
	t.Publish(Event{Type: "stats", Data: s})
}

// Subscribe returns a channel of events; call the cancel func when done.
// Subscribers reports how many event-stream listeners are connected (used as a
// heuristic for "is a UI open to answer firewall prompts").
func (t *Tracker) Subscribers() int {
	t.subMu.Lock()
	defer t.subMu.Unlock()
	return len(t.subs)
}

func (t *Tracker) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 512)
	t.subMu.Lock()
	t.subs[ch] = struct{}{}
	t.subMu.Unlock()
	return ch, func() {
		t.subMu.Lock()
		delete(t.subs, ch)
		t.subMu.Unlock()
	}
}

// Publish broadcasts an event, dropping it for slow subscribers.
func (t *Tracker) Publish(e Event) {
	t.subMu.Lock()
	for ch := range t.subs {
		select {
		case ch <- e:
		default:
		}
	}
	t.subMu.Unlock()
}

// Log stores a log line and publishes it.
func (t *Tracker) Log(level, msg string) {
	l := LogLine{Time: time.Now(), Level: level, Msg: msg}
	t.logMu.Lock()
	t.logs = append(t.logs, l)
	if len(t.logs) > t.maxLogs {
		t.logs = t.logs[len(t.logs)-t.maxLogs:]
	}
	t.logMu.Unlock()
	t.Publish(Event{Type: "log", Data: l})
}

// Logs returns the last n log lines.
func (t *Tracker) Logs(n int) []LogLine {
	t.logMu.Lock()
	defer t.logMu.Unlock()
	if n <= 0 || n > len(t.logs) {
		n = len(t.logs)
	}
	out := make([]LogLine, n)
	copy(out, t.logs[len(t.logs)-n:])
	return out
}

// MarshalEvent encodes the data payload.
func MarshalEvent(e Event) []byte {
	b, _ := json.Marshal(e.Data)
	return b
}
