package intercept

import (
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// State of a flow.
type State string

const (
	StatePendingRequest  State = "pending_request"
	StatePendingResponse State = "pending_response"
	StateSent            State = "sent"
	StateDone            State = "done"
	StateError           State = "error"
	StateDropped         State = "dropped"
)

// Header is an ordered name/value pair.
type Header [2]string

// Flow is one HTTP request/response pair.
type Flow struct {
	ID          uint64    `json:"id"`
	Time        time.Time `json:"time"`
	DurationMS  int64     `json:"duration_ms"`
	Source      string    `json:"source"`
	App         string    `json:"app,omitempty"`
	PID         int       `json:"pid,omitempty"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	TLS         bool      `json:"tls"`
	InScope     bool      `json:"in_scope"`
	Intercepted bool      `json:"intercepted"`
	Edited      bool      `json:"edited"`
	Rewritten   bool      `json:"rewritten"`

	Method           string   `json:"method"`
	URL              string   `json:"url"`
	Path             string   `json:"path"`
	Proto            string   `json:"proto"`
	ReqHeaders       []Header `json:"req_headers"`
	ReqSize          int64    `json:"req_size"`
	ReqBodyTruncated bool     `json:"req_body_truncated"`

	Status            int      `json:"status"`
	StatusText        string   `json:"status_text"`
	RespHeaders       []Header `json:"resp_headers"`
	RespSize          int64    `json:"resp_size"`
	RespBodyTruncated bool     `json:"resp_body_truncated"`
	ContentType       string   `json:"content_type"`
	WebSocket         bool     `json:"websocket"`

	State State  `json:"state"`
	Error string `json:"error,omitempty"`

	Findings []Finding `json:"findings,omitempty"`

	p *flowPriv
}

type flowPriv struct {
	mu       sync.Mutex
	reqBody  []byte
	respBody []byte
}

func (f *Flow) priv() *flowPriv {
	if f.p == nil {
		f.p = &flowPriv{}
	}
	return f.p
}

// FlowDetail adds bodies and raw text.
type FlowDetail struct {
	Flow
	ReqBody     string `json:"req_body"`
	ReqBodyB64  bool   `json:"req_body_b64"`
	RespBody    string `json:"resp_body"`
	RespBodyB64 bool   `json:"resp_body_b64"`
	ReqRaw      string `json:"req_raw"`
	RespRaw     string `json:"resp_raw"`
	ReqBodyCut  bool   `json:"req_body_cut"`
	RespBodyCut bool   `json:"resp_body_cut"`
}

func (f *Flow) snapshot() Flow {
	f.priv().mu.Lock()
	defer f.priv().mu.Unlock()
	cp := Flow{}
	cp.ID, cp.Time, cp.DurationMS, cp.Source, cp.App, cp.PID = f.ID, f.Time, f.DurationMS, f.Source, f.App, f.PID
	cp.Host, cp.Port, cp.TLS, cp.InScope, cp.Intercepted, cp.Edited, cp.Rewritten = f.Host, f.Port, f.TLS, f.InScope, f.Intercepted, f.Edited, f.Rewritten
	cp.Method, cp.URL, cp.Path, cp.Proto = f.Method, f.URL, f.Path, f.Proto
	cp.ReqHeaders = append([]Header(nil), f.ReqHeaders...)
	cp.ReqSize, cp.ReqBodyTruncated = f.ReqSize, f.ReqBodyTruncated
	cp.Status, cp.StatusText = f.Status, f.StatusText
	cp.RespHeaders = append([]Header(nil), f.RespHeaders...)
	cp.RespSize, cp.RespBodyTruncated, cp.ContentType, cp.WebSocket = f.RespSize, f.RespBodyTruncated, f.ContentType, f.WebSocket
	cp.State, cp.Error = f.State, f.Error
	cp.Findings = append([]Finding(nil), f.Findings...)
	if cp.ReqHeaders == nil {
		cp.ReqHeaders = []Header{}
	}
	if cp.RespHeaders == nil {
		cp.RespHeaders = []Header{}
	}
	return cp
}

// Detail builds the full view including bodies.
func (f *Flow) Detail() FlowDetail { return f.DetailCut(0) }

// DetailCut builds the full view, truncating bodies/raws to max bytes (0 = no limit).
func (f *Flow) DetailCut(max int) FlowDetail {
	d := FlowDetail{Flow: f.snapshot()}
	f.priv().mu.Lock()
	req, resp := f.priv().reqBody, f.priv().respBody
	f.priv().mu.Unlock()
	d.ReqRaw = rawRequest(&d.Flow, req)
	d.RespRaw = rawResponse(&d.Flow, resp)
	if max > 0 {
		if len(req) > max {
			req = req[:max]
			d.ReqBodyCut = true
		}
		if len(resp) > max {
			resp = resp[:max]
			d.RespBodyCut = true
		}
		if len(d.ReqRaw) > max {
			d.ReqRaw = d.ReqRaw[:max]
		}
		if len(d.RespRaw) > max {
			d.RespRaw = d.RespRaw[:max]
		}
	}
	d.ReqBody, d.ReqBodyB64 = encodeBody(req)
	d.RespBody, d.RespBodyB64 = encodeBody(resp)
	return d
}

func encodeBody(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	if utf8.Valid(b) && !hasBinary(b) {
		return string(b), false
	}
	return base64.StdEncoding.EncodeToString(b), true
}

func hasBinary(b []byte) bool {
	n := 0
	for _, c := range b {
		if c == 0 || (c < 0x20 && c != '\n' && c != '\r' && c != '\t' && c != 0x1b) {
			n++
			if n > 8 {
				return true
			}
		}
	}
	return false
}

func rawRequest(f *Flow, body []byte) string {
	if f.Method == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString(f.Method + " " + f.Path + " " + orProto(f.Proto) + "\r\n")
	for _, h := range f.ReqHeaders {
		b.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

func rawResponse(f *Flow, body []byte) string {
	if f.Status == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(orProto(f.Proto) + " " + f.StatusText + "\r\n")
	for _, h := range f.RespHeaders {
		b.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

func orProto(p string) string {
	if p == "" {
		return "HTTP/1.1"
	}
	return p
}

// Store is the in-memory ring of flows.
type Store struct {
	mu     sync.Mutex
	flows  []*Flow
	byID   map[uint64]*Flow
	nextID uint64
	max    int
}

// NewStore creates a store holding at most max flows.
func NewStore(max int) *Store {
	if max <= 0 {
		max = 10000
	}
	return &Store{byID: map[uint64]*Flow{}, max: max}
}

// SetMax changes the capacity.
func (s *Store) SetMax(max int) {
	if max <= 0 {
		return
	}
	s.mu.Lock()
	s.max = max
	s.trimLocked()
	s.mu.Unlock()
}

// Add assigns an id and stores the flow.
func (s *Store) Add(f *Flow) {
	s.mu.Lock()
	s.nextID++
	f.ID = s.nextID
	if f.Time.IsZero() {
		f.Time = time.Now()
	}
	s.flows = append(s.flows, f)
	s.byID[f.ID] = f
	s.trimLocked()
	s.mu.Unlock()
}

func (s *Store) trimLocked() {
	for len(s.flows) > s.max {
		old := s.flows[0]
		s.flows = s.flows[1:]
		delete(s.byID, old.ID)
	}
}

// Get returns a flow by id.
func (s *Store) Get(id uint64) *Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byID[id]
}

// Delete removes one flow.
func (s *Store) Delete(id uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return false
	}
	delete(s.byID, id)
	for i, f := range s.flows {
		if f.ID == id {
			s.flows = append(s.flows[:i], s.flows[i+1:]...)
			break
		}
	}
	return true
}

// Clear drops everything.
func (s *Store) Clear() {
	s.mu.Lock()
	s.flows = nil
	s.byID = map[uint64]*Flow{}
	s.mu.Unlock()
}

// Count returns the number of stored flows.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.flows)
}

// Filter selects flows.
type Filter struct {
	Q         string
	Host      string
	Method    string
	Status    string // exact "200" or prefix "4"
	ScopeOnly bool
	IDs       map[uint64]bool
	Source    string
	Body      string // substring searched in request+response bodies
}

// List returns matching flows newest first, with the total match count.
func (s *Store) List(f Filter, limit, offset int) ([]Flow, int) {
	s.mu.Lock()
	all := append([]*Flow(nil), s.flows...)
	s.mu.Unlock()
	var out []Flow
	q := strings.ToLower(f.Q)
	for i := len(all) - 1; i >= 0; i-- {
		fl := all[i].snapshot()
		if f.IDs != nil && !f.IDs[fl.ID] {
			continue
		}
		if f.ScopeOnly && !fl.InScope {
			continue
		}
		if f.Host != "" && !strings.Contains(strings.ToLower(fl.Host), strings.ToLower(f.Host)) {
			continue
		}
		if f.Method != "" && !strings.EqualFold(fl.Method, f.Method) {
			continue
		}
		if f.Source != "" && fl.Source != f.Source {
			continue
		}
		if f.Status != "" && !strings.HasPrefix(strconv.Itoa(fl.Status), f.Status) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(fl.URL), q) && !strings.Contains(strings.ToLower(fl.App), q) &&
			!strings.Contains(strings.ToLower(fl.ContentType), q) {
			continue
		}
		if f.Body != "" {
			all[i].priv().mu.Lock()
			rb, pb := all[i].priv().reqBody, all[i].priv().respBody
			all[i].priv().mu.Unlock()
			needle := strings.ToLower(f.Body)
			if !strings.Contains(strings.ToLower(string(rb)), needle) && !strings.Contains(strings.ToLower(string(pb)), needle) {
				continue
			}
		}
		out = append(out, fl)
	}
	total := len(out)
	if offset > 0 {
		if offset >= len(out) {
			out = nil
		} else {
			out = out[offset:]
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []Flow{}
	}
	return out, total
}

// All returns every flow (oldest first) for export.
func (s *Store) All() []*Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]*Flow(nil), s.flows...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
