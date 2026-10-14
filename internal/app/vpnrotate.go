package app

import (
	"math/rand"
	"sync"
	"time"

	"cyberboba/internal/config"
	"cyberboba/internal/vpn"
)

// VPNRotator cycles the active tunnel among a set of VPN profiles on a timer.
// A rule routing action=vpn to the rotation's name resolves (at dial time) to
// the currently-active member's fwmark via Current().
type VPNRotator struct {
	mu      sync.Mutex
	mgr     *vpn.Manager
	rots    map[string]config.VPNRotation
	state   map[string]*vpnRotState
	logf    func(level, format string, args ...interface{})
	publish func(group, member string)
}

type vpnRotState struct {
	idx    int
	last   time.Time
	active string
}

// NewVPNRotator creates a rotator bound to the VPN manager.
func NewVPNRotator(mgr *vpn.Manager, logf func(string, string, ...interface{}), publish func(string, string)) *VPNRotator {
	if logf == nil {
		logf = func(string, string, ...interface{}) {}
	}
	if publish == nil {
		publish = func(string, string) {}
	}
	return &VPNRotator{mgr: mgr, rots: map[string]config.VPNRotation{}, state: map[string]*vpnRotState{}, logf: logf, publish: publish}
}

// SetConfig reconciles the configured rotations: starts enabled ones (bringing
// up their first member) and tears down removed/disabled ones.
func (r *VPNRotator) SetConfig(rots []config.VPNRotation) {
	r.mu.Lock()
	want := map[string]config.VPNRotation{}
	for _, x := range rots {
		want[x.Name] = x
	}
	// stop removed or disabled
	for name := range r.rots {
		w, ok := want[name]
		if !ok || !w.Enabled {
			if st := r.state[name]; st != nil && st.active != "" {
				member := st.active
				go func() { _ = r.mgr.Down(member) }()
			}
			delete(r.state, name)
		}
	}
	r.rots = want
	// start newly enabled
	var toStart []config.VPNRotation
	for name, w := range want {
		if w.Enabled && len(w.VPNs) > 0 && r.state[name] == nil {
			toStart = append(toStart, w)
		}
	}
	r.mu.Unlock()
	for _, w := range toStart {
		idx := 0
		if w.Mode == "random" && len(w.VPNs) > 1 {
			idx = rand.Intn(len(w.VPNs))
		}
		member := w.VPNs[idx]
		r.mu.Lock()
		r.state[w.Name] = &vpnRotState{idx: idx, last: time.Now(), active: member}
		r.mu.Unlock()
		r.logf("info", "vpn rotation %q starting on %s", w.Name, member)
		if err := r.mgr.Up(member); err != nil {
			r.logf("error", "vpn rotation %q: up %s: %v", w.Name, member, err)
		}
		r.publish(w.Name, member)
	}
}

// Tick advances any rotation whose interval has elapsed: brings up the next
// member, then brings down the previous one after it is up.
func (r *VPNRotator) Tick() {
	r.mu.Lock()
	type due struct {
		name, next, prev string
	}
	var dues []due
	now := time.Now()
	for name, w := range r.rots {
		if !w.Enabled || len(w.VPNs) == 0 {
			continue
		}
		st := r.state[name]
		if st == nil {
			continue
		}
		every := time.Duration(w.EverySec) * time.Second
		if every <= 0 {
			every = 300 * time.Second
		}
		if now.Sub(st.last) < every || len(w.VPNs) < 2 {
			continue
		}
		next := nextRotIdx(w.Mode, st.idx, len(w.VPNs))
		prev := st.active
		st.idx = next
		st.last = now
		st.active = w.VPNs[next]
		dues = append(dues, due{name: name, next: w.VPNs[next], prev: prev})
	}
	r.mu.Unlock()
	for _, d := range dues {
		r.logf("info", "vpn rotation %q -> %s", d.name, d.next)
		if err := r.mgr.Up(d.next); err != nil {
			r.logf("error", "vpn rotation %q: up %s: %v", d.name, d.next, err)
			continue
		}
		r.publish(d.name, d.next)
		if d.prev != "" && d.prev != d.next {
			prev := d.prev
			time.AfterFunc(3*time.Second, func() { _ = r.mgr.Down(prev) })
		}
	}
}

func nextRotIdx(mode string, cur, n int) int {
	if n <= 1 {
		return 0
	}
	if mode == "sequential" {
		return (cur + 1) % n
	}
	j := rand.Intn(n)
	if j == cur {
		j = (cur + 1) % n
	}
	return j
}

// Current returns the active member of a rotation name, or (name,false) if it
// is not a (running) rotation.
func (r *VPNRotator) Current(name string) (string, bool) {
	if r == nil {
		return "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rots[name]; !ok {
		return "", false
	}
	if st := r.state[name]; st != nil && st.active != "" {
		return st.active, true
	}
	if w, ok := r.rots[name]; ok && len(w.VPNs) > 0 {
		return w.VPNs[0], true
	}
	return "", false
}

// Status is the live view of a VPN rotation.
type VPNRotStatus struct {
	Name      string   `json:"name"`
	Enabled   bool     `json:"enabled"`
	Current   string   `json:"current"`
	Members   []string `json:"members"`
	EverySec  int      `json:"every_sec"`
	Mode      string   `json:"mode"`
	NextInSec int      `json:"next_in_sec"`
}

// Status returns every configured rotation's live state.
func (r *VPNRotator) Status() []VPNRotStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	out := make([]VPNRotStatus, 0, len(r.rots))
	for name, w := range r.rots {
		s := VPNRotStatus{Name: name, Enabled: w.Enabled, Members: append([]string(nil), w.VPNs...), EverySec: w.EverySec, Mode: w.Mode}
		if st := r.state[name]; st != nil {
			s.Current = st.active
			s.NextInSec = w.EverySec - int(now.Sub(st.last).Seconds())
			if s.NextInSec < 0 {
				s.NextInSec = 0
			}
		}
		out = append(out, s)
	}
	return out
}

// Stop brings down all active rotation tunnels.
func (r *VPNRotator) Stop() {
	r.mu.Lock()
	var members []string
	for _, st := range r.state {
		if st.active != "" {
			members = append(members, st.active)
		}
	}
	r.state = map[string]*vpnRotState{}
	r.mu.Unlock()
	for _, m := range members {
		_ = r.mgr.Down(m)
	}
}
