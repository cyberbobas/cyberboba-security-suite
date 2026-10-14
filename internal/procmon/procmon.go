// Package procmon is a Task-Manager-style process monitor: a full snapshot of
// every process on the host with live CPU%, memory, state and ownership, plus
// the ability to send a signal (kill) to a process. It reads /proc directly.
package procmon

import (
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// clkTck is the kernel's USER_HZ. It is 100 on virtually every Linux build
// (x86/arm); procmon assumes this to turn jiffies into seconds.
const clkTck = 100.0

// Proc is one process in the snapshot.
type Proc struct {
	PID     int     `json:"pid"`
	PPID    int     `json:"ppid"`
	Name    string  `json:"name"`
	Cmd     string  `json:"cmd,omitempty"`
	User    string  `json:"user"`
	UID     int     `json:"uid"`
	State   string  `json:"state"`   // R,S,D,Z,T,I + description
	CPUPct  float64 `json:"cpu_pct"` // since the previous snapshot
	RSSKB   int64   `json:"rss_kb"`  // resident memory
	Threads int     `json:"threads"`
	Started int64   `json:"started,omitempty"` // unix seconds
	Kernel  bool    `json:"kernel"`            // kernel thread (no userspace image)
	System  bool    `json:"system"`            // kernel thread or system/service account (uid<1000)
	Conns   int     `json:"conns,omitempty"`   // active tracked connections (filled by the API)
}

type cpuSample struct {
	jiffies uint64
	at      time.Time
}

// Monitor keeps per-PID CPU history so each snapshot can report CPU% over the
// interval since the previous call.
type Monitor struct {
	mu       sync.Mutex
	prev     map[int]cpuSample
	users    map[int]string
	bootTime int64
	ncpu     int
}

// New builds a monitor.
func New() *Monitor {
	return &Monitor{prev: map[int]cpuSample{}, users: map[int]string{}, bootTime: bootTime(), ncpu: numCPU()}
}

// List returns a fresh snapshot of all processes.
func (m *Monitor) List() []Proc {
	des, _ := os.ReadDir("/proc")
	now := time.Now()
	out := make([]Proc, 0, len(des))
	live := map[int]bool{}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, de := range des {
		pid, err := strconv.Atoi(de.Name())
		if err != nil {
			continue
		}
		p, jiff, ok := m.read(pid)
		if !ok {
			continue
		}
		live[pid] = true
		if prev, had := m.prev[pid]; had {
			dt := now.Sub(prev.at).Seconds()
			if dt > 0 && jiff >= prev.jiffies {
				pct := (float64(jiff-prev.jiffies) / clkTck) / dt * 100.0
				if max := float64(m.ncpu) * 100.0; pct > max {
					pct = max
				}
				p.CPUPct = round1(pct)
			}
		}
		m.prev[pid] = cpuSample{jiffies: jiff, at: now}
		out = append(out, p)
	}
	// forget dead pids so the map does not grow unbounded
	for pid := range m.prev {
		if !live[pid] {
			delete(m.prev, pid)
		}
	}
	return out
}

// read parses /proc/<pid> into a Proc. jiff is utime+stime for CPU accounting.
func (m *Monitor) read(pid int) (Proc, uint64, bool) {
	statb, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return Proc{}, 0, false
	}
	raw := string(statb)
	// comm is field 2, wrapped in () and may contain spaces/parens.
	lp := strings.IndexByte(raw, '(')
	rp := strings.LastIndexByte(raw, ')')
	if lp < 0 || rp < 0 || rp < lp {
		return Proc{}, 0, false
	}
	comm := raw[lp+1 : rp]
	rest := strings.Fields(raw[rp+2:]) // fields starting at field 3 (state)
	if len(rest) < 20 {
		return Proc{}, 0, false
	}
	p := Proc{PID: pid, Name: comm, UID: -1}
	p.State = stateName(rest[0])                    // field 3
	p.PPID, _ = strconv.Atoi(rest[1])               // field 4
	utime, _ := strconv.ParseUint(rest[11], 10, 64) // field 14
	stime, _ := strconv.ParseUint(rest[12], 10, 64) // field 15
	p.Threads, _ = strconv.Atoi(rest[17])           // field 20
	start, _ := strconv.ParseUint(rest[19], 10, 64) // field 22 (jiffies since boot)
	if m.bootTime > 0 {
		p.Started = m.bootTime + int64(start/clkTck)
	}
	jiff := utime + stime

	// resident memory from statm (field 2 = resident pages)
	if sm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/statm"); err == nil {
		f := strings.Fields(string(sm))
		if len(f) >= 2 {
			if pages, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				p.RSSKB = pages * int64(os.Getpagesize()) / 1024
			}
		}
	}

	// command line (empty for kernel threads)
	if cl, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline"); err == nil {
		c := strings.TrimSpace(strings.ReplaceAll(strings.TrimRight(string(cl), "\x00"), "\x00", " "))
		p.Cmd = c
		if c == "" {
			p.Kernel = true // no userspace command line → kernel thread
		}
	}
	// a nicer name for userspace procs whose comm was truncated to 15 chars
	if !p.Kernel {
		if exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil {
			base := strings.TrimSuffix(exe, " (deleted)")
			if i := strings.LastIndexByte(base, '/'); i >= 0 {
				base = base[i+1:]
			}
			if len(p.Name) == 15 && strings.HasPrefix(base, p.Name) {
				p.Name = base
			}
		}
	}

	// owner uid from /proc/<pid>/status
	if st, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status"); err == nil {
		for _, line := range strings.Split(string(st), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fs := strings.Fields(line)
				if len(fs) >= 2 {
					p.UID, _ = strconv.Atoi(fs[1])
				}
				break
			}
		}
	}
	p.User = m.userName(p.UID)
	// system = kernel thread or a system/service account (uid below the first
	// regular login uid, 1000 on Debian/Ubuntu/Mint).
	p.System = p.Kernel || (p.UID >= 0 && p.UID < 1000)
	return p, jiff, true
}

func (m *Monitor) userName(uid int) string {
	if uid < 0 {
		return ""
	}
	if n, ok := m.users[uid]; ok {
		return n
	}
	n := strconv.Itoa(uid)
	if u, err := user.LookupId(n); err == nil {
		n = u.Username
	}
	m.users[uid] = n
	return n
}

// Kill sends a signal to a process. sig is "TERM" (default) or "KILL".
func (m *Monitor) Kill(pid int, sig string) error {
	s := syscall.SIGTERM
	switch strings.ToUpper(strings.TrimPrefix(strings.ToUpper(sig), "SIG")) {
	case "", "TERM", "15":
		s = syscall.SIGTERM
	case "KILL", "9":
		s = syscall.SIGKILL
	case "HUP", "1":
		s = syscall.SIGHUP
	case "INT", "2":
		s = syscall.SIGINT
	}
	return syscall.Kill(pid, s)
}

func stateName(s string) string {
	code := ""
	if len(s) > 0 {
		code = s[:1]
	}
	desc := map[string]string{"R": "running", "S": "sleeping", "D": "disk-wait", "Z": "zombie", "T": "stopped", "t": "traced", "X": "dead", "I": "idle"}[code]
	if desc == "" {
		return code
	}
	return code + " " + desc
}

func bootTime() int64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "btime ") {
			v, _ := strconv.ParseInt(strings.TrimSpace(line[6:]), 10, 64)
			return v
		}
	}
	return 0
}

func numCPU() int {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 1
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "cpu") && len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
			n++
		}
	}
	if n == 0 {
		n = 1
	}
	return n
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
