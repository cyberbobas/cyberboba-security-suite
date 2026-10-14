package api

import (
	"errors"
	"net/http"
	"os"
	"sort"
	"strconv"

	"cyberboba/internal/sysstat"
)

func (s *Server) procmonRoutes() {
	m := s.mux

	m.HandleFunc("GET /api/sysstat", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.d.Sys.Sample())
	})

	// Free memory the system is holding: drop the page/inode cache and, when
	// asked, cycle swap back into RAM. Needs root (the daemon runs as root).
	// Body (all optional, default = caches only): {"caches":true,"swap":false,"compact":false}.
	m.HandleFunc("POST /api/system/reclaim", func(w http.ResponseWriter, r *http.Request) {
		in := struct {
			Caches  *bool `json:"caches"`
			Swap    bool  `json:"swap"`
			Compact bool  `json:"compact"`
		}{}
		_ = readJSON(r, &in)
		caches := in.Caches == nil || *in.Caches // default on
		writeJSON(w, sysstat.Reclaim(caches, in.Compact, in.Swap))
	})

	// Full Task-Manager-style process snapshot with live CPU%, memory, owner
	// and per-process active connection counts.
	m.HandleFunc("GET /api/procmon", func(w http.ResponseWriter, r *http.Request) {
		ps := s.d.ProcMon.List()

		// active tracked connections per pid
		connByPID := map[int]int{}
		conns := s.d.Tracker.List(2000, false)
		for i := range conns {
			c := &conns[i]
			if c.State == "open" && c.PID > 0 {
				connByPID[c.PID]++
			}
		}

		var totCPU, totRSS float64
		users := map[string]bool{}
		sys := 0
		for i := range ps {
			ps[i].Conns = connByPID[ps[i].PID]
			totCPU += ps[i].CPUPct
			totRSS += float64(ps[i].RSSKB)
			if ps[i].System {
				sys++
			} else if ps[i].User != "" {
				users[ps[i].User] = true
			}
		}
		sort.Slice(ps, func(i, j int) bool {
			if ps[i].CPUPct != ps[j].CPUPct {
				return ps[i].CPUPct > ps[j].CPUPct
			}
			return ps[i].RSSKB > ps[j].RSSKB
		})
		writeJSON(w, map[string]interface{}{
			"processes": ps,
			"summary": map[string]interface{}{
				"total":   len(ps),
				"system":  sys,
				"user":    len(ps) - sys,
				"cpu_pct": round1(totCPU),
				"rss_kb":  int64(totRSS),
				"own_pid": os.Getpid(),
			},
		})
	})

	// Send a signal to a process. Default SIGTERM; ?signal=KILL for SIGKILL.
	m.HandleFunc("POST /api/processes/{pid}/kill", func(w http.ResponseWriter, r *http.Request) {
		pid, err := strconv.Atoi(r.PathValue("pid"))
		if err != nil || pid <= 0 {
			writeErr(w, 400, errors.New("invalid pid"))
			return
		}
		sig := r.URL.Query().Get("signal")
		if sig == "" {
			var in struct {
				Signal string `json:"signal"`
			}
			_ = readJSON(r, &in)
			sig = in.Signal
		}
		// safety: never let the UI kill init or the cyberboba daemon itself.
		if pid == 1 {
			writeErr(w, 403, errors.New("refusing to kill pid 1 (init)"))
			return
		}
		if pid == os.Getpid() {
			writeErr(w, 403, errors.New("refusing to kill the cyberboba daemon itself"))
			return
		}
		if err := s.d.ProcMon.Kill(pid, sig); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "pid": pid, "signal": sigName(sig)})
	})
}

func sigName(s string) string {
	if s == "" {
		return "TERM"
	}
	return s
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
