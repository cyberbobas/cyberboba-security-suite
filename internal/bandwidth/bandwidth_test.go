package bandwidth

import (
	"testing"

	"cyberboba/internal/stats"
)

func mkConn(id uint64, app string, in, out int64, open bool) stats.Conn {
	st := stats.ConnState("closed")
	if open {
		st = "open"
	}
	return stats.Conn{ID: id, App: app, BytesIn: in, BytesOut: out, State: st}
}

func TestMeterAccumulatesDeltas(t *testing.T) {
	m := New("")
	// A connection opens at 0 bytes and grows; the meter counts a conn's full
	// cumulative bytes from first sight (dt=0 here, so no rate is computed).
	m.Sample([]stats.Conn{mkConn(1, "chromium", 100, 10, true)})
	// second sample: +900 in, +90 out -> cumulative 1000 / 100
	m.Sample([]stats.Conn{mkConn(1, "chromium", 1000, 100, true)})
	s := m.Snapshot()
	if len(s.Apps) != 1 || s.Apps[0].App != "chromium" {
		t.Fatalf("expected chromium, got %+v", s.Apps)
	}
	a := s.Apps[0]
	if a.TotalIn != 1000 || a.TotalOut != 100 {
		t.Fatalf("session totals wrong: in=%d out=%d", a.TotalIn, a.TotalOut)
	}
	if a.TodayIn != 1000 || a.TodayOut != 100 {
		t.Fatalf("today totals wrong: in=%d out=%d", a.TodayIn, a.TodayOut)
	}
	if a.Conns != 1 {
		t.Fatalf("expected 1 active conn, got %d", a.Conns)
	}
}

func TestMeterSurvivesConnEviction(t *testing.T) {
	m := New("")
	m.Sample([]stats.Conn{mkConn(1, "curl", 0, 0, true)})
	m.Sample([]stats.Conn{mkConn(1, "curl", 500, 500, false)}) // closed, final bytes
	// conn evicted from tracker; a NEW conn reuses nothing
	m.Sample([]stats.Conn{mkConn(2, "curl", 0, 0, true)})
	m.Sample([]stats.Conn{mkConn(2, "curl", 300, 0, true)})
	s := m.Snapshot()
	if s.Apps[0].TotalIn != 800 {
		t.Fatalf("expected 800 in across two conns, got %d", s.Apps[0].TotalIn)
	}
}

func TestMeterReset(t *testing.T) {
	m := New("")
	m.Sample([]stats.Conn{mkConn(1, "x", 0, 0, true)})
	m.Sample([]stats.Conn{mkConn(1, "x", 100, 0, true)})
	m.Reset()
	if len(m.Snapshot().Apps) != 0 {
		t.Fatal("reset should clear apps")
	}
}
