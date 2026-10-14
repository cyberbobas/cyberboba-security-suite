package sysstat

import "testing"

func TestSampleBasics(t *testing.T) {
	m := New()
	_ = m.Sample() // first call primes CPU deltas
	s := m.Sample()
	if s.CPU.NCPU < 1 {
		t.Fatalf("ncpu = %d", s.CPU.NCPU)
	}
	if s.Mem.TotalKB <= 0 {
		t.Fatalf("mem total = %d", s.Mem.TotalKB)
	}
	if s.Mem.Pct < 0 || s.Mem.Pct > 100 {
		t.Fatalf("mem pct out of range: %v", s.Mem.Pct)
	}
	if s.CPU.Pct < 0 || s.CPU.Pct > 100 {
		t.Fatalf("cpu pct out of range: %v", s.CPU.Pct)
	}
	// temps are hardware-dependent; just ensure values are sane when present.
	for _, tp := range s.Temps {
		if tp.Celsius < 0 || tp.Celsius > 150 {
			t.Fatalf("implausible temp %+v", tp)
		}
	}
}
