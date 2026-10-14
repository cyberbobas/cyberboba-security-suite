package sysstat

import "testing"

func TestReclaimNoopSnapshots(t *testing.T) {
	// Requesting nothing must not error and must still capture snapshots.
	r := Reclaim(false, false, false)
	if len(r.Actions) != 0 {
		t.Fatalf("expected no actions, got %v", r.Actions)
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", r.Warnings)
	}
	if r.Before.TotalKB == 0 || r.After.TotalKB == 0 {
		t.Fatal("snapshots should report total memory")
	}
}

func TestTrimSwapRefusesWhenUnsafe(t *testing.T) {
	// No swap configured -> refuse.
	if err := trimSwap(Mem{SwapKB: 0}); err == nil {
		t.Fatal("expected refusal when no swap configured")
	}
	// Swap empty -> refuse.
	if err := trimSwap(Mem{SwapKB: 1000, SwapUsed: 0}); err == nil {
		t.Fatal("expected refusal when swap already empty")
	}
	// Used swap would not fit in available RAM -> refuse (never runs swapoff).
	if err := trimSwap(Mem{SwapKB: 4 << 20, SwapUsed: 2 << 20, AvailKB: 1 << 20}); err == nil {
		t.Fatal("expected refusal when swap would not fit in RAM")
	}
}

func TestTrimSpace(t *testing.T) {
	if trimSpace("hi\n\r ") != "hi" {
		t.Fatalf("trimSpace failed: %q", trimSpace("hi\n\r "))
	}
}
