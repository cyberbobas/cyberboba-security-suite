package procmon

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestListFindsSelf(t *testing.T) {
	m := New()
	ps := m.List()
	if len(ps) < 2 {
		t.Fatalf("expected many processes, got %d", len(ps))
	}
	var self *Proc
	for i := range ps {
		if ps[i].PID == os.Getpid() {
			self = &ps[i]
			break
		}
	}
	if self == nil {
		t.Fatal("own process not in snapshot")
	}
	if self.Name == "" {
		t.Fatal("own process has empty name")
	}
	if self.Threads < 1 {
		t.Fatalf("own process threads = %d", self.Threads)
	}
	if self.Kernel {
		t.Fatal("own process should not be a kernel thread")
	}
	if self.CPUPct < 0 {
		t.Fatalf("cpu%% negative: %v", self.CPUPct)
	}
}

func TestKillSendsSignal(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	pid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	m := New()
	if err := m.Kill(pid, "KILL"); err != nil {
		t.Fatalf("kill: %v", err)
	}
	select {
	case <-done: // process reaped
	case <-time.After(3 * time.Second):
		_ = m.Kill(pid, "KILL")
		t.Fatal("process did not die after SIGKILL")
	}
}

func TestStateName(t *testing.T) {
	if stateName("S") != "S sleeping" || stateName("R") != "R running" || stateName("Z") != "Z zombie" {
		t.Fatal("stateName mapping wrong")
	}
	if stateName("?") != "?" {
		t.Fatal("unknown state should pass through")
	}
}
