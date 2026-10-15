package sysstat

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Reclaim frees cached/buffered memory and, optionally, cycles swap back into
// RAM. All operations need root (the daemon runs as root). Each requested step
// is attempted independently; a step that fails adds a warning but does not
// abort the others. The result carries memory snapshots taken immediately
// before and after so the caller can show how much was actually freed.
type ReclaimResult struct {
	Actions  []string `json:"actions"`            // steps that ran successfully
	Warnings []string `json:"warnings,omitempty"` // steps that were skipped or failed, with the reason
	Before   Mem      `json:"before"`
	After    Mem      `json:"after"`
	// FreedKB is the drop in used memory (before.UsedKB - after.UsedKB); it can
	// be negative if the system got busier between snapshots.
	FreedKB int64 `json:"freed_kb"`
	// SwapFreedKB is the drop in used swap.
	SwapFreedKB int64 `json:"swap_freed_kb"`
}

// Reclaim performs the requested cleanup steps.
//   - caches:  sync() then drop page cache, dentries and inodes.
//   - compact: ask the kernel to compact memory (defragment), best effort.
//   - swap:    swapoff -a then swapon -a, moving every swapped page back into
//     RAM. Refused when used swap would not fit in available RAM (it would
//     thrash or OOM the box).
func Reclaim(caches, compact, swap bool) ReclaimResult {
	res := ReclaimResult{Before: mem(), Actions: []string{}}

	if swap {
		if err := trimSwap(res.Before); err != nil {
			res.Warnings = append(res.Warnings, "swap: "+err.Error())
		} else {
			res.Actions = append(res.Actions, "cycled swap back into RAM")
		}
	}
	if caches {
		if err := dropCaches(); err != nil {
			res.Warnings = append(res.Warnings, "drop caches: "+err.Error())
		} else {
			res.Actions = append(res.Actions, "dropped page cache / dentries / inodes")
		}
	}
	if compact {
		if err := writeProc("/proc/sys/vm/compact_memory", "1"); err != nil {
			res.Warnings = append(res.Warnings, "compact memory: "+err.Error())
		} else {
			res.Actions = append(res.Actions, "compacted memory")
		}
	}

	res.After = mem()
	res.FreedKB = res.Before.UsedKB - res.After.UsedKB
	res.SwapFreedKB = res.Before.SwapUsed - res.After.SwapUsed
	return res
}

// dropCaches flushes dirty pages to disk and then releases the reclaimable
// page cache. Writing 3 drops pagecache + slab (dentries/inodes).
func dropCaches() error {
	osSync()
	return writeProc("/proc/sys/vm/drop_caches", "3")
}

// trimSwap moves swapped pages back into RAM (swapoff -a) and re-enables swap
// (swapon -a). It refuses when the swapped-out data would not comfortably fit
// in available RAM, which would otherwise thrash or OOM the machine.
func trimSwap(m Mem) error {
	if m.SwapKB == 0 {
		return fmt.Errorf("no swap configured")
	}
	if m.SwapUsed == 0 {
		return fmt.Errorf("swap already empty")
	}
	const marginKB = 256 * 1024 // keep 256 MiB headroom
	if m.SwapUsed+marginKB > m.AvailKB {
		return fmt.Errorf("unsafe: %d MiB in swap needs more free RAM than the %d MiB available — close something first",
			m.SwapUsed/1024, m.AvailKB/1024)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "swapoff", "-a").CombinedOutput(); err != nil {
		// Best effort to restore swap even if swapoff partially ran.
		_ = exec.Command("swapon", "-a").Run()
		msg := trimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("swapoff: %s", msg)
	}
	if out, err := exec.Command("swapon", "-a").CombinedOutput(); err != nil {
		msg := trimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("swapon (swap is now OFF, re-enable manually): %s", msg)
	}
	return nil
}

func writeProc(path, val string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(val + "\n")
	return err
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
