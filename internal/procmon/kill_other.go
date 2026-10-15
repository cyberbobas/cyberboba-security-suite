//go:build !linux

package procmon

import (
	"os"
	"syscall"
)

// killProc on non-Linux ignores the specific signal and best-effort kills the
// process (syscall.Kill is Linux/Unix-only).
func killProc(pid int, sig syscall.Signal) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
