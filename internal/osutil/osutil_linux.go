//go:build linux

// Package osutil holds tiny OS-specific process helpers so the rest of the
// code stays portable (it compiles on macOS/Windows; Linux-only features are
// no-ops there).
package osutil

import (
	"os/exec"
	"syscall"
)

// SetPgid puts the child in its own process group so it is not killed by a
// signal sent to the daemon's group.
func SetPgid(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
