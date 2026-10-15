//go:build !linux

package osutil

import "os/exec"

// SetPgid is a no-op on non-Linux platforms.
func SetPgid(cmd *exec.Cmd) {}
