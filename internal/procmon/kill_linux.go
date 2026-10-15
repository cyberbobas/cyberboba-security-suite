//go:build linux

package procmon

import "syscall"

func killProc(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }
