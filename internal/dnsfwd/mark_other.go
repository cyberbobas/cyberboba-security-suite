//go:build !linux

package dnsfwd

import "syscall"

// markControl is a no-op on non-Linux platforms.
func markControl(mark uint32) func(network, address string, c syscall.RawConn) error { return nil }
