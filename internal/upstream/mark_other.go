//go:build !linux

package upstream

import "syscall"

// markControl is a no-op on non-Linux platforms (SO_MARK / fwmark routing is
// Linux-specific), so marked dials fall back to a normal dial.
func markControl(mark uint32, onErr func(error)) func(network, address string, c syscall.RawConn) error {
	return nil
}
