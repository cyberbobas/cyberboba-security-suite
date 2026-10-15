//go:build linux

package dnsfwd

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// markControl returns a Dialer Control hook that stamps the firewall mark on
// the socket (Linux fwmark routing).
func markControl(mark uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		})
	}
}
