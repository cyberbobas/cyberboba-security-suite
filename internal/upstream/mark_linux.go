//go:build linux

package upstream

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// markControl returns a net.Dialer Control hook that sets the firewall mark
// (SO_MARK) on the socket so netfilter does not redirect it and policy routing
// can steer it. onErr is called once if the mark cannot be set.
func markControl(mark uint32, onErr func(error)) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		if serr != nil && onErr != nil {
			onErr(serr)
		}
		return nil
	}
}
