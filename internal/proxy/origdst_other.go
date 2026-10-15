//go:build !linux

package proxy

import (
	"errors"
	"net/netip"
)

// getOriginalDst is Linux-only: transparent REDIRECT and SO_ORIGINAL_DST do
// not exist on other platforms (use explicit SOCKS5/HTTP proxy mode there).
func getOriginalDst(fd int, v6 bool) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("transparent redirect is Linux-only")
}
