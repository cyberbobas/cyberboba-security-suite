//go:build linux

package proxy

import (
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const soOriginalDst = 80 // SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST

// getOriginalDst reads the pre-REDIRECT destination of a transparently
// intercepted connection (Linux netfilter SO_ORIGINAL_DST).
func getOriginalDst(fd int, v6 bool) (netip.AddrPort, error) {
	if !v6 {
		var addr unix.RawSockaddrInet4
		l := uint32(unsafe.Sizeof(addr))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.SOL_IP), soOriginalDst,
			uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&l)), 0)
		if errno != 0 {
			return netip.AddrPort{}, errno
		}
		port := (uint16(addr.Port&0xff) << 8) | uint16(addr.Port>>8)
		return netip.AddrPortFrom(netip.AddrFrom4(addr.Addr), port), nil
	}
	var addr unix.RawSockaddrInet6
	l := uint32(unsafe.Sizeof(addr))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.SOL_IPV6), soOriginalDst,
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&l)), 0)
	if errno != 0 {
		return netip.AddrPort{}, errno
	}
	port := (uint16(addr.Port&0xff) << 8) | uint16(addr.Port>>8)
	return netip.AddrPortFrom(netip.AddrFrom16(addr.Addr), port), nil
}
