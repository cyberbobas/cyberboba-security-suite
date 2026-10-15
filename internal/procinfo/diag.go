package procinfo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// Exact socket lookup through NETLINK_SOCK_DIAG (what `ss` uses).
//
// Parsing /proc/net/tcp is a *walk* over the kernel's hash table; while a
// browser opens dozens of connections at once the walk can skip entries, and
// the socket of a connection we just accepted then looks "not found". The
// diag request asks the kernel for exactly one 4-tuple and gets its inode
// and uid atomically, which is both faster and reliable under churn.

const (
	sockDiagByFamily = 20 // SOCK_DIAG_BY_FAMILY
	netlinkSockDiag  = 4  // NETLINK_SOCK_DIAG
	tcpAllStates     = 0xfff
)

// inetDiagReqV2 mirrors struct inet_diag_req_v2 (56 bytes).
type inetDiagReqV2 struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	Pad      uint8
	States   uint32
	ID       inetDiagSockID
}

// inetDiagSockID mirrors struct inet_diag_sockid (48 bytes).
type inetDiagSockID struct {
	SPort  [2]byte // big endian
	DPort  [2]byte // big endian
	Src    [16]byte
	Dst    [16]byte
	If     uint32
	Cookie [2]uint32
}

// inetDiagMsg mirrors struct inet_diag_msg (72 bytes).
type inetDiagMsg struct {
	Family  uint8
	State   uint8
	Timer   uint8
	Retrans uint8
	ID      inetDiagSockID
	Expires uint32
	RQueue  uint32
	WQueue  uint32
	UID     uint32
	Inode   uint32
}

var errDiagUnavailable = errors.New("sock_diag unavailable")

// diagLookup returns (inode, uid) of the TCP socket whose local endpoint is
// local and remote endpoint is remote, trying AF_INET for IPv4 pairs and
// AF_INET6 (v4-mapped) when the IPv4 query finds nothing.
func diagLookup(local, remote netip.AddrPort) (uint64, int, error) {
	l, r := local.Addr().Unmap(), remote.Addr().Unmap()
	if l.Is4() && r.Is4() {
		if inode, uid, err := diagQuery(syscall.AF_INET, l, local.Port(), r, remote.Port()); err == nil {
			return inode, uid, nil
		} else if errors.Is(err, errDiagUnavailable) {
			return 0, -1, err
		}
		// dual-stack socket: the kernel keys it under AF_INET6 with ::ffff:a.b.c.d
		return diagQuery(syscall.AF_INET6, netip.AddrFrom16(l.As16()), local.Port(), netip.AddrFrom16(r.As16()), remote.Port())
	}
	return diagQuery(syscall.AF_INET6, netip.AddrFrom16(l.As16()), local.Port(), netip.AddrFrom16(r.As16()), remote.Port())
}

func diagQuery(family int, src netip.Addr, sport uint16, dst netip.Addr, dport uint16) (uint64, int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkSockDiag)
	if err != nil {
		return 0, -1, fmt.Errorf("%w: %v", errDiagUnavailable, err)
	}
	defer syscall.Close(fd)
	tv := syscall.NsecToTimeval(int64(500 * time.Millisecond))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	req := inetDiagReqV2{Family: uint8(family), Protocol: syscall.IPPROTO_TCP, States: tcpAllStates}
	binary.BigEndian.PutUint16(req.ID.SPort[:], sport)
	binary.BigEndian.PutUint16(req.ID.DPort[:], dport)
	if family == syscall.AF_INET {
		s4, d4 := src.As4(), dst.As4()
		copy(req.ID.Src[:4], s4[:])
		copy(req.ID.Dst[:4], d4[:])
	} else {
		req.ID.Src, req.ID.Dst = src.As16(), dst.As16()
	}
	req.ID.Cookie = [2]uint32{^uint32(0), ^uint32(0)} // INET_DIAG_NOCOOKIE

	const reqLen = syscall.NLMSG_HDRLEN + int(unsafe.Sizeof(inetDiagReqV2{}))
	buf := make([]byte, reqLen)
	h := (*syscall.NlMsghdr)(unsafe.Pointer(&buf[0]))
	h.Len, h.Type, h.Flags, h.Seq, h.Pid = uint32(reqLen), sockDiagByFamily, syscall.NLM_F_REQUEST, uint32(time.Now().UnixNano()), 0
	*(*inetDiagReqV2)(unsafe.Pointer(&buf[syscall.NLMSG_HDRLEN])) = req

	if err := syscall.Sendto(fd, buf, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, -1, fmt.Errorf("%w: send: %v", errDiagUnavailable, err)
	}
	resp := make([]byte, 8192)
	n, _, err := syscall.Recvfrom(fd, resp, 0)
	if err != nil {
		return 0, -1, fmt.Errorf("%w: recv: %v", errDiagUnavailable, err)
	}
	msgs, err := syscall.ParseNetlinkMessage(resp[:n])
	if err != nil {
		return 0, -1, fmt.Errorf("%w: parse: %v", errDiagUnavailable, err)
	}
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_ERROR:
			if len(m.Data) >= 4 {
				if e := -int32(binary.LittleEndian.Uint32(m.Data[:4])); e != 0 {
					if syscall.Errno(e) == syscall.ENOENT {
						return 0, -1, os.ErrNotExist
					}
					return 0, -1, fmt.Errorf("%w: %v", errDiagUnavailable, syscall.Errno(e))
				}
			}
			return 0, -1, os.ErrNotExist
		case sockDiagByFamily:
			if len(m.Data) < int(unsafe.Sizeof(inetDiagMsg{})) {
				continue
			}
			dm := (*inetDiagMsg)(unsafe.Pointer(&m.Data[0]))
			return uint64(dm.Inode), int(dm.UID), nil
		}
	}
	return 0, -1, os.ErrNotExist
}
