package proxy

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

// StartSOCKS opens an inbound SOCKS5 listener. Applications that are
// configured to use it get the same rule-based routing as intercepted
// traffic, and it works without root (process attribution still uses /proc).
func (e *Engine) StartSOCKS(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	e.listeners = append(e.listeners, ln)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-e.closed:
					return
				default:
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			go e.handleSOCKS(c)
		}
	}()
	return nil
}

func (e *Engine) handleSOCKS(client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(client, hdr[:]); err != nil || hdr[0] != 5 {
		client.Close()
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(client, methods); err != nil {
		client.Close()
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		client.Close()
		return
	}
	var req [4]byte
	if _, err := io.ReadFull(client, req[:]); err != nil || req[0] != 5 {
		client.Close()
		return
	}
	if req[1] != 1 { // CONNECT only
		client.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		client.Close()
		return
	}
	var host string
	var ip netip.Addr
	switch req[3] {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(client, b[:]); err != nil {
			client.Close()
			return
		}
		ip = netip.AddrFrom4(b)
	case 4:
		var b [16]byte
		if _, err := io.ReadFull(client, b[:]); err != nil {
			client.Close()
			return
		}
		ip = netip.AddrFrom16(b)
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(client, l[:]); err != nil {
			client.Close()
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(client, b); err != nil {
			client.Close()
			return
		}
		host = strings.ToLower(string(b))
		if a, err := netip.ParseAddr(host); err == nil {
			ip, host = a, ""
		}
	default:
		client.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		client.Close()
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(client, pb[:]); err != nil {
		client.Close()
		return
	}
	port := binary.BigEndian.Uint16(pb[:])
	// Reply success before relaying (bound address is informational).
	if _, err := client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		client.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})
	src := netip.MustParseAddrPort(client.RemoteAddr().String())
	local := netip.MustParseAddrPort(client.LocalAddr().String())
	e.serve(client, src, local, netip.AddrPortFrom(ip, port), host, true)
}
