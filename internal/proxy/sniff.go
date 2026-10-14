package proxy

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// sniffHost tries to extract a hostname from the first bytes a client sent:
// a TLS ClientHello SNI or an HTTP/1.x Host header.
func sniffHost(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if b[0] == 0x16 {
		return sniffSNI(b)
	}
	return sniffHTTPHost(b)
}

func sniffHTTPHost(b []byte) string {
	// Must look like "METHOD SP target SP HTTP/1."
	sp := bytes.IndexByte(b, ' ')
	if sp <= 0 || sp > 10 {
		return ""
	}
	for _, c := range b[:sp] {
		if c < 'A' || c > 'Z' {
			return ""
		}
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	hdr := b
	if end >= 0 {
		hdr = b[:end]
	}
	for _, line := range bytes.Split(hdr, []byte("\r\n")) {
		if len(line) > 5 && strings.EqualFold(string(line[:5]), "host:") {
			h := strings.TrimSpace(string(line[5:]))
			if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h, "]") {
				h = h[:i]
			}
			h = strings.Trim(h, "[]")
			return strings.ToLower(h)
		}
	}
	return ""
}

// sniffSNI parses a TLS record containing a ClientHello and returns the
// server_name extension value.
func sniffSNI(b []byte) string {
	if len(b) < 5+4 || b[0] != 0x16 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	body := b[5:]
	if len(body) > recLen {
		body = body[:recLen]
	}
	if len(body) < 4 || body[0] != 0x01 { // ClientHello
		return ""
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	p := body[4:]
	if len(p) > hsLen {
		p = p[:hsLen]
	}
	// version(2) random(32)
	if len(p) < 34 {
		return ""
	}
	p = p[34:]
	// session id
	if len(p) < 1 {
		return ""
	}
	sl := int(p[0])
	if len(p) < 1+sl {
		return ""
	}
	p = p[1+sl:]
	// cipher suites
	if len(p) < 2 {
		return ""
	}
	cl := int(binary.BigEndian.Uint16(p))
	if len(p) < 2+cl {
		return ""
	}
	p = p[2+cl:]
	// compression
	if len(p) < 1 {
		return ""
	}
	cm := int(p[0])
	if len(p) < 1+cm {
		return ""
	}
	p = p[1+cm:]
	if len(p) < 2 {
		return ""
	}
	el := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) > el {
		p = p[:el]
	}
	for len(p) >= 4 {
		typ := binary.BigEndian.Uint16(p)
		l := int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if len(p) < l {
			return ""
		}
		if typ == 0 { // server_name
			d := p[:l]
			if len(d) < 2 {
				return ""
			}
			ll := int(binary.BigEndian.Uint16(d))
			d = d[2:]
			if len(d) > ll {
				d = d[:ll]
			}
			for len(d) >= 3 {
				nt := d[0]
				nl := int(binary.BigEndian.Uint16(d[1:]))
				d = d[3:]
				if len(d) < nl {
					return ""
				}
				if nt == 0 {
					return strings.ToLower(string(d[:nl]))
				}
				d = d[nl:]
			}
			return ""
		}
		p = p[l:]
	}
	return ""
}
