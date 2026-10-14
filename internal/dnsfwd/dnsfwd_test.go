package dnsfwd

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"cyberboba/internal/config"
	"cyberboba/internal/upstream"
)

// fake upstream DNS server answering A 93.184.216.34 for anything.
func fakeDNS(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
			b.EnableCompression()
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}})
			out, _ := b.Finish()
			pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestResolveAndCache(t *testing.T) {
	cfg := config.Default()
	cfg.Proxifier.DNSUpstream = fakeDNS(t)
	d := upstream.New(cfg, nil, nil)
	f := New(cfg, d, func(name string) upstream.Route {
		if name == "blocked.test" {
			return upstream.Route{Action: config.ActionBlock}
		}
		return upstream.Route{Action: config.ActionDirect}
	}, nil)

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("www.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	resp, err := f.Resolve(q)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) < 12 || resp[0] != 0 || resp[1] != 7 {
		t.Fatalf("bad response id")
	}
	if got := f.Lookup(netip.MustParseAddr("93.184.216.34")); got != "www.example.com" {
		t.Fatalf("cache: %q", got)
	}
	f.Remember(netip.MustParseAddr("10.1.1.1"), "Foo.Local.", time.Minute)
	if f.Lookup(netip.MustParseAddr("10.1.1.1")) != "foo.local" {
		t.Fatal("remember")
	}

	b = dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 8, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("blocked.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ = b.Finish()
	resp, err = f.Resolve(q)
	if err != nil {
		t.Fatal(err)
	}
	if resp[3]&0x0f != 3 {
		t.Fatalf("expected NXDOMAIN, rcode=%d", resp[3]&0x0f)
	}
}
