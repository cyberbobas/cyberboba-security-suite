package intercept

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"cyberboba/internal/config"
)

func TestRewriteRequestResponse(t *testing.T) {
	e, _, _ := newEngine(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Secret", "topsecret")
		w.Header().Set("Server", "origin")
		io.WriteString(w, "hello INJECT world header="+r.Header.Get("X-Added")+" ua="+r.Header.Get("User-Agent"))
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))

	cfg := e.Config()
	cfg.Rewrites = []config.Rewrite{
		{Name: "add header", Target: "request", Part: "header", Header: "X-Added", Replace: "yes"},
		{Name: "patch ua", Target: "request", Part: "header", Header: "User-Agent", Match: ".*", Replace: "cyberboba"},
		{Name: "drop secret", Target: "response", Part: "header", Header: "X-Secret", Remove: true},
		{Name: "patch body", Target: "response", Part: "body", Match: "INJECT", Replace: "REPLACED"},
	}
	e.SetConfig(cfg)

	clientEnd, engineEnd := net.Pipe()
	go e.HandleConn(engineEnd, nil, "", ap.Addr(), int(ap.Port()), Meta{App: "curl"})
	go func() { io.WriteString(clientEnd, "GET /x HTTP/1.1\r\nHost: t\r\nUser-Agent: orig\r\n\r\n") }()
	clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(newBufReader(clientEnd), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.Header.Get("X-Secret") != "" {
		t.Fatal("X-Secret not removed")
	}
	if !strings.Contains(string(body), "REPLACED") || strings.Contains(string(body), "INJECT") {
		t.Fatalf("body not rewritten: %q", body)
	}
	if !strings.Contains(string(body), "header=yes") {
		t.Fatalf("request header not added: %q", body)
	}
	if !strings.Contains(string(body), "ua=cyberboba") {
		t.Fatalf("user-agent not rewritten: %q", body)
	}
	flows, _ := e.Store().List(Filter{}, 10, 0)
	if len(flows) != 1 || !flows[0].Rewritten {
		t.Fatalf("flow not marked rewritten: %+v", flows)
	}
}

func TestSessionRoundTrip(t *testing.T) {
	e, _, _ := newEngine(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "session-body")
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "https://"))
	clientEnd, engineEnd := net.Pipe()
	go e.HandleConn(engineEnd, nil, "s.test", ap.Addr(), int(ap.Port()), Meta{App: "x"})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(e.CA().PEM())
	tc := tls.Client(clientEnd, &tls.Config{ServerName: "s.test", RootCAs: pool})
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://s.test/", nil)
	req.Write(tc)
	http.ReadResponse(newBufReader(tc), req)
	tc.Close()

	dir := t.TempDir()
	path, n, err := e.SaveSession(dir, "")
	if err != nil || n != 1 {
		t.Fatalf("save: %v n=%d", err, n)
	}
	e2, _, _ := newEngine(t)
	loaded, err := e2.LoadSession(path, true)
	if err != nil || loaded != 1 {
		t.Fatalf("load: %v n=%d", err, loaded)
	}
	fl, _ := e2.Store().List(Filter{}, 10, 0)
	if len(fl) != 1 || fl[0].Host != "s.test" || fl[0].Status != 200 {
		t.Fatalf("loaded flow wrong: %+v", fl)
	}
	d := e2.Store().Get(fl[0].ID).Detail()
	if d.RespBody != "session-body" {
		t.Fatalf("body lost: %q", d.RespBody)
	}
	// body search
	if _, total := e2.Store().List(Filter{Body: "session"}, 10, 0); total != 1 {
		t.Fatal("body search failed")
	}
	if _, total := e2.Store().List(Filter{Body: "nope"}, 10, 0); total != 0 {
		t.Fatal("body search false positive")
	}
}
