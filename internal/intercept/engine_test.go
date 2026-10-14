package intercept

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberboba/internal/config"
	"cyberboba/internal/upstream"
)

func newEngine(t *testing.T) (*Engine, *[]Event, *sync.Mutex) {
	t.Helper()
	cfg := config.Default()
	cfg.Intercept.CADir = t.TempDir()
	cfg.Intercept.MaxBody = 1 << 20
	d := upstream.New(cfg, nil, nil)
	var events []Event
	var mu sync.Mutex
	e, err := New(cfg.Intercept, d, func(ev Event) { mu.Lock(); events = append(events, ev); mu.Unlock() }, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e, &events, &mu
}

func TestCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	fp := ca.Fingerprint()
	ca2, err := LoadOrCreateCA(dir)
	if err != nil || ca2.Fingerprint() != fp {
		t.Fatal("reload mismatch")
	}
	leaf, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.PEM())
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: pool}); err != nil {
		t.Fatal(err)
	}
	if l2, _ := ca.Leaf("example.com"); l2 != leaf {
		t.Fatal("leaf not cached")
	}
	if err := ca.Regenerate(); err != nil || ca.Fingerprint() == fp {
		t.Fatal("regenerate")
	}
}

// TestTLSInterception terminates TLS for a client that trusts the cyberboba
// CA and forwards to a local HTTPS test server.
func TestTLSInterception(t *testing.T) {
	e, events, mu := newEngine(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"path":"` + r.URL.Path + `","body":"` + string(b) + `"}`))
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "https://"))

	// client side: a pipe into the engine, with the engine told the real destination
	clientEnd, engineEnd := net.Pipe()
	go e.HandleConn(engineEnd, nil, "localhost", ap.Addr(), int(ap.Port()), Meta{App: "test", PID: 1})

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(e.CA().PEM())
	tc := tls.Client(clientEnd, &tls.Config{ServerName: "localhost", RootCAs: pool})
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	req, _ := http.NewRequest("POST", "https://localhost/hello?x=1", strings.NewReader("payload"))
	req.Header.Set("Content-Type", "text/plain")
	if err := req.Write(tc); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(newBufReader(tc), req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"body":"payload"`) || resp.Header.Get("X-Echo-Method") != "POST" {
		t.Fatalf("bad response %d %s", resp.StatusCode, body)
	}
	tc.Close()

	flows, total := e.Store().List(Filter{}, 10, 0)
	if total != 1 {
		t.Fatalf("flows=%d", total)
	}
	f := flows[0]
	if f.Method != "POST" || f.URL != "https://localhost:"+strconv.Itoa(int(ap.Port()))+"/hello?x=1" || f.Status != 200 || !f.TLS || f.App != "test" || f.State != StateDone {
		t.Fatalf("flow %+v", f)
	}
	d := e.Store().Get(f.ID).Detail()
	if d.ReqBody != "payload" || !strings.HasPrefix(d.ReqRaw, "POST /hello?x=1 HTTP/1.1\r\nHost: localhost") || !strings.Contains(d.RespRaw, "application/json") {
		t.Fatalf("detail %+v", d)
	}
	mu.Lock()
	n := len(*events)
	mu.Unlock()
	if n < 2 {
		t.Fatalf("expected flow events, got %d", n)
	}
	if cu := Curl(e.Store().Get(f.ID)); !strings.Contains(cu, "-X 'POST'") || !strings.Contains(cu, "--data-binary 'payload'") {
		t.Fatalf("curl: %s", cu)
	}
	if har := string(HAR(e.Store().All())); !strings.Contains(har, `"method": "POST"`) {
		t.Fatalf("har: %s", har[:200])
	}
}

// TestHoldAndEdit holds a plain-HTTP request, edits it, forwards it.
func TestHoldAndEdit(t *testing.T) {
	e, _, _ := newEngine(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("path=" + r.URL.Path + " hdr=" + r.Header.Get("X-Edited")))
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	yes := true
	e.Toggle(nil, nil, &yes, nil)

	clientEnd, engineEnd := net.Pipe()
	go e.HandleConn(engineEnd, nil, "", ap.Addr(), int(ap.Port()), Meta{App: "curl"})
	go func() {
		io.WriteString(clientEnd, "GET /orig HTTP/1.1\r\nHost: x\r\n\r\n")
	}()
	// wait for pending
	var pend []FlowDetail
	for i := 0; i < 50 && len(pend) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
		pend = e.Pending()
	}
	if len(pend) != 1 || pend[0].State != StatePendingRequest {
		t.Fatalf("pending: %+v", pend)
	}
	edited := "GET /edited HTTP/1.1\nHost: x\nX-Edited: yes\n\n"
	if err := e.Forward(pend[0].ID, edited); err != nil {
		t.Fatal(err)
	}
	clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(newBufReader(clientEnd), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "path=/edited hdr=yes" {
		t.Fatalf("body %q", body)
	}
	f := e.Store().Get(pend[0].ID).snapshot()
	if !f.Edited || !f.Intercepted || f.Path != "/edited" {
		t.Fatalf("flow %+v", f)
	}
	// drop path
	go func() { io.WriteString(clientEnd, "GET /two HTTP/1.1\r\nHost: x\r\n\r\n") }()
	pend = nil
	for i := 0; i < 50 && len(pend) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
		pend = e.Pending()
	}
	if len(pend) != 1 {
		t.Fatal("no second pending")
	}
	e.Drop(pend[0].ID)
	resp, err = http.ReadResponse(newBufReader(clientEnd), nil)
	if err != nil || resp.StatusCode != 502 {
		t.Fatalf("drop: %v %v", err, resp)
	}
}

func TestRepeaterAndScope(t *testing.T) {
	e, _, _ := newEngine(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/r" {
			http.Redirect(w, r, "/final", 302)
			return
		}
		w.Write([]byte("ok " + r.URL.Path + " " + r.Header.Get("X-A")))
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	raw := "GET /r HTTP/1.1\r\nHost: " + ap.String() + "\r\nX-A: 1\r\n\r\n"
	d, err := e.Send(ap.Addr().String(), int(ap.Port()), false, raw, true, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != 200 || d.RespBody != "ok /final " || d.Source != "repeater" {
		t.Fatalf("repeater: %+v", d)
	}
	d, _ = e.Send(ap.Addr().String(), int(ap.Port()), false, raw, false, 5*time.Second)
	if d.Status != 302 {
		t.Fatalf("no-follow: %d", d.Status)
	}
	cfg := e.Config()
	cfg.Scope.Include = []string{"*.example.com"}
	cfg.Scope.Exclude = []string{"bad.example.com"}
	e.SetConfig(cfg)
	if !e.InScope("a.example.com") || e.InScope("bad.example.com") || e.InScope("other.org") {
		t.Fatal("scope")
	}
	if _, n := e.Store().List(Filter{Status: "3"}, 0, 0); n != 2 {
		t.Fatalf("filter status: %d", n)
	}
}

func newBufReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }
