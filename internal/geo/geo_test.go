package geo

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestFlag(t *testing.T) {
	if Flag("US") == "" || Flag("NL") == "" {
		t.Fatal("expected flags")
	}
	if Flag("") != "" || Flag("USA") != "" || Flag("1X") != "" {
		t.Fatal("bad codes should yield no flag")
	}
}

func TestPrivateAndLoopback(t *testing.T) {
	c := New(false, "", 0, nil, nil) // disabled: public lookups return not-found
	if info, ok := c.Lookup("127.0.0.1"); !ok || !info.Private {
		t.Fatalf("loopback: %+v %v", info, ok)
	}
	if info, ok := c.Lookup("10.0.0.5:443"); !ok || info.Country != "Local Network" {
		t.Fatalf("private: %+v %v", info, ok)
	}
	if _, ok := c.Lookup("8.8.8.8"); ok {
		t.Fatal("disabled cache should miss public ip")
	}
}

func TestLookupCachesAndNonBlocking(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprintf(w, `{"status":"success","country":"Netherlands","countryCode":"NL","city":"Amsterdam","isp":"Acme","query":"%s"}`, "1.2.3.4")
	}))
	defer srv.Close()
	c := New(true, srv.URL+"/{ip}", 1, srv.Client(), nil)

	// first call is a miss (async fetch kicked off)
	if _, ok := c.Lookup("1.2.3.4"); ok {
		t.Fatal("first lookup should miss while fetching")
	}
	// wait for the background fetch
	deadline := time.Now().Add(2 * time.Second)
	var info Info
	for time.Now().Before(deadline) {
		var ok bool
		if info, ok = c.Lookup("1.2.3.4"); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if info.CC != "NL" || info.Country != "Netherlands" || info.Flag == "" {
		t.Fatalf("resolved: %+v", info)
	}
	// repeated lookups are served from cache (no extra provider hits)
	for i := 0; i < 5; i++ {
		c.Lookup("1.2.3.4")
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("expected 1 provider hit, got %d", n)
	}
}

func TestLookupNow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"success","country":"Germany","countryCode":"DE"}`)
	}))
	defer srv.Close()
	c := New(true, srv.URL+"/{ip}", 1, srv.Client(), nil)
	info, err := c.LookupNow("9.9.9.9")
	if err != nil || info.CC != "DE" {
		t.Fatalf("lookupnow: %+v %v", info, err)
	}
}
