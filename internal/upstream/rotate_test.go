package upstream

import (
	"testing"
	"time"

	"cyberboba/internal/config"
)

func TestRotateSequentialAndInterval(t *testing.T) {
	cfg := &config.Config{Proxies: []config.Proxy{
		{Name: "a", Type: config.ProxySOCKS5, Addr: "1.1.1.1:1"},
		{Name: "b", Type: config.ProxySOCKS5, Addr: "2.2.2.2:1"},
		{Name: "c", Type: config.ProxySOCKS5, Addr: "3.3.3.3:1"},
		{Name: "rot", Type: config.ProxyRotate, Hops: []string{"a", "b", "c"}, RotateEverySec: 1, RotateMode: "sequential"},
	}}
	d := New(cfg, nil, nil)
	g := &cfg.Proxies[3]
	i0 := d.rotPick(g, false)
	// within the interval it must not change
	if d.rotPick(g, false) != i0 {
		t.Fatal("member changed before interval elapsed")
	}
	// force advance → sequential next
	i1 := d.rotPick(g, true)
	if i1 != (i0+1)%3 {
		t.Fatalf("sequential expected %d, got %d", (i0+1)%3, i1)
	}
	i2 := d.rotPick(g, true)
	if i2 != (i1+1)%3 {
		t.Fatalf("sequential wrap expected %d, got %d", (i1+1)%3, i2)
	}
}

func TestRotateStatusAndTick(t *testing.T) {
	cfg := &config.Config{Proxies: []config.Proxy{
		{Name: "a", Type: config.ProxySOCKS5, Addr: "1.1.1.1:1"},
		{Name: "b", Type: config.ProxySOCKS5, Addr: "2.2.2.2:1"},
		{Name: "rot", Type: config.ProxyRotate, Hops: []string{"a", "b"}, RotateEverySec: 1, RotateMode: "sequential"},
	}}
	d := New(cfg, nil, nil)
	st := d.RotationStates()
	if len(st) != 1 || st[0].Name != "rot" || st[0].EverySec != 1 {
		t.Fatalf("status: %+v", st)
	}
	first := d.rotPick(&cfg.Proxies[2], false)
	// simulate interval elapse by backdating
	d.rotMu.Lock()
	d.rot["rot"].last = time.Now().Add(-2 * time.Second)
	d.rotMu.Unlock()
	ch := d.TickRotations()
	if len(ch) != 1 || ch[0].Group != "rot" {
		t.Fatalf("tick change: %+v", ch)
	}
	if got := d.rotPick(&cfg.Proxies[2], false); got == first {
		t.Fatal("member should have advanced after tick")
	}
}

func TestRandomAvoidsRepeat(t *testing.T) {
	cfg := &config.Config{Proxies: []config.Proxy{
		{Name: "a", Type: config.ProxySOCKS5, Addr: "1.1.1.1:1"},
		{Name: "b", Type: config.ProxySOCKS5, Addr: "2.2.2.2:1"},
		{Name: "rot", Type: config.ProxyRotate, Hops: []string{"a", "b"}, RotateEverySec: 1, RotateMode: "random"},
	}}
	d := New(cfg, nil, nil)
	g := &cfg.Proxies[2]
	cur := d.rotPick(g, false)
	for i := 0; i < 20; i++ {
		n := d.rotPick(g, true)
		if n == cur {
			t.Fatal("random rotation repeated the same member")
		}
		cur = n
	}
}
