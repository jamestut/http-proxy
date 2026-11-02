package proxy

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReverseConfig(t *testing.T) {
	valid := `{"upstreams":{"a":{"auth":{"type":"basic","username":"alice","password":"secret"}}},"defaults":{"ip":"a"}}`
	cfg, err := ParseReverseConfig([]byte(valid), "config.json")
	if err != nil || cfg.Upstreams["a"].Auth.Username != "alice" {
		t.Fatalf("valid reverse config: %v", err)
	}
	for _, input := range []string{
		`{"upstreams":{"a":{"host":""}}}`,
		`{"upstreams":{"a":{"host":null}}}`,
		`{"upstreams":{"a":{}}}`,
		`{"upstreams":{"a":{"auth":{"type":"basic","username":"alice","password":"one"}},"b":{"auth":{"type":"basic","username":"alice","password":"one"}}}}`,
	} {
		if _, err := ParseReverseConfig([]byte(input), "config.json"); err == nil {
			t.Errorf("accepted invalid config %s", input)
		}
	}
	if _, err := ParseReverseConfig([]byte(`{"upstreams":{"a":{"auth":{"type":"basic","username":"alice","password":"one"}},"b":{"auth":{"type":"basic","username":"alice","password":"two"}}}}`), "config.json"); err != nil {
		t.Fatalf("same username with different passwords: %v", err)
	}
	if _, err := ParseConfig([]byte(valid), "config.json"); err == nil {
		t.Fatal("standard upstream accepted without host")
	}
}

func TestReverseDialRoute(t *testing.T) {
	cfg, err := ParseReverseConfig([]byte(`{"upstreams":{"a":{"auth":{"type":"basic","username":"alice","password":"secret"}}},"defaults":{"ip":"a"}}`), "config.json")
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[Config]
	current.Store(cfg)
	called := false
	p := NewReverseProxyHandler(&current, func(_ context.Context, name, target string) (net.Conn, error) {
		called = true
		if name != "a" || target != "127.0.0.1:1234" {
			t.Errorf("dial received %q, %q", name, target)
		}
		return nil, context.Canceled
	}).(*proxyHandler)
	_, err = p.dialTarget(context.Background(), cfg, "127.0.0.1:1234")
	if !called || err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("callback called=%v error=%v", called, err)
	}
}
