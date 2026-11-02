package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"agent":{"address":"https://example.com:8443","username":"agent1","password":"secret","proxy_url":"http://user:pass@localhost:3128"},"proxy":{}}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.options.ConnectTimeout != 30*time.Second || cfg.options.RetryDelay != 5*time.Second || cfg.options.PingIdle != 30*time.Second || cfg.options.PingTimeout != 15*time.Second {
		t.Fatalf("unexpected default timeouts: %+v", cfg.options)
	}
	if cfg.options.ProxyURL == nil || cfg.options.ProxyURL.User.Username() != "user" {
		t.Fatal("proxy credentials not loaded")
	}
	for _, invalid := range []string{
		strings.Replace(data, "https://example.com:8443", "http://example.com:8443", 1),
		strings.Replace(data, `"proxy":{}`, `"proxy":null`, 1),
		strings.Replace(data, `"password":"secret"`, `"password":"secret","ping_idle":"0s"`, 1),
		strings.Replace(data, `"proxy":{}`, `"proxy":{"unknown":true}`, 1),
		strings.Replace(data, `"proxy":{}`, `"proxy":{"auth":{"type":"basic","credentials":[{"username":"user","password":"secret"}]}}`, 1),
		strings.Replace(data, `"proxy":{}`, `"proxy":{"tls":{"cert":"unused.pem","key":"unused.key"}}`, 1),
	} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatalf("accepted invalid config: %s", invalid)
		}
	}
}

func TestReloadPreservesOldConfigurationOnFailure(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "agent-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	path := filepath.Join(dir, "config.json")
	write := func(data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"agent":{"address":"https://example.com","username":"agent1","password":"old"},"proxy":{}}`)
	r, err := newRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.lock.Close()
	defer r.control.Close()
	go r.serveControl()
	before := r.current.Load()
	write(`{"agent":{"address":"https://example.com","username":"agent1","password":"new"},"proxy":{"unknown":true}}`)
	if err := sendReload(path); err == nil {
		t.Fatal("reload accepted invalid proxy configuration")
	}
	if r.current.Load() != before || r.options.Load().Password != "old" {
		t.Fatal("failed reload changed configuration")
	}
	write(`{"agent":{"address":"https://example.com","username":"agent1","password":"new"},"proxy":{}}`)
	if err := sendReload(path); err != nil {
		t.Fatal(err)
	}
	if r.current.Load() == before || r.options.Load().Password != "new" {
		t.Fatal("valid reload did not update configuration")
	}
}
