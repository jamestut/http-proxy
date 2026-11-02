package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigDefaultsAndValidation(t *testing.T) {
	dir := t.TempDir()
	cert, key, _ := testCertificate(t, dir)
	path := filepath.Join(dir, "config.json")
	base := map[string]any{"agent_listener": map[string]any{"cert": cert, "key": key}, "proxy": map[string]any{}}
	write := func(value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(base)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.clientListen != "127.0.0.1:8080" || cfg.agentListen != "127.0.0.1:8443" || cfg.shutdown != 5*time.Second || cfg.pingIdle != 30*time.Second || cfg.pingTimeout != 15*time.Second {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	for _, value := range []any{
		map[string]any{"proxy": map[string]any{}},
		map[string]any{"agent_listener": map[string]any{"cert": cert, "key": key, "ping_idle": "0s"}, "proxy": map[string]any{}},
		map[string]any{"agent_listener": map[string]any{"cert": cert, "key": key}, "proxy": map[string]any{"upstreams": map[string]any{"agent": map[string]any{"host": "http://localhost"}}}},
		map[string]any{"agent_listener": map[string]any{"cert": cert, "key": key}, "proxy": map[string]any{}, "unknown": true},
	} {
		write(value)
		if _, err := loadConfig(path); err == nil {
			t.Fatalf("accepted invalid config: %v", value)
		}
	}
}
