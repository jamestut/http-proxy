package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"http-proxy/internal/proxy"
)

type agentListenerConfig struct {
	Listen          string `json:"listen"`
	Cert            string `json:"cert"`
	Key             string `json:"key"`
	ShutdownTimeout string `json:"shutdown_timeout"`
	PingIdle        string `json:"ping_idle"`
	PingTimeout     string `json:"ping_timeout"`
}

type fileConfig struct {
	ClientListen string              `json:"client_listen"`
	Agent        agentListenerConfig `json:"agent_listener"`
	Proxy        json.RawMessage     `json:"proxy"`
}

type config struct {
	clientListen string
	agentListen  string
	certificate  *tls.Certificate
	shutdown     time.Duration
	pingIdle     time.Duration
	pingTimeout  time.Duration
	proxy        *proxy.Config
}

func duration(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q", value)
	}
	return d, nil
}

func configPath(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(filepath.Dir(base), path)
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw fileConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("config must contain exactly one JSON object")
	}
	if len(raw.Proxy) == 0 {
		return nil, errors.New("proxy configuration is required")
	}
	cfg := &config{clientListen: raw.ClientListen, agentListen: raw.Agent.Listen}
	if cfg.clientListen == "" {
		cfg.clientListen = "127.0.0.1:8080"
	}
	if cfg.agentListen == "" {
		cfg.agentListen = "127.0.0.1:8443"
	}
	for _, addr := range []string{cfg.clientListen, cfg.agentListen} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("invalid listen address %q: %w", addr, err)
		}
	}
	if raw.Agent.Cert == "" || raw.Agent.Key == "" {
		return nil, errors.New("agent listener certificate and key are required")
	}
	cert, err := tls.LoadX509KeyPair(configPath(path, raw.Agent.Cert), configPath(path, raw.Agent.Key))
	if err != nil {
		return nil, fmt.Errorf("load agent listener certificate: %w", err)
	}
	cfg.certificate = &cert
	if cfg.shutdown, err = duration(raw.Agent.ShutdownTimeout, 5*time.Second); err != nil {
		return nil, fmt.Errorf("shutdown_timeout: %w", err)
	}
	if cfg.pingIdle, err = duration(raw.Agent.PingIdle, 30*time.Second); err != nil {
		return nil, fmt.Errorf("ping_idle: %w", err)
	}
	if cfg.pingTimeout, err = duration(raw.Agent.PingTimeout, 15*time.Second); err != nil {
		return nil, fmt.Errorf("ping_timeout: %w", err)
	}
	cfg.proxy, err = proxy.ParseReverseConfig(raw.Proxy, path)
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}
	return cfg, nil
}
