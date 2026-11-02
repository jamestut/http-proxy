package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"http-proxy/internal/proxy"
	"http-proxy/internal/reverse"
)

type rawAgent struct {
	Address        string `json:"address"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	ProxyURL       string `json:"proxy_url"`
	CA             string `json:"ca"`
	ConnectTimeout string `json:"connect_timeout"`
	RetryDelay     string `json:"retry_delay"`
	PingIdle       string `json:"ping_idle"`
	PingTimeout    string `json:"ping_timeout"`
}

type snapshot struct {
	proxy   *proxy.Config
	options reverse.ClientOptions
}

func loadConfig(path string) (*snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var raw struct {
		Agent *rawAgent       `json:"agent"`
		Proxy json.RawMessage `json:"proxy"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("config must contain exactly one JSON object")
	}
	if raw.Agent == nil || len(raw.Proxy) == 0 || bytes.Equal(bytes.TrimSpace(raw.Proxy), []byte("null")) {
		return nil, fmt.Errorf("agent and proxy objects are required")
	}
	a := raw.Agent
	u, err := url.Parse(a.Address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("agent address must be an HTTPS URL without credentials, path, query, or fragment")
	}
	if err := proxy.ValidateURLHost(u); err != nil {
		return nil, fmt.Errorf("agent address: %w", err)
	}
	if err := proxy.ValidateCredential(proxy.Credential{Username: a.Username, Password: a.Password}); err != nil {
		return nil, fmt.Errorf("agent credentials: %w", err)
	}
	opts := reverse.ClientOptions{Address: a.Address, Username: a.Username, Password: a.Password}
	if a.ProxyURL != "" {
		p, err := url.Parse(a.ProxyURL)
		if err != nil || p.Scheme != "http" || p.Hostname() == "" || (p.Path != "" && p.Path != "/") || p.RawQuery != "" || p.ForceQuery || p.Fragment != "" || p.Opaque != "" {
			return nil, fmt.Errorf("proxy_url must be an HTTP proxy URL without path, query, or fragment")
		}
		if err := proxy.ValidateURLHost(p); err != nil {
			return nil, fmt.Errorf("proxy_url: %w", err)
		}
		opts.ProxyURL = p
	}
	if a.CA != "" {
		caPath := a.CA
		if !filepath.IsAbs(caPath) {
			caPath = filepath.Join(filepath.Dir(path), caPath)
		}
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read agent CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system CA pool: %w", err)
		}
		if err := proxy.AddCACertificates(roots, pem); err != nil {
			return nil, fmt.Errorf("invalid agent CA file: %w", err)
		}
		opts.Roots = roots
	}
	durations := []struct {
		name, value string
		fallback    time.Duration
		dest        *time.Duration
	}{
		{"connect_timeout", a.ConnectTimeout, 30 * time.Second, &opts.ConnectTimeout},
		{"retry_delay", a.RetryDelay, 5 * time.Second, &opts.RetryDelay},
		{"ping_idle", a.PingIdle, 30 * time.Second, &opts.PingIdle},
		{"ping_timeout", a.PingTimeout, 15 * time.Second, &opts.PingTimeout},
	}
	for _, d := range durations {
		*d.dest = d.fallback
		if d.value != "" {
			v, err := time.ParseDuration(d.value)
			if err != nil || v <= 0 {
				return nil, fmt.Errorf("%s must be a positive duration", d.name)
			}
			*d.dest = v
		}
	}
	var listener struct {
		Auth json.RawMessage `json:"auth"`
		TLS  struct {
			Cert string `json:"cert"`
			Key  string `json:"key"`
		} `json:"tls"`
	}
	if err := json.Unmarshal(raw.Proxy, &listener); err == nil {
		if len(listener.Auth) != 0 && !bytes.Equal(bytes.TrimSpace(listener.Auth), []byte("null")) {
			return nil, fmt.Errorf("proxy auth is not supported by the agent")
		}
		if listener.TLS.Cert != "" || listener.TLS.Key != "" {
			return nil, fmt.Errorf("proxy listener TLS cert and key are not supported by the agent")
		}
	}
	cfg, err := proxy.ParseConfig(raw.Proxy, path)
	if err != nil {
		return nil, fmt.Errorf("proxy config: %w", err)
	}
	return &snapshot{proxy: cfg, options: opts}, nil
}
