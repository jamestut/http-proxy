package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"http-proxy/internal/proxy"
)

func loadConfig(path string) (*proxy.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var raw struct {
		Proxy json.RawMessage `json:"proxy"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("config must contain exactly one JSON object")
	}
	if len(raw.Proxy) == 0 || bytes.Equal(bytes.TrimSpace(raw.Proxy), []byte("null")) {
		return nil, errors.New("proxy configuration is required")
	}
	return proxy.ParseConfig(raw.Proxy, path)
}
