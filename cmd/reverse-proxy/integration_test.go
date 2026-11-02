package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"http-proxy/internal/proxy"
	"http-proxy/internal/reverse"
)

func testCertificate(t *testing.T, dir string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyData}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add test CA")
	}
	return cert, keyPath, roots
}

func TestEndToEndRoutingReloadAndConnectProxy(t *testing.T) {
	dir := t.TempDir()
	runtimeDir, err := os.MkdirTemp("/tmp", "rp-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(runtimeDir) })
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	cert, key, roots := testCertificate(t, dir)
	path := filepath.Join(dir, "reverse.json")
	writeConfig := func(password string, agent bool) {
		t.Helper()
		upstreams := map[string]any{}
		defaults := map[string]any{}
		if agent {
			upstreams["edge"] = map[string]any{"auth": map[string]string{"type": "basic", "username": "edge", "password": password}}
			defaults["ip"] = "edge"
		}
		value := map[string]any{"client_listen": "127.0.0.1:0", "agent_listener": map[string]any{"listen": "127.0.0.1:0", "cert": cert, "key": key, "shutdown_timeout": "1s"}, "proxy": map[string]any{"upstreams": upstreams, "defaults": defaults}}
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig("old", true)
	r, err := newRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- r.run(ctx) }()
	defer func() {
		cancel()
		if err := <-serverDone; err != nil {
			t.Errorf("server: %v", err)
		}
	}()

	directCfg, err := proxy.ParseConfig([]byte(`{}`), path)
	if err != nil {
		t.Fatal(err)
	}
	var direct atomic.Pointer[proxy.Config]
	direct.Store(directCfg)
	var transitCount, upstreamCount atomic.Int32
	baseHandler := proxy.NewProxyHandler(&direct)
	transit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { transitCount.Add(1); baseHandler.ServeHTTP(w, req) }))
	defer transit.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { upstreamCount.Add(1); baseHandler.ServeHTTP(w, req) }))
	defer upstream.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { fmt.Fprint(w, "through agent") }))
	defer backend.Close()

	agentConfig := fmt.Sprintf(`{"upstreams":{"office":{"host":%q}},"defaults":{"ip":"office"}}`, upstream.URL)
	agentCfg, err := proxy.ParseConfig([]byte(agentConfig), path)
	if err != nil {
		t.Fatal(err)
	}
	var agentCurrent atomic.Pointer[proxy.Config]
	agentCurrent.Store(agentCfg)
	proxyURL, _ := url.Parse(transit.URL)
	agentDone := make(chan error, 1)
	go func() {
		agentDone <- reverse.Run(ctx, func() reverse.ClientOptions {
			return reverse.ClientOptions{Address: "https://" + r.agentListener.Addr().String(), Username: "edge", Password: "old", ProxyURL: proxyURL, Roots: roots, ConnectTimeout: time.Second, RetryDelay: 50 * time.Millisecond, PingIdle: time.Second, PingTimeout: time.Second, Handler: proxy.NewProxyHandler(&agentCurrent)}
		})
	}()
	proxyAddress, _ := url.Parse("http://" + r.clientListener.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyAddress)}, Timeout: 2 * time.Second}
	request := func() (string, error) {
		resp, err := client.Get(backend.URL)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return "", fmt.Errorf("status %d", resp.StatusCode)
		}
		var b strings.Builder
		_, err = io.Copy(&b, resp.Body)
		return b.String(), err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		value, err := request()
		if err == nil && value == "through agent" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent did not become ready: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if transitCount.Load() == 0 || upstreamCount.Load() == 0 {
		t.Fatalf("expected both CONNECT proxy and agent upstream, got %d and %d", transitCount.Load(), upstreamCount.Load())
	}

	writeConfig("new", true)
	if err := r.reload(); err != nil {
		t.Fatal(err)
	}
	if value, err := request(); err != nil || value != "through agent" {
		t.Fatalf("credential reload disconnected healthy agent: %q %v", value, err)
	}

	writeConfig("", false)
	if err := r.reload(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-agentDone:
		if err != nil {
			t.Fatalf("agent did not exit cleanly: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("removed agent did not exit")
	}
}
