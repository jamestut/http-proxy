package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func runtimeTestDir(t *testing.T) string {
	t.Helper()
	// Keep Unix socket paths short on systems with a small sockaddr_un limit.
	dir, err := os.MkdirTemp("/tmp", "http-proxy-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	return dir
}

func runtimeTestAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func runtimeTestBindPort(t *testing.T, address string) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func runtimeWrite(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runtimeCert(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func runtimeStart(t *testing.T, addr, path string) *runtimeServer {
	t.Helper()
	bind, port := runtimeTestBindPort(t, addr)
	r, err := newRuntime(bind, port, path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("server stopped: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	return r
}

func runtimeReload(t *testing.T, address string) error {
	t.Helper()
	bind, port := runtimeTestBindPort(t, address)
	return sendReload(bind, port)
}

func runtimeNewRuntime(t *testing.T, address, path string) (*runtimeServer, error) {
	t.Helper()
	bind, port := runtimeTestBindPort(t, address)
	return newRuntime(bind, port, path)
}

func runtimeControlPaths(t *testing.T, address string) (string, string) {
	t.Helper()
	bind, port := runtimeTestBindPort(t, address)
	_, _, key, err := normalizeBindPort(bind, port)
	if err != nil {
		t.Fatal(err)
	}
	return controlPaths(key)
}

func TestRuntimeWildcardBindAndReload(t *testing.T) {
	dir := runtimeTestDir(t)
	path := filepath.Join(dir, "config.json")
	runtimeWrite(t, path, `{"auth":{"type":"basic","credentials":[{"username":"client","password":"first"}]}}`)
	ipv6, err := net.Listen("tcp6", "[::1]:0")
	hasIPv6 := err == nil
	if hasIPv6 {
		ipv6.Close()
	}

	for _, bind := range []string{"all", "0.0.0.0", "::"} {
		t.Run(bind, func(t *testing.T) {
			_, port := runtimeTestBindPort(t, runtimeTestAddress(t))
			r := runtimeStart(t, net.JoinHostPort(bind, strconv.Itoa(port)), path)
			for _, host := range []string{"127.0.0.1", "::1"} {
				if host == "::1" && !hasIPv6 {
					continue
				}
				address := net.JoinHostPort(host, strconv.Itoa(port))
				transport := &http.Transport{}
				client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				resp, err := client.Get("http://" + address + "/")
				if err != nil {
					t.Fatalf("connect to %s: %v", address, err)
				}
				resp.Body.Close()
				transport.CloseIdleConnections()
				if resp.StatusCode != http.StatusProxyAuthRequired {
					t.Errorf("%s: status = %d, want %d", address, resp.StatusCode, http.StatusProxyAuthRequired)
				}
			}
			old := r.current.Load()
			if err := command([]string{"reload", "-b", bind, "-p", strconv.Itoa(port)}); err != nil {
				t.Fatal(err)
			}
			if r.current.Load() == old {
				t.Fatal("reload did not replace configuration")
			}
		})
	}
}

func TestRuntimeWildcardPortConflict(t *testing.T) {
	dir := runtimeTestDir(t)
	path := filepath.Join(dir, "config.json")
	runtimeWrite(t, path, `{}`)
	occupied, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port
	if r, err := newRuntime("all", port, path); err == nil {
		r.listener.Close()
		r.control.Close()
		r.lock.Close()
		t.Fatal("wildcard bind succeeded with wildcard port occupied")
	}
}

func TestNormalizeBindPort(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if _, _, _, err := normalizeBindPort("all", port); err == nil {
			t.Errorf("port %d accepted", port)
		}
	}
	if _, _, _, err := normalizeBindPort("", 8080); err == nil {
		t.Error("empty bind accepted")
	}
	bind, _, key, err := normalizeBindPort("0:0:0:0:0:0:0:1", 8080)
	if err != nil || bind != "::1" || key != "[::1]:8080" {
		t.Errorf("IPv6 normalization = %q, %q, %v", bind, key, err)
	}
}

func TestRuntimeReloadAtomicAndControlPermissions(t *testing.T) {
	dir := runtimeTestDir(t)
	path := filepath.Join(dir, "config.json")
	runtimeWrite(t, path, `{}`)
	addr := runtimeTestAddress(t)
	r := runtimeStart(t, addr, path)
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{filepath.Dir(r.controlPath), 0o700}, {r.controlPath, 0o600}} {
		info, err := os.Stat(item.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != item.mode {
			t.Errorf("%s mode = %o, want %o", item.path, got, item.mode)
		}
	}
	_, lock := runtimeControlPaths(t, addr)
	info, err := os.Stat(lock)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("lock mode = %o", info.Mode().Perm())
	}
	if _, err := runtimeNewRuntime(t, addr, path); err == nil {
		t.Fatal("expected duplicate instance error")
	}
	old := r.current.Load()
	runtimeWrite(t, path, `{"auth":{"type":"basic","credentials":[{"username":"newuser","password":"secret"}]}}`)
	if err := runtimeReload(t, addr); err != nil {
		t.Fatal(err)
	}
	active := r.current.Load()
	if active == old || active.Auth == nil || active.Auth.Credentials[0].Username != "newuser" {
		t.Fatal("valid config not loaded")
	}
	runtimeWrite(t, path, `{"bad": true}`)
	if err := runtimeReload(t, addr); err == nil {
		t.Fatal("invalid config reload succeeded")
	}
	if r.current.Load() != active {
		t.Fatal("invalid reload replaced configuration")
	}
	cert, key := runtimeCert(t, dir, "switch")
	runtimeWrite(t, path, fmt.Sprintf(`{"tls":{"cert":%q,"key":%q}}`, cert, key))
	if err := runtimeReload(t, addr); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("mode change: %v", err)
	}
	if r.current.Load() != active {
		t.Fatal("TLS mode change replaced configuration")
	}
}

func TestRuntimeTLSCertificateReload(t *testing.T) {
	dir := runtimeTestDir(t)
	firstCert, firstKey := runtimeCert(t, dir, "first")
	secondCert, secondKey := runtimeCert(t, dir, "second")
	path := filepath.Join(dir, "config.json")
	runtimeWrite(t, path, fmt.Sprintf(`{"tls":{"cert":%q,"key":%q}}`, firstCert, firstKey))
	addr := runtimeTestAddress(t)
	r := runtimeStart(t, addr, path)
	getCert := func() string {
		t.Helper()
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		state := c.ConnectionState()
		if state.NegotiatedProtocol != "h2" {
			t.Errorf("ALPN = %q, want h2", state.NegotiatedProtocol)
		}
		return state.PeerCertificates[0].Subject.CommonName
	}
	if got := getCert(); got != "first" {
		t.Fatalf("initial cert = %s", got)
	}
	runtimeWrite(t, path, fmt.Sprintf(`{"tls":{"cert":%q,"key":%q}}`, secondCert, secondKey))
	if err := runtimeReload(t, addr); err != nil {
		t.Fatal(err)
	}
	if got := getCert(); got != "second" {
		t.Fatalf("reloaded cert = %s", got)
	}
	if r.current.Load().Certificate == nil {
		t.Fatal("certificate missing")
	}
	runtimeWrite(t, path, `{}`)
	if err := runtimeReload(t, addr); err == nil {
		t.Fatal("removing TLS should require restart")
	}
	if got := getCert(); got != "second" {
		t.Fatalf("failed reload changed cert = %s", got)
	}
}

func TestRuntimeHTTP2ReloadOnExistingConnection(t *testing.T) {
	dir := runtimeTestDir(t)
	cert, key := runtimeCert(t, dir, "http2")
	path := filepath.Join(dir, "config.json")
	writeConfig := func(password string) {
		runtimeWrite(t, path, fmt.Sprintf(`{"tls":{"cert":%q,"key":%q},"auth":{"type":"basic","credentials":[{"username":"client","password":%q}]}}`, cert, key, password))
	}
	writeConfig("first")
	addr := runtimeTestAddress(t)
	runtimeStart(t, addr, path)
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request := func(password string) (int, bool) {
		t.Helper()
		var reused bool
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), "GET", "https://"+addr+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("client:"+password)))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.ProtoMajor != 2 {
			t.Fatalf("protocol = %s", resp.Proto)
		}
		return resp.StatusCode, reused
	}
	if status, _ := request("first"); status == http.StatusProxyAuthRequired {
		t.Fatal("initial credentials rejected")
	}
	writeConfig("second")
	if err := runtimeReload(t, addr); err != nil {
		t.Fatal(err)
	}
	if status, reused := request("first"); status != http.StatusProxyAuthRequired || !reused {
		t.Fatalf("old credentials after reload: status %d, reused %v", status, reused)
	}
	if status, reused := request("second"); status == http.StatusProxyAuthRequired || !reused {
		t.Fatalf("new credentials after reload: status %d, reused %v", status, reused)
	}
}
