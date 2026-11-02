package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func integrationConnect(t *testing.T, proxy, target, credential string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if credential != "" {
		credential = "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(credential)) + "\r\n"
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, credential); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
	}
	return conn, reader, response.StatusCode
}

func TestIntegrationTunnelSurvivesReload(t *testing.T) {
	dir := runtimeTestDir(t)
	path := filepath.Join(dir, "config.json")
	config := func(password string) string {
		return fmt.Sprintf(`{"proxy":{"auth":{"type":"basic","credentials":[{"username":"client","password":%q}]}}}`, password)
	}
	runtimeWrite(t, path, config("first"))
	addr := runtimeTestAddress(t)
	runtimeStart(t, addr, path)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	conn, reader, status := integrationConnect(t, addr, echo.Addr().String(), "client:first")
	defer conn.Close()
	if status != http.StatusOK {
		t.Fatalf("CONNECT status %d", status)
	}
	check := func(s string) {
		t.Helper()
		if _, err := io.WriteString(conn, s); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(s))
		if _, err := io.ReadFull(reader, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != s {
			t.Fatalf("echo %q, want %q", buf, s)
		}
	}
	check("before")
	runtimeWrite(t, path, config("second"))
	if err := runtimeReload(t, addr); err != nil {
		t.Fatal(err)
	}
	check("after")
	old, _, status := integrationConnect(t, addr, echo.Addr().String(), "client:first")
	old.Close()
	if status != http.StatusProxyAuthRequired {
		t.Fatalf("old credential status %d", status)
	}
	fresh, _, status := integrationConnect(t, addr, echo.Addr().String(), "client:second")
	fresh.Close()
	if status != http.StatusOK {
		t.Fatalf("new credential status %d", status)
	}
}

func TestIntegrationUpstreamCAReload(t *testing.T) {
	dir := runtimeTestDir(t)
	certPath, keyPath := runtimeCert(t, dir, "localhost")
	otherCert, _ := runtimeCert(t, dir, "other")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	upstream.EnableHTTP2 = true
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	upstream.StartTLS()
	defer upstream.Close()
	_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	writeConfig := func(ca string) {
		runtimeWrite(t, path, fmt.Sprintf(`{"proxy":{"tls":{"upstream_ca":%q},"upstreams":{"u":{"host":"https://localhost:%s"}},"defaults":{"ip":"u"}}}`, ca, port))
	}
	writeConfig(certPath)
	addr := runtimeTestAddress(t)
	runtimeStart(t, addr, path)
	connect := func() int {
		conn, _, status := integrationConnect(t, addr, "127.0.0.1:12345", "")
		conn.Close()
		return status
	}
	if status := connect(); status != http.StatusOK {
		t.Fatalf("trusted upstream status %d", status)
	}
	writeConfig(otherCert)
	if err := runtimeReload(t, addr); err != nil {
		t.Fatal(err)
	}
	if status := connect(); status != http.StatusBadGateway {
		t.Fatalf("removed trust status %d", status)
	}
	writeConfig(certPath)
	if err := runtimeReload(t, addr); err != nil {
		t.Fatal(err)
	}
	if status := connect(); status != http.StatusOK {
		t.Fatalf("restored trust status %d", status)
	}
}
