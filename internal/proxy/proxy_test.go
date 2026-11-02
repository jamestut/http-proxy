package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func testProxy(t *testing.T, cfg *Config) (*httptest.Server, *atomic.Pointer[Config]) {
	t.Helper()
	var current atomic.Pointer[Config]
	current.Store(cfg)
	ts := httptest.NewServer(NewProxyHandler(&current))
	t.Cleanup(ts.Close)
	return ts, &current
}

func testEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func TestHTTPProxyAuthAndForwarding(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" {
			t.Errorf("proxy or hop header reached origin: %v", r.Header)
		}
		if r.URL.Path != "/path" || r.URL.RawQuery != "x=1" {
			t.Errorf("unexpected URL %s", r.URL)
		}
		fmt.Fprint(w, "response")
	}))
	defer origin.Close()
	cfg := &Config{Auth: &AuthConfig{Credentials: []Credential{{Username: "alice", Password: "秘密:word"}}}}
	server, current := testProxy(t, cfg)
	proxyURL, _ := url.Parse(server.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	defer client.CloseIdleConnections()
	resp, err := client.Get(origin.URL + "/path?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 407 || !strings.Contains(resp.Header.Get("Proxy-Authenticate"), `charset="UTF-8"`) {
		t.Fatalf("unexpected auth challenge: %#v", resp)
	}
	req, _ := http.NewRequest("GET", origin.URL+"/path?x=1", nil)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:秘密:word")))
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "secret")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "response" {
		t.Fatalf("HTTP response %d %q", resp.StatusCode, body)
	}
	current.Store(&Config{Auth: &AuthConfig{Credentials: []Credential{{Username: "bob", Password: "new"}}}})
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 407 {
		t.Fatalf("old credentials after reload: %d", resp.StatusCode)
	}
}

func TestConnectHTTP1(t *testing.T) {
	target := testEcho(t)
	server, _ := testProxy(t, &Config{})
	address := strings.TrimPrefix(server.URL, "http://")
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\npipelined", target, target)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT response: %v %v", resp, err)
	}
	got := make([]byte, len("pipelined"))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "pipelined" {
		t.Fatalf("tunnel: %q %v", got, err)
	}
}

func TestUpstreamHTTP1ConnectAuthenticationAndFailure(t *testing.T) {
	var count atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.Method != "CONNECT" || r.Host != "example.com:80" {
			t.Errorf("upstream request: %s %s", r.Method, r.Host)
		}
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("proxy:pass:word")) {
			t.Error("wrong upstream auth")
		}
		h, ok := w.(http.Hijacker)
		if !ok {
			t.Error("missing hijacker")
			return
		}
		conn, rw, err := h.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n")
		rw.Flush()
		_, _ = io.Copy(conn, rw)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	name := "proxy"
	cfg := &Config{Upstreams: map[string]*Upstream{name: {URL: u, Auth: &Credential{Username: "proxy", Password: "pass:word"}}}, policy: policy{defaults: rawDefaults{Domain: &name}}}
	var current atomic.Pointer[Config]
	current.Store(cfg)
	p := NewProxyHandler(&current).(*proxyHandler)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := p.dialTarget(ctx, cfg, "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("hello"))
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello" {
		t.Fatalf("relay: %q %v", got, err)
	}
	if count.Load() != 1 {
		t.Fatal("upstream not used")
	}
	failure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "refused", 403) }))
	defer failure.Close()
	badURL, _ := url.Parse(failure.URL)
	bad := &Config{Upstreams: map[string]*Upstream{name: {URL: badURL}}, policy: policy{defaults: rawDefaults{IP: &name}}}
	if c, err := p.dialTarget(ctx, bad, "127.0.0.1:1"); err == nil {
		c.Close()
		t.Fatal("upstream failure unexpectedly succeeded")
	}
}

func TestUpstreamH2MultiplexAndSnapshotTrust(t *testing.T) {
	var connections, streams atomic.Int32
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != "CONNECT" {
			t.Errorf("unexpected protocol/method: %s %s", r.Proto, r.Method)
		}
		streams.Add(1)
		w.WriteHeader(201)
		w.(http.Flusher).Flush()
		_, _ = io.Copy(&flushingWriter{w}, r.Body)
	}))
	up.EnableHTTP2 = true
	up.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	up.StartTLS()
	defer up.Close()
	u, _ := url.Parse(up.URL)
	roots := x509.NewCertPool()
	roots.AddCert(up.Certificate())
	name := "proxy"
	cfg := &Config{Upstreams: map[string]*Upstream{name: {URL: u}}, Roots: roots, policy: policy{defaults: rawDefaults{IP: &name}}}
	var current atomic.Pointer[Config]
	current.Store(cfg)
	p := NewProxyHandler(&current).(*proxyHandler)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var c [2]net.Conn
	var errs [2]error
	var wg sync.WaitGroup
	for i := range c {
		wg.Add(1)
		go func(i int) { defer wg.Done(); c[i], errs[i] = p.dialTarget(ctx, cfg, "127.0.0.1:1234") }(i)
	}
	wg.Wait()
	for i := range c {
		if errs[i] != nil {
			t.Fatalf("h2 CONNECT %d: %v", i, errs[i])
		}
		defer c[i].Close()
	}
	for i := range c {
		if _, err := c[i].Write([]byte("abc")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 3)
		if _, err := io.ReadFull(c[i], buf); err != nil || string(buf) != "abc" {
			t.Fatalf("stream %d: %q %v", i, buf, err)
		}
	}
	if connections.Load() != 1 || streams.Load() != 2 {
		t.Fatalf("connections=%d streams=%d", connections.Load(), streams.Load())
	}
	bad := &Config{Upstreams: map[string]*Upstream{name: {URL: u}}, Roots: x509.NewCertPool(), policy: policy{defaults: rawDefaults{IP: &name}}}
	current.Store(bad)
	if conn, err := p.dialTarget(ctx, bad, "127.0.0.1:1234"); err == nil {
		conn.Close()
		t.Fatal("new snapshot reused old trusted connection")
	}
}

func TestDownstreamH2Connect(t *testing.T) {
	target := testEcho(t)
	var cfg atomic.Pointer[Config]
	cfg.Store(&Config{})
	ts := httptest.NewUnstartedServer(NewProxyHandler(&cfg))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	tr := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // Test server uses an ephemeral self-signed certificate.
	defer tr.CloseIdleConnections()
	reader, writer := io.Pipe()
	req, _ := http.NewRequest("CONNECT", ts.URL, reader)
	req.Host = target
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := tr.RoundTrip(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	defer writer.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != 200 {
		t.Fatalf("unexpected response: %s %d", resp.Proto, resp.StatusCode)
	}
	if _, err := writer.Write([]byte("h2 tunnel")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("h2 tunnel"))
	if _, err := io.ReadFull(resp.Body, got); err != nil || string(got) != "h2 tunnel" {
		t.Fatalf("h2 echo: %q %v", got, err)
	}
}

func TestConnectHTTP1ServerHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("ready"))
		_ = conn.(*net.TCPConn).CloseWrite()
		data, _ := io.ReadAll(conn)
		received <- string(data)
	}()
	server, _ := testProxy(t, &Config{})
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr(), ln.Addr())
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("response %v %v", resp, err)
	}
	data, err := io.ReadAll(br)
	if err != nil || string(data) != "ready" {
		t.Fatalf("server half close: %q %v", data, err)
	}
	_, err = conn.Write([]byte("client response"))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got != "client response" {
			t.Fatalf("server got %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive client response")
	}
}

func TestDownstreamH2ClientHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		_, _ = conn.Write(append([]byte("received:"), data...))
	}()
	var cfg atomic.Pointer[Config]
	cfg.Store(&Config{})
	ts := httptest.NewUnstartedServer(NewProxyHandler(&cfg))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	tr := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer tr.CloseIdleConnections()
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("CONNECT", ts.URL, pr)
	req.Host = ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := tr.RoundTrip(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = pw.Write([]byte("hello"))
	_ = pw.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil || string(got) != "received:hello" {
		t.Fatalf("response %q %v", got, err)
	}
}

func TestUpstreamHTTPSFallbackAndSuccess2xx(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.Method != http.MethodConnect {
			t.Errorf("upstream got %s %s", r.Proto, r.Method)
		}
		h := w.(http.Hijacker)
		conn, rw, err := h.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 201 Created\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	roots := x509.NewCertPool()
	roots.AddCert(up.Certificate())
	name := "proxy"
	cfg := &Config{Upstreams: map[string]*Upstream{name: {URL: u}}, Roots: roots, policy: policy{defaults: rawDefaults{IP: &name}}}
	var current atomic.Pointer[Config]
	current.Store(cfg)
	p := NewProxyHandler(&current).(*proxyHandler)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := p.dialTarget(ctx, cfg, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello" {
		t.Fatalf("fallback echo %q %v", got, err)
	}
}

func TestHeadAndStreamedResponse(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5")
		if r.Method != "HEAD" {
			_, _ = io.WriteString(w, "hello")
		}
	}))
	defer origin.Close()
	proxy, _ := testProxy(t, &Config{})
	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	defer client.CloseIdleConnections()
	for _, method := range []string{"HEAD", "GET"} {
		req, _ := http.NewRequest(method, origin.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.ContentLength != 5 || (method == "HEAD" && len(body) != 0) || (method == "GET" && string(body) != "hello") {
			t.Fatalf("%s length %d body %q", method, resp.ContentLength, body)
		}
	}
}

func TestHTTPResponseStreamsBeforeOriginFinishes(t *testing.T) {
	allowFinish := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		<-allowFinish
		_, _ = io.WriteString(w, "second")
	}))
	defer origin.Close()
	proxy, _ := testProxy(t, &Config{})
	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Get(origin.URL)
	if err != nil {
		close(allowFinish)
		t.Fatal(err)
	}
	defer resp.Body.Close()
	first := make([]byte, 5)
	_, err = io.ReadFull(resp.Body, first)
	close(allowFinish)
	if err != nil || string(first) != "first" {
		t.Fatalf("streamed chunk %q %v", first, err)
	}
	rest, err := io.ReadAll(resp.Body)
	if err != nil || string(rest) != "second" {
		t.Fatalf("remaining chunk %q %v", rest, err)
	}
}

func TestStalledUpstreamDoesNotBlockNewSnapshot(t *testing.T) {
	stalled, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := stalled.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	name := "proxy"
	slowURL, _ := url.Parse("https://" + stalled.Addr().String())
	old := &Config{Upstreams: map[string]*Upstream{name: {URL: slowURL}}, policy: policy{defaults: rawDefaults{IP: &name}}}
	var current atomic.Pointer[Config]
	current.Store(old)
	p := NewProxyHandler(&current).(*proxyHandler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := p.dialTarget(ctx, old, "127.0.0.1:1234")
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	var held net.Conn
	select {
	case held = <-accepted:
		defer held.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("upstream was not dialed")
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "test", 403) }))
	defer up.Close()
	fastURL, _ := url.Parse(up.URL)
	newConfig := &Config{Upstreams: map[string]*Upstream{name: {URL: fastURL}}, policy: policy{defaults: rawDefaults{IP: &name}}}
	current.Store(newConfig)
	fastDone := make(chan error, 1)
	go func() {
		c, err := p.dialTarget(context.Background(), newConfig, "127.0.0.1:1234")
		if c != nil {
			c.Close()
		}
		fastDone <- err
	}()
	select {
	case <-fastDone:
	case <-time.After(2 * time.Second):
		t.Fatal("new snapshot blocked on old handshake")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("stalled handshake succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Error("cancellation failed to interrupt handshake")
	}
}
