package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestClientDestinationRejectsScopedIPv6(t *testing.T) {
	for _, authority := range []string{
		"[fe80::1%en0]:80",
		"[fe80::1%25en0]:80",
		"[fe80::1%en0]",
		"[fe80::1%25en0]",
	} {
		if _, err := clientDestination(authority, "80"); err == nil {
			t.Errorf("accepted scoped destination %q", authority)
		}
	}
	for _, authority := range []string{"[2001:db8::1]:80", "[2001:db8::1]", "example.com:80"} {
		if _, err := clientDestination(authority, "80"); err != nil {
			t.Errorf("rejected unscoped destination %q: %v", authority, err)
		}
	}
	if _, err := destination("[fe80::1%en0]:80", "80"); err != nil {
		t.Errorf("configured upstream destination rejected: %v", err)
	}
	if _, err := ParseConfig([]byte(`{"upstreams":{"a":{"host":"http://[fe80::1%25en0]:8080"}}}`), "config.json"); err != nil {
		t.Errorf("configured scoped upstream rejected: %v", err)
	}
}

func TestScopedClientRequests(t *testing.T) {
	name := "agent"
	cfg := &Config{
		Upstreams: map[string]*Upstream{name: {}},
		policy:    policy{defaults: rawDefaults{IP: &name}},
	}
	var current atomic.Pointer[Config]
	current.Store(cfg)
	var calls atomic.Int32
	handler := NewReverseProxyHandler(&current, func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, fmt.Errorf("test dial")
	})
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	for _, proto := range []string{"http1", "http2"} {
		for _, method := range []string{http.MethodGet, http.MethodConnect} {
			for _, tc := range []struct {
				name, authority string
				status          int
				wantCalls       int32
			}{
				{"scoped", "[fe80::1%25en0]:80", http.StatusBadRequest, 0},
				{"raw zone", "[fe80::1%en0]:80", http.StatusBadRequest, 0},
				{"unscoped", "[2001:db8::1]:80", http.StatusBadGateway, 1},
			} {
				t.Run(proto+"/"+method+"/"+tc.name, func(t *testing.T) {
					calls.Store(0)
					wantStatus := tc.status
					// The HTTP/2 server rejects an invalid raw URL escape before
					// the handler runs, resetting the stream instead of sending 400.
					if proto == "http2" && method == http.MethodGet && tc.name == "raw zone" {
						wantStatus = 0
					}
					var status int
					if proto == "http1" {
						status = scopedHTTP1Status(t, server, method, tc.authority)
					} else {
						status = scopedHTTP2Status(t, server, method, tc.authority)
					}
					if status != wantStatus || calls.Load() != tc.wantCalls {
						t.Fatalf("status = %d, dial calls = %d; want %d, %d", status, calls.Load(), wantStatus, tc.wantCalls)
					}
				})
			}
		}
	}
}

func TestScopedClientRequestsDoNotReachRoutes(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		http.Error(w, "unexpected connection", http.StatusBadGateway)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	name := "upstream"
	for _, route := range []struct {
		name string
		cfg  *Config
	}{
		{"direct", &Config{}},
		{"upstream", &Config{Upstreams: map[string]*Upstream{name: {URL: upstreamURL}}, policy: policy{defaults: rawDefaults{IP: &name}}}},
	} {
		for _, method := range []string{http.MethodGet, http.MethodConnect} {
			for _, authority := range []string{"[fe80::1%en0]:80", "[fe80::1%25en0]:80"} {
				t.Run(route.name+"/"+method+"/"+authority, func(t *testing.T) {
					var current atomic.Pointer[Config]
					current.Store(route.cfg)
					r := &http.Request{Method: method, Host: authority, URL: &url.URL{Scheme: "http", Host: authority}, Header: make(http.Header)}
					w := httptest.NewRecorder()
					NewProxyHandler(&current).ServeHTTP(w, r)
					if w.Code != http.StatusBadRequest || w.Body.String() != "invalid destination\n" {
						t.Fatalf("response = %d %q", w.Code, w.Body.String())
					}
					if upstreamCalls.Load() != 0 {
						t.Fatal("scoped destination reached upstream")
					}
				})
			}
		}
	}
}

func scopedHTTP1Status(t *testing.T, server *httptest.Server, method, authority string) int {
	t.Helper()
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}) // Test server certificate.
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	target := authority
	if method != http.MethodConnect {
		target = "http://" + authority + "/"
	}
	if _, err := fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", method, target, authority); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func scopedHTTP2Status(t *testing.T, server *httptest.Server, method, authority string) int {
	t.Helper()
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) // Test server certificate.
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("HTTP/2 was not negotiated")
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	fields := []hpack.HeaderField{{Name: ":method", Value: method}, {Name: ":authority", Value: authority}}
	if method != http.MethodConnect {
		fields = append(fields, hpack.HeaderField{Name: ":scheme", Value: "http"}, hpack.HeaderField{Name: ":path", Value: "http://" + authority + "/"})
	}
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					t.Fatal(err)
				}
			}
		case *http2.MetaHeadersFrame:
			var status int
			if _, err := fmt.Sscanf(f.PseudoValue("status"), "%d", &status); err != nil {
				t.Fatal(err)
			}
			return status
		case *http2.RSTStreamFrame:
			if f.ErrCode == http2.ErrCodeProtocol {
				return 0
			}
			t.Fatalf("HTTP/2 stream reset: %v", f.ErrCode)
		case *http2.GoAwayFrame:
			t.Fatalf("HTTP/2 connection closed: %v", f.ErrCode)
		}
	}
}

func TestScopedDestinationAuthenticationFirst(t *testing.T) {
	var current atomic.Pointer[Config]
	current.Store(&Config{Auth: &AuthConfig{Credentials: []Credential{{Username: "alice", Password: "secret"}}}})
	r := &http.Request{Method: http.MethodConnect, Host: "[fe80::1%en0]:80", URL: &url.URL{}, Header: make(http.Header)}
	w := httptest.NewRecorder()
	NewProxyHandler(&current).ServeHTTP(w, r)
	if w.Code != http.StatusProxyAuthRequired || !strings.Contains(w.Header().Get("Proxy-Authenticate"), "Basic") {
		t.Fatalf("authentication response = %d, %q", w.Code, w.Header().Get("Proxy-Authenticate"))
	}
}
