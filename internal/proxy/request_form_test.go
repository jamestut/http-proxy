package proxy

import (
	"bufio"
	"bytes"
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

func TestHTTPRequestForms(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/path" || r.URL.RawQuery != "x=1" {
			t.Errorf("origin URL = %s, want /path?x=1", r.URL)
		}
		fmt.Fprint(w, "response")
	}))
	defer origin.Close()

	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[Config]
	current.Store(&Config{})
	handler := NewProxyHandler(&current)

	for _, tc := range []struct {
		name string
		url  *url.URL
		host string
	}{
		{
			name: "absolute URL",
			url:  &url.URL{Scheme: "http", Host: originURL.Host, Path: "/path", RawQuery: "x=1"},
			host: originURL.Host,
		},
		{
			name: "origin form with Host",
			url:  &url.URL{Path: "/path", RawQuery: "x=1"},
			host: originURL.Host,
		},
		{
			name: "HTTPS absolute URL rejected",
			url:  &url.URL{Scheme: "https", Host: originURL.Host, Path: "/path", RawQuery: "x=1"},
			host: originURL.Host,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Method: http.MethodGet, URL: tc.url, Host: tc.host, Header: make(http.Header)}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if tc.name == "HTTPS absolute URL rejected" {
				if w.Code != http.StatusBadRequest {
					t.Fatalf("response = %d, want 400", w.Code)
				}
				return
			}
			if w.Code != http.StatusOK || w.Body.String() != "response" {
				t.Fatalf("response = %d %q, want 200 %q", w.Code, w.Body.String(), "response")
			}
		})
	}
}

func TestHTTP2OriginFormRequestUsesAuthority(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/path?x=1" {
			t.Errorf("origin URL = %s, want /path?x=1", r.URL)
		}
		fmt.Fprint(w, "response")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(originURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	authority := net.JoinHostPort("localhost", port)

	var current atomic.Pointer[Config]
	current.Store(&Config{})
	server := httptest.NewUnstartedServer(NewProxyHandler(&current))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			status, body := rawHTTP2Request(t, server, scheme, authority)
			if status != http.StatusOK || body != "response" {
				t.Fatalf("request = %d %q, want 200 %q", status, body, "response")
			}
		})
	}
}

func TestHTTP1TLSOriginFormRequest(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "response")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[Config]
	current.Store(&Config{})
	server := httptest.NewTLSServer(NewProxyHandler(&current))
	defer server.Close()

	conn, err := tls.Dial("tcp", strings.TrimPrefix(server.URL, "https://"), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) // Test server certificate.
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET /path?x=1 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", originURL.Host); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "response" {
		t.Fatalf("response = %d %q, error %v", resp.StatusCode, body, err)
	}
}

func rawHTTP2Request(t *testing.T, server *httptest.Server, scheme, authority string) (int, string) {
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
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodGet},
		{Name: ":scheme", Value: scheme},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: "/path?x=1"},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	var status int
	var body strings.Builder
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
			if _, err := fmt.Sscanf(f.PseudoValue("status"), "%d", &status); err != nil {
				t.Fatal(err)
			}
		case *http2.DataFrame:
			_, _ = body.Write(f.Data())
			if f.StreamEnded() {
				return status, body.String()
			}
		case *http2.RSTStreamFrame:
			t.Fatalf("HTTP/2 stream reset: %v", f.ErrCode)
		case *http2.GoAwayFrame:
			t.Fatalf("HTTP/2 connection closed: %v", f.ErrCode)
		}
	}
}
