package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestDomainNullResolvesBeforeIPRouting(t *testing.T) {
	var upstreamCalls atomic.Int32
	destinations := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		destinations <- r.Host
		if r.Method != http.MethodConnect {
			t.Errorf("upstream method = %s, want CONNECT", r.Method)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := rw.Flush(); err != nil {
			t.Error(err)
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			t.Error(err)
			return
		}
		_ = req.Body.Close()
		fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nupstream")
	}))
	defer upstream.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "direct") }))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(originURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	target := "http://localhost:" + port + "/"

	for _, tc := range []struct {
		name, ipRules, want string
		usesUpstream        bool
	}{
		{"IP default uses upstream", `"ip":{}`, "upstream", true},
		{"null IP rules use direct", `"ip":{"127.0.0.0/8":null,"::1/128":null}`, "direct", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := fmt.Sprintf(`{"upstreams":{"u":{"host":%q}},"defaults":{"domain":"u","unqualified-domain":"u","ip":"u"},"domain":{"localhost":null},%s}`, upstream.URL, tc.ipRules)
			cfg, err := loadTestConfig(t, config)
			if err != nil {
				t.Fatal(err)
			}
			proxy, _ := testProxy(t, cfg)
			proxyURL, _ := url.Parse(proxy.URL)
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
			defer client.CloseIdleConnections()
			before := upstreamCalls.Load()
			resp, err := client.Get(target)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK || string(body) != tc.want {
				t.Fatalf("response status=%d body=%q error=%v", resp.StatusCode, body, err)
			}
			if tc.usesUpstream {
				if upstreamCalls.Load() != before+1 {
					t.Fatal("expected exactly one upstream CONNECT")
				}
				select {
				case authority := <-destinations:
					host, gotPort, err := net.SplitHostPort(authority)
					if err != nil || gotPort != port {
						t.Fatalf("unexpected CONNECT target %q", authority)
					}
					if _, err := netip.ParseAddr(host); err != nil {
						t.Fatalf("hostname sent upstream rather than resolved IP: %q", host)
					}
				case <-time.After(time.Second):
					t.Fatal("upstream CONNECT not observed")
				}
			} else if upstreamCalls.Load() != before {
				t.Fatal("null IP rule did not use direct connection")
			}
		})
	}
}
