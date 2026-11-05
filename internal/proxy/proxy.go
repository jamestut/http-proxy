package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// proxyHandler holds upstream HTTP/2 connections for the currently active snapshot.
type proxyHandler struct {
	current *atomic.Pointer[Config]
	dial    func(context.Context, string, string) (net.Conn, error)
	mu      sync.Mutex
	config  *Config
	pools   map[string]*upstreamPool
}

type upstreamPool struct {
	mu   sync.Mutex
	conn *http2.ClientConn
}

func NewProxyHandler(current *atomic.Pointer[Config]) http.Handler {
	return &proxyHandler{current: current}
}

func NewReverseProxyHandler(current *atomic.Pointer[Config], dial func(context.Context, string, string) (net.Conn, error)) http.Handler {
	return &proxyHandler{current: current, dial: dial}
}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg := p.current.Load()
	if cfg == nil {
		http.Error(w, "proxy unavailable", http.StatusServiceUnavailable)
		return
	}
	if !proxyAuthorized(r, cfg.Auth) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="http-proxy", charset="UTF-8"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r, cfg)
		return
	}
	p.serveHTTP(w, r, cfg)
}

func proxyAuthorized(r *http.Request, auth *AuthConfig) bool {
	if auth == nil {
		return true
	}
	header := r.Header.Get("Proxy-Authorization")
	scheme, encoded, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false
	}
	valid := 0
	for _, cred := range auth.Credentials {
		valid |= subtle.ConstantTimeCompare([]byte(username), []byte(cred.Username)) & subtle.ConstantTimeCompare([]byte(password), []byte(cred.Password))
	}
	return valid == 1
}

func (p *proxyHandler) serveHTTP(w http.ResponseWriter, r *http.Request, cfg *Config) {
	if r.URL == nil || r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "expected an absolute HTTP URL", http.StatusBadRequest)
		return
	}
	target, err := clientDestination(r.URL.Host, "80")
	if err != nil {
		http.Error(w, "invalid destination", http.StatusBadRequest)
		return
	}
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return p.dialTarget(ctx, cfg, target)
		},
	}
	defer transport.CloseIdleConnections()
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header = r.Header.Clone()
	stripHopHeaders(out.Header)
	out.Header.Del("Proxy-Authorization")
	out.Header.Del("Proxy-Authenticate")
	out.Close = false
	resp, err := transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "proxy connection failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	stripHopHeaders(resp.Header)
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(&flushingWriter{w}, resp.Body)
}

func stripHopHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, field := range strings.Split(value, ",") {
			h.Del(strings.TrimSpace(field))
		}
	}
	for _, field := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(field)
	}
}

func (p *proxyHandler) serveConnect(w http.ResponseWriter, r *http.Request, cfg *Config) {
	target, err := clientDestination(r.Host, "")
	if err != nil {
		http.Error(w, "invalid destination", http.StatusBadRequest)
		return
	}
	upstream, err := p.dialTarget(r.Context(), cfg, target)
	if err != nil {
		http.Error(w, "proxy connection failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	if r.ProtoMajor == 1 {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "tunnel unavailable", http.StatusInternalServerError)
			return
		}
		client, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffered.Flush(); err != nil {
			return
		}
		relay(r.Context(), upstream, client, buffered.Reader, client)
		return
	}
	if r.ProtoMajor != 2 {
		http.Error(w, "unsupported protocol", http.StatusHTTPVersionNotSupported)
		return
	}
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	// The HTTP handler API cannot end only the response side of an HTTP/2
	// stream while continuing to read its request body.
	relay(r.Context(), upstream, r.Body, r.Body, &flushingWriter{w})
}

type flushingWriter struct{ w http.ResponseWriter }

func (w *flushingWriter) Write(b []byte) (int, error) {
	n, err := w.w.Write(b)
	if f, ok := w.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

type closeWriter interface{ CloseWrite() error }

// relay preserves half-closes so protocols that wait for EOF can return a response.
func relay(ctx context.Context, upstream net.Conn, downstream io.Closer, fromClient io.Reader, toClient io.Writer) {
	stop := context.AfterFunc(ctx, func() { _ = upstream.Close(); _ = downstream.Close() })
	defer stop()
	done := make(chan struct{})
	go func() {
		_, err := io.Copy(upstream, fromClient)
		if cw, ok := upstream.(closeWriter); ok && err == nil {
			_ = cw.CloseWrite()
		} else {
			_ = upstream.Close()
			_ = downstream.Close()
		}
		close(done)
	}()
	_, err := io.Copy(toClient, upstream)
	if cw, ok := downstream.(closeWriter); ok && err == nil {
		_ = cw.CloseWrite()
	} else {
		_ = downstream.Close()
		_ = upstream.Close()
	}
	<-done
	_ = downstream.Close()
	_ = upstream.Close()
}

func clientDestination(authority, defaultPort string) (string, error) {
	target, err := destination(authority, defaultPort)
	if err != nil {
		return "", err
	}
	host, _, _ := net.SplitHostPort(target)
	if strings.Contains(host, ":") && strings.Contains(host, "%") {
		return "", errors.New("scoped IPv6 destinations are not supported")
	}
	return target, nil
}

func destination(authority, defaultPort string) (string, error) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil && defaultPort != "" {
		if strings.Contains(authority, ":") && !(strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]")) {
			return "", err
		}
		host, port = strings.Trim(authority, "[]"), defaultPort
		err = nil
	}
	if err != nil || host == "" {
		return "", errors.New("invalid authority")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("invalid port")
	}
	return net.JoinHostPort(host, port), nil
}

func (p *proxyHandler) dialTarget(ctx context.Context, cfg *Config, target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return p.dialRoute(ctx, cfg, cfg.RouteIP(addr), target)
	}
	if route := cfg.RouteDomain(host); route != nil {
		return p.dialRoute(ctx, cfg, route, target)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, addr := range addrs {
		route := cfg.RouteIP(addr)
		conn, err := p.dialRoute(ctx, cfg, route, net.JoinHostPort(addr.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
		// A selected proxy failure must never become an implicit direct fallback.
		if route != nil || ctx.Err() != nil {
			break
		}
	}
	if last == nil {
		last = errors.New("no addresses")
	}
	return nil, last
}

func (p *proxyHandler) dialRoute(ctx context.Context, cfg *Config, route *string, target string) (net.Conn, error) {
	if route == nil {
		return (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", target)
	}
	up := cfg.Upstreams[*route]
	if up == nil {
		return nil, errors.New("unknown upstream")
	}
	if p.dial != nil {
		return p.dial(ctx, *route, target)
	}
	return p.dialUpstream(ctx, cfg, *route, up, target)
}

func (p *proxyHandler) pool(cfg *Config, name string) *upstreamPool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current.Load() != cfg {
		return &upstreamPool{}
	}
	if p.config != cfg {
		p.config, p.pools = cfg, make(map[string]*upstreamPool)
	}
	if p.pools[name] == nil {
		p.pools[name] = &upstreamPool{}
	}
	return p.pools[name]
}

func (p *proxyHandler) dialUpstream(ctx context.Context, cfg *Config, name string, up *Upstream, target string) (net.Conn, error) {
	pool := p.pool(cfg, name)
	pool.mu.Lock()
	if pool.conn != nil && pool.conn.CanTakeNewRequest() {
		cc := pool.conn
		pool.mu.Unlock()
		return connectH2(ctx, cc, up.Auth, target)
	}
	address, err := destination(up.URL.Host, map[bool]string{true: "443", false: "80"}[up.URL.Scheme == "https"])
	if err != nil {
		pool.mu.Unlock()
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		pool.mu.Unlock()
		return nil, err
	}
	if up.URL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{RootCAs: cfg.Roots, ServerName: up.URL.Hostname(), NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12})
		if err = tlsConn.HandshakeContext(dialCtx); err != nil {
			conn.Close()
			pool.mu.Unlock()
			return nil, err
		}
		conn = tlsConn
		if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
			cc, err := (&http2.Transport{IdleConnTimeout: 30 * time.Second}).NewClientConn(conn)
			if err != nil {
				conn.Close()
				pool.mu.Unlock()
				return nil, err
			}
			pool.conn = cc
			pool.mu.Unlock()
			return connectH2(ctx, cc, up.Auth, target)
		}
	}
	pool.mu.Unlock()
	return connectH1(ctx, conn, up.Auth, target)
}

func setUpstreamAuth(h http.Header, auth *Credential) {
	if auth != nil {
		h.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth.Username+":"+auth.Password)))
	}
}

func connectH1(ctx context.Context, conn net.Conn, auth *Credential, target string) (net.Conn, error) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	setUpstreamAuth(req.Header, auth)
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		conn.Close()
		return nil, fmt.Errorf("upstream CONNECT failed: %d", resp.StatusCode)
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func connectH2(ctx context.Context, cc *http2.ClientConn, auth *Credential, target string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(30*time.Second, cancel)
	reader, writer := io.Pipe()
	req := (&http.Request{Method: http.MethodConnect, URL: &url.URL{Host: target}, Host: target, Header: make(http.Header), Body: reader}).WithContext(ctx)
	setUpstreamAuth(req.Header, auth)
	resp, err := cc.RoundTrip(req)
	timer.Stop()
	if err != nil {
		cancel()
		reader.Close()
		writer.Close()
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		cancel()
		resp.Body.Close()
		writer.Close()
		return nil, fmt.Errorf("upstream CONNECT failed: %d", resp.StatusCode)
	}
	return &h2Tunnel{reader: resp.Body, writer: writer, cancel: cancel}, nil
}

type h2Tunnel struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	cancel context.CancelFunc
}

func (c *h2Tunnel) Read(b []byte) (int, error)       { return c.reader.Read(b) }
func (c *h2Tunnel) Write(b []byte) (int, error)      { return c.writer.Write(b) }
func (c *h2Tunnel) Close() error                     { c.cancel(); _ = c.writer.Close(); return c.reader.Close() }
func (c *h2Tunnel) CloseWrite() error                { return c.writer.Close() }
func (c *h2Tunnel) LocalAddr() net.Addr              { return tunnelAddr("h2-local") }
func (c *h2Tunnel) RemoteAddr() net.Addr             { return tunnelAddr("h2-upstream") }
func (c *h2Tunnel) SetDeadline(time.Time) error      { return nil }
func (c *h2Tunnel) SetReadDeadline(time.Time) error  { return nil }
func (c *h2Tunnel) SetWriteDeadline(time.Time) error { return nil }

type tunnelAddr string

func (a tunnelAddr) Network() string { return "h2" }
func (a tunnelAddr) String() string  { return string(a) }
