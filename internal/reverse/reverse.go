package reverse

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const stopPath = "/_reverse/terminate"

// Server manages authenticated reverse connections.
type Server struct {
	auth                  func(string, string) (string, bool)
	timeout               time.Duration
	replace               sync.Mutex
	pending               sync.WaitGroup
	mu                    sync.Mutex
	sessions              map[string]*session
	closed                bool
	pingIdle, pingTimeout time.Duration
}
type session struct {
	cc   *http2.ClientConn
	conn *carrier
	done chan struct{}
}

func NewServer(auth func(string, string) (string, bool), shutdownTimeout time.Duration) *Server {
	if shutdownTimeout <= 0 {
		shutdownTimeout = 5 * time.Second
	}
	return &Server{auth: auth, timeout: shutdownTimeout, sessions: make(map[string]*session)}
}

// SetShutdownTimeout configures the time allowed for subsequent terminations.
func (s *Server) SetShutdownTimeout(timeout time.Duration) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	s.mu.Lock()
	s.timeout = timeout
	s.mu.Unlock()
}

// SetPing configures health checks for subsequently registered connections.
func (s *Server) SetPing(idle, timeout time.Duration) {
	s.mu.Lock()
	s.pingIdle, s.pingTimeout = idle, timeout
	s.mu.Unlock()
}
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }
func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 2 || r.Method != http.MethodPost {
		http.Error(w, "HTTP/2 POST required", http.StatusHTTPVersionNotSupported)
		return
	}
	user, pass, ok := r.BasicAuth()
	if !ok || s.auth == nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="reverse"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.replace.Lock()
	name, ok := s.auth(user, pass)
	if !ok || name == "" {
		s.replace.Unlock()
		w.Header().Set("WWW-Authenticate", `Basic realm="reverse"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	f, ok := w.(http.Flusher)
	if !ok {
		s.replace.Unlock()
		http.Error(w, "streaming unavailable", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.replace.Unlock()
		http.Error(w, "server closed", http.StatusServiceUnavailable)
		return
	}
	idle, timeout := s.pingIdle, s.pingTimeout
	s.mu.Unlock()
	s.replace.Unlock()
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		http.Error(w, "streaming deadline unavailable", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	f.Flush()
	c := newCarrier(r.Body, flushWriter{w, f})
	tr := &http2.Transport{AllowHTTP: true, ReadIdleTimeout: idle, PingTimeout: timeout}
	cc, err := tr.NewClientConn(c)
	if err == nil {
		err = controller.SetWriteDeadline(time.Time{})
	}
	if err != nil {
		c.Close()
		return
	}
	s.replace.Lock()
	currentName, valid := s.auth(user, pass)
	s.mu.Lock()
	if s.closed || !valid || currentName != name {
		s.mu.Unlock()
		s.replace.Unlock()
		cc.Close()
		c.Close()
		return
	}
	sess := &session{cc: cc, conn: c, done: make(chan struct{})}
	old := s.sessions[name]
	s.sessions[name] = sess
	s.mu.Unlock()
	if old != nil {
		s.stopAsync(old)
	}
	s.replace.Unlock()
	select {
	case <-r.Context().Done():
	case <-c.done:
	}
	cc.Close()
	c.Close()
	s.mu.Lock()
	if s.sessions[name] == sess {
		delete(s.sessions, name)
	}
	s.mu.Unlock()
	close(sess.done)
}
func (s *Server) stop(sess *session) {
	s.mu.Lock()
	timeout := s.timeout
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://reverse"+stopPath, nil)
	resp, err := sess.cc.RoundTrip(req)
	if err == nil {
		resp.Body.Close()
	}
	select {
	case <-sess.done:
	case <-ctx.Done():
	}
	sess.cc.Close()
	sess.conn.Close()
}

// stopAsync must be called while holding replace, so Close can safely wait.
func (s *Server) stopAsync(sess *session) {
	s.pending.Add(1)
	go func() { defer s.pending.Done(); s.stop(sess) }()
}
func (s *Server) Remove(name string) {
	s.replace.Lock()
	defer s.replace.Unlock()
	s.mu.Lock()
	sess := s.sessions[name]
	if sess != nil {
		delete(s.sessions, name)
	}
	s.mu.Unlock()
	if sess != nil {
		s.stopAsync(sess)
	}
}
func (s *Server) Close() {
	s.replace.Lock()
	defer s.replace.Unlock()
	s.mu.Lock()
	s.closed = true
	sessions := s.sessions
	s.sessions = make(map[string]*session)
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, sess := range sessions {
		wg.Add(1)
		go func(sess *session) { defer wg.Done(); s.stop(sess) }(sess)
	}
	wg.Wait()
	s.pending.Wait()
}

// Dial opens a CONNECT stream to target through the named agent.
func (s *Server) Dial(ctx context.Context, name, target string) (net.Conn, error) {
	s.mu.Lock()
	sess := s.sessions[name]
	s.mu.Unlock()
	if sess == nil {
		return nil, fmt.Errorf("reverse agent %q is not connected", name)
	}
	ctx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(30*time.Second, cancel)
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+target, pr)
	if err != nil {
		timer.Stop()
		cancel()
		pr.Close()
		pw.Close()
		return nil, err
	}
	req.Host = target
	resp, err := sess.cc.RoundTrip(req)
	timer.Stop()
	if err != nil {
		cancel()
		pr.Close()
		pw.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		resp.Body.Close()
		pw.Close()
		return nil, fmt.Errorf("reverse CONNECT: %s", resp.Status)
	}
	return &streamConn{reader: resp.Body, writer: pw, cancel: cancel}, nil
}

type ClientOptions struct {
	Address, Username, Password                       string
	ProxyURL                                          *url.URL
	Roots                                             *x509.CertPool
	ConnectTimeout, RetryDelay, PingIdle, PingTimeout time.Duration
	Handler                                           http.Handler
}

// Run reconnects until the context is cancelled or the server terminates the agent.
func Run(ctx context.Context, options func() ClientOptions) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		opts := options()
		stopped, _ := runOnce(ctx, opts)
		if stopped {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		delay := opts.RetryDelay
		if delay <= 0 {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func runOnce(ctx context.Context, opts ClientOptions) (bool, error) {
	u, err := url.Parse(opts.Address)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return false, errors.New("reverse address must be an HTTPS URL")
	}
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, u.String(), pr)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(opts.Username, opts.Password)
	tr := &http2.Transport{TLSClientConfig: &tls.Config{RootCAs: opts.Roots, MinVersion: tls.VersionTLS12}, ReadIdleTimeout: opts.PingIdle, PingTimeout: opts.PingTimeout}
	tr.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		return dialTLS(ctx, network, addr, cfg, opts.ProxyURL, opts.ConnectTimeout)
	}
	defer tr.CloseIdleConnections()
	var timer *time.Timer
	if opts.ConnectTimeout > 0 {
		timer = time.AfterFunc(opts.ConnectTimeout, cancel)
	}
	resp, err := tr.RoundTrip(req)
	if timer != nil {
		timer.Stop()
	}
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return false, fmt.Errorf("reverse registration: %s", resp.Status)
	}
	c := newCarrier(resp.Body, pw)
	defer c.Close()
	stopped := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == stopPath {
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			select {
			case stopped <- struct{}{}:
			default:
			}
			return
		}
		if opts.Handler == nil {
			http.Error(w, "no handler", http.StatusServiceUnavailable)
			return
		}
		opts.Handler.ServeHTTP(w, r)
	})
	done := make(chan struct{})
	go func() {
		(&http2.Server{ReadIdleTimeout: opts.PingIdle, PingTimeout: opts.PingTimeout}).ServeConn(c, &http2.ServeConnOpts{Handler: handler})
		close(done)
	}()
	select {
	case <-stopped:
		c.Close()
		<-done
		return true, nil
	case <-done:
		select {
		case <-stopped:
			return true, nil
		default:
			return false, errors.New("reverse connection closed")
		}
	case <-ctx.Done():
		c.Close()
		<-done
		return false, ctx.Err()
	}
}
func dialTLS(ctx context.Context, network, addr string, cfg *tls.Config, proxy *url.URL, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	dialAddr := addr
	if proxy != nil {
		if proxy.Scheme != "http" || proxy.Host == "" {
			return nil, errors.New("proxy must be an HTTP URL")
		}
		dialAddr = proxy.Host
		if proxy.Port() == "" {
			dialAddr = net.JoinHostPort(proxy.Hostname(), "80")
		}
	}
	c, err := d.DialContext(ctx, network, dialAddr)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		c.SetDeadline(time.Now().Add(timeout))
	}
	fail := func(err error) (net.Conn, error) { c.Close(); return nil, err }
	if proxy != nil {
		req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: make(http.Header)}
		if proxy.User != nil {
			pass, _ := proxy.User.Password()
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(proxy.User.Username()+":"+pass)))
		}
		if err = req.Write(c); err != nil {
			return fail(err)
		}
		br := bufio.NewReader(c)
		resp, e := http.ReadResponse(br, req)
		if e != nil {
			return fail(e)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fail(fmt.Errorf("proxy CONNECT: %s", resp.Status))
		}
		if br.Buffered() != 0 {
			return fail(errors.New("unexpected buffered proxy data"))
		}
	}
	conf := cfg.Clone()
	if conf.ServerName == "" {
		conf.ServerName, _, _ = net.SplitHostPort(addr)
	}
	conf.NextProtos = []string{"h2"}
	tc := tls.Client(c, conf)
	if err = tc.HandshakeContext(ctx); err != nil {
		return fail(err)
	}
	if tc.ConnectionState().NegotiatedProtocol != "h2" {
		return fail(errors.New("server did not negotiate HTTP/2"))
	}
	c.SetDeadline(time.Time{})
	return tc, nil
}

type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (w flushWriter) Write(p []byte) (int, error) { n, err := w.w.Write(p); w.f.Flush(); return n, err }
func (w flushWriter) Close() error {
	return http.NewResponseController(w.w).SetWriteDeadline(time.Now().Add(-time.Second))
}

type carrier struct {
	r       io.ReadCloser
	w       io.Writer
	done    chan struct{}
	once    sync.Once
	writeMu sync.Mutex
}

func newCarrier(r io.ReadCloser, w io.Writer) *carrier {
	return &carrier{r: r, w: w, done: make(chan struct{})}
}
func (c *carrier) Read(p []byte) (int, error) {
	n, e := c.r.Read(p)
	if e != nil {
		c.Close()
	}
	return n, e
}
func (c *carrier) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	select {
	case <-c.done:
		c.writeMu.Unlock()
		return 0, net.ErrClosed
	default:
	}
	n, e := c.w.Write(p)
	c.writeMu.Unlock()
	if e != nil {
		c.Close()
	}
	return n, e
}
func (c *carrier) Close() error {
	c.once.Do(func() {
		close(c.done)
		if w, ok := c.w.(io.Closer); ok {
			w.Close()
		}
		c.r.Close()
		c.writeMu.Lock()
		c.writeMu.Unlock()
	})
	return nil
}
func (c *carrier) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *carrier) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *carrier) SetDeadline(time.Time) error      { return nil }
func (c *carrier) SetReadDeadline(time.Time) error  { return nil }
func (c *carrier) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return "reverse" }
func (a dummyAddr) String() string  { return string(a) }

type streamConn struct {
	cancel context.CancelFunc
	reader io.ReadCloser
	writer *io.PipeWriter
	once   sync.Once
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *streamConn) Close() error {
	c.once.Do(func() { c.cancel(); c.writer.Close(); c.reader.Close() })
	return nil
}
func (c *streamConn) CloseWrite() error                { return c.writer.Close() }
func (c *streamConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *streamConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *streamConn) SetDeadline(time.Time) error      { return errors.New("deadlines unsupported") }
func (c *streamConn) SetReadDeadline(time.Time) error  { return errors.New("deadlines unsupported") }
func (c *streamConn) SetWriteDeadline(time.Time) error { return errors.New("deadlines unsupported") }
