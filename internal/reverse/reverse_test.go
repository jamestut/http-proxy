package reverse

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestRegistrationStreamsReplacementAndRemoval(t *testing.T) {
	s := NewServer(func(u, p string) (string, bool) { return u, p == "secret" }, time.Second)
	defer s.Close()
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("unexpected method: %s", r.Method)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		buf := make([]byte, 128)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	})
	opts := func() ClientOptions {
		return ClientOptions{Address: ts.URL, Username: "agent", Password: "secret", Roots: roots, RetryDelay: time.Millisecond * 10, Handler: handler}
	}
	start := func() (context.CancelFunc, <-chan error) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, opts) }()
		return cancel, done
	}
	cancel1, done1 := start()
	defer cancel1()
	waitDial := func() {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			c, err := s.Dial(ctx, "agent", "example.com:80")
			cancel()
			if err == nil {
				c.Close()
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("agent did not connect: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitDial()
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, err := s.Dial(ctx, "agent", "example.com:80")
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			if _, err = c.Write([]byte("hello")); err != nil {
				t.Error(err)
				return
			}
			b := make([]byte, 5)
			if _, err = io.ReadFull(c, b); err != nil || string(b) != "hello" {
				t.Errorf("echo: %q %v", b, err)
			}
		}()
	}
	wg.Wait()
	cancel2, done2 := start()
	defer cancel2()
	select {
	case err := <-done1:
		if err != nil {
			t.Fatalf("old agent: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("old agent not terminated")
	}
	waitDial()
	s.Remove("agent")
	select {
	case err := <-done2:
		if err != nil {
			t.Fatalf("new agent: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("new agent not terminated")
	}
}

func TestRegistrationAuthenticationAndProtocol(t *testing.T) {
	s := NewServer(func(u, p string) (string, bool) { return u, p == "secret" }, time.Second)
	defer s.Close()
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	client := &http.Client{Transport: &http2.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL, nil)
	req.SetBasicAuth("agent", "wrong")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %s", resp.Status)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://example/", nil)
	r.SetBasicAuth("agent", "secret")
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusHTTPVersionNotSupported {
		t.Fatalf("HTTP/1 status = %d", w.Code)
	}
}

func TestRegistrationTimeoutIncludesResponse(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	start := time.Now()
	_, err := runOnce(context.Background(), ClientOptions{Address: ts.URL, Roots: roots, ConnectTimeout: 100 * time.Millisecond})
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("registration timeout: %v after %v", err, time.Since(start))
	}
}

func TestReplacementDoesNotWaitForOldAgent(t *testing.T) {
	s := NewServer(func(u, p string) (string, bool) { return u, p == "secret" }, 2*time.Second)
	defer s.Close()
	client, server := net.Pipe()
	oldConn := newCarrier(client, client)
	done := make(chan struct{})
	go func() {
		(&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })})
		close(done)
	}()
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(oldConn)
	if err != nil {
		t.Fatal(err)
	}
	s.sessions["agent"] = &session{cc: cc, conn: oldConn, done: done}
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, func() ClientOptions {
			return ClientOptions{Address: ts.URL, Username: "agent", Password: "secret", Roots: roots, RetryDelay: 10 * time.Millisecond, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			})}
		})
	}()
	deadline := time.Now().Add(time.Second)
	for {
		attempt, cancelAttempt := context.WithTimeout(context.Background(), 100*time.Millisecond)
		c, err := s.Dial(attempt, "agent", "example.com:80")
		if err == nil {
			c.Close()
			cancelAttempt()
			break
		}
		cancelAttempt()
		if time.Now().After(deadline) {
			t.Fatalf("replacement delayed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.Remove("agent")
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("agent did not exit")
	}
}

func TestDialCancelsStalledConnect(t *testing.T) {
	s := NewServer(nil, time.Second)
	client, server := net.Pipe()
	c := newCarrier(client, client)
	done := make(chan struct{})
	requestDone := make(chan struct{})
	go func() {
		(&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done(); close(requestDone) })})
		close(done)
	}()
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cc.Close(); c.Close(); <-done }()
	s.sessions["agent"] = &session{cc: cc, conn: c, done: done}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := s.Dial(ctx, "agent", "example.com:80"); err == nil {
		t.Fatal("expected cancellation")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("agent request was not canceled")
	}
}

func TestCarrierCloseUnblocksFlowControlledWrite(t *testing.T) {
	started := make(chan struct{})
	closed := make(chan struct{})
	writeDone := make(chan struct{})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		c := newCarrier(r.Body, flushWriter{w, w.(http.Flusher)})
		go func() { close(started); _, _ = c.Write(make([]byte, 32<<20)); close(writeDone) }()
		<-started
		select {
		case <-writeDone:
			t.Error("large write did not block")
		case <-time.After(100 * time.Millisecond):
		}
		c.Close()
		close(closed)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	client := &http.Client{Transport: &http2.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	resp, err := client.Post(ts.URL, "application/octet-stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("close blocked on flow-controlled write")
	}
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("write did not stop")
	}
}

func TestRemoveDoesNotWaitForUnresponsiveAgent(t *testing.T) {
	s := NewServer(nil, time.Second)
	client, server := net.Pipe()
	c := newCarrier(client, client)
	done := make(chan struct{})
	go func() {
		(&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })})
		close(done)
	}()
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(c)
	if err != nil {
		t.Fatal(err)
	}
	s.sessions["agent"] = &session{cc: cc, conn: c, done: done}
	removed := make(chan struct{})
	go func() { s.Remove("agent"); close(removed) }()
	select {
	case <-removed:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("Remove waited for unresponsive agent")
	}
	if _, err := s.Dial(context.Background(), "agent", "example.com:80"); err == nil {
		t.Fatal("removed agent is still registered")
	}
	s.Close()
}

type gatedWriter struct {
	http.ResponseWriter
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *gatedWriter) Flush() {
	w.once.Do(func() { close(w.reached); <-w.release })
	w.ResponseWriter.(http.Flusher).Flush()
}
func (w *gatedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestRegistrationRechecksAuthenticationAfterSetup(t *testing.T) {
	var allowed atomic.Bool
	allowed.Store(true)
	s := NewServer(func(u, p string) (string, bool) { return u, allowed.Load() && p == "secret" }, time.Second)
	defer s.Close()
	reached, release := make(chan struct{}), make(chan struct{})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Handler().ServeHTTP(&gatedWriter{ResponseWriter: w, reached: reached, release: release}, r)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, func() ClientOptions {
			return ClientOptions{Address: ts.URL, Username: "agent", Password: "secret", Roots: roots, RetryDelay: time.Second}
		})
	}()
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("registration did not start")
	}
	allowed.Store(false)
	removed := make(chan struct{})
	go func() { s.Remove("agent"); close(removed) }()
	select {
	case <-removed:
	case <-time.After(time.Second):
		t.Fatal("registration blocked removal")
	}
	close(release)
	time.Sleep(100 * time.Millisecond)
	if _, err := s.Dial(context.Background(), "agent", "example.com:80"); err == nil {
		t.Fatal("revoked registration installed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client did not stop")
	}
}
