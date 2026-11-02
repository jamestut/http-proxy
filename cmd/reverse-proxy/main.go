package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"http-proxy/internal/proxy"
	"http-proxy/internal/reverse"
)

var commit = "dev"
var date = "unknown"

type runtimeServer struct {
	path           string
	current        atomic.Pointer[config]
	proxyConfig    atomic.Pointer[proxy.Config]
	reverse        *reverse.Server
	clientHTTP     *http.Server
	agentHTTP      *http.Server
	clientListener net.Listener
	agentListener  net.Listener
	control        net.Listener
	lock           *os.File
	mu             sync.Mutex
}

type controlResponse struct {
	Error string `json:"error,omitempty"`
}

func controlPaths(path string) (string, string) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), fmt.Sprintf("http-proxy-%d", os.Getuid()))
	} else {
		dir = filepath.Join(dir, "http-proxy")
	}
	sum := sha256.Sum256([]byte("reverse-proxy:" + path))
	name := hex.EncodeToString(sum[:8])
	return filepath.Join(dir, name+".sock"), filepath.Join(dir, name+".lock")
}

func listenControl(path string) (net.Listener, *os.File, error) {
	socket, lockPath := controlPaths(path)
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || stat.Uid != uint32(os.Getuid()) {
		return nil, nil, errors.New("runtime directory is not a private directory owned by the current user")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, nil, err
	}
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, nil, err
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	if err := lock.Chmod(0600); err != nil {
		lock.Close()
		return nil, nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, nil, errors.New("instance is already running")
	}
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		lock.Close()
		return nil, nil, err
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		lock.Close()
		return nil, nil, err
	}
	if err := os.Chmod(socket, 0600); err != nil {
		ln.Close()
		lock.Close()
		return nil, nil, err
	}
	return ln, lock, nil
}

func newRuntime(path string) (_ *runtimeServer, err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	r := &runtimeServer{path: path}
	r.current.Store(cfg)
	r.proxyConfig.Store(cfg.proxy)
	r.control, r.lock, err = listenControl(path)
	if err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}
	defer func() {
		if err != nil {
			r.control.Close()
			r.lock.Close()
		}
	}()
	r.clientListener, err = net.Listen("tcp", cfg.clientListen)
	if err != nil {
		return nil, fmt.Errorf("client listener: %w", err)
	}
	defer func() {
		if err != nil {
			r.clientListener.Close()
		}
	}()
	r.agentListener, err = net.Listen("tcp", cfg.agentListen)
	if err != nil {
		return nil, fmt.Errorf("agent listener: %w", err)
	}
	r.reverse = reverse.NewServer(r.authenticate, cfg.shutdown)
	r.reverse.SetPing(cfg.pingIdle, cfg.pingTimeout)
	r.clientHTTP = &http.Server{Handler: proxy.NewReverseProxyHandler(&r.proxyConfig, r.reverse.Dial), ReadHeaderTimeout: 10 * time.Second}
	if cfg.proxy.Certificate != nil {
		r.clientHTTP.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return r.current.Load().proxy.Certificate, nil }}
	}
	r.agentHTTP = &http.Server{Handler: r.reverse.Handler(), ReadHeaderTimeout: 10 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return r.current.Load().certificate, nil }}}
	if cfg.proxy.Auth != nil && cfg.proxy.Certificate == nil {
		log.Print("warning: proxy authentication is enabled on a plain HTTP listener")
	}
	return r, nil
}

func (r *runtimeServer) authenticate(username, password string) (string, bool) {
	for name, up := range r.current.Load().proxy.Upstreams {
		cred := up.Auth
		if cred != nil && subtle.ConstantTimeCompare([]byte(username), []byte(cred.Username))&subtle.ConstantTimeCompare([]byte(password), []byte(cred.Password)) == 1 {
			return name, true
		}
	}
	return "", false
}

func (r *runtimeServer) reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg, err := loadConfig(r.path)
	if err != nil {
		return err
	}
	old := r.current.Load()
	if cfg.clientListen != old.clientListen || cfg.agentListen != old.agentListen {
		return errors.New("changing listener addresses requires a restart")
	}
	if (cfg.proxy.Certificate == nil) != (old.proxy.Certificate == nil) {
		return errors.New("changing the client listener between HTTP and HTTPS requires a restart")
	}
	r.current.Store(cfg)
	r.proxyConfig.Store(cfg.proxy)
	r.reverse.SetPing(cfg.pingIdle, cfg.pingTimeout)
	r.reverse.SetShutdownTimeout(cfg.shutdown)
	for name := range old.proxy.Upstreams {
		if _, ok := cfg.proxy.Upstreams[name]; !ok {
			r.reverse.Remove(name)
		}
	}
	if cfg.proxy.Auth != nil && cfg.proxy.Certificate == nil {
		log.Print("warning: proxy authentication is enabled on a plain HTTP listener")
	}
	return nil
}

func (r *runtimeServer) serveControl() {
	for {
		conn, err := r.control.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			var request struct {
				Action string `json:"action"`
			}
			if err := json.NewDecoder(conn).Decode(&request); err != nil || request.Action != "reload" {
				_ = json.NewEncoder(conn).Encode(controlResponse{Error: "invalid control request"})
				return
			}
			if err := r.reload(); err != nil {
				_ = json.NewEncoder(conn).Encode(controlResponse{Error: err.Error()})
				return
			}
			_ = json.NewEncoder(conn).Encode(controlResponse{})
		}()
	}
}

func sendReload(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	socket, _ := controlPaths(path)
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(conn).Encode(map[string]string{"action": "reload"}); err != nil {
		return err
	}
	var response controlResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return err
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	return nil
}

func (r *runtimeServer) run(ctx context.Context) error {
	defer r.lock.Close()
	defer r.control.Close()
	defer r.clientListener.Close()
	defer r.agentListener.Close()
	defer r.reverse.Close()
	go r.serveControl()
	errs := make(chan error, 2)
	go func() {
		if r.current.Load().proxy.Certificate != nil {
			errs <- r.clientHTTP.ServeTLS(r.clientListener, "", "")
		} else {
			errs <- r.clientHTTP.Serve(r.clientListener)
		}
	}()
	go func() { errs <- r.agentHTTP.ServeTLS(r.agentListener, "", "") }()
	var err error
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	_ = r.clientHTTP.Close()
	_ = r.agentHTTP.Close()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func command(args []string) error {
	if len(args) == 1 && args[0] == "version" {
		fmt.Printf("version: %s\nbuild date: %s\n", commit, date)
		if info, ok := debug.ReadBuildInfo(); ok {
			fmt.Printf("go version: %s\n", info.GoVersion)
		}
		return nil
	}
	if len(args) == 0 || (args[0] != "run" && args[0] != "reload") {
		return errors.New("usage: reverse-proxy {run|reload} --config <path> | reverse-proxy version")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	var path string
	flags.StringVar(&path, "config", "", "path to JSON configuration")
	flags.StringVar(&path, "c", "", "path to JSON configuration")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if path == "" || flags.NArg() != 0 {
		return errors.New("--config is required")
	}
	if args[0] == "reload" {
		if err := sendReload(path); err != nil {
			return err
		}
		fmt.Println("configuration reloaded")
		return nil
	}
	r, err := newRuntime(path)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return r.run(ctx)
}

func main() {
	if err := command(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "reverse-proxy:", err)
		os.Exit(1)
	}
}
