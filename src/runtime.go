package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"http-proxy/internal/proxy"
)

type runtimeServer struct {
	current     atomic.Pointer[proxy.Config]
	configPath  string
	listener    net.Listener
	control     net.Listener
	controlPath string
	lock        *os.File
	http        *http.Server
	reloadMu    sync.Mutex
}

type controlRequest struct {
	Action string `json:"action"`
}

type controlResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func normalizeBindPort(bind string, port int) (string, int, string, error) {
	if bind == "" {
		return "", 0, "", errors.New("bind host must not be empty")
	}
	if port < 1 || port > 65535 {
		return "", 0, "", fmt.Errorf("invalid listen port %d", port)
	}
	if bind != "all" {
		if ip := net.ParseIP(bind); ip != nil {
			bind = ip.String()
		}
	}
	key := net.JoinHostPort(bind, strconv.Itoa(port))
	return bind, port, key, nil
}

func runtimeDir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "http-proxy")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("http-proxy-%d", os.Getuid()))
}

func controlPaths(address string) (string, string) {
	sum := sha256.Sum256([]byte(address))
	name := hex.EncodeToString(sum[:8])
	dir := runtimeDir()
	return filepath.Join(dir, name+".sock"), filepath.Join(dir, name+".lock")
}

func prepareRuntimeDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create runtime directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime path is not a directory: %s", dir)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("runtime directory is not owned by current user: %s", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure runtime directory: %w", err)
	}
	return nil
}

func acquireLock(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open instance lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("instance is already running: %w", err)
	}
	return file, nil
}

func newRuntime(bind string, port int, configPath string) (_ *runtimeServer, err error) {
	bind, port, key, err := normalizeBindPort(bind, port)
	if err != nil {
		return nil, err
	}
	configPath, err = filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	socket, lockPath := controlPaths(key)
	if err := prepareRuntimeDir(filepath.Dir(socket)); err != nil {
		return nil, err
	}
	lock, err := acquireLock(lockPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			lock.Close()
		}
	}()
	if bind == "all" {
		bind = ""
	}
	address := net.JoinHostPort(bind, strconv.Itoa(port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", address, err)
	}
	defer func() {
		if err != nil {
			listener.Close()
		}
	}()
	// The instance lock guarantees that no live instance owns this socket.
	if err = os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale control socket: %w", err)
	}
	control, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen on control socket: %w", err)
	}
	defer func() {
		if err != nil {
			control.Close()
		}
	}()
	if err = os.Chmod(socket, 0o600); err != nil {
		return nil, fmt.Errorf("secure control socket: %w", err)
	}
	r := &runtimeServer{configPath: configPath, listener: listener, control: control, controlPath: socket, lock: lock}
	r.current.Store(cfg)
	r.http = &http.Server{Handler: proxy.NewProxyHandler(&r.current), ReadHeaderTimeout: 10 * time.Second}
	if cfg.Certificate != nil {
		r.http.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return r.current.Load().Certificate, nil
			},
		}
	}
	r.warnInsecure(cfg)
	return r, nil
}

func (r *runtimeServer) warnInsecure(cfg *proxy.Config) {
	if cfg.Auth != nil && cfg.Certificate == nil {
		log.Print("warning: proxy authentication is enabled on a plain HTTP listener")
	}
}

func (r *runtimeServer) reload() error {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()
	cfg, err := loadConfig(r.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if (r.current.Load().Certificate == nil) != (cfg.Certificate == nil) {
		return errors.New("changing listener between HTTP and HTTPS requires a restart")
	}
	r.current.Store(cfg)
	r.warnInsecure(cfg)
	return nil
}

func (r *runtimeServer) serveControl() {
	for {
		conn, err := r.control.Accept()
		if err != nil {
			return
		}
		go r.handleControl(conn)
	}
}

func (r *runtimeServer) handleControl(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var request controlRequest
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(controlResponse{Error: "invalid control request"})
		return
	}
	if request.Action != "reload" {
		_ = json.NewEncoder(conn).Encode(controlResponse{Error: "unknown control action"})
		return
	}
	if err := r.reload(); err != nil {
		_ = json.NewEncoder(conn).Encode(controlResponse{Error: err.Error()})
		return
	}
	_ = json.NewEncoder(conn).Encode(controlResponse{OK: true})
}

func sendReload(bind string, port int) error {
	_, _, key, err := normalizeBindPort(bind, port)
	if err != nil {
		return err
	}
	socket, _ := controlPaths(key)
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect control socket: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(controlRequest{Action: "reload"}); err != nil {
		return err
	}
	var response controlResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return err
	}
	if !response.OK {
		return errors.New(response.Error)
	}
	return nil
}

func (r *runtimeServer) run(ctx context.Context) error {
	defer r.lock.Close()
	defer r.control.Close()
	defer r.listener.Close()
	go r.serveControl()
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = r.http.Close()
		case <-stopped:
		}
	}()
	var err error
	if r.current.Load().Certificate != nil {
		err = r.http.ServeTLS(r.listener, "", "")
	} else {
		err = r.http.Serve(r.listener)
	}
	close(stopped)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
