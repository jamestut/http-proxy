package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
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

func main() {
	if err := command(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}

func command(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agent run -c <path> | reload -c <path> | version")
	}
	switch args[0] {
	case "run", "reload":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		var path string
		flags.StringVar(&path, "c", "", "path to JSON configuration")
		flags.StringVar(&path, "config", "", "path to JSON configuration")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if path == "" || flags.NArg() != 0 {
			return fmt.Errorf("%s requires --config and no positional arguments", args[0])
		}
		path, err := filepath.Abs(path)
		if err != nil {
			return err
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
	case "version":
		if len(args) != 1 {
			return errors.New("version does not accept arguments")
		}
		revision, commitDate, modified, goVersion := "unknown", "unknown", "unknown", "unknown"
		if info, ok := debug.ReadBuildInfo(); ok {
			goVersion = info.GoVersion
			for _, setting := range info.Settings {
				switch setting.Key {
				case "vcs.revision":
					revision = setting.Value
				case "vcs.time":
					commitDate = setting.Value
				case "vcs.modified":
					modified = setting.Value
				}
			}
		}
		fmt.Printf("version: %s\nbuild date: %s\ncommit: %s\ncommit date: %s\nmodified: %s\ngo version: %s\n", commit, date, revision, commitDate, modified, goVersion)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

type runtimeAgent struct {
	path    string
	current atomic.Pointer[proxy.Config]
	options atomic.Pointer[reverse.ClientOptions]
	mu      sync.Mutex
	control net.Listener
	socket  string
	lock    *os.File
}

type response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func controlPaths(path string) (string, string) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), fmt.Sprintf("http-proxy-%d", os.Getuid()))
	} else {
		dir = filepath.Join(dir, "http-proxy")
	}
	hash := sha256.Sum256([]byte("agent:" + path))
	name := hex.EncodeToString(hash[:8])
	return filepath.Join(dir, name+".sock"), filepath.Join(dir, name+".lock")
}

func newRuntime(path string) (_ *runtimeAgent, err error) {
	cfg, err := loadConfig(path)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	socket, lockPath := controlPaths(path)
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || stat.Uid != uint32(os.Getuid()) {
		return nil, fmt.Errorf("invalid runtime directory: %s", dir)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open instance lock: %w", err)
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	defer func() {
		if err != nil {
			lock.Close()
		}
	}()
	if err = lock.Chmod(0600); err != nil {
		return nil, err
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, fmt.Errorf("instance is already running: %w", err)
	}
	if err = os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
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
	if err = os.Chmod(socket, 0600); err != nil {
		return nil, err
	}
	r := &runtimeAgent{path: path, control: control, socket: socket, lock: lock}
	r.current.Store(cfg.proxy)
	cfg.options.Handler = proxy.NewProxyHandler(&r.current)
	r.options.Store(&cfg.options)
	return r, nil
}

func (r *runtimeAgent) reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg, err := loadConfig(r.path)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg.options.Handler = r.options.Load().Handler
	r.current.Store(cfg.proxy)
	r.options.Store(&cfg.options)
	return nil
}

func (r *runtimeAgent) serveControl() {
	for {
		conn, err := r.control.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			var request struct {
				Action string `json:"action"`
			}
			if err := json.NewDecoder(conn).Decode(&request); err != nil || request.Action != "reload" {
				_ = json.NewEncoder(conn).Encode(response{Error: "invalid control request"})
				return
			}
			if err := r.reload(); err != nil {
				_ = json.NewEncoder(conn).Encode(response{Error: err.Error()})
				return
			}
			_ = json.NewEncoder(conn).Encode(response{OK: true})
		}()
	}
}

func sendReload(path string) error {
	socket, _ := controlPaths(path)
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect control socket: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(struct {
		Action string `json:"action"`
	}{Action: "reload"}); err != nil {
		return err
	}
	var result response
	if err := json.NewDecoder(conn).Decode(&result); err != nil {
		return err
	}
	if !result.OK {
		return errors.New(result.Error)
	}
	return nil
}

func (r *runtimeAgent) run(ctx context.Context) error {
	defer r.lock.Close()
	defer r.control.Close()
	defer os.Remove(r.socket)
	go r.serveControl()
	err := reverse.Run(ctx, func() reverse.ClientOptions { return *r.options.Load() })
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return err
}
