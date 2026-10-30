package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
)

const (
	defaultBind = "127.0.0.1"
	defaultPort = 8080
)

var (
	commit = "dev"
	date   = "unknown"
)

func main() {
	if err := command(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "http-proxy:", err)
		os.Exit(1)
	}
}

func command(args []string) error {
	if len(args) == 0 {
		usage := fmt.Sprintf(`Usage:
  http-proxy run -c <path> [-b <host>] [-p <port>]
  http-proxy reload [-b <host>] [-p <port>]
  http-proxy version

Options:
  -c, --config <path>  JSON configuration file (required by run)
  -b, --bind <host>    TCP bind host, or "all" to listen on all interfaces
                       (default: %s)
  -p, --port <port>    TCP listen port (default: %d)

Examples:
  http-proxy run -c config.json -b all
  http-proxy reload -b all`, defaultBind, defaultPort)
		return errors.New(usage)
	}
	switch args[0] {
	case "run":
		flags := flag.NewFlagSet("run", flag.ContinueOnError)
		var bind string
		var port int
		var config string
		flags.StringVar(&bind, "bind", defaultBind, "TCP bind host or all")
		flags.StringVar(&bind, "b", defaultBind, "TCP bind host or all")
		flags.IntVar(&port, "port", defaultPort, "TCP listen port")
		flags.IntVar(&port, "p", defaultPort, "TCP listen port")
		flags.StringVar(&config, "config", "", "path to JSON configuration")
		flags.StringVar(&config, "c", "", "path to JSON configuration")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || config == "" {
			return errors.New("run requires --config and no positional arguments")
		}
		server, err := newRuntime(bind, port, config)
		if err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return server.run(ctx)
	case "reload":
		flags := flag.NewFlagSet("reload", flag.ContinueOnError)
		var bind string
		var port int
		flags.StringVar(&bind, "bind", defaultBind, "TCP bind host or all")
		flags.StringVar(&bind, "b", defaultBind, "TCP bind host or all")
		flags.IntVar(&port, "port", defaultPort, "TCP listen port")
		flags.IntVar(&port, "p", defaultPort, "TCP listen port")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("reload does not accept positional arguments")
		}
		if err := sendReload(bind, port); err != nil {
			return err
		}
		fmt.Println("configuration reloaded")
		return nil
	case "version":
		if len(args) != 1 {
			return errors.New("version does not accept arguments")
		}
		printVersion()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printVersion() {
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
}
