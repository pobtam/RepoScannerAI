// Command vfmcp is a read-only Claude connector for vulnframework: an MCP
// server over stdio that answers questions about findings, repositories, runs,
// coverage and NuGuard from vulnframework's own HTTP API (VM-F-1101..1108).
//
// It reads through the API only, with GET only, and sees exactly what the
// identity the API grants it may see. It cannot request scans, change
// settings, or change any finding, approval or record.
//
//	vfmcp -api-url http://127.0.0.1:5173 -ui-url http://127.0.0.1:5173
//
// Standard output carries the protocol and nothing else; diagnostics go to
// standard error.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const version = "0.1.0"

// defaultURL is the interface's development server, which run.sh starts in
// both the demonstration and real mode. In real mode the API's own port
// refuses anonymous callers, and the development server is what vouches for
// the local user (REAL-REPOS.md §7), so this is the address that works in
// both.
const defaultURL = "http://127.0.0.1:5173"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "vfmcp:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		apiURL  = flag.String("api-url", defaultURL, "vulnframework API to read (through the interface's development server in real mode)")
		uiURL   = flag.String("ui-url", "", "interface address used in links (default: -api-url)")
		timeout = flag.Duration("timeout", 15*time.Second, "time allowed for each API call")
		showVer = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println("vfmcp", version)
		return nil
	}
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected arguments %v", flag.Args())
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	c, err := NewClient(*apiURL, *timeout, nil)
	if err != nil {
		return err
	}
	ui := strings.TrimRight(*uiURL, "/")
	if ui == "" {
		ui = c.base.String()
	}
	tools := &Tools{c: c, ui: ui}
	srv := NewServer(tools.All(), log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("vfmcp serving on stdio (read-only)", "version", version, "api", c.base.String(), "ui", ui)
	// Serve blocks reading standard input, so a signal is waited for beside
	// it: the client stops a server with SIGINT or SIGTERM and expects it to
	// go, not to linger until the next line arrives.
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, os.Stdin, os.Stdout) }()
	select {
	case err := <-done:
		if err != nil && ctx.Err() == nil {
			return err
		}
	case <-ctx.Done():
	}
	return nil
}
