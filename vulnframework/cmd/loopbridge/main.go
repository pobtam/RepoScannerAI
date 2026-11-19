// Command loopbridge forwards one loopback port inside the scan container to
// the same service on the Mac, for run.sh --real --nuguard.
//
//	loopbridge -listen 127.0.0.1:8090 -to host.docker.internal:8090 -ready /tmp/loopbridge.ready
//
// NuGuard runs on the Mac, bound to the Mac's loopback. The NuGuard client
// allows plain http only to a loopback host, because the API key crosses the
// connection; from inside the container the Mac is host.docker.internal,
// which is not loopback. This bridge lets the client keep talking to
// http://127.0.0.1:<port>, its rule unchanged, and carries the bytes over
// Docker Desktop's own host connection. It listens on loopback only, so
// nothing outside the container can use it, and it reads nothing it carries.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "", "loopback address to listen on, such as 127.0.0.1:8090")
	to := flag.String("to", "", "address to forward to, such as host.docker.internal:8090")
	ready := flag.String("ready", "", "file created once listening, for a starter to wait on")
	flag.Parse()

	ln, err := listenLoopback(*listen)
	if err != nil {
		log.Fatalf("loopbridge: %v", err)
	}
	if *to == "" {
		log.Fatal("loopbridge: -to is required")
	}
	if *ready != "" {
		if err := os.WriteFile(*ready, nil, 0o600); err != nil {
			log.Fatalf("loopbridge: %v", err)
		}
	}
	log.Printf("loopbridge: %s -> %s", ln.Addr(), *to)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if err := serve(ctx, ln, func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", *to)
	}); err != nil {
		log.Fatalf("loopbridge: %v", err)
	}
}

// listenLoopback listens on addr, which must be a loopback IP: the bridge is
// for the container's own processes only.
func listenLoopback(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("-listen %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("-listen %q: only a loopback IP address is allowed", addr)
	}
	return net.Listen("tcp", addr)
}

// serve accepts until ctx ends, joining each connection to a new one from
// dial. A connection that cannot be dialled is closed: the client then sees
// the service as unreachable, which it already reports as a coverage gap.
func serve(ctx context.Context, ln net.Listener, dial func(context.Context) (net.Conn, error)) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			up, err := dial(ctx)
			if err != nil {
				log.Printf("loopbridge: %v", err)
				return
			}
			defer up.Close()
			join(c, up)
		}()
	}
}

// join copies both ways until either side is done, passing a half-close on
// so a request that ends its body still gets its answer.
func join(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
}
