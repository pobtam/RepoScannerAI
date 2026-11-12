package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTheBridgeListensOnLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "192.168.1.10:0", "localhost:0", "host.docker.internal:0", "[::]:0", "nonsense"} {
		if ln, err := listenLoopback(addr); err == nil {
			ln.Close()
			t.Errorf("%s was accepted", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		ln, err := listenLoopback(addr)
		if err != nil {
			if strings.Contains(addr, "::1") {
				continue // no IPv6 loopback here
			}
			t.Fatalf("%s: %v", addr, err)
		}
		ln.Close()
	}
}

// bridge starts a bridge in front of target and returns its address.
func bridge(t *testing.T, dial func(context.Context) (net.Conn, error)) string {
	t.Helper()
	ln, err := listenLoopback("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, dial) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return ln.Addr().String()
}

func TestTheBridgeCarriesHTTPBothWays(t *testing.T) {
	var gotAuth, gotBody string
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","path":"`+r.URL.Path+`"}`)
	}))
	defer svc.Close()
	target := strings.TrimPrefix(svc.URL, "http://")
	addr := bridge(t, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", target)
	})

	// Several requests on one keep-alive connection, and a body large
	// enough to need more than one read.
	big := strings.Repeat("x", 1<<20)
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/scans", strings.NewReader(big))
		req.Header.Set("Authorization", "Bearer test-only")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(b) != `{"status":"ok","path":"/v1/scans"}` {
			t.Fatalf("answer %d %s", resp.StatusCode, b)
		}
		if gotAuth != "Bearer test-only" || len(gotBody) != len(big) {
			t.Fatalf("the service saw auth %q and %d bytes", gotAuth, len(gotBody))
		}
	}
}

func TestATargetThatIsDownIsAClosedConnection(t *testing.T) {
	addr := bridge(t, func(context.Context) (net.Conn, error) { return nil, errors.New("connection refused") })
	c := &http.Client{Timeout: 5 * time.Second}
	if _, err := c.Get("http://" + addr + "/v1/readyz"); err == nil {
		t.Fatal("a request through a bridge to nothing succeeded")
	}
}
