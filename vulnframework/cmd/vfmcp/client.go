package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The connector's only way out: vulnframework's own HTTP API, read-only.
//
// Read-only is enforced twice, and neither depends on a tool being written
// carefully (VM-F-1101, VM-F-1102):
//
//   - the transport refuses every method but GET and HEAD before anything
//     reaches the network, as gh.TokenClient does for GitHub;
//   - the client refuses every path that is not in the route inventory
//     (routes.go), so a tool cannot reach a write endpoint even with GET.
//
// It carries no credential. In local real mode the interface's development
// server vouches for the caller (REAL-REPOS.md §7), and the connector inherits
// exactly that identity; in the demonstration the API grants its one fixed
// identity. Either way the API decides what is visible, never the connector
// (VM-F-1103), and the connector never sets an identity header itself.

// ErrWriteRefused is returned for any method other than GET or HEAD.
var ErrWriteRefused = errors.New("vfmcp: refused: the connector is read-only and sends GET and HEAD only")

// readOnlyTransport refuses writes before they reach the network.
type readOnlyTransport struct{ next http.RoundTripper }

func (t readOnlyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return nil, ErrWriteRefused
	}
	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(r)
}

// identityHeaders are the names the API's HeaderAuth reads (cmd/apiserver
// -user-header and friends). The connector never sends them: asserting an
// identity is the authenticating proxy's job, and a connector that set them
// would be impersonating whoever it named.
var identityHeaders = []string{"X-Auth-User", "X-Auth-Level", "X-Auth-Repos"}

// Client reads the API.
type Client struct {
	base    *url.URL
	http    *http.Client
	timeout time.Duration
	// flagName is the flag that set base, named in every connection error so
	// the person reading it knows what to change.
	flagName string
}

// NewClient builds a client for the API at rawURL.
//
// Plain http is accepted only to a loopback host: finding data in clear text
// across a network is a disclosure, like the NuGuard client's rule.
func NewClient(rawURL string, timeout time.Duration, next http.RoundTripper) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(rawURL, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("-api-url %q does not parse as a URL (for example http://127.0.0.1:5173)", rawURL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("-api-url %s: plain http is refused to a host that is not this machine; "+
				"use https, or the local address", rawURL)
		}
	default:
		return nil, fmt.Errorf("-api-url %s: the scheme must be http or https", rawURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("-api-url must not carry credentials; the connector sends none")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		base:     u,
		timeout:  timeout,
		flagName: "-api-url",
		http: &http.Client{
			Transport: readOnlyTransport{next: next},
			// A redirect could lead off the inventory or off this machine; the
			// API never redirects a read, so one is an error.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("vfmcp: the API answered with a redirect, which a read never needs; refusing to follow it")
			},
		},
	}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// APIError is the API's own refusal, carried to Claude in its words.
type APIError struct {
	Status int
	Path   string
	Err    string `json:"error"`
	Detail string `json:"detail"`
	Remedy string `json:"remedy"`
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "the vulnframework API answered %d for %s", e.Status, e.Path)
	if e.Err != "" {
		fmt.Fprintf(&b, ": %s", e.Err)
	}
	if e.Detail != "" {
		fmt.Fprintf(&b, " (%s)", e.Detail)
	}
	if e.Remedy != "" {
		fmt.Fprintf(&b, ". Remedy: %s", e.Remedy)
	}
	return b.String()
}

// Get reads path (with query) into out. Path must match the route inventory.
func (c *Client) Get(ctx context.Context, path string, query url.Values, out any) error {
	if _, ok := matchRoute(path); !ok {
		return fmt.Errorf("vfmcp: refused: %s is not in the connector's route inventory of reads", path)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	u := *c.base
	u.Path = c.base.Path + path
	u.RawPath = c.base.Path + escapePath(path)
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vfmcp/"+version)
	for _, h := range identityHeaders {
		req.Header.Del(h)
	}

	res, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrWriteRefused) {
			return err
		}
		if ctx.Err() != nil {
			return fmt.Errorf("the vulnframework API at %s (%s) did not answer within %s. Check that it is "+
				"running (./run.sh or ./run.sh --real), or raise -timeout", c.base, c.flagName, c.timeout)
		}
		return fmt.Errorf("cannot reach the vulnframework API at %s (%s): %v. Start it with ./run.sh "+
			"(demonstration) or ./run.sh --real, or correct %s", c.base, c.flagName, scrub(err), c.flagName)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("reading the API's answer for %s: %v", path, err)
	}
	if res.StatusCode != http.StatusOK {
		e := &APIError{Status: res.StatusCode, Path: path}
		_ = json.Unmarshal(body, e)
		if res.StatusCode == http.StatusUnauthorized {
			e.Remedy = strings.TrimSpace(e.Remedy + " The connector sends no credential. In real mode the API " +
				"serves only callers vouched for by the interface's development server, so point " + c.flagName +
				" at it (http://127.0.0.1:5173, started by ./run.sh --real), not at the API's own port.")
		}
		return e
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("the API's answer for %s is not the JSON expected: %v", path, err)
	}
	return nil
}

// escapePath escapes each segment of a path built from identifiers, so a
// repository name cannot add segments or a query.
func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// scrub keeps a transport error's cause and drops any URL userinfo it might
// quote. The connector holds no credential, but an error message is the
// usual way one leaks, so the rule is applied anyway.
func scrub(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}
