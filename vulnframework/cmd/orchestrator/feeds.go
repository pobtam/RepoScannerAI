package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// maxFeedBytes bounds a cached feed body. The feed package enforces its own
// bound when it reads; this one only stops the cache from holding more.
const maxFeedBytes = 256 << 20

// onceTransport serves each successful GET from memory after the first.
//
// The feed sources fetch their whole catalogue on every lookup, and the
// post-sweep pass looks up once per repository. Without this a twenty-repo
// sweep downloads the KEV catalogue and the EPSS snapshot twenty times each,
// and could score repositories against two different days' snapshots.
//
// Only a 200 is kept. A failure is not cached, so a feed that recovers
// mid-pass is used for the repositories after it.
type onceTransport struct {
	base http.RoundTripper

	mu    sync.Mutex
	cache map[string]cachedResponse
}

type cachedResponse struct {
	header http.Header
	body   []byte
}

func newFeedClient() *http.Client {
	return &http.Client{
		Timeout:   2 * time.Minute,
		Transport: &onceTransport{base: http.DefaultTransport, cache: map[string]cachedResponse{}},
	}
}

func (t *onceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet {
		return t.base.RoundTrip(req)
	}
	key := req.URL.String()

	// Held across the fetch: the pass is sequential, and two concurrent
	// lookups of one catalogue should share one download, not race two.
	t.mu.Lock()
	defer t.mu.Unlock()

	if c, ok := t.cache[key]; ok {
		return c.response(req), nil
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", key, err)
	}
	if len(body) > maxFeedBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", key, maxFeedBytes)
	}
	c := cachedResponse{header: resp.Header.Clone(), body: body}
	t.cache[key] = c
	return c.response(req), nil
}

func (c cachedResponse) response(req *http.Request) *http.Response {
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        c.header.Clone(),
		Body:          io.NopCloser(bytes.NewReader(c.body)),
		ContentLength: int64(len(c.body)),
		Request:       req,
	}
}
