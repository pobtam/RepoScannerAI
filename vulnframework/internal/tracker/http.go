package tracker

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/wanaware/vulnframework/internal/model"
)

// maxResponse bounds what a backend may return. A tracker that answers with a
// gigabyte must not take the orchestrator with it.
const maxResponse = 8 << 20

// do performs a request and decodes the response.
//
// The error carries the status and a bounded excerpt of the body, because the
// difference between an expired token, a missing scope and a rate limit is only
// visible there — and that difference is exactly what an operator reading a
// queued retry needs to know.
func do(client Doer, req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("tracker: %s %s: %w", req.Method, req.URL.Host+req.URL.Path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("tracker: reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("tracker: %s %s: status %d: %s",
			req.Method, req.URL.Host+req.URL.Path, resp.StatusCode, excerpt(body))
	}
	if out == nil {
		return nil
	}
	if len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("tracker: decoding response from %s: %w", req.URL.Host+req.URL.Path, err)
	}
	return nil
}

func excerpt(b []byte) string {
	const limit = 200
	if len(b) > limit {
		return string(b[:limit]) + "…"
	}
	return string(b)
}

// assertCommentSafe is the transport-level credential guard.
//
// The spec builder already checks what it composed, but a backend renders text
// of its own — closure comments, link notes, JSON envelopes — and this is the
// last point at which any of it can be stopped. Cheap, and it makes the
// invariant hold for text no spec ever saw.
func assertCommentSafe(text string) error {
	return model.AssertNoCredential("tracker request", []byte(text))
}
