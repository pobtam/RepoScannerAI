package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/store"
)

var qAt = time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)

func req(id, repo, batch string, at time.Time) store.ScanRequest {
	return store.ScanRequest{ID: id, Repo: repo, BatchID: batch, Source: store.SourceWeb,
		RequestedBy: "pat", RequestedAt: at, Status: store.ScanQueued}
}

func TestScanQueueOnEveryBackend(t *testing.T) {
	ctx := context.Background()
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			s := b.open(t)

			// Queueing.
			got, merged, err := s.EnqueueScan(ctx, req("sr_1", "octo/api", "", qAt))
			if err != nil || merged || got.Status != store.ScanQueued {
				t.Fatalf("first enqueue: %+v merged=%v err=%v", got, merged, err)
			}

			// A second request for the same repository merges into the first.
			got, merged, err = s.EnqueueScan(ctx, req("sr_2", "octo/api", "", qAt.Add(time.Second)))
			if err != nil || !merged || got.ID != "sr_1" {
				t.Fatalf("duplicate enqueue: %+v merged=%v err=%v; want sr_1 merged", got, merged, err)
			}
			if _, ok, _ := s.GetScanRequest(ctx, "sr_2"); ok {
				t.Error("the merged request was stored as a second row")
			}

			// A refused request is an audit row; it never takes the slot.
			refused := req("sr_r", "octo/api", "", qAt.Add(2*time.Second))
			refused.Status, refused.Reason = store.ScanRefused, "excluded by a person"
			if _, merged, err := s.EnqueueScan(ctx, refused); err != nil || merged {
				t.Fatalf("refused audit row: merged=%v err=%v", merged, err)
			}
			bad := refused
			bad.ID, bad.Reason = "sr_bad", ""
			if _, _, err := s.EnqueueScan(ctx, bad); err == nil {
				t.Error("a refused request without a reason was accepted")
			}

			// A batch is claimed together; an unrelated request waits.
			for _, r := range []store.ScanRequest{
				req("sr_b1", "octo/web", "b1", qAt.Add(3*time.Second)),
				req("sr_b2", "octo/cli", "b1", qAt.Add(3*time.Second)),
				req("sr_x", "octo/docs", "", qAt.Add(4*time.Second)),
			} {
				if _, _, err := s.EnqueueScan(ctx, r); err != nil {
					t.Fatal(err)
				}
			}

			claimed, ok, err := s.ClaimScans(ctx, "w1", qAt.Add(time.Minute))
			if err != nil || !ok || len(claimed) != 1 || claimed[0].ID != "sr_1" {
				t.Fatalf("first claim: %+v ok=%v err=%v; want sr_1 alone (oldest)", claimed, ok, err)
			}
			if claimed[0].Status != store.ScanRunning || claimed[0].WorkerID != "w1" || claimed[0].StartedAt == nil {
				t.Errorf("claimed request: %+v", claimed[0])
			}
			claimed, _, _ = s.ClaimScans(ctx, "w1", qAt.Add(2*time.Minute))
			if len(claimed) != 2 || claimed[0].BatchID != "b1" || claimed[1].BatchID != "b1" {
				t.Fatalf("batch claim: %+v; want both b1 requests together", claimed)
			}

			// While a repository's request runs, a new one still merges.
			if got, merged, _ := s.EnqueueScan(ctx, req("sr_3", "octo/api", "", qAt.Add(3*time.Minute))); !merged || got.ID != "sr_1" {
				t.Errorf("enqueue while running: %+v merged=%v; want merged into sr_1", got, merged)
			}

			// Only the claiming worker finishes, only from running, with a
			// reason where one is due.
			if err := s.FinishScan(ctx, "sr_1", "w2", store.ScanFinished, "", "", qAt); !errors.Is(err, store.ErrScanNotRunning) {
				t.Errorf("another worker finished sr_1: %v", err)
			}
			if err := s.FinishScan(ctx, "sr_1", "w1", store.ScanTimedOut, "", "", qAt); err == nil {
				t.Error("a timed-out scan without a reason was accepted")
			}
			if err := s.FinishScan(ctx, "sr_1", "w1", store.ScanTimedOut, "exceeded the 15m0s limit", "", qAt.Add(4*time.Minute)); err != nil {
				t.Fatal(err)
			}
			if err := s.FinishScan(ctx, "sr_1", "w1", store.ScanFinished, "", "", qAt); !errors.Is(err, store.ErrScanNotRunning) {
				t.Errorf("a finished request was finished again: %v", err)
			}

			// Its slot is free again: a new request for the repository queues.
			if got, merged, _ := s.EnqueueScan(ctx, req("sr_4", "octo/api", "", qAt.Add(5*time.Minute))); merged || got.ID != "sr_4" {
				t.Errorf("enqueue after finish: %+v merged=%v; want a new request", got, merged)
			}

			// Interruption: a stale heartbeat is marked interrupted, with a
			// reason, and frees the slot for a retry.
			if err := s.HeartbeatScans(ctx, "w1", []string{"sr_b1"}, qAt.Add(10*time.Minute)); err != nil {
				t.Fatal(err)
			}
			n, err := s.InterruptStaleScans(ctx, qAt.Add(5*time.Minute), "worker restarted during the scan", qAt.Add(11*time.Minute))
			if err != nil || n != 1 {
				t.Fatalf("interrupt stale: n=%d err=%v; want only sr_b2 (sr_b1 had a fresh heartbeat)", n, err)
			}
			b2, _, _ := s.GetScanRequest(ctx, "sr_b2")
			if b2.Status != store.ScanInterrupted || b2.Reason == "" || b2.FinishedAt == nil {
				t.Errorf("interrupted request: %+v", b2)
			}
			n, _ = s.InterruptWorkerScans(ctx, "w1", "worker stopped", qAt.Add(12*time.Minute))
			if n != 1 {
				t.Errorf("interrupt worker: n=%d, want 1 (sr_b1)", n)
			}
			retry := req("sr_5", "octo/cli", "", qAt.Add(13*time.Minute))
			retry.RetryOf = "sr_b2"
			if got, merged, err := s.EnqueueScan(ctx, retry); err != nil || merged || got.RetryOf != "sr_b2" {
				t.Errorf("retry of an interrupted request: %+v merged=%v err=%v", got, merged, err)
			}

			// Listing, newest first; and the rate-limit count.
			list, _ := s.ScanRequests(ctx, store.ScanQuery{Repo: "octo/api"})
			if len(list) != 3 || list[0].ID != "sr_4" {
				t.Errorf("octo/api requests: %d, first %s; want sr_4, sr_r, sr_1", len(list), firstID(list))
			}
			if n, _ := s.CountScanRequests(ctx, "pat", qAt.Add(4*time.Minute)); n != 2 {
				t.Errorf("requests by pat since +4m: %d, want 2 (sr_4, sr_5)", n)
			}

			// Nothing left queued but sr_x, sr_4 and sr_5.
			left := 0
			for {
				c, ok, _ := s.ClaimScans(ctx, "w9", qAt.Add(time.Hour))
				if !ok {
					break
				}
				left += len(c)
			}
			if left != 3 {
				t.Errorf("claimed %d remaining requests, want 3", left)
			}
		})
	}
}

func firstID(l []store.ScanRequest) string {
	if len(l) == 0 {
		return "(none)"
	}
	return l[0].ID
}

// A repository's scan results are most recent first by when the run started,
// across run kinds. Ordering by run_id compared identifiers as text, so a
// sweep run (S-...) sorted above a later manual run (M-...).
func TestScanResultsAreNewestFirstAcrossRunKinds(t *testing.T) {
	ctx := context.Background()
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			s := b.open(t)
			if err := s.UpsertRepo(ctx, store.Repo{Name: "octo/api", Tier: 2}); err != nil {
				t.Fatal(err)
			}
			sweep, err := s.CreateRun(ctx, store.KindSweep, "timer", "img", nil)
			if err != nil {
				t.Fatal(err)
			}
			manual, err := s.CreateRun(ctx, store.KindManual, "scan request", "img", nil)
			if err != nil {
				t.Fatal(err)
			}
			if !manual.StartedAt.After(sweep.StartedAt) {
				t.Fatalf("test setup: manual run %v does not start after sweep run %v", manual.StartedAt, sweep.StartedAt)
			}
			for _, run := range []store.Run{sweep, manual} {
				if err := s.RecordScanResult(ctx, store.RepoScanResult{RunID: run.ID, Repo: "octo/api", Outcome: "complete"}); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.ScanResults(ctx, "octo/api", 1)
			if err != nil || len(got) != 1 {
				t.Fatalf("ScanResults: %v %v", got, err)
			}
			if got[0].RunID != manual.ID {
				t.Errorf("most recent result is %s; want the later manual run %s", got[0].RunID, manual.ID)
			}
		})
	}
}
