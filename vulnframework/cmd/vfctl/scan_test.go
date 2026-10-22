package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/store"
)

func TestScanCommandsQueueMergeAndRefuse(t *testing.T) {
	st := migrated(t)
	ctx := context.Background()
	prevUser, prevNow := currentUser, now
	currentUser = func() string { return "pat" }
	now = func() time.Time { return time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { currentUser, now = prevUser, prevNow })

	for _, r := range []store.Repo{{Name: "octo/api", Tier: 2}, {Name: "octo/web", Tier: 3}, {Name: "octo/old", Tier: 3, Archived: true}} {
		if err := st.UpsertRepo(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetExclusion(ctx, store.RepoExclusion{Name: "octo/old", Reason: "a vendored mirror", ExcludedBy: "pat", ExcludedAt: now()}); err != nil {
		t.Fatal(err)
	}

	if out := mustExec(t, st, "scan", "request", "octo/api"); !strings.Contains(out, "queued sr_") {
		t.Errorf("request: %s", out)
	}
	if out := mustExec(t, st, "scan", "request", "octo/api"); !strings.Contains(out, "not queued twice") {
		t.Errorf("duplicate: %s", out)
	}
	if _, err := exec(t, st, "scan", "request", "octo/old"); err == nil || !strings.Contains(err.Error(), "a vendored mirror") {
		t.Errorf("excluded: %v", err)
	}
	out := mustExec(t, st, "scan", "enqueue", "-all", "-source", "timer")
	if !strings.Contains(out, "1 queued, 1 already queued or running") {
		t.Errorf("enqueue -all: %s", out)
	}
	list := mustExec(t, st, "scan", "list")
	for _, want := range []string{"octo/api", "octo/web", "refused", "a vendored mirror", "timer"} {
		if !strings.Contains(list, want) {
			t.Errorf("list lacks %q:\n%s", want, list)
		}
	}
	rows, _ := st.ScanRequests(ctx, store.ScanQuery{Repo: "octo/web"})
	if len(rows) != 1 || rows[0].Source != store.SourceTimer || rows[0].BatchID == "" || rows[0].RequestedBy != "timer" {
		t.Errorf("the timer's request: %+v", rows)
	}
}
