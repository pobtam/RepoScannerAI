package main

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/store"
)

func exec(t *testing.T, st store.Store, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := Exec(context.Background(), st, args, &out)
	return out.String(), err
}

func mustExec(t *testing.T, st store.Store, args ...string) string {
	t.Helper()
	out, err := exec(t, st, args...)
	if err != nil {
		t.Fatalf("vfctl %s: %v", strings.Join(args, " "), err)
	}
	return out
}

func TestRepoAddWritesEveryField(t *testing.T) {
	st := store.NewMemory()
	out := mustExec(t, st, "repo", "add", "org/web", "-languages", "JavaScript, go", "-tier", "1", "-lockfile", "-test-suite")
	if !strings.Contains(out, "added org/web") {
		t.Errorf("output %q does not report the add", out)
	}

	got, err := st.GetRepo(context.Background(), "org/web")
	if err != nil {
		t.Fatalf("GetRepo: %v", err)
	}
	want := store.Repo{
		Name: "org/web", Tier: 1, Languages: []string{"go", "javascript"},
		HasLockfile: true, HasTestSuite: true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored %+v, want %+v", got, want)
	}
}

func TestRepoAddDefaultsToTierThree(t *testing.T) {
	st := store.NewMemory()
	mustExec(t, st, "repo", "add", "org/api", "-languages", "go")
	got, _ := st.GetRepo(context.Background(), "org/api")
	if got.Tier != 3 || got.HasLockfile || got.HasTestSuite {
		t.Errorf("stored %+v; an unflagged repository is tier 3 with no lockfile and no test suite", got)
	}
}

func TestRepoAddUpdatesWithoutDiscardingFieldsItDoesNotOwn(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.UpsertRepo(ctx, store.Repo{
		Name: "org/api", Tier: 3, Languages: []string{"go"},
		Codeowners: []string{"team-api"}, ModuleTopology: "multi",
	}); err != nil {
		t.Fatal(err)
	}

	out := mustExec(t, st, "repo", "add", "org/api", "-languages", "go", "-tier", "2")
	if !strings.Contains(out, "updated org/api") {
		t.Errorf("output %q does not report an update", out)
	}
	got, _ := st.GetRepo(ctx, "org/api")
	if got.Tier != 2 {
		t.Errorf("tier = %d, want 2", got.Tier)
	}
	if !reflect.DeepEqual(got.Codeowners, []string{"team-api"}) || got.ModuleTopology != "multi" {
		t.Errorf("update discarded code owners or topology: %+v", got)
	}
}

func TestRepoAddUpdatesOnlyTheFlagsGiven(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	mustExec(t, st, "repo", "add", "org/web", "-languages", "javascript", "-tier", "1", "-test-suite")

	mustExec(t, st, "repo", "add", "org/web", "-lockfile")
	got, _ := st.GetRepo(ctx, "org/web")
	want := store.Repo{Name: "org/web", Tier: 1, Languages: []string{"javascript"}, HasLockfile: true, HasTestSuite: true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("after adding -lockfile: %+v, want %+v", got, want)
	}

	mustExec(t, st, "repo", "add", "org/web", "-test-suite=false")
	if got, _ := st.GetRepo(ctx, "org/web"); got.HasTestSuite || got.Tier != 1 || !got.HasLockfile {
		t.Errorf("-test-suite=false changed more than the test suite: %+v", got)
	}

	if _, err := exec(t, st, "repo", "add", "org/web", "-tier", "9"); err == nil {
		t.Error("an update to tier 9 succeeded")
	}
	if got, _ := st.GetRepo(ctx, "org/web"); got.Tier != 1 {
		t.Errorf("a refused update still changed the tier to %d", got.Tier)
	}
}

func TestRepoAddRefusesWhatWouldScanNothing(t *testing.T) {
	cases := map[string][]string{
		"no languages":     {"repo", "add", "org/api"},
		"unknown language": {"repo", "add", "org/api", "-languages", "python"},
		"tier zero":        {"repo", "add", "org/api", "-languages", "go", "-tier", "0"},
		"tier four":        {"repo", "add", "org/api", "-languages", "go", "-tier", "4"},
		"flag before name": {"repo", "add", "-languages", "go", "org/api"},
		"stray argument":   {"repo", "add", "org/api", "-languages", "go", "extra"},
		"spaces in name":   {"repo", "add", "org/my api", "-languages", "go"},
		"path traversal":   {"repo", "add", "../etc", "-languages", "go"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			st := store.NewMemory()
			if _, err := exec(t, st, args...); err == nil {
				t.Fatalf("vfctl %s succeeded; want a refusal", strings.Join(args, " "))
			}
			names, _ := st.RepoNames(context.Background())
			if len(names) != 0 {
				t.Errorf("a refused add still registered %v", names)
			}
		})
	}
}

func TestRepoList(t *testing.T) {
	st := store.NewMemory()
	if out := mustExec(t, st, "repo", "list"); !strings.Contains(out, "no repositories registered") {
		t.Errorf("empty list printed %q", out)
	}

	mustExec(t, st, "repo", "add", "org/web", "-languages", "javascript", "-lockfile")
	mustExec(t, st, "repo", "add", "org/api", "-languages", "go", "-tier", "1", "-test-suite")
	mustExec(t, st, "repo", "remove", "org/web")

	lines := strings.Split(strings.TrimSpace(mustExec(t, st, "repo", "list")), "\n")
	if len(lines) != 3 {
		t.Fatalf("list printed %d lines, want header + 2:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	if f := strings.Fields(lines[1]); !reflect.DeepEqual(f, []string{"org/api", "1", "go", "no", "yes", "active"}) {
		t.Errorf("org/api row = %v", f)
	}
	if f := strings.Fields(lines[2]); !reflect.DeepEqual(f, []string{"org/web", "3", "javascript", "yes", "no", "archived"}) {
		t.Errorf("org/web row = %v", f)
	}
}

func TestRepoRemoveArchivesAndAddRestores(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	mustExec(t, st, "repo", "add", "org/api", "-languages", "go")

	mustExec(t, st, "repo", "remove", "org/api")
	got, err := st.GetRepo(ctx, "org/api")
	if err != nil {
		t.Fatalf("remove deleted the record; it must archive it: %v", err)
	}
	if !got.Archived {
		t.Fatal("remove did not archive the repository")
	}
	if out := mustExec(t, st, "repo", "remove", "org/api"); !strings.Contains(out, "already archived") {
		t.Errorf("second remove printed %q", out)
	}

	if out := mustExec(t, st, "repo", "add", "org/api", "-languages", "go"); !strings.Contains(out, "restored") {
		t.Errorf("re-add printed %q, want restored", out)
	}
	if got, _ := st.GetRepo(ctx, "org/api"); got.Archived {
		t.Error("re-adding an archived repository left it archived")
	}

	if _, err := exec(t, st, "repo", "remove", "org/nope"); err == nil {
		t.Error("removing an unregistered repository succeeded")
	}
}

func TestUnknownCommandsAreRefused(t *testing.T) {
	st := store.NewMemory()
	for _, args := range [][]string{{}, {"repos"}, {"repo"}, {"repo", "delete", "x"}, {"repo", "list", "x"}} {
		if _, err := exec(t, st, args...); err == nil {
			t.Errorf("vfctl %q succeeded", args)
		}
	}
}

// TestWhatVfctlRegistersIsWhatTheSweepScans is the point of the command: the
// registry is only useful if the orchestrator plans from it and hands the
// recorded profile to the scanner. In particular the lockfile flag must reach
// the scan profile — before vfctl existed nothing on the sweep path set it,
// so npm audit never ran in a sweep.
func TestWhatVfctlRegistersIsWhatTheSweepScans(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	mustExec(t, st, "repo", "add", "org/web", "-languages", "javascript", "-tier", "2", "-lockfile", "-test-suite")
	mustExec(t, st, "repo", "add", "org/gone", "-languages", "go")
	mustExec(t, st, "repo", "remove", "org/gone")

	var fleet []store.Repo
	names, _ := st.RepoNames(ctx)
	for _, n := range names {
		r, _ := st.GetRepo(ctx, n)
		fleet = append(fleet, r)
	}

	d := orchestrator.NewFakeDispatcher()
	o := orchestrator.New(st, d, orchestrator.NewRateBudget(10), orchestrator.Config{CreditsPerScan: 1})
	if _, err := o.Sweep(ctx, store.KindSweep, "test", fleet, orchestrator.DefaultSelector); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	jobs := d.Dispatched()
	if len(jobs) != 1 {
		t.Fatalf("sweep dispatched %d jobs, want 1 (the archived repository must not be scanned)", len(jobs))
	}
	p := jobs[0].Profile
	if p.Repo != "org/web" || p.Tier != 2 || !p.HasLockfile || !p.HasTestSuite ||
		len(p.Languages) != 1 || p.Languages[0] != "javascript" {
		t.Errorf("sweep scanned with profile %+v; it must carry what vfctl registered", p)
	}
}
