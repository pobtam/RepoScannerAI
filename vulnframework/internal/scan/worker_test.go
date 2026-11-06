package scan_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
)

// plain is an adapter with none of the optional capabilities.
type plain struct {
	name   string
	runErr error
}

func (p plain) Name() string                   { return p.name }
func (p plain) Version() string                { return "1" }
func (p plain) Supports(scan.RepoProfile) bool { return true }
func (p plain) Run(context.Context, string, scan.RunOpts) (scan.RawOutput, error) {
	return scan.RawOutput{Tool: p.name}, p.runErr
}
func (p plain) Normalize(scan.RawOutput) ([]model.RawFinding, error) { return nil, nil }

// multi wraps several tools, like a remote scanning service.
type multi struct {
	plain
	ran  []string
	gaps []scan.CoverageGap
	inv  *scan.AIInventory
}

func (m multi) Run(context.Context, string, scan.RunOpts) (scan.RawOutput, error) {
	return scan.RawOutput{Tool: m.name, Versions: map[string]string{m.name + "/rules": "abc"}}, m.runErr
}
func (m multi) SubTools(scan.RawOutput) ([]string, []scan.CoverageGap, error) {
	return m.ran, m.gaps, nil
}
func (m multi) Inventory(scan.RawOutput) *scan.AIInventory { return m.inv }

func scanWith(t *testing.T, adapters ...scan.Adapter) scan.Result {
	t.Helper()
	reg, err := scan.NewRegistry(adapters...)
	if err != nil {
		t.Fatal(err)
	}
	res, err := scan.NewWorker(reg).Scan(context.Background(), "S-1", "org/r", t.TempDir(),
		scan.RepoProfile{Repo: "org/r"}, scan.RunOpts{Mode: scan.ModeFull, CommitSHA: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// A lost sub-tool is a gap and makes the scan partial (VM-F-211), named so
// the report says which one; the others count as run.
func TestASubToolGapMakesTheScanPartial(t *testing.T) {
	inv := &scan.AIInventory{Source: "multi 1"}
	res := scanWith(t, plain{name: "local"}, multi{
		plain: plain{name: "multi"}, ran: []string{"multi/a"}, inv: inv,
		gaps: []scan.CoverageGap{{Tool: "multi/b", Cause: "tool_failed", Owner: scan.OwnerPlatform}},
	})
	if res.Outcome != model.ScanPartial {
		t.Errorf("outcome %s, want partial", res.Outcome)
	}
	if !reflect.DeepEqual(res.ToolsOK, []string{"local", "multi", "multi/a"}) ||
		!reflect.DeepEqual(res.ToolsFailed, []string{"multi/b"}) {
		t.Errorf("ok %v failed %v", res.ToolsOK, res.ToolsFailed)
	}
	if len(res.Gaps) != 1 || res.Gaps[0].Classification != scan.GapPartial {
		t.Errorf("gaps %+v", res.Gaps)
	}
	if res.AIInventory != inv || res.ToolVersions["multi/rules"] != "abc" || res.CommitSHA != "abc123" {
		t.Errorf("inventory %v versions %v commit %q", res.AIInventory, res.ToolVersions, res.CommitSHA)
	}
}

// An adapter none of whose tools ran did not run: alone, the scan failed.
func TestNoSubToolRanIsAFailedAdapter(t *testing.T) {
	res := scanWith(t, multi{
		plain: plain{name: "multi"},
		gaps:  []scan.CoverageGap{{Tool: "multi/a", Cause: "tool_failed", Owner: scan.OwnerPlatform}},
	})
	if res.Outcome != model.ScanFailed || len(res.ToolsOK) != 0 {
		t.Errorf("outcome %s ok %v failed %v", res.Outcome, res.ToolsOK, res.ToolsFailed)
	}
	if res.Gaps[0].Classification != scan.GapTotal {
		t.Errorf("gaps %+v", res.Gaps)
	}
}

// An adapter's own cause and owner are kept; any other failure is the
// platform's execution failure, as before.
func TestAnAdapterAttributesItsOwnFailure(t *testing.T) {
	res := scanWith(t,
		plain{name: "a", runErr: &scan.GapError{Cause: "repo_too_large", Owner: scan.OwnerRepo, Detail: "too big"}},
		plain{name: "b", runErr: errors.New("binary missing")},
	)
	got := map[string]scan.CoverageGap{}
	for _, g := range res.Gaps {
		got[g.Tool] = g
	}
	if g := got["a"]; g.Cause != "repo_too_large" || g.Owner != scan.OwnerRepo || g.Detail != "too big" {
		t.Errorf("a: %+v", g)
	}
	if g := got["b"]; g.Cause != "execution_failed" || g.Owner != scan.OwnerPlatform {
		t.Errorf("b: %+v", g)
	}
}

// Adapters with no optional capability are recorded exactly as before.
func TestPlainAdaptersAreUnaffected(t *testing.T) {
	res := scanWith(t, plain{name: "a"}, plain{name: "b"})
	if res.Outcome != model.ScanComplete || !reflect.DeepEqual(res.ToolsOK, []string{"a", "b"}) ||
		len(res.ToolsFailed) != 0 || len(res.Gaps) != 0 || res.AIInventory != nil ||
		!reflect.DeepEqual(res.ToolVersions, map[string]string{"a": "1", "b": "1"}) {
		t.Errorf("%+v", res)
	}
}
