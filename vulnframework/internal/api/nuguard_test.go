package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/api"
	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/nuguard"
	"github.com/wanaware/vulnframework/internal/nuguard/nuguardfake"
	"github.com/wanaware/vulnframework/internal/nuguardopt"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/store"
)

// NuGuard controls through the API (VM-UI-F-1201..1212): roles, the five
// write gates, the ceiling, backward compatibility of scan requests, and the
// preview agreeing with what the scan worker then does.

var public = caller{"anon", "public"}

// narrowCeiling is an operator who allows two of the three AI tools, no
// posture, and five minutes.
func narrowCeiling() nuguardopt.Ceiling {
	return nuguardopt.Ceiling{Configured: true, AllowTools: []string{"nga-rules", "atlas"}, AllowPosture: false,
		MaxTimeoutS: 300, Defaults: nuguardopt.Fleet{Enabled: true, Tools: []string{"nga-rules", "atlas"}, TimeoutS: 300}}
}

// reported writes the status a scan worker with this ceiling publishes.
func (e *scanEnv) reported(t *testing.T, c nuguardopt.Ceiling, at time.Time) {
	t.Helper()
	if err := e.st.PutNuGuardStatus(context.Background(), store.NuGuardStatus{
		Configured: c.Configured, Reachable: c.Configured, CheckedAt: at, PinnedVersion: "0.9.15",
		ServiceVersion: "0.9.15", VersionOK: c.Configured, Ceiling: c,
	}); err != nil {
		t.Fatal(err)
	}
}

func (e *scanEnv) put(t *testing.T, path string, c caller, body string) (int, map[string]any, []byte) {
	return e.do(t, http.MethodPut, path, c, body, map[string]string{
		"Sec-Fetch-Site": "same-origin", api.CSRFHeader: e.csrf(t, c), "Content-Type": "application/json",
	})
}

func TestNuGuardPageByRole(t *testing.T) {
	for name, open := range scanBackends(t) {
		t.Run(name, func(t *testing.T) {
			e := newScanEnv(t, open(t), true)
			e.reported(t, narrowCeiling(), e.now)

			if status, _, raw := e.do(t, http.MethodGet, "/v1/nuguard", public, "", nil); status != http.StatusForbidden {
				t.Errorf("public = %d %s; the public sees none of it", status, raw)
			}
			for _, path := range []string{"/v1/nuguard/audit", "/v1/repos/octo/api/nuguard", "/v1/nuguard/preview?repo=octo/api"} {
				if status, _, _ := e.do(t, http.MethodGet, path, public, "", nil); status != http.StatusForbidden {
					t.Errorf("public GET %s = %d, want 403", path, status)
				}
			}
			status, m, raw := e.do(t, http.MethodGet, "/v1/nuguard", engineer, "", nil)
			if status != 200 || m["configured"] != true || m["can_edit"] != false {
				t.Errorf("engineer = %d %s; want the page, read-only", status, raw)
			}
			status, m, raw = e.do(t, http.MethodGet, "/v1/nuguard", owner, "", nil)
			if status != 200 || m["can_edit"] != true {
				t.Errorf("security owner = %d %s; want can_edit", status, raw)
			}
			fleet := m["fleet"].(map[string]any)
			if fleet["set"] != false || !reflect.DeepEqual(fleet["settings"].(map[string]any)["tools"], []any{"nga-rules", "atlas"}) {
				t.Errorf("an unset fleet shows %v; want the worker's defaults, marked not set", fleet)
			}
			// An engineer may not change anything.
			body := `{"enabled":true,"tools":["atlas"],"include_posture":false,"timeout_s":120}`
			if status, _, raw := e.put(t, "/v1/nuguard/settings", engineer, body); status != http.StatusForbidden {
				t.Errorf("engineer PUT settings = %d %s; want 403", status, raw)
			}
			if status, _, raw := e.put(t, "/v1/repos/octo/api/nuguard", engineer, `{"mode":"off"}`); status != http.StatusForbidden {
				t.Errorf("engineer PUT override = %d %s; want 403", status, raw)
			}
		})
	}
}

func TestNuGuardNotConfiguredIsOneLine(t *testing.T) {
	for name, open := range scanBackends(t) {
		t.Run(name, func(t *testing.T) {
			e := newScanEnv(t, open(t), true)
			// No worker has reported: not configured, as the demonstration is.
			status, m, raw := e.do(t, http.MethodGet, "/v1/nuguard", owner, "", nil)
			if status != 200 || m["configured"] != false || !strings.HasPrefix(m["note"].(string), nuguardopt.NotConfigured) || m["can_edit"] != false {
				t.Fatalf("no status = %d %s", status, raw)
			}
			e.reported(t, nuguardopt.Ceiling{}, e.now) // a worker with no -nuguard-url
			_, m, _ = e.do(t, http.MethodGet, "/v1/nuguard", owner, "", nil)
			if m["configured"] != false || m["note"] != nuguardopt.NotConfigured {
				t.Errorf("worker without NuGuard = %v", m)
			}
			body := `{"enabled":false,"tools":[],"include_posture":false,"timeout_s":120}`
			if status, _, raw := e.put(t, "/v1/nuguard/settings", owner, body); status != http.StatusConflict {
				t.Errorf("settings on a deployment without NuGuard = %d %s; want 409", status, raw)
			}
			if status, _, raw := e.write(t, "/v1/scans", owner, `{"repo":"octo/api","nuguard":{"mode":"on"}}`); status != http.StatusUnprocessableEntity {
				t.Errorf("asking for NuGuard where there is none = %d %s; want 422", status, raw)
			}
		})
	}
}

func TestNuGuardSettingsPassEveryGateAndTheCeiling(t *testing.T) {
	for name, open := range scanBackends(t) {
		t.Run(name, func(t *testing.T) {
			e := newScanEnv(t, open(t), true)
			e.reported(t, narrowCeiling(), e.now)
			ok := `{"enabled":true,"tools":["atlas"],"include_posture":false,"timeout_s":120,"reason":"atlas only for now"}`
			token := e.csrf(t, owner)
			same := map[string]string{"Sec-Fetch-Site": "same-origin", api.CSRFHeader: token}

			for _, c := range []struct {
				name string
				hdr  map[string]string
				body string
				want int
			}{
				{"no CSRF token", map[string]string{"Sec-Fetch-Site": "same-origin"}, ok, 403},
				{"forged CSRF token", map[string]string{"Sec-Fetch-Site": "same-origin", api.CSRFHeader: "AAAA"}, ok, 403},
				{"cross-site", map[string]string{"Sec-Fetch-Site": "cross-site", api.CSRFHeader: token}, ok, 403},
				{"no origin headers", map[string]string{api.CSRFHeader: token}, ok, 403},
				{"unknown field", same, `{"enabled":true,"tools":["atlas"],"include_posture":false,"timeout_s":120,"network":true}`, 400},
				{"missing field", same, `{"enabled":true,"tools":["atlas"]}`, 400},
				{"two values", same, ok + ok, 400},
				{"tool above the ceiling", same, `{"enabled":true,"tools":["semgrep"],"include_posture":false,"timeout_s":120}`, 422},
				{"tool users may not choose", same, `{"enabled":true,"tools":["osv"],"include_posture":false,"timeout_s":120}`, 422},
				{"posture not allowed", same, `{"enabled":true,"tools":["atlas"],"include_posture":true,"timeout_s":120}`, 422},
				{"timeout above the ceiling", same, `{"enabled":true,"tools":["atlas"],"include_posture":false,"timeout_s":900}`, 422},
				{"on with no tool", same, `{"enabled":true,"tools":[],"include_posture":false,"timeout_s":120}`, 422},
			} {
				status, _, raw := e.do(t, http.MethodPut, "/v1/nuguard/settings", owner, c.body, c.hdr)
				if status != c.want {
					t.Errorf("%s: %d %s; want %d", c.name, status, raw, c.want)
				}
				if c.want == 422 && !strings.Contains(string(raw), "ceiling") {
					t.Errorf("%s: a 422 that does not name the ceiling: %s", c.name, raw)
				}
			}
			status, _, raw := e.do(t, http.MethodPut, "/v1/nuguard/settings", owner,
				`{"enabled":true,"tools":["semgrep"],"include_posture":false,"timeout_s":120}`, same)
			if status != 422 || !strings.Contains(string(raw), "tools") || !strings.Contains(string(raw), "nga-rules, atlas") {
				t.Errorf("the 422 must name the field and the ceiling: %s", raw)
			}
			if _, ok, _ := e.st.NuGuardSettings(context.Background()); ok {
				t.Fatal("a refused change was stored")
			}

			status, m, raw := e.put(t, "/v1/nuguard/settings", owner, ok)
			if status != 200 || m["fleet"].(map[string]any)["set"] != true {
				t.Fatalf("a valid change = %d %s", status, raw)
			}
			audit := m["audit"].([]any)
			if len(audit) != 1 {
				t.Fatalf("audit = %v, want the one change", audit)
			}
			entry := audit[0].(map[string]any)
			if entry["changed_by"] != "pat" || entry["reason"] != "atlas only for now" || entry["after"] == nil {
				t.Errorf("audit entry = %v", entry)
			}
			_, page, _ := e.do(t, http.MethodGet, "/v1/nuguard/audit", engineer, "", nil)
			if len(page["entries"].([]any)) != 1 {
				t.Errorf("audit page = %v", page)
			}

			// The rate limit: ten changes a minute, then 429.
			for i := 0; i < 9; i++ {
				e.put(t, "/v1/nuguard/settings", owner, ok)
			}
			if status, _, raw := e.put(t, "/v1/nuguard/settings", owner, ok); status != http.StatusTooManyRequests {
				t.Errorf("the eleventh change in a minute = %d %s; want 429", status, raw)
			}
		})
	}
}

func TestRepositoryOverrideAndPreview(t *testing.T) {
	for name, open := range scanBackends(t) {
		t.Run(name, func(t *testing.T) {
			e := newScanEnv(t, open(t), true)
			e.reported(t, narrowCeiling(), e.now)

			if status, _, raw := e.put(t, "/v1/repos/octo/nope/nuguard", owner, `{"mode":"off"}`); status != http.StatusNotFound {
				t.Errorf("override for an unregistered repository = %d %s", status, raw)
			}
			if status, _, raw := e.put(t, "/v1/repos/octo/api/nuguard", owner, `{"mode":"sometimes"}`); status != 422 {
				t.Errorf("bad mode = %d %s", status, raw)
			}
			if status, _, raw := e.put(t, "/v1/repos/octo/api/nuguard", owner, `{"mode":"on","tools":["semgrep"]}`); status != 422 {
				t.Errorf("override tool above the ceiling = %d %s", status, raw)
			}
			status, m, raw := e.put(t, "/v1/repos/octo/api/nuguard", owner, `{"mode":"off","reason":"vendored code"}`)
			if status != 200 {
				t.Fatalf("set override = %d %s", status, raw)
			}
			eff := m["effective"].(map[string]any)
			if eff["enabled"] != false || eff["from"] != "repository" || eff["reason"] != "off for this repository" {
				t.Errorf("effective after override = %v", eff)
			}
			_, view, _ := e.do(t, http.MethodGet, "/v1/nuguard", engineer, "", nil)
			if view["override_count"].(float64) != 1 {
				t.Errorf("override count = %v", view["override_count"])
			}

			// Preview: what a scan would use, by the same resolution the worker runs.
			_, p, raw := e.do(t, http.MethodGet, "/v1/nuguard/preview?repo=octo/api", engineer, "", nil)
			if p["effective"].(map[string]any)["enabled"] != false {
				t.Errorf("preview without options = %s", raw)
			}
			_, p, raw = e.do(t, http.MethodGet, "/v1/nuguard/preview?repo=octo/api&nuguard=on&tools=atlas", engineer, "", nil)
			pe := p["effective"].(map[string]any)
			if pe["enabled"] != true || pe["from"] != "scan" || !reflect.DeepEqual(pe["tools"], []any{"atlas"}) {
				t.Errorf("preview on for this scan = %s", raw)
			}
			if status, _, raw := e.do(t, http.MethodGet, "/v1/nuguard/preview?repo=octo/api&nuguard=on&tools=semgrep", engineer, "", nil); status != 422 {
				t.Errorf("preview with a tool above the ceiling = %d %s", status, raw)
			}

			// Clearing: inherit with nothing of its own.
			status, m, _ = e.put(t, "/v1/repos/octo/api/nuguard", owner, `{"mode":"inherit"}`)
			if status != 200 || m["override"] != nil {
				t.Errorf("cleared override = %d %v", status, m["override"])
			}
		})
	}
}

func TestScanRequestsCarryNuGuardOptionsAndStayCompatible(t *testing.T) {
	for name, open := range scanBackends(t) {
		t.Run(name, func(t *testing.T) {
			e := newScanEnv(t, open(t), true)
			e.reported(t, narrowCeiling(), e.now)
			ctx := context.Background()

			// {repo} alone: exactly today's request.
			status, m, raw := e.write(t, "/v1/scans", owner, `{"repo":"octo/api"}`)
			if status != http.StatusCreated {
				t.Fatalf("{repo} alone = %d %s", status, raw)
			}
			if _, has := m["request"].(map[string]any)["nuguard"]; has {
				t.Errorf("a request that asked nothing reports NuGuard options: %s", raw)
			}
			// Invalid options are refused, and nothing is queued.
			if status, _, raw := e.write(t, "/v1/scans", owner, `{"repo":"octo/web","nuguard":{"mode":"on","tools":["semgrep"]}}`); status != 422 {
				t.Errorf("tool above the ceiling = %d %s", status, raw)
			}
			if status, _, raw := e.write(t, "/v1/scans", owner, `{"repo":"octo/web","nuguard":{"mode":"on","network":true}}`); status != 400 {
				t.Errorf("unknown NuGuard field = %d %s", status, raw)
			}
			if rows, _ := e.st.ScanRequests(ctx, store.ScanQuery{Repo: "octo/web"}); len(rows) != 0 {
				t.Fatalf("refused requests queued %+v", rows)
			}
			e.now = e.now.Add(2 * time.Minute)
			e.reported(t, narrowCeiling(), e.now)
			status, m, raw = e.write(t, "/v1/scans", owner, `{"repo":"octo/web","nuguard":{"mode":"on","tools":["atlas"],"keep_sbom":true}}`)
			if status != http.StatusCreated {
				t.Fatalf("with options = %d %s", status, raw)
			}
			rows, _ := e.st.ScanRequests(ctx, store.ScanQuery{Repo: "octo/web"})
			want := &nuguardopt.Request{Mode: nuguardopt.RequestOn, Tools: []string{"atlas"}, KeepSBOM: true}
			if len(rows) != 1 || !reflect.DeepEqual(rows[0].NuGuard, want) {
				t.Errorf("stored options = %+v, want %+v", rows, want)
			}

			// Scan all, with no body (today) and with one scan-level option
			// that every repository in the batch carries. The two queued
			// requests are run to the end first, so the batch queues afresh.
			finishAll := func() {
				for {
					claimed, ok, err := e.st.ClaimScans(ctx, "w", e.now)
					if err != nil {
						t.Fatal(err)
					}
					if !ok {
						return
					}
					for _, c := range claimed {
						if err := e.st.FinishScan(ctx, c.ID, "w", store.ScanFinished, "", "", e.now); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			finishAll()
			e.now = e.now.Add(2 * time.Minute)
			e.reported(t, narrowCeiling(), e.now)
			status, m, raw = e.write(t, "/v1/scans/all", owner, "")
			if status != http.StatusCreated || m["queued"].(float64) != 2 {
				t.Fatalf("scan all with no body = %d %s", status, raw)
			}
			for _, r := range m["requests"].([]any) {
				if _, has := r.(map[string]any)["nuguard"]; has {
					t.Errorf("scan all with no body asked NuGuard for something: %v", r)
				}
			}
			finishAll()
			status, m, raw = e.write(t, "/v1/scans/all", owner, `{"nuguard":{"mode":"off"}}`)
			if status != http.StatusCreated || m["queued"].(float64) != 2 {
				t.Fatalf("scan all with an option = %d %s", status, raw)
			}
			for _, r := range m["requests"].([]any) {
				if ng := r.(map[string]any)["nuguard"]; !reflect.DeepEqual(ng, map[string]any{"mode": "off"}) {
					t.Errorf("a batch request carries %v, want the batch's option", ng)
				}
			}
			e.now = e.now.Add(2 * time.Minute)
			if status, _, raw := e.write(t, "/v1/scans/all", owner, `{"repo":"octo/api"}`); status != 400 {
				t.Errorf("scan all with an unknown field = %d %s; want 400", status, raw)
			}
		})
	}
}

func TestStaleStatusIsNeverShownAsCurrent(t *testing.T) {
	for name, open := range scanBackends(t) {
		t.Run(name, func(t *testing.T) {
			e := newScanEnv(t, open(t), true)
			e.reported(t, narrowCeiling(), e.now.Add(-20*time.Minute))
			_, m, raw := e.do(t, http.MethodGet, "/v1/nuguard", engineer, "", nil)
			st := m["status"].(map[string]any)
			if st["stale"] != true || !strings.HasPrefix(st["stale_note"].(string), "status unknown: the scan worker has not reported since ") {
				t.Errorf("stale status = %s", raw)
			}
			for _, k := range []string{"reachable", "version_ok", "service_version"} {
				if _, has := st[k]; has {
					t.Errorf("a stale status shows %s as if current: %s", k, raw)
				}
			}
		})
	}
}

func TestTheStoredAISBOMIsServedAndNothingElse(t *testing.T) {
	for name, open := range scanBackends(t) {
		t.Run(name, func(t *testing.T) {
			e := newScanEnv(t, open(t), true)
			ctx := context.Background()
			run, err := e.st.CreateRun(ctx, store.KindManual, "test", "img", map[string]string{})
			if err != nil {
				t.Fatal(err)
			}
			path := "/v1/repos/octo/api/ai-sbom/" + run.ID
			if status, _, raw := e.do(t, http.MethodGet, path, engineer, "", nil); status != 404 || !strings.Contains(string(raw), "kept no AI-SBOM") {
				t.Errorf("none kept = %d %s", status, raw)
			}
			doc := `{"components":[{"name":"openai"}]}`
			if err := e.st.PutAISBOM(ctx, store.AISBOM{RunID: run.ID, Repo: "octo/api", CommitSHA: "abc", NuGuardVersion: "0.9.15",
				SizeBytes: int64(len(doc)), SHA256: "f00", Document: json.RawMessage(doc), StoredAt: e.now}); err != nil {
				t.Fatal(err)
			}
			status, m, raw := e.do(t, http.MethodGet, path, engineer, "", nil)
			if status != 200 || m["components"] == nil {
				t.Errorf("stored = %d %s", status, raw)
			}
			if status, _, _ := e.do(t, http.MethodGet, path+"?format=cyclonedx", engineer, "", nil); status != http.StatusNotImplemented {
				t.Errorf("cyclonedx = %d, want 501 until a converter exists", status)
			}
			if status, _, _ := e.do(t, http.MethodGet, path, public, "", nil); status != 403 {
				t.Errorf("public = %d, want 403", status)
			}
			if err := e.st.PutAISBOM(ctx, store.AISBOM{RunID: run.ID, Repo: "octo/web", CommitSHA: "abc", NuGuardVersion: "0.9.15",
				SizeBytes: 9 << 20, SHA256: "f00", Withheld: "over the cap", StoredAt: e.now}); err != nil {
				t.Fatal(err)
			}
			if status, _, raw := e.do(t, http.MethodGet, "/v1/repos/octo/web/ai-sbom/"+run.ID, engineer, "", nil); status != 404 || !strings.Contains(string(raw), "over the cap") {
				t.Errorf("withheld = %d %s", status, raw)
			}
		})
	}
}

func TestANuGuardFindingHasItsOwnSectionAndFilter(t *testing.T) {
	for name, open := range scanBackends(t) {
		t.Run(name, func(t *testing.T) {
			e := newScanEnv(t, open(t), true)
			ctx := context.Background()
			run, err := e.st.CreateRun(ctx, store.KindSweep, "test", "img", map[string]string{})
			if err != nil {
				t.Fatal(err)
			}
			cls := model.Classification{Severity: model.SeverityHigh, Reachable: model.ReachableTrue, DepClass: model.DepNotApplicable}
			ng := model.RawFinding{Repo: "octo/api", Category: model.CategoryCode, Tool: "nuguard", SubTool: "nga-rules",
				ToolVersion: "0.9.15", RuleID: "NGA-PROMPT-INJ-001", File: "agent/chat.go", Function: "buildPrompt",
				Classification: cls, Annotations: map[string]string{
					"nuguard/0.9.15/source_tool": "nga-rules", "nuguard/0.9.15/owasp_llm_ref": "LLM01",
					"nuguard/0.9.15/mitre_atlas_technique": "AML.T0051",
				}}
			local := model.RawFinding{Repo: "octo/api", Category: model.CategoryCode, Tool: "gosec", ToolVersion: "v2",
				RuleID: "G404", File: "token.go", Classification: cls}
			if _, err := e.st.UpsertObservations(ctx, run.ID, "octo/api", []model.RawFinding{ng, local}); err != nil {
				t.Fatal(err)
			}
			eff := &nuguardopt.Effective{Enabled: true, Tools: []string{"nga-rules"}, TimeoutS: 300, From: "fleet"}
			if err := e.st.RecordScanResult(ctx, store.RepoScanResult{RunID: run.ID, Repo: "octo/api", Outcome: model.ScanComplete,
				ToolsOK: []string{"gosec", "nuguard", "nuguard/nga-rules"}, EffectiveNuGuard: eff}); err != nil {
				t.Fatal(err)
			}

			status, m, raw := e.do(t, http.MethodGet, "/v1/findings/"+fingerprint.Compute(ng), owner, "", nil)
			if status != 200 {
				t.Fatalf("detail = %d %s", status, raw)
			}
			sec, ok := m["nuguard"].(map[string]any)
			if !ok {
				t.Fatalf("a NuGuard finding has no NuGuard section: %s", raw)
			}
			for k, want := range map[string]any{"rule": "NGA-PROMPT-INJ-001", "sub_tool": "nga-rules", "owasp_llm_ref": "LLM01",
				"mitre_atlas_technique": "AML.T0051", "function": "buildPrompt", "version": "0.9.15", "last_run": run.ID} {
				if sec[k] != want {
					t.Errorf("nuguard.%s = %v, want %v", k, sec[k], want)
				}
			}
			if sec["effective"].(map[string]any)["from"] != "fleet" {
				t.Errorf("the last scan's options are missing: %v", sec["effective"])
			}
			_, m, _ = e.do(t, http.MethodGet, "/v1/findings/"+fingerprint.Compute(local), owner, "", nil)
			if _, has := m["nuguard"]; has {
				t.Error("a gosec finding has a NuGuard section")
			}

			_, m, raw = e.do(t, http.MethodGet, "/v1/findings?scope=open&found_by=nuguard", owner, "", nil)
			if fs := m["findings"].([]any); len(fs) != 1 || fs[0].(map[string]any)["fingerprint"] != fingerprint.Compute(ng) {
				t.Errorf("found_by=nuguard = %s", raw)
			}
			if status, _, _ := e.do(t, http.MethodGet, "/v1/findings?scope=open&found_by=bogus", owner, "", nil); status != 400 {
				t.Errorf("an unknown found_by = %d, want 400 (an ignored filter shows a list nobody asked for)", status)
			}
		})
	}
}

// A NuGuard finding from a clone with uncommitted changes says NuGuard
// scanned the commit, and stops saying so once a scan of a clean tree
// observes it again.
func TestANuGuardFindingSaysWhatNuGuardScanned(t *testing.T) {
	for name, open := range scanBackends(t) {
		t.Run(name, func(t *testing.T) {
			e := newScanEnv(t, open(t), true)
			ctx := context.Background()
			cls := model.Classification{Severity: model.SeverityHigh, Reachable: model.ReachableTrue, DepClass: model.DepNotApplicable}
			observe := func(annotations map[string]string) {
				run, err := e.st.CreateRun(ctx, store.KindSweep, "test", "img", map[string]string{})
				if err != nil {
					t.Fatal(err)
				}
				f := model.RawFinding{Repo: "octo/api", Category: model.CategoryCode, Tool: "nuguard", SubTool: "atlas",
					ToolVersion: "0.9.15", RuleID: "NGA-TOOL-001", File: "agent/tools.go", Classification: cls, Annotations: annotations}
				if _, err := e.st.UpsertObservations(ctx, run.ID, "octo/api", []model.RawFinding{f}); err != nil {
					t.Fatal(err)
				}
			}
			fp := fingerprint.Compute(model.RawFinding{Repo: "octo/api", Category: model.CategoryCode, Tool: "nuguard",
				RuleID: "NGA-TOOL-001", File: "agent/tools.go"})
			scanned := func() any {
				_, m, raw := e.do(t, http.MethodGet, "/v1/findings/"+fp, owner, "", nil)
				sec, ok := m["nuguard"].(map[string]any)
				if !ok {
					t.Fatalf("no NuGuard section: %s", raw)
				}
				return sec["scanned"]
			}

			note := "NuGuard scanned the committed state, not the working tree"
			observe(map[string]string{"nuguard/0.9.15/source_tool": "atlas", "nuguard/0.9.15/scanned": note})
			if got := scanned(); got != note {
				t.Errorf("scanned = %v, want %q", got, note)
			}
			observe(map[string]string{"nuguard/0.9.15/source_tool": "atlas"})
			if got := scanned(); got != nil {
				t.Errorf("after a scan of a clean tree, scanned = %v, want absent", got)
			}
		})
	}
}

// TestThePreviewIsWhatTheWorkerDoes is the integration: the scan worker
// publishes its ceiling, the API previews a scan, the request is queued
// through the API, and the real worker runs it through the real adapter
// against the fake NuGuard. The options the scan records are the preview's.
func TestThePreviewIsWhatTheWorkerDoes(t *testing.T) {
	for name, open := range scanBackends(t) {
		t.Run(name, func(t *testing.T) {
			e := newScanEnv(t, open(t), true)
			ctx := context.Background()
			if err := e.st.UpsertRepo(ctx, store.Repo{Name: "octo/api", Tier: 2, Languages: []string{"go"}}); err != nil {
				t.Fatal(err)
			}

			result, err := os.ReadFile("../../testdata/fixtures/nuguard/ai-code.json")
			if err != nil {
				t.Fatal(err)
			}
			const key = "preview-test-key"
			fake := nuguardfake.New(key, "0.9.15")
			t.Cleanup(fake.Close)
			fake.Default = &nuguardfake.Script{Result: result}
			fake.ToolsAllowed = []string{"nga-rules", "atlas"} // the service itself offers two
			fake.Narrow = true
			ng := adapters.NewNuGuard(&nuguard.Client{BaseURL: fake.URL, APIKey: func() (string, error) { return key, nil }}, "0.9.15", nil)
			reg, err := scan.NewRegistry(ng)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
			_ = os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("5d0c7e9a1b2c3d4e5f60718293a4b5c6d7e8f901\n"), 0o644)
			o := orchestrator.New(e.st, &orchestrator.LocalDispatcher{Worker: scan.NewWorker(reg), WorkDir: func(string) string { return dir }},
				orchestrator.NewRateBudget(10), orchestrator.Config{MaxConcurrentScans: 1, CreditsPerScan: 1})
			o.Clock = func() time.Time { return e.now }
			c := nuguardopt.Ceiling{Configured: true, AllowTools: []string{"nga-rules", "atlas", "semgrep"}, AllowPosture: true,
				MaxTimeoutS: 600, Defaults: nuguardopt.Fleet{Enabled: true, Tools: []string{"nga-rules", "atlas", "semgrep"}, TimeoutS: 600}}
			w := &orchestrator.ScanWorker{Orch: o, ID: "w1", Credits: 10, NuGuard: &orchestrator.NuGuardControl{Ceiling: c, Pinned: "0.9.15",
				Probe: func(ctx context.Context) orchestrator.NuGuardProbe {
					p := ng.Probe(ctx)
					return orchestrator.NuGuardProbe{Reachable: p.Reachable, ServiceVersion: p.ServiceVersion, ToolsAllowed: p.ToolsAllowed, Err: p.Err}
				}}}
			if err := w.PublishNuGuardStatus(ctx); err != nil {
				t.Fatal(err)
			}

			// A fleet setting with posture, and a scan asking for all three
			// tools: the service offers two, so the preview clips one.
			if status, _, raw := e.put(t, "/v1/nuguard/settings", owner,
				`{"enabled":true,"tools":["nga-rules","atlas"],"include_posture":true,"timeout_s":300}`); status != 200 {
				t.Fatalf("settings = %d %s", status, raw)
			}
			q := url.Values{"repo": {"octo/api"}, "nuguard": {"on"}, "tools": {"nga-rules,atlas,semgrep"}}
			status, _, raw := e.do(t, http.MethodGet, "/v1/nuguard/preview?"+q.Encode(), owner, "", nil)
			if status != 200 {
				t.Fatalf("preview = %d %s", status, raw)
			}
			var preview api.NuGuardPreview
			if err := json.Unmarshal(raw, &preview); err != nil {
				t.Fatal(err)
			}
			if len(preview.Clips) != 1 || preview.Clips[0].Asked != "semgrep" || preview.Clips[0].Why != "not offered by the service" {
				t.Fatalf("preview clips = %+v, want semgrep not offered by the service", preview.Clips)
			}

			if status, _, raw := e.write(t, "/v1/scans", owner,
				`{"repo":"octo/api","nuguard":{"mode":"on","tools":["nga-rules","atlas","semgrep"]}}`); status != http.StatusCreated {
				t.Fatalf("scan = %d %s", status, raw)
			}
			if did, err := w.RunOnce(ctx); err != nil || !did {
				t.Fatalf("RunOnce: did=%v err=%v", did, err)
			}
			res, err := e.st.ScanResults(ctx, "octo/api", 1)
			if err != nil || len(res) != 1 || res[0].EffectiveNuGuard == nil {
				t.Fatalf("result = %+v, %v", res, err)
			}
			if !reflect.DeepEqual(*res[0].EffectiveNuGuard, preview.Effective) {
				t.Errorf("the worker used\n  %+v\nbut the preview said\n  %+v", *res[0].EffectiveNuGuard, preview.Effective)
			}
			if got := fake.Submissions()[0].Options["tools"]; !reflect.DeepEqual(got, []any{"nga-rules", "atlas"}) {
				t.Errorf("NuGuard was asked for %v", got)
			}
		})
	}
}
