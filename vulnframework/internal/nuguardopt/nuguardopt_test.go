package nuguardopt

import (
	"reflect"
	"testing"
)

func ceiling() Ceiling {
	return Ceiling{
		Configured: true, AllowTools: []string{"nga-rules", "atlas", "semgrep"}, AllowPosture: true, MaxTimeoutS: 600,
		Defaults: Fleet{Enabled: true, Tools: []string{"nga-rules", "atlas", "semgrep"}, TimeoutS: 600},
	}
}

func ptr[T any](v T) *T { return &v }

func TestResolveNuGuardOptions(t *testing.T) {
	narrow := ceiling()
	narrow.AllowTools = []string{"nga-rules"}
	narrow.AllowPosture = false
	narrow.MaxTimeoutS = 120
	offered := ceiling()
	offered.ServiceTools = []string{"nga-rules", "atlas"}

	cases := []struct {
		name      string
		c         Ceiling
		fleet     *Fleet
		repo      *RepoOverride
		req       *Request
		enabled   bool
		tools     []string
		posture   bool
		timeout   int
		from      string
		reason    string
		clips     int
		notReqTop string // first NotRequested tool, or ""
	}{
		{name: "not configured", c: Ceiling{}, enabled: false, tools: []string{}, from: "deployment",
			reason: NotConfigured, notReqTop: "nuguard"},
		{name: "never configured in the interface uses the worker defaults", c: ceiling(), enabled: true,
			tools: []string{"nga-rules", "atlas", "semgrep"}, timeout: 600, from: "worker default"},
		{name: "fleet off", c: ceiling(), fleet: &Fleet{Enabled: false, Tools: []string{"atlas"}, TimeoutS: 300},
			tools: []string{"atlas"}, timeout: 300, from: "fleet", reason: "off for the fleet", notReqTop: "nuguard"},
		{name: "fleet on, fewer tools", c: ceiling(), fleet: &Fleet{Enabled: true, Tools: []string{"atlas"}, TimeoutS: 300},
			enabled: true, tools: []string{"atlas"}, timeout: 300, from: "fleet", notReqTop: "nuguard/nga-rules"},
		{name: "repository off beats fleet on", c: ceiling(), fleet: &Fleet{Enabled: true, Tools: []string{"atlas"}, TimeoutS: 300},
			repo: &RepoOverride{Mode: RepoOff}, tools: []string{"atlas"}, timeout: 300, from: "repository",
			reason: "off for this repository", notReqTop: "nuguard"},
		{name: "repository on beats fleet off, with its own tools", c: ceiling(),
			fleet:   &Fleet{Enabled: false, Tools: []string{"atlas"}, TimeoutS: 300},
			repo:    &RepoOverride{Mode: RepoOn, Tools: []string{"semgrep"}, IncludePosture: ptr(true)},
			enabled: true, tools: []string{"semgrep"}, posture: true, timeout: 300, from: "repository", notReqTop: "nuguard/nga-rules"},
		{name: "repository inherit keeps the fleet's switch but may narrow tools", c: ceiling(),
			fleet:   &Fleet{Enabled: true, Tools: []string{"nga-rules", "atlas"}, TimeoutS: 300},
			repo:    &RepoOverride{Mode: RepoInherit, Tools: []string{"atlas"}},
			enabled: true, tools: []string{"atlas"}, timeout: 300, from: "fleet", notReqTop: "nuguard/nga-rules"},
		{name: "scan off beats repository on", c: ceiling(), repo: &RepoOverride{Mode: RepoOn},
			req: &Request{Mode: RequestOff}, tools: []string{"nga-rules", "atlas", "semgrep"}, timeout: 600, from: "scan",
			reason: "off for this scan", notReqTop: "nuguard"},
		{name: "scan on beats repository off", c: ceiling(), repo: &RepoOverride{Mode: RepoOff},
			req: &Request{Mode: RequestOn, Tools: []string{"nga-rules"}}, enabled: true, tools: []string{"nga-rules"},
			timeout: 600, from: "scan", notReqTop: "nuguard/atlas"},
		{name: "scan default changes nothing", c: ceiling(), repo: &RepoOverride{Mode: RepoOff},
			req: &Request{Mode: RequestDefault}, tools: []string{"nga-rules", "atlas", "semgrep"}, timeout: 600,
			from: "repository", reason: "off for this repository", notReqTop: "nuguard"},
		{name: "a stored setting above a lowered ceiling is clipped and noted", c: narrow,
			fleet:   &Fleet{Enabled: true, Tools: []string{"nga-rules", "atlas", "semgrep"}, IncludePosture: true, TimeoutS: 600},
			enabled: true, tools: []string{"nga-rules"}, timeout: 120, from: "fleet", clips: 4, notReqTop: "nuguard/atlas"},
		{name: "nothing left after clipping turns NuGuard off, with the reason", c: narrow,
			fleet: &Fleet{Enabled: true, Tools: []string{"atlas"}, TimeoutS: 60}, tools: []string{}, timeout: 60,
			from: "fleet", reason: "no tool it may run remains after the operator's limits", clips: 1, notReqTop: "nuguard"},
		{name: "a tool the service does not offer is left out", c: offered, enabled: true,
			tools: []string{"nga-rules", "atlas"}, timeout: 600, from: "worker default", clips: 1, notReqTop: "nuguard/semgrep"},
		{name: "a tool users may not choose is never run", c: ceiling(),
			fleet:   &Fleet{Enabled: true, Tools: []string{"osv", "atlas"}, TimeoutS: 300},
			enabled: true, tools: []string{"atlas"}, timeout: 300, from: "fleet", clips: 1, notReqTop: "nuguard/nga-rules"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, clips := ResolveNuGuardOptions(tc.c, tc.fleet, tc.repo, tc.req)
			if e.Enabled != tc.enabled {
				t.Errorf("enabled = %v, want %v", e.Enabled, tc.enabled)
			}
			if !reflect.DeepEqual(e.Tools, tc.tools) {
				t.Errorf("tools = %v, want %v", e.Tools, tc.tools)
			}
			if e.IncludePosture != tc.posture {
				t.Errorf("posture = %v, want %v", e.IncludePosture, tc.posture)
			}
			if e.TimeoutS != tc.timeout {
				t.Errorf("timeout = %d, want %d", e.TimeoutS, tc.timeout)
			}
			if e.From != tc.from {
				t.Errorf("from = %q, want %q", e.From, tc.from)
			}
			if e.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", e.Reason, tc.reason)
			}
			if len(clips) != tc.clips || !reflect.DeepEqual(clips, e.Clips) {
				t.Errorf("clips = %+v (on the result %+v), want %d", clips, e.Clips, tc.clips)
			}
			top := ""
			if len(e.NotRequested) > 0 {
				top = e.NotRequested[0].Tool
			}
			if top != tc.notReqTop {
				t.Errorf("not requested = %+v, want first %q", e.NotRequested, tc.notReqTop)
			}
			for _, n := range e.NotRequested {
				if n.Reason == "" {
					t.Errorf("%s not requested without a reason", n.Tool)
				}
			}
		})
	}
}

func TestKeepSBOMOnlyWhenNuGuardRuns(t *testing.T) {
	e, _ := ResolveNuGuardOptions(ceiling(), nil, nil, &Request{Mode: RequestOn, KeepSBOM: true})
	if !e.KeepSBOM {
		t.Error("keep_sbom asked for and NuGuard on, but not kept")
	}
	e, _ = ResolveNuGuardOptions(ceiling(), nil, &RepoOverride{Mode: RepoOff}, &Request{Mode: RequestDefault, KeepSBOM: true})
	if e.KeepSBOM {
		t.Error("keep_sbom set while NuGuard is off")
	}
}

func TestValidateRefusesWhatTheCeilingDoesNotAllow(t *testing.T) {
	c := ceiling()
	c.AllowTools = []string{"nga-rules", "atlas"}
	c.AllowPosture = false
	c.MaxTimeoutS = 300
	fields := func(errs []FieldError) []string {
		var out []string
		for _, e := range errs {
			out = append(out, e.Field)
		}
		return out
	}
	if got := fields(ValidateFleet(c, Fleet{Enabled: true, Tools: []string{"atlas"}, TimeoutS: 300})); got != nil {
		t.Errorf("a fleet setting within the ceiling refused: %v", got)
	}
	got := fields(ValidateFleet(c, Fleet{Enabled: true, Tools: []string{"semgrep", "osv"}, IncludePosture: true, TimeoutS: 900}))
	want := []string{"tools", "tools", "include_posture", "timeout_s"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fields refused = %v, want %v", got, want)
	}
	if got := fields(ValidateFleet(c, Fleet{Enabled: true, Tools: []string{}, TimeoutS: 60})); !reflect.DeepEqual(got, []string{"tools"}) {
		t.Errorf("on with no tool: %v", got)
	}
	if got := fields(ValidateFleet(Ceiling{}, Fleet{Enabled: true, Tools: []string{"atlas"}, TimeoutS: 60})); len(got) == 0 || got[0] != "enabled" {
		t.Errorf("turning on an unconfigured NuGuard: %v", got)
	}
	if got := fields(ValidateRepo(c, RepoOverride{Mode: "sometimes"})); !reflect.DeepEqual(got, []string{"mode"}) {
		t.Errorf("bad mode: %v", got)
	}
	if got := fields(ValidateRequest(c, Request{Mode: RequestOff, Tools: []string{"atlas"}})); !reflect.DeepEqual(got, []string{"nuguard"}) {
		t.Errorf("tools with off: %v", got)
	}
	if got := fields(ValidateRequest(c, Request{Mode: RequestOn, Tools: []string{"semgrep"}})); !reflect.DeepEqual(got, []string{"nuguard.tools"}) {
		t.Errorf("tool above the ceiling: %v", got)
	}
}
