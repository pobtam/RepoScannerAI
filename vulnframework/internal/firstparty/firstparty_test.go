package firstparty_test

import (
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/model"
)

// Phase 11 — first-party classification and wave propagation.
//
// This is where FirstPartyPath is finally POPULATED from real classification.
// It has been dormant since Phase 6: the field existed, policy rule 5 read it,
// and nothing ever set it — which is exactly how the Phase 6 projection bug
// survived. The store dropped the field and every test passed, because no test
// carried a real value along the path.

const (
	ownerRepo    = "org/wanaware-common"
	consumerRepo = "org/wanaware-api"
	sharedModule = "github.com/wanaware/common"
)

func registry(t *testing.T) *firstparty.Registry {
	t.Helper()
	r, err := firstparty.ParseRegistry([]byte(`
version: 1
wave2_trigger: merge
modules:
  github.com/wanaware/common: org/wanaware-common
  github.com/wanaware/auth: org/wanaware-auth
  github.com/wanaware/telemetry: org/wanaware-telemetry
`))
	if err != nil {
		t.Fatalf("ParseRegistry: %v", err)
	}
	return r
}

// --- The registry ------------------------------------------------------------

func TestRegistryAnswersOwnershipAndMembership(t *testing.T) {
	r := registry(t)

	if owner, ok := r.Owner(sharedModule); !ok || owner != ownerRepo {
		t.Errorf("Owner(%q) = (%q, %v), want (%q, true)", sharedModule, owner, ok, ownerRepo)
	}
	if !r.IsFirstParty(sharedModule) {
		t.Error("the shared module is not recognised as first-party")
	}
	// A submodule of a first-party module belongs to the same owner: nobody
	// lists every package, and a registry that required it would silently
	// treat most of the tree as third-party.
	if owner, ok := r.Owner(sharedModule + "/internal/hash"); !ok || owner != ownerRepo {
		t.Errorf("a subpackage resolved to (%q, %v), want the module's owner", owner, ok)
	}
	// And a module that merely shares a prefix does not.
	for _, notOurs := range []string{
		"github.com/wanaware/commonwealth",
		"github.com/wanawarehouse/common",
		"golang.org/x/crypto",
	} {
		if r.IsFirstParty(notOurs) {
			t.Errorf("%q was classified first-party on a prefix match; the owning repository would be "+
				"asked to fix a module it does not own", notOurs)
		}
	}
}

// TestRegistryRefusesAnEntryItCannotAct  On covers the configuration guard. A
// module with no owner cannot be remediated upstream, and recording it as
// first-party would route its findings to nobody — they would leave the
// consumer's queue and arrive nowhere.
func TestRegistryRefusesAnEntryItCannotActOn(t *testing.T) {
	bad := map[string]string{
		"no owner":        "version: 1\nmodules:\n  github.com/wanaware/common: \"\"\n",
		"no module":       "version: 1\nmodules:\n  \"\": org/x\n",
		"bad trigger":     "version: 1\nwave2_trigger: vibes\nmodules:\n  github.com/wanaware/common: org/x\n",
		"unknown version": "version: 9\nmodules:\n  github.com/wanaware/common: org/x\n",
	}
	for name, doc := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := firstparty.ParseRegistry([]byte(doc)); err == nil {
				t.Error("an unusable registry entry was accepted")
			}
		})
	}
}

// --- Classification (§12.2) --------------------------------------------------

// TestClassificationWalksTheImportPath is §12.2. The vulnerable module is
// third-party; what makes this a first-party problem is the hop in between.
func TestClassificationWalksTheImportPath(t *testing.T) {
	r := registry(t)

	cases := []struct {
		name string
		path []string
		want string
	}{
		{
			name: "first-party hop between the repository and the vulnerable module",
			path: []string{consumerRepo, sharedModule, "golang.org/x/crypto"},
			want: sharedModule,
		},
		{
			name: "several first-party hops takes the one nearest the consumer",
			path: []string{consumerRepo, sharedModule, "github.com/wanaware/auth", "golang.org/x/crypto"},
			want: sharedModule,
		},
		{
			name: "direct third-party dependency is not first-party",
			path: []string{consumerRepo, "golang.org/x/crypto"},
			want: "",
		},
		{
			name: "the vulnerable module IS the first-party module",
			path: []string{consumerRepo, sharedModule},
			want: sharedModule,
		},
		{
			name: "no path at all",
			path: nil,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := r.ClassifyPath(tc.path)
			if got != tc.want {
				t.Errorf("ClassifyPath(%v) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestTheOwnerIsNotBlockedOnItself is the case that would deadlock the whole
// design. A finding in the OWNING repository must not be classified as
// first-party-blocked: it would be told to wait for an upstream fix that only
// it can make, and nothing would ever unblock it.
func TestTheOwnerIsNotBlockedOnItself(t *testing.T) {
	r := registry(t)

	raw := model.RawFinding{
		Repo: ownerRepo, Category: model.CategoryDependency,
		Module: "golang.org/x/crypto", PrimaryID: "GO-2025-3106",
		ImportPath: []string{ownerRepo, sharedModule, "golang.org/x/crypto"},
	}
	classified := r.Classify(raw)
	if classified.Classification.FirstPartyPath != nil {
		t.Errorf("the owning repository's own finding was classified first-party (%q); it would be told "+
			"to wait for a fix only it can make, and nothing would ever unblock it",
			*classified.Classification.FirstPartyPath)
	}

	// The consumer's identical finding IS classified.
	raw.Repo = consumerRepo
	raw.ImportPath = []string{consumerRepo, sharedModule, "golang.org/x/crypto"}
	classified = r.Classify(raw)
	if classified.Classification.FirstPartyPath == nil {
		t.Fatal("the consumer's finding was not classified first-party")
	}
	if *classified.Classification.FirstPartyPath != sharedModule {
		t.Errorf("first_party_path = %q, want %q", *classified.Classification.FirstPartyPath, sharedModule)
	}
}

// TestClassificationNeverGuesses is the negative half. A module absent from the
// registry is third-party, full stop — inferring first-party membership from a
// path prefix or an organisation name would route a finding to a repository
// that does not own the code, and the owner would have no idea why.
func TestClassificationNeverGuesses(t *testing.T) {
	r := registry(t)
	raw := model.RawFinding{
		Repo: consumerRepo, Category: model.CategoryDependency,
		Module: "golang.org/x/crypto",
		// Plausible, unregistered, and organisationally ours.
		ImportPath: []string{consumerRepo, "github.com/wanaware/not-registered", "golang.org/x/crypto"},
	}
	if got := r.Classify(raw); got.Classification.FirstPartyPath != nil {
		t.Errorf("an unregistered module was classified first-party (%q); the registry is the only "+
			"authority on ownership (VM-F-601)", *got.Classification.FirstPartyPath)
	}
}

// --- The reverse-dependency index (§12.1, VM-F-602) -------------------------

func TestIndexAnswersConsumersFromDependencyManifests(t *testing.T) {
	idx := firstparty.NewIndex(registry(t))
	idx.Add(firstparty.Dependency{Repo: consumerRepo, Module: sharedModule, Version: "v1.4.0"})
	idx.Add(firstparty.Dependency{Repo: "org/wanaware-jobs", Module: sharedModule, Version: "v1.4.0"})
	idx.Add(firstparty.Dependency{Repo: "org/wanaware-web", Module: sharedModule, Version: "v1.2.0"})
	// The owner is not its own consumer.
	idx.Add(firstparty.Dependency{Repo: ownerRepo, Module: sharedModule, Version: "v1.4.0"})
	// An unrelated dependency.
	idx.Add(firstparty.Dependency{Repo: consumerRepo, Module: "golang.org/x/crypto", Version: "v0.35.0"})

	consumers := idx.Consumers(sharedModule)
	var names []string
	for _, c := range consumers {
		names = append(names, c.Repo)
	}
	want := []string{"org/wanaware-api", "org/wanaware-jobs", "org/wanaware-web"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("Consumers = %v, want %v (sorted, and excluding the owner itself)", names, want)
	}

	// VM-F-612: the index is a standing artifact, queryable with no finding in
	// sight, so exposure can be assessed before an advisory arrives.
	if n := len(idx.Consumers("github.com/wanaware/auth")); n != 0 {
		t.Errorf("a module with no consumers reported %d", n)
	}
}

// TestVersionSpreadIsDetectedBeforeDispatch covers VM-F-613. Consumers on
// divergent versions cannot be advanced to one target in a single wave, and
// the spec is explicit about why it matters: discovering it as half a wave of
// failed builds is the failure mode.
func TestVersionSpreadIsDetectedBeforeDispatch(t *testing.T) {
	idx := firstparty.NewIndex(registry(t))
	idx.Add(firstparty.Dependency{Repo: "org/a", Module: sharedModule, Version: "v1.4.0"})
	idx.Add(firstparty.Dependency{Repo: "org/b", Module: sharedModule, Version: "v1.4.0"})
	idx.Add(firstparty.Dependency{Repo: "org/c", Module: sharedModule, Version: "v1.1.0"})
	idx.Add(firstparty.Dependency{Repo: "org/d", Module: sharedModule, Version: "v0.9.0"})

	spread := idx.VersionSpread(sharedModule)
	if len(spread.Versions) != 3 {
		t.Errorf("spread reports %d distinct versions, want 3: %+v", len(spread.Versions), spread.Versions)
	}
	if !spread.Diverged() {
		t.Error("a fleet on three different versions does not read as diverged")
	}
	if spread.Newest != "v1.4.0" {
		t.Errorf("newest = %q, want v1.4.0", spread.Newest)
	}
	// The repositories furthest behind are named, because those are the ones
	// that will fail to build against the target.
	if len(spread.Laggards) == 0 {
		t.Error("the spread names no laggards; a wave would discover them as failed builds")
	}
}

// sleep bounds how long a propagation may take before it is treated as
// looping. Two seconds is generous for a graph of four edges and short enough
// that non-termination is caught rather than waited out.
func sleep() { <-time.After(2 * time.Second) }
