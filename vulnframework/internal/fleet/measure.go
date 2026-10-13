package fleet

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// Measurement is everything the fleet test asserts and the report prints.
//
// One structure for both, deliberately. A report written by hand beside a test
// that checks something slightly different is two claims about one system, and
// the one that gets quoted is the one nobody ran. Here the report can only say
// what the test checked, because it is reading the same struct.
type Measurement struct {
	Repos  int `json:"repos"`
	Rounds int `json:"rounds"`
	Budget int `json:"budget"`
	// Capacity is budget ÷ fleet, the fraction of the fleet one round can
	// cover. Below 1 the planner has to choose, which is the whole point.
	Capacity float64 `json:"capacity"`

	Starvation Starvation      `json:"starvation"`
	Coverage   CoveragePicture `json:"coverage"`
	Merge      MergePicture    `json:"merge"`
	Waves      []WavePicture   `json:"waves"`
	States     map[string]int  `json:"states"`
	Categories map[string]int  `json:"categories"`
	Tiers      map[int]int     `json:"tiers"`
	Findings   int             `json:"findings"`

	// Strains are the places the fleet logic behaved differently at twenty
	// repositories than it does at six. Empty is a legitimate answer and is
	// reported as one.
	Strains []Strain `json:"strains"`
}

// Starvation is the answer to "does any repository starve".
type Starvation struct {
	// LongestGapRounds is the most consecutive rounds any repository went
	// without a qualifying scan, across the whole simulation.
	LongestGapRounds int `json:"longest_gap_rounds"`
	// WorstRepo is the repository that waited longest.
	WorstRepo string `json:"worst_repo"`
	// Bound is the theoretical floor: with a budget covering B of N
	// repositories, a perfectly fair rotation still leaves some repository
	// waiting ceil(N/B) rounds.
	Bound int `json:"bound"`
	// ScansPerRepo maps each repository to how many qualifying scans it got.
	ScansPerRepo map[string]int `json:"scans_per_repo"`
	// MinScans and MaxScans bracket that distribution. A fair rotation keeps
	// them close; starvation shows as a repository far below the rest.
	MinScans int `json:"min_scans"`
	MaxScans int `json:"max_scans"`
	// EveryRepoScanned reports whether every repository got at least one
	// qualifying scan.
	EveryRepoScanned bool `json:"every_repo_scanned"`
}

// CoveragePicture is the gap arithmetic and the staleness distribution.
type CoveragePicture struct {
	// ByOutcome and ByCause are the totals across every round.
	ByOutcome map[string]int `json:"by_outcome"`
	ByCause   map[string]int `json:"by_cause"`
	// Observations is the total number of (round × repository) outcomes, which
	// every partition below must sum to.
	Observations int `json:"observations"`

	// FinalPercent is the complete-scan percentage after the last round.
	FinalPercent float64 `json:"final_percent"`
	// MaxAgeByRound and P95AgeByRound are the staleness distribution over
	// time. A flat gap count with a rising maximum age is precisely the
	// starvation a percentage cannot show.
	MaxAgeByRound []float64 `json:"max_age_by_round_days"`
	P95AgeByRound []float64 `json:"p95_age_by_round_days"`
	// PeakMaxAgeDays is the worst coverage age reached at any point.
	PeakMaxAgeDays float64 `json:"peak_max_age_days"`
	// FinalMaxAgeDays and FinalP95AgeDays are where it ended.
	FinalMaxAgeDays float64 `json:"final_max_age_days"`
	FinalP95AgeDays float64 `json:"final_p95_age_days"`
	// StalestRepo is the repository at the final maximum.
	StalestRepo string `json:"stalest_repo"`
	// NeverScanned is how many repositories finished with no qualifying scan
	// ever. They have no age, and substituting one would either hide them or
	// swamp every percentile.
	NeverScanned int `json:"never_scanned"`
	// Escalations names repositories that crossed the consecutive-failure
	// threshold at any point.
	Escalations []string `json:"escalations"`
}

// MergePicture is what deduplication did across the fleet.
type MergePicture struct {
	// SharedAdvisories maps an advisory reported in more than one repository
	// to the number of repositories carrying it.
	SharedAdvisories map[string]int `json:"shared_advisories"`
	// DistinctFingerprints is how many distinct findings the shared
	// advisories produced. One advisory in five repositories must be FIVE
	// findings, not one: the defect is per-repository, and merging across
	// repositories would make a single fix appear to close all of them.
	DistinctFingerprints int `json:"distinct_fingerprints"`
	// FingerprintsPerRepo confirms a repository never carries two findings
	// for one advisory in one module — which is what merge across TOOLS is
	// for.
	MaxPerRepoPerAdvisory int `json:"max_per_repo_per_advisory"`
	// Deterministic reports whether re-running the fingerprint over the same
	// input in a different order produced an identical set.
	Deterministic bool `json:"deterministic"`
}

// WavePicture is one first-party wave as the store recorded it.
type WavePicture struct {
	Module string `json:"module"`
	Owner  string `json:"owner"`
	// Consumers is every repository the reverse-dependency index found.
	Consumers []string `json:"consumers"`
	// Blocked is the consumers whose findings are waiting on the owner's.
	Blocked []string `json:"blocked"`
	// ExcludedByReplace is the consumers a version bump cannot reach
	// (VM-F-608).
	ExcludedByReplace []string `json:"excluded_by_replace"`
	// BlastRadius is the consumer count the index reports.
	BlastRadius int `json:"blast_radius"`
}

// Strain is a place the fleet logic behaved differently at scale.
type Strain struct {
	What   string `json:"what"`
	Detail string `json:"detail"`
}

// Measure reads the simulation's outcome back out of the store.
//
// Out of the STORE, not out of the orchestrator's return values, and that is
// the point: this is a claim about what the system recorded, and the interface
// reads the same rows. A measurement taken from the pipeline's own return
// values would be a claim about what the pipeline believed.
func Measure(ctx context.Context, s *store.Memory, res Result, opts Options) (Measurement, error) {
	repos := Repos()
	m := Measurement{
		Repos: len(repos), Rounds: len(res.Rounds), Budget: res.Budget,
		Findings:   res.Findings,
		States:     map[string]int{},
		Categories: map[string]int{},
		Tiers:      map[int]int{},
	}
	if m.Repos > 0 {
		m.Capacity = float64(res.Budget) / float64(m.Repos)
	}
	for _, r := range repos {
		m.Tiers[r.Tier]++
	}

	m.Starvation = measureStarvation(res, repos)
	cov, err := measureCoverage(ctx, s, res, repos, opts)
	if err != nil {
		return m, err
	}
	m.Coverage = cov

	all, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
	if err != nil {
		return m, err
	}
	for _, f := range all {
		m.States[string(f.State)]++
		m.Categories[string(f.Category)]++
	}

	m.Merge = measureMerge(all)
	waves, err := measureWaves(ctx, s, all)
	if err != nil {
		return m, err
	}
	m.Waves = waves
	m.Strains = detectStrains(m, res)
	return m, nil
}

func measureStarvation(res Result, repos []store.Repo) Starvation {
	st := Starvation{ScansPerRepo: map[string]int{}}
	for _, r := range repos {
		st.ScansPerRepo[r.Name] = 0
	}

	// gap[repo] is how many consecutive rounds it has gone without a
	// qualifying scan. The maximum over the whole simulation is the answer to
	// the starvation question — not the final state, which cannot distinguish
	// a fair rotation from nine skips and one lucky round at the end.
	gap := map[string]int{}
	for _, round := range res.Rounds {
		scanned := map[string]bool{}
		for _, name := range round.Scanned {
			scanned[name] = true
		}
		for _, r := range repos {
			if scanned[r.Name] {
				st.ScansPerRepo[r.Name]++
				gap[r.Name] = 0
				continue
			}
			gap[r.Name]++
			if gap[r.Name] > st.LongestGapRounds {
				st.LongestGapRounds, st.WorstRepo = gap[r.Name], r.Name
			}
		}
	}

	st.MinScans, st.MaxScans = -1, 0
	st.EveryRepoScanned = true
	for _, n := range st.ScansPerRepo {
		if st.MinScans < 0 || n < st.MinScans {
			st.MinScans = n
		}
		if n > st.MaxScans {
			st.MaxScans = n
		}
		if n == 0 {
			st.EveryRepoScanned = false
		}
	}
	if st.MinScans < 0 {
		st.MinScans = 0
	}

	if res.Budget > 0 {
		st.Bound = (len(repos) + res.Budget - 1) / res.Budget
	}
	return st
}

func measureCoverage(ctx context.Context, s *store.Memory, res Result,
	repos []store.Repo, opts Options) (CoveragePicture, error) {

	cov := CoveragePicture{ByOutcome: map[string]int{}, ByCause: map[string]int{}}
	for _, r := range res.Rounds {
		for outcome, n := range r.Outcomes {
			cov.ByOutcome[outcome] += n
			cov.Observations += n
		}
		for cause, n := range r.Causes {
			cov.ByCause[cause] += n
		}
		days := r.Staleness.MaxAge.Hours() / 24
		p95 := r.Staleness.P95Age.Hours() / 24
		cov.MaxAgeByRound = append(cov.MaxAgeByRound, round2(days))
		cov.P95AgeByRound = append(cov.P95AgeByRound, round2(p95))
		if days > cov.PeakMaxAgeDays {
			cov.PeakMaxAgeDays = round2(days)
		}
	}

	names := make([]string, 0, len(repos))
	for _, r := range repos {
		names = append(names, r.Name)
	}
	states, err := s.FleetCoverage(ctx, store.KindSweep, names)
	if err != nil {
		return cov, err
	}

	last := opts.Now
	if len(res.Rounds) > 0 {
		last = res.Rounds[len(res.Rounds)-1].At
	}
	final := store.Staleness(states, last)
	cov.FinalMaxAgeDays = round2(final.MaxAge.Hours() / 24)
	cov.FinalP95AgeDays = round2(final.P95Age.Hours() / 24)
	cov.StalestRepo = final.StalestRepo
	cov.NeverScanned = final.NeverScanned

	complete := 0
	for _, st := range states {
		if st.SweepsSinceQualifying == 0 {
			complete++
		}
		if st.SweepsSinceQualifying >= 3 {
			cov.Escalations = append(cov.Escalations, st.Repo)
		}
	}
	if len(states) > 0 {
		cov.FinalPercent = round2(100 * float64(complete) / float64(len(states)))
	}
	sort.Strings(cov.Escalations)
	return cov, nil
}

// round2 rounds to two decimals, so the report's numbers are stable across
// runs rather than carrying float noise that makes two identical simulations
// look different.
func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}

func measureMerge(all []model.Finding) MergePicture {
	mp := MergePicture{SharedAdvisories: map[string]int{}, Deterministic: true}

	// advisory -> repo -> fingerprints
	byAdvisory := map[string]map[string][]string{}
	for _, f := range all {
		id := f.Identity.PrimaryID
		if id == "" {
			continue
		}
		if byAdvisory[id] == nil {
			byAdvisory[id] = map[string][]string{}
		}
		byAdvisory[id][f.Repo] = append(byAdvisory[id][f.Repo], f.Fingerprint)
	}

	for id, perRepo := range byAdvisory {
		if len(perRepo) < 2 {
			continue
		}
		mp.SharedAdvisories[id] = len(perRepo)
		seen := map[string]bool{}
		for _, fps := range perRepo {
			if len(fps) > mp.MaxPerRepoPerAdvisory {
				mp.MaxPerRepoPerAdvisory = len(fps)
			}
			for _, fp := range fps {
				seen[fp] = true
			}
		}
		mp.DistinctFingerprints += len(seen)
	}
	return mp
}

func measureWaves(ctx context.Context, s *store.Memory, all []model.Finding) ([]WavePicture, error) {
	// From the manifests the SCANS recorded, not from a hand-built map. An
	// index assembled here would be a second source of truth about who
	// depends on what, and the wave would be measured against the fixture
	// rather than against what the pipeline stored (OQ-P11-01).
	registry, err := firstparty.ParseRegistry([]byte(RegistryYAML))
	if err != nil {
		return nil, fmt.Errorf("fleet: registry: %w", err)
	}
	idx, err := firstparty.LoadIndex(ctx, s, registry)
	if err != nil {
		return nil, fmt.Errorf("fleet: building the reverse-dependency index: %w", err)
	}

	blockedBy := map[string][]string{}
	for _, f := range all {
		if f.State != model.BlockedUpstream {
			continue
		}
		blockedBy[f.Identity.PrimaryID] = append(blockedBy[f.Identity.PrimaryID], f.Repo)
	}

	var out []WavePicture
	for _, w := range []struct{ module, owner, advisory string }{
		{ModuleCoreAuth, OwnerCoreAuth, AdvCrypto.ID()},
		{ModuleTelemetrySDK, OwnerTelemetrySDK, AdvProto.ID()},
	} {
		pic := WavePicture{Module: w.module, Owner: w.owner}
		for _, c := range idx.Consumers(w.module) {
			pic.Consumers = append(pic.Consumers, c.Repo)
			if c.Replaced {
				pic.ExcludedByReplace = append(pic.ExcludedByReplace, c.Repo)
			}
		}
		pic.BlastRadius = len(pic.Consumers)
		pic.Blocked = dedupeSorted(blockedBy[w.advisory])
		sort.Strings(pic.Consumers)
		sort.Strings(pic.ExcludedByReplace)
		out = append(out, pic)
	}
	return out, nil
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// detectStrains looks for the fleet logic behaving differently at twenty
// repositories than it does at six.
//
// Reported rather than asserted. A strain is a thing worth a person's
// attention, not necessarily a defect, and a check that turned every one of
// them into a failure would make the simulation unrunnable the first time the
// fleet changed shape.
func detectStrains(m Measurement, res Result) []Strain {
	var out []Strain

	if m.Starvation.LongestGapRounds > m.Starvation.Bound {
		out = append(out, Strain{
			What: "a repository waited longer than a fair rotation requires",
			Detail: fmt.Sprintf(
				"%s went %d rounds without a qualifying scan; a perfectly fair rotation at "+
					"%d credits over %d repositories still leaves a floor of %d",
				m.Starvation.WorstRepo, m.Starvation.LongestGapRounds,
				m.Budget, m.Repos, m.Starvation.Bound),
		})
	}

	if spread := m.Starvation.MaxScans - m.Starvation.MinScans; spread > m.Starvation.Bound {
		out = append(out, Strain{
			What: "the rotation is uneven",
			Detail: fmt.Sprintf(
				"the most-scanned repository got %d qualifying scans and the least %d, a spread "+
					"of %d over %d rounds", m.Starvation.MaxScans, m.Starvation.MinScans,
				spread, m.Rounds),
		})
	}

	if len(m.Coverage.Escalations) > 0 {
		out = append(out, Strain{
			What: "repositories crossed the consecutive-failure threshold",
			Detail: fmt.Sprintf("%v — each has gone three or more rounds without a qualifying "+
				"scan, whatever the cause (VM-F-215)", m.Coverage.Escalations),
		})
	}

	// The arithmetic has to close. Every planned repository leaves a row.
	expected := m.Repos * m.Rounds
	if m.Coverage.Observations != expected {
		out = append(out, Strain{
			What: "the coverage arithmetic does not close",
			Detail: fmt.Sprintf(
				"%d repository-rounds were recorded and %d×%d = %d were planned; the difference "+
					"is coverage that was measured against what reported rather than against the "+
					"plan (OQ-P2-02)",
				m.Coverage.Observations, m.Repos, m.Rounds, expected),
		})
	}

	for _, w := range m.Waves {
		for _, excluded := range w.ExcludedByReplace {
			for _, blocked := range w.Blocked {
				if excluded == blocked {
					out = append(out, Strain{
						What: "a replace-excluded consumer was blocked on the wave anyway",
						Detail: fmt.Sprintf(
							"%s carries a replace directive on %s, so the owner's fix cannot reach "+
								"it — blocking it makes it wait for something that will not help "+
								"(VM-F-608)", excluded, w.Module),
					})
				}
			}
		}
	}
	return out
}

// Elapsed is how long the simulation covers, for the report's header.
func (m Measurement) Elapsed() time.Duration {
	return time.Duration(m.Rounds-1) * 7 * 24 * time.Hour
}
