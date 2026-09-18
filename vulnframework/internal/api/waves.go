package api

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// The first-party wave view (VM-UI-F-7xx).
//
// A wave is one root cause with one unblocking action across several
// repositories. The figures that matter are DEPEND and REACH, kept apart: one
// number for both overstates the incident and burns the credibility the next
// real incident needs.

func (s *Server) handleWaves(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// The blocked consumers are the waves in flight: a finding waiting on an
	// upstream first-party fix names the module it is waiting for.
	blocked, err := s.cfg.Store.ListFindings(ctx, store.Query{
		Scope: store.ScopeOpen, States: []model.State{model.BlockedUpstream},
	})
	if err != nil {
		s.failStore(w, r, err)
		return
	}

	if s.cfg.Registry == nil {
		// No registry: the question cannot be answered, and an empty list
		// would answer it with "no waves" — which reads as "no shared
		// modules" rather than "nobody has told the framework which modules
		// are ours".
		s.fail(w, r, http.StatusServiceUnavailable, "no first-party registry",
			"no first-party module registry is configured, so the framework does not know which "+
				"modules this organisation owns and cannot compute waves",
			"configure config/firstparty.yaml; without it, first-party findings are treated as "+
				"ordinary third-party ones (VM-F-601)")
		return
	}
	index, err := s.buildIndex(r)
	if err != nil {
		s.failStore(w, r, err)
		return
	}

	// Keyed by the registered MODULE, not by the classified path.
	//
	// The classifier records the first-party hop nearest the consumer, which
	// is often a subpackage — and a wave keyed by a subpackage finds no
	// consumers, because every manifest row names the module. It would render
	// as a wave affecting nobody, which reads as good news.
	byModule := map[string][]model.Finding{}
	for _, f := range blocked {
		if f.Classification.FirstPartyPath == nil {
			continue
		}
		module, ok := s.cfg.Registry.Module(*f.Classification.FirstPartyPath)
		if !ok {
			// Classified against a registry that no longer lists the module.
			// Skipped loudly rather than shown under a key nothing matches.
			s.log.Warn("api: a blocked finding names a module the registry no longer lists",
				"finding", f.Fingerprint, "path", *f.Classification.FirstPartyPath)
			continue
		}
		byModule[module] = append(byModule[module], f)
	}

	out := []Wave{}
	modules := make([]string, 0, len(byModule))
	for m := range byModule {
		modules = append(modules, m)
	}
	sort.Strings(modules)

	for _, module := range modules {
		wave := Wave{Module: module, Trigger: s.trigger(), Consumers: []Consumer{}}
		if owner, ok := index.Owner(module); ok {
			wave.OwnerRepo = owner
		}

		// The upstream finding, from the consumers' own references: a
		// consumer records what it is blocked by (VM-F-604).
		for _, f := range byModule[module] {
			if f.Refs.UpstreamFinding != nil && *f.Refs.UpstreamFinding != "" {
				wave.UpstreamFP = *f.Refs.UpstreamFinding
				break
			}
		}
		if wave.UpstreamFP != "" {
			if up, err := s.cfg.Store.GetFinding(ctx, wave.UpstreamFP); err == nil {
				wave.UpstreamState = string(up.State)
				if pr, ok, err := s.cfg.Store.RemediationPRForFinding(ctx, up.Fingerprint); err == nil && ok {
					wave.Wave1PR = pr.URL
					at := pr.OpenedAt
					wave.Wave1PRAt = &at
					wave.Wave1AgeHours = s.now().Sub(at).Hours()
				}
			}
		}

		// Reachability per consumer, from the consumers' own findings. The
		// tri-state is preserved: a consumer nobody has determined is UNKNOWN,
		// which is neither reached nor safe (VM-UI-F-707).
		reach := map[string]string{}
		for _, f := range byModule[module] {
			reach[f.Repo] = string(reachableOrUnknown(f.Classification.Reachable))
		}
		radius := index.BlastRadius(module, reach)
		wave.DependCount, wave.ReachCount, wave.UnknownCount = radius.Depend, radius.Reach, radius.Unknown

		for _, c := range index.Consumers(module) {
			out := Consumer{
				Repo: c.Repo, Version: c.Version, Replaced: c.Replaced,
				Reachable: orDefault(reach[c.Repo], string(model.ReachableUnknown)),
				Reason:    c.Reason,
			}
			if repo, err := s.cfg.Store.GetRepo(ctx, c.Repo); err == nil {
				out.Tier = repo.Tier
			}
			if c.Replaced {
				// Shown WITHIN the wave, not omitted (VM-UI-F-704, VM-UI-F-710).
				out.Excluded = true
				if out.Reason == "" {
					out.Reason = "excluded: a replace directive points this consumer at a local " +
						"path, so bumping the version would not change what it builds (VM-F-608)"
				}
			}
			wave.Consumers = append(wave.Consumers, out)
		}

		spread := index.VersionSpread(module)
		wave.VersionSpread = map[string]int{}
		for _, c := range index.Consumers(module) {
			if c.Version != "" {
				wave.VersionSpread[c.Version]++
			}
		}
		wave.Steps = emptyIfNil(waveSteps(wave, spread, s.trigger()))
		out2 := wave
		out = append(out, out2)
	}
	s.write(w, r, http.StatusOK, out)
}

// trigger is the configured wave-two trigger.
func (s *Server) trigger() string {
	if s.cfg.Wave2Trigger != "" {
		return s.cfg.Wave2Trigger
	}
	return "merge"
}

// waveSteps enumerates what clears the wave, in order (VM-UI-F-709).
func waveSteps(wave Wave, spread firstparty.Spread, trigger string) []string {
	steps := []string{
		fmt.Sprintf("1. the upstream fix lands in %s (wave 1)", orDefault(wave.OwnerRepo, "the owning repository")),
	}
	if trigger == "tag" {
		// Called out, because with a tag trigger a merge is NOT sufficient and
		// a reader who stops at the merge will believe the wave is done.
		steps = append(steps,
			"2. the owning repository publishes a TAG. With trigger=tag a merge is not enough: "+
				"nothing propagates until the version exists for consumers to resolve")
	} else {
		steps = append(steps, "2. the upstream pull request merges (trigger=merge)")
	}
	steps = append(steps,
		fmt.Sprintf("3. %d consumers are bumped to the fixed version (wave 2)", wave.DependCount))
	if len(wave.VersionSpread) > 1 {
		steps = append(steps,
			fmt.Sprintf("NOTE: consumers are on %d different versions (%v), which may prevent a "+
				"single-target wave — laggards need a larger jump and may not build",
				len(wave.VersionSpread), spread.Versions))
	}
	excluded := 0
	for _, c := range wave.Consumers {
		if c.Excluded {
			excluded++
		}
	}
	if excluded > 0 {
		steps = append(steps,
			fmt.Sprintf("4. %d excluded consumers need a person: a wave cannot advance them and "+
				"they are waiting for a fix that has already shipped (VM-AD §6.1.4)", excluded))
	}
	return steps
}

// buildIndex loads the reverse-dependency index the wave view reads.
//
// From the CONFIGURED registry and the scanner-written dependency rows — the
// same two inputs the wave planner uses, so the view cannot show a wave the
// planner would not plan.
func (s *Server) buildIndex(r *http.Request) (*firstparty.Index, error) {
	return firstparty.LoadIndex(r.Context(), s.cfg.Store, s.cfg.Registry)
}
