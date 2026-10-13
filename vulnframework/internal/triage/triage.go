// Package triage enriches new findings with model-produced narrative
// (VM-AD §9).
//
// Everything mechanical stays out of here. Triage produces a description, an
// impact statement and a remediation recommendation; priority is arithmetic and
// belongs to internal/score (VM-F-305), and no suppression is ever applied —
// only nominated (VM-F-307).
//
// All scanner output, advisory text and repository content consumed here is
// untrusted data. Text inside a finding that looks like an instruction is data,
// not an instruction (VM-F-309), and the validator below is what enforces that
// rather than the prompt.
package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
)

// BatchSize bounds one request (VM-AD §9.1).
//
// Per-finding calls are non-compliant (VM-F-308) and roughly an order of
// magnitude more expensive: the static system prompt and repository profile are
// re-sent for every finding instead of being cached once per batch.
const (
	MinBatchSize = 40
	MaxBatchSize = 60
)

// RepoProfile is the context a batch carries. No repository source is sent
// (VM-AD §9.2) — only the shape of the repository.
type RepoProfile struct {
	Repo           string   `json:"repo"`
	Languages      []string `json:"languages"`
	Tier           int      `json:"tier"`
	HasTestSuite   bool     `json:"has_test_suite"`
	ModuleTopology string   `json:"module_topology,omitempty"`
}

// Request is one batched triage call.
type Request struct {
	System   string      `json:"system"`
	Profile  RepoProfile `json:"profile"`
	Findings []Item      `json:"findings"`
	Model    string      `json:"model"`
}

// Item is one finding as presented to the model. It carries identity and
// classification, never a secret value (VM-F-263) and never repository source.
type Item struct {
	Fingerprint string   `json:"fingerprint"`
	Category    string   `json:"category"`
	PrimaryID   string   `json:"primary_id,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	Module      string   `json:"module,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
	File        string   `json:"file,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Reachable   string   `json:"reachable,omitempty"`
	Current     string   `json:"current_version,omitempty"`
	Fixed       string   `json:"fixed_version,omitempty"`
	Summary     string   `json:"summary,omitempty"`
}

// Verdict is the model's output for one finding (VM-AD §9.2).
//
// There is deliberately no priority field: priority is computed by
// internal/score, not produced by inference (VM-F-305, VM-AD §9.2). A verdict
// that tried to supply one would be rejected as an unknown field.
type Verdict struct {
	Fingerprint            string  `json:"fingerprint"`
	Description            string  `json:"description"`
	Impact                 string  `json:"impact"`
	Remediation            string  `json:"remediation"`
	FalsePositiveCandidate bool    `json:"false_positive_candidate"`
	FPReasoning            *string `json:"fp_reasoning"`
	Confidence             string  `json:"confidence"`
}

// Client is the inference boundary.
//
// It is an interface so the whole package runs offline against a fake, with no
// credentials and no network — the standing requirement for every external
// system in this build.
type Client interface {
	Triage(ctx context.Context, req Request) ([]Verdict, error)
}

// Cache stores verdicts by fingerprint (VM-F-306).
//
// An unchanged finding is not re-triaged on a subsequent run: the narrative for
// a fingerprint does not change unless the finding does, and re-triaging the
// whole fleet every sweep is the single largest avoidable cost in the pipeline.
type Cache interface {
	Get(ctx context.Context, fingerprint string) (model.Triage, bool, error)
	Put(ctx context.Context, fingerprint string, t model.Triage) error
}

// Triager batches, validates and caches triage.
type Triager struct {
	Client Client
	Cache  Cache
	Model  string
	Clock  func() time.Time

	// Unavailable, when set, says why no narrative can be produced — no
	// credential, inference not enabled — and Run makes no inference call.
	// Findings still advance: the run is never blocked on triage (VM-AD §9.3),
	// so a finding is scored and routed with no narrative rather than held in
	// DETECTED, and nothing is written in place of the narrative. The reason
	// is carried in Stats.Unavailable so the run can say it.
	Unavailable string
}

// Stats summarises a triage pass.
type Stats struct {
	// Eligible counts findings in a triage-eligible state.
	Eligible int
	// Cached counts findings skipped because a verdict already existed
	// (VM-F-306).
	Cached int
	// Requested counts findings actually sent for inference.
	Requested int
	// Batches counts inference calls made.
	Batches int
	// Validated counts verdicts accepted.
	Validated int
	// Rejected counts verdicts refused by validation.
	Rejected int
	// Retried counts findings re-sent after a first-pass mismatch.
	Retried int
	// Unresolved counts findings marked triaged with a null verdict after two
	// failures — the run is never blocked on triage (VM-AD §9.3).
	Unresolved []string
	// Unavailable is Triager.Unavailable when it applied: every finding not
	// already cached is Unresolved because no inference was attempted, not
	// because inference failed.
	Unavailable string `json:",omitempty"`
}

// Eligible reports whether a finding's state admits triage.
//
// Triage runs on DETECTED and REGRESSED only (VM-AD §9.1). A finding already in
// flight or already decided is not re-narrated.
func Eligible(state model.State) bool {
	return state == model.Detected || state == model.Regressed
}

// Batches splits items into compliant batch sizes.
//
// The last batch may be smaller than MinBatchSize — there is no way to avoid
// that with a finite input — but no batch exceeds MaxBatchSize, which is the
// bound that matters for context and cost.
func Batches(items []Item) [][]Item {
	if len(items) == 0 {
		return nil
	}
	var out [][]Item
	for i := 0; i < len(items); i += MaxBatchSize {
		end := i + MaxBatchSize
		if end > len(items) {
			end = len(items)
		}
		out = append(out, items[i:end])
	}
	return out
}

// Run triages a batch of findings, returning verdicts by fingerprint.
//
// On a validation mismatch it retries once with the unmatched subset; on a
// second failure those findings are marked triaged with a null verdict rather
// than blocking the run (VM-AD §9.3). A run that stalls because a model returned
// malformed JSON is worse than a run with some un-narrated findings: the
// findings themselves are already detected, scored and routable.
func (t *Triager) Run(ctx context.Context, profile RepoProfile, items []Item) (map[string]model.Triage, Stats, error) {
	stats := Stats{Eligible: len(items)}
	out := map[string]model.Triage{}

	// Cache first (VM-F-306).
	var pending []Item
	for _, it := range items {
		if t.Cache != nil {
			cached, ok, err := t.Cache.Get(ctx, it.Fingerprint)
			if err != nil {
				return nil, stats, fmt.Errorf("triage cache: %w", err)
			}
			if ok {
				out[it.Fingerprint] = cached
				stats.Cached++
				continue
			}
		}
		pending = append(pending, it)
	}

	if t.Unavailable != "" {
		stats.Unavailable = t.Unavailable
		for _, it := range pending {
			stats.Unresolved = append(stats.Unresolved, it.Fingerprint)
		}
		sort.Strings(stats.Unresolved)
		return out, stats, nil
	}
	if t.Client == nil {
		return nil, stats, fmt.Errorf("triage: no client, and no reason given for its absence")
	}
	stats.Requested = len(pending)

	for _, batch := range Batches(pending) {
		verdicts, rejected, err := t.callAndValidate(ctx, profile, batch)
		stats.Batches++
		if err != nil {
			return nil, stats, err
		}
		stats.Rejected += rejected

		// Retry once with whatever came back unmatched (VM-AD §9.3).
		var missing []Item
		for _, it := range batch {
			if _, ok := verdicts[it.Fingerprint]; !ok {
				missing = append(missing, it)
			}
		}
		if len(missing) > 0 {
			stats.Retried += len(missing)
			retryVerdicts, retryRejected, err := t.callAndValidate(ctx, profile, missing)
			stats.Batches++
			if err != nil {
				return nil, stats, err
			}
			stats.Rejected += retryRejected
			for fp, v := range retryVerdicts {
				verdicts[fp] = v
			}
		}

		now := t.now()
		for _, it := range batch {
			v, ok := verdicts[it.Fingerprint]
			if !ok {
				// Second failure: proceed without a narrative rather than
				// blocking the run.
				stats.Unresolved = append(stats.Unresolved, it.Fingerprint)
				continue
			}
			tr := model.Triage{
				Description:            v.Description,
				Impact:                 v.Impact,
				Remediation:            v.Remediation,
				FalsePositiveCandidate: v.FalsePositiveCandidate,
				FPReasoning:            v.FPReasoning,
				TriagedAt:              &now,
				Model:                  t.Model,
			}
			out[it.Fingerprint] = tr
			stats.Validated++
			if t.Cache != nil {
				if err := t.Cache.Put(ctx, it.Fingerprint, tr); err != nil {
					return nil, stats, fmt.Errorf("triage cache: %w", err)
				}
			}
		}
	}

	sort.Strings(stats.Unresolved)
	return out, stats, nil
}

// callAndValidate makes one inference call and validates its response.
func (t *Triager) callAndValidate(ctx context.Context, profile RepoProfile, batch []Item) (map[string]Verdict, int, error) {
	req := Request{
		System:   SystemPrompt,
		Profile:  profile,
		Findings: batch,
		Model:    t.Model,
	}
	raw, err := t.Client.Triage(ctx, req)
	if err != nil {
		return nil, 0, fmt.Errorf("triage: inference: %w", err)
	}
	accepted, rejected := Validate(batch, raw)
	return accepted, rejected, nil
}

func (t *Triager) now() time.Time {
	if t.Clock != nil {
		return t.Clock().UTC()
	}
	return time.Now().UTC()
}

// ItemFrom builds a triage item from a stored finding.
//
// It is the redaction boundary for triage: a secret finding contributes its
// detector rule and path, never a value, because there is no value in the
// record to contribute (VM-F-263).
func ItemFrom(f model.Finding) Item {
	it := Item{
		Fingerprint: f.Fingerprint,
		Category:    string(f.Category),
		PrimaryID:   f.Identity.PrimaryID,
		Aliases:     f.Identity.Aliases,
		Module:      f.Location.Module,
		Severity:    string(f.Classification.Severity),
		Reachable:   string(f.Classification.Reachable),
		Current:     f.Versions.Current,
		Fixed:       f.Versions.Fixed,
	}
	if f.Identity.RuleID != nil {
		it.RuleID = *f.Identity.RuleID
	}
	if f.Location.File != nil {
		it.File = *f.Location.File
	}
	return it
}

// identifiers returns every identifier a batch legitimately contains, upper
// cased, for the fabrication check.
func identifiers(batch []Item) map[string]bool {
	ids := map[string]bool{}
	add := func(s string) {
		if s = strings.ToUpper(strings.TrimSpace(s)); s != "" {
			ids[s] = true
		}
	}
	for _, it := range batch {
		add(it.PrimaryID)
		for _, a := range it.Aliases {
			add(a)
		}
		add(it.RuleID)
		add(it.Module)
		add(it.Fixed)
		add(it.Current)
	}
	return ids
}

// MarshalRequest renders a request as the JSON a client would send, for
// inspection and for fixture tests.
func MarshalRequest(req Request) ([]byte, error) {
	return json.MarshalIndent(req, "", "  ")
}
