package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/tracker"
)

// TicketRequest is one repository's ticket pass.
type TicketRequest struct {
	Repo    store.Repo
	RunID   string
	Service *tracker.Service
	Policy  *policy.Engine
	View    policy.StoreView

	// ReportURL is the link every ticket must carry (VM-F-809).
	ReportURL string
}

// TicketStats is what a ticket pass did.
type TicketStats struct {
	ParentCreated int
	OwnTickets    int
	PRTickets     int
	Reopened      int
	Closed        int
	// Aggregated is what went into the run parent instead of its own ticket
	// (VM-F-808). Reported so a caller can see that "not ticketed" is not the
	// same as "not recorded".
	Aggregated []tracker.AggregateRow
	// Drained counts queued operations replayed this pass (VM-F-812).
	Drained int
	// Failed counts subjects whose ticket operation was queued rather than
	// applied. Not an error: the run continues.
	Failed int
}

// TicketPass creates and maintains a repository's tickets for one run.
//
// The ordering is deliberate. The DRAIN runs first, so a backlog from an
// earlier outage is cleared before new work is added to it — and so recovery
// needs no human action at all, which is the whole of OQ-P8-02. A queue that
// only drains when someone remembers to call a command is a queue that grows.
func (o *Orchestrator) TicketPass(ctx context.Context, req TicketRequest) (TicketStats, error) {
	var stats TicketStats
	if req.Service == nil {
		return stats, fmt.Errorf("orchestrator: a ticket pass needs a tracker service")
	}
	if req.ReportURL == "" {
		// Every ticket must link its report (VM-F-809); refusing here is
		// better than emitting tickets that cannot be traced back.
		return stats, fmt.Errorf("orchestrator: a ticket pass needs a report URL (VM-F-809)")
	}
	now := o.clock()

	// 1. Drain first. Automatic recovery, no manual step (OQ-P8-02).
	drained, err := req.Service.Drain(ctx, now, 100)
	if err != nil {
		return stats, err
	}
	stats.Drained = drained

	open, err := o.Store.ListFindings(ctx, store.Query{Scope: store.ScopeOpen, Repo: req.Repo.Name})
	if err != nil {
		return stats, err
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Fingerprint < open[j].Fingerprint })

	pr := policy.Repo{
		Name: req.Repo.Name, Tier: req.Repo.Tier,
		Language:     policy.Language(primaryLanguage(req.Repo)),
		HasTestSuite: req.Repo.HasTestSuite,
	}

	// 2. The run parent, before the children, so children can link to it.
	parent, err := o.ensureRunParent(ctx, req, &stats)
	if err != nil {
		return stats, err
	}

	// 3. Per finding: its own ticket, or a line in the parent's aggregate.
	aggregate := map[model.Priority]int{}
	for _, f := range open {
		outcome, ok := o.outcomeFor(f, pr, req)
		if !ok {
			continue
		}

		if f.State == model.Regressed {
			// A recurrence reopens the original rather than opening a second
			// ticket (VM-F-806).
			if _, err := req.Service.Reopen(ctx, f); err != nil {
				return stats, err
			}
			stats.Reopened++
		}

		if !tracker.NeedsOwnTicket(f, outcome) {
			// Not ticketed is not the same as not recorded: it goes into the
			// parent's aggregated table (VM-F-808).
			if model.PartitionOf(f.State) != model.PartitionResolved {
				aggregate[f.Priority]++
			}
			continue
		}

		spec, err := tracker.SpecFor(f, tracker.SpecOptions{
			ReportURL: req.ReportURL,
			Assignee:  assigneeFor(req.Repo),
			Parent:    parentRef(parent),
		})
		if err != nil {
			return stats, err
		}
		ref, created, err := req.Service.Ensure(ctx, spec)
		if err != nil {
			return stats, err
		}
		if ref.Zero() {
			// Queued behind an outage. The run continues (VM-F-812).
			stats.Failed++
			continue
		}
		if created {
			stats.OwnTickets++
		}
		if parent != nil && !parent.Zero() {
			if err := req.Service.Tracker.Link(ctx, ref, *parent); err != nil {
				// A missing link is a navigation loss, not a correctness one:
				// recorded, never fatal.
				stats.Failed++
			}
		}
	}

	// 4. The pull request's own ticket (§13.3 row 2).
	prTickets, err := o.ensurePRTickets(ctx, req, parent)
	if err != nil {
		return stats, err
	}
	stats.PRTickets = prTickets

	// 5. Update the parent with what was aggregated into it.
	stats.Aggregated = aggregateRows(req.Repo.Name, aggregate)
	if parent != nil && !parent.Zero() {
		body := tracker.RunParentBody(tracker.RunSummary{
			RunID: req.RunID, ReportURL: req.ReportURL,
			Counts:     map[string]int{"open findings": len(open), "individually ticketed": stats.OwnTickets},
			Aggregated: stats.Aggregated,
		})
		if err := req.Service.Tracker.Comment(ctx, *parent, body); err != nil {
			stats.Failed++
		}
	}
	return stats, nil
}

// ensureRunParent creates the run's parent ticket, once per run.
//
// Once per RUN, not once per repository: the parent carries that run's counts
// and deltas, and a parent shared across runs would attribute one run's numbers
// to another.
func (o *Orchestrator) ensureRunParent(ctx context.Context, req TicketRequest, stats *TicketStats) (*tracker.Ref, error) {
	existing, ok, err := o.Store.GetRunTicket(ctx, req.RunID)
	if err != nil {
		return nil, err
	}
	if ok {
		return &tracker.Ref{Backend: existing.Backend, ID: existing.Ref, URL: existing.URL}, nil
	}

	spec := tracker.Spec{
		Fingerprint: "run:" + req.RunID,
		Title:       "Security run " + req.RunID,
		Body: tracker.RunParentBody(tracker.RunSummary{
			RunID: req.RunID, ReportURL: req.ReportURL,
		}),
		Repo:      req.Repo.Name,
		ReportURL: req.ReportURL,
		Labels:    []string{"vf", "vf-run"},
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	ref, err := req.Service.Tracker.Create(ctx, spec)
	if err != nil {
		// A tracker outage must not fail the run (VM-F-812). Without a parent
		// the children simply go unlinked this pass.
		stats.Failed++
		return nil, nil
	}
	if err := o.Store.SaveRunTicket(ctx, store.RunTicket{
		RunID: req.RunID, Backend: ref.Backend, Ref: ref.ID, URL: ref.URL, CreatedAt: o.clock(),
	}); err != nil {
		return nil, err
	}
	stats.ParentCreated++
	return &ref, nil
}

// ensurePRTickets gives each open remediation pull request its own ticket
// (§13.3 row 2).
//
// Deliberately NOT through Service.Ensure. That path records into the
// fingerprint-keyed `tickets` table, which has a foreign key to `findings` — a
// pull request is not a finding, and a synthetic key like "pr:<branch>" only
// looked workable because the in-memory backend has no foreign keys to
// enforce. The reference belongs on the pull request row, where it already is.
//
// Idempotency is the same shape as everywhere else: the stored reference
// first, then the backend by its carrier, then create (VM-F-804/805).
func (o *Orchestrator) ensurePRTickets(ctx context.Context, req TicketRequest, parent *tracker.Ref) (int, error) {
	prs, err := o.Store.OpenRemediationPRs(ctx, req.Repo.Name)
	if err != nil {
		return 0, err
	}

	created := 0
	for _, pr := range prs {
		if pr.TicketRef != "" {
			continue
		}
		carrier := "pr:" + pr.Branch
		spec := tracker.Spec{
			Fingerprint: carrier,
			Title:       fmt.Sprintf("Review security pull request #%d (%s)", pr.Number, pr.Repo),
			Body:        prTicketBody(pr, req.ReportURL),
			Repo:        pr.Repo,
			Assignee:    assigneeFor(req.Repo),
			Parent:      parent,
			ReportURL:   req.ReportURL,
			Labels:      []string{"vf", "vf-pull-request"},
		}
		if err := spec.Validate(); err != nil {
			return created, err
		}

		// The reconciliation path: a lost ticket_ref must not produce a second
		// ticket, exactly as a lost ticket record must not for a finding.
		ref, found, err := req.Service.Tracker.Find(ctx, carrier)
		if err != nil {
			// A tracker outage must not fail the run (VM-F-812).
			continue
		}
		if !found {
			ref, err = req.Service.Tracker.Create(ctx, spec)
			if err != nil {
				continue
			}
			created++
		}

		pr.TicketRef, pr.TicketURL = ref.ID, ref.URL
		if err := o.Store.SaveRemediationPR(ctx, pr); err != nil {
			return created, err
		}
		if parent != nil && !parent.Zero() {
			_ = req.Service.Tracker.Link(ctx, ref, *parent)
		}
	}
	return created, nil
}

func prTicketBody(pr store.RemediationPR, reportURL string) string {
	return fmt.Sprintf(
		"A security remediation pull request is open and needs a human decision.\n\n"+
			"- **Pull request:** %s\n- **Branch:** `%s`\n- **Fix group:** `%s`\n- **Findings addressed:** %d\n\n"+
			"Pull requests are never merged automatically (VM-F-541). Merging does not close the findings "+
			"either: they reach VERIFIED only when a later scan of the default branch no longer observes "+
			"them (VM-F-533).\n\n[Full report](%s)\n",
		pr.URL, pr.Branch, pr.FixGroupID, len(pr.Findings), reportURL)
}

// outcomeFor re-evaluates policy for a finding.
//
// Re-evaluated rather than persisted from the routing pass because policy is a
// pure function of the finding, the repository and the configuration: the
// answer is the same, and storing it would create a second copy that can drift
// from the table that is supposed to be authoritative.
func (o *Orchestrator) outcomeFor(f model.Finding, pr policy.Repo, req TicketRequest) (policy.Outcome, bool) {
	if req.Policy == nil {
		return "", false
	}
	if f.State == model.Detected {
		// Untriaged: policy runs after triage, so there is no decision yet.
		return "", false
	}
	decision, err := req.Policy.Evaluate(f, pr, req.View)
	if err != nil {
		// A hole in the table is loud elsewhere; here it means no ticket
		// decision can be made, and inventing one would be worse.
		return "", false
	}
	return decision.Outcome, true
}

func aggregateRows(repo string, byPriority map[model.Priority]int) []tracker.AggregateRow {
	out := make([]tracker.AggregateRow, 0, len(byPriority))
	for p, n := range byPriority {
		out = append(out, tracker.AggregateRow{Repo: repo, Priority: p, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

func parentRef(p *tracker.Ref) *tracker.Ref {
	if p == nil || p.Zero() {
		return nil
	}
	return p
}

// assigneeFor resolves the ticket assignee from repository code ownership
// (VM-F-810), falling back to the configured owner.
func assigneeFor(r store.Repo) string {
	if len(r.Codeowners) > 0 {
		return r.Codeowners[0]
	}
	return ""
}

// RunTicketSweeper drains queued tracker operations on an interval.
//
// The ticket pass already drains, so this exists for the gap between passes: a
// backend that recovers ten minutes after a sweep should not wait for the next
// one. Neither path requires a human (OQ-P8-02).
func (o *Orchestrator) RunTicketSweeper(ctx context.Context, svc *tracker.Service, every time.Duration, onErr func(error)) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := svc.Drain(ctx, o.clock(), 100); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}
