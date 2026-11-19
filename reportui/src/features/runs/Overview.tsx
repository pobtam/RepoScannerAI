/**
 * The run overview (U3, VM-UI-F-2xx).
 *
 * Coverage gaps come FIRST, above the rollup (VM-UI-F-206): a repository that
 * was not scanned is more urgent than a repository with findings, and burying
 * it below the counts is how a fleet convinces itself it is clean.
 *
 * Every count links to the filtered list that produced it (VM-UI-F-108), so
 * any figure on this page can be checked by clicking it. A number nobody can
 * reproduce is a number nobody should act on.
 */
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { Overview as OverviewData } from '../../api/schemas';
import { Badge, Caveat, CopyButton, ErrorState, Loading, Panel } from '../../components/primitives';
import { Link } from '../../lib/router';
import { formatDateTime, pct } from '../../lib/format';
import { ClipNotes, EffectiveText, NotRequestedList } from '../nuguard/NuGuard';

export function LatestOverview() {
  const q = useQuery({ queryKey: ['run', 'latest'], queryFn: api.latestRun, refetchInterval: 60_000 });
  if (q.isLoading) return <Loading what="the latest run" />;
  if (q.error != null) return <ErrorState error={q.error} what="the latest run" />;
  return <RunOverview data={q.data!} />;
}

export function RunPage({ runID }: { runID: string }) {
  const q = useQuery({ queryKey: ['run', runID], queryFn: () => api.run(runID) });
  if (q.isLoading) return <Loading what={`run ${runID}`} />;
  if (q.error != null) return <ErrorState error={q.error} what={`run ${runID}`} />;
  return <RunOverview data={q.data!} />;
}

export function RunOverview({ data }: { data: OverviewData }) {
  const { run, counts, delta, coverage, provenance } = data;
  const runQuery = `?scope=run&run=${encodeURIComponent(run.id)}`;

  return (
    <div className="overview">
      <header className="detail-head">
        <h1>
          {/* The identifier and its start time always travel together: the
              identifier is not self-dating and the timestamp is not unique
              (VM-UI-F-207a). */}
          Run {run.id}
          <CopyButton value={run.id} label="the run identifier" />
          <span className="muted"> · started {formatDateTime(run.started_at)}</span>
          <Badge tone={`kind-${run.kind}`}>{run.kind}</Badge>
        </h1>
        <p className="muted">
          {run.trigger && <>triggered by {run.trigger} · </>}
          {run.repos_scanned} of {run.repos_planned} repositories scanned
          {run.repos_failed > 0 && <> · {run.repos_failed} failed</>}
        </p>
      </header>

      {/* Whether these figures are the state AS OF the run, or the state NOW.
          A run-scoped view showing live state has to say so (VM-UI-F-424). */}
      {data.live ? (
        <Panel tone="warning" title="These figures are live, not a snapshot">
          <p>{data.live_note}</p>
        </Panel>
      ) : (
        <p className="muted small snapshot-note">
          These figures are read from the immutable report issued for this run
          {data.snapshot_id && <> ({data.snapshot_id})</>}, so a finding fixed since the run still
          appears here as it was then (VM-UI-F-102).
          {data.content_hash && (
            <>
              {' '}
              Content hash <span className="mono">{data.content_hash.slice(0, 16)}…</span>
              <CopyButton value={data.content_hash} label="the content hash" />
            </>
          )}
        </p>
      )}

      {run.partial && (
        <Panel tone="urgent" title="This run did not cover the fleet">
          <p>{run.partial_note}</p>
          <p className="muted">
            Every count below is therefore lower than the fleet's actual position rather than
            better. A drop caused by a failed scan looks identical to a drop caused by remediation.
          </p>
        </Panel>
      )}

      {data.caveats && data.caveats.length > 0 && (
        <Panel tone="warning" title="What these numbers rest on">
          <ul>
            {data.caveats.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </Panel>
      )}

      {/* COVERAGE FIRST (VM-UI-F-206). */}
      <Panel
        title="Coverage"
        subtitle="read this before the counts: a repository nobody scanned is more urgent than a repository with findings"
        tone={coverage.percent < 100 ? 'urgent' : undefined}
      >
        <div className="figures">
          <Figure label="In scope" value={coverage.in_scope} />
          <Figure label="Complete" value={coverage.complete} />
          <Figure label="Partial" value={coverage.partial} tone={coverage.partial > 0 ? 'warn' : undefined} />
          <Figure label="Failed" value={coverage.failed} tone={coverage.failed > 0 ? 'warn' : undefined} />
          <Figure
            label="Never dispatched"
            value={coverage.not_dispatched}
            tone={coverage.not_dispatched > 0 ? 'warn' : undefined}
            hint="the scan never started: dispatch itself failed, or the budget ran out"
          />
          <Figure
            label="No result"
            value={coverage.no_result}
            tone={coverage.no_result > 0 ? 'warn' : undefined}
            hint="dispatched and the result was lost — a different problem from never dispatched"
          />
          <Figure label="Coverage" value={pct(coverage.percent)} />
        </div>
        {(coverage.unscanned_repos ?? []).length > 0 && (
          <p>
            <strong>Not scanned in this run:</strong>{' '}
            {(coverage.unscanned_repos ?? []).map((r) => (
              <Link key={r} to={`/repos/${r}`}>
                {r}{' '}
              </Link>
            ))}
            — <Link to="/coverage">read the gaps</Link>
          </p>
        )}
        {(coverage.escalations ?? []).length > 0 && (
          <p className="state state-warning">
            {(coverage.escalations ?? []).length} repositories are past the consecutive-failure threshold:{' '}
            {(coverage.escalations ?? []).map((e) => `${e.repo} (${e.sweeps_since_qualifying} runs)`).join(', ')}
          </p>
        )}
      </Panel>

      <Panel title="Findings" subtitle="every figure links to the list that produced it">
        <div className="figures">
          <Figure label="Total" value={counts.total} to={`/findings${runQuery}`} />
          <Figure label="Unresolved" value={counts.unresolved} to={`/findings?scope=open`} />
          <Figure
            label="Pending verification"
            value={counts.pending_verification}
            to={`/findings?scope=all&state=MERGED`}
            hint="merged, and not yet proven gone by a scan. Neither resolved nor unresolved (VM-F-159)"
          />
          <Figure label="Resolved" value={counts.resolved} to={`/findings?scope=all&state=VERIFIED`} />
          <Figure
            label="Not re-observed"
            value={counts.not_reobserved}
            to={`/findings?scope=open&notReobserved=true`}
            tone={counts.not_reobserved > 0 ? 'warn' : undefined}
            hint="unresolved and unseen by the last applicable run. AMBIGUOUS between a fix and a coverage gap — never counted as resolved"
          />
          <Figure
            label="Past SLA"
            value={counts.sla_breached}
            to={`/findings?scope=open&slaBreached=true`}
            tone={counts.sla_breached > 0 ? 'warn' : undefined}
            caveat={
              provenance.sla_windows_calibrated
                ? undefined
                : 'provisional: the remediation windows behind this figure have not been reviewed by anyone (VM-OQ-02)'
            }
          />
          <Figure
            label="SLA not computed"
            value={counts.sla_not_computed}
            hint="nobody looked. A breach count of zero with these outstanding is not assurance (OQ-P7-03)"
          />
          <Figure label="SLA paused" value={counts.sla_paused} hint="the clock is stopped; not the same as compliant" />
        </div>

        <div className="split">
          <Breakdown title="By priority" counts={counts.by_priority ?? {}} param="priority" />
          <Breakdown title="By category" counts={counts.by_category ?? {}} param="category" />
          <Breakdown title="By state" counts={counts.by_state ?? {}} param="state" />
        </div>
      </Panel>

      <Panel
        title="Secrets awaiting a human"
        subtitle="none of these is closed until a person decides; decide with ./vfctl.sh finding pending"
      >
        <div className="figures">
          <Figure
            label="Suppression proposals"
            value={counts.suppression_proposals_pending}
            to={`/findings?scope=open&category=secret&state=FALSE_POSITIVE_CANDIDATE`}
            tone={counts.suppression_proposals_pending > 0 ? 'warn' : undefined}
            hint="secrets still in the files that a repository allowlist hides. An allowlist anyone with commit access can write is a proposal, not a suppression"
          />
          <Figure
            label="Proposals overdue"
            value={counts.suppression_proposals_overdue}
            to={`/findings?scope=open&category=secret&state=NEEDS_HUMAN`}
            tone={counts.suppression_proposals_overdue > 0 ? 'warn' : undefined}
            hint="unreviewed past the secret SLA window, and escalated again"
          />
          <Figure
            label="Removed, rotation unconfirmed"
            value={counts.secrets_removed_rotation_unconfirmed}
            tone={counts.secrets_removed_rotation_unconfirmed > 0 ? 'warn' : undefined}
            hint="gone from the files but still in history, and live until rotated. Removal is not remediation (VM-F-856)"
          />
        </div>
      </Panel>

      <Panel
        title="Not fixed, by reason"
        subtitle="'tried and failed' and 'nothing to do' are different states of the world (VM-F-704)"
      >
        {Object.keys(counts.not_fixed_by_reason ?? {}).length === 0 ? (
          <p className="muted">No unresolved finding carries a reason code.</p>
        ) : (
          <Breakdown title="" counts={counts.not_fixed_by_reason ?? {}} param="reason" />
        )}
        {counts.not_fixed_unexplained > 0 && (
          <p className="state state-warning">
            {counts.not_fixed_unexplained} unresolved findings carry NO reason code at all. That is
            a gap in the pipeline rather than a category of risk: nobody can action a queue entry
            with no explanation.
          </p>
        )}
      </Panel>

      <Panel
        title="Change since the previous run"
        subtitle={
          delta.comparable
            ? `compared with ${delta.previous_run} — the previous run of the same kind (VM-UI-F-309)`
            : 'no previous run of this kind, so no delta is shown'
        }
      >
        {delta.comparable ? (
          <div className="figures">
            <Figure label="New" value={delta.new} to={`/findings${runQuery}`} />
            <Figure
              label="No longer observed"
              value={delta.no_longer_observed}
              hint="deliberately not called 'fixed': a finding not seen may have been fixed, or may simply not have been looked for (VM-ADR-12)"
            />
            <Figure label="Verified" value={delta.verified} hint="actually proven gone by a qualifying scan" />
            <Figure
              label="Regressed"
              value={delta.regressed}
              tone={delta.regressed > 0 ? 'warn' : undefined}
              hint="came back after being verified — a different failure from a new finding"
            />
            <Figure label="Unresolved change" value={signed(delta.unresolved_change)} />
          </div>
        ) : (
          <p className="muted">
            A delta against zero would present this run as though everything had just appeared.
          </p>
        )}
      </Panel>

      <Panel title="How this run was produced">
        <dl className="record">
          <dt>Scanner image</dt>
          <dd className="mono small">{provenance.scanner_image}</dd>
          <dt>Tool versions</dt>
          <dd className="mono small">
            {Object.entries(provenance.tool_versions ?? {})
              .map(([t, v]) => `${t} ${v}`)
              .join(' · ') || '—'}
          </dd>
          <dt>Scoring inputs</dt>
          <dd>
            {provenance.scoring_inputs_available} of {provenance.scoring_inputs_declared} answered
            {provenance.scoring_inputs_available < provenance.scoring_inputs_declared && (
              <Caveat
                text="a priority computed without the exploitation inputs is missing the part that would have argued loudest (OQ-AUDIT-01)"
                short="narrower than it looks"
              />
            )}
          </dd>
          <dt>Thresholds calibrated</dt>
          <dd>{provenance.thresholds_calibrated ? 'yes' : 'no (VM-OQ-06)'}</dd>
          <dt>SLA windows calibrated</dt>
          <dd>{provenance.sla_windows_calibrated ? 'yes' : 'no (VM-OQ-02)'}</dd>
        </dl>
      </Panel>

      {data.nuguard && data.nuguard.length > 0 && (
        <Panel title="NuGuard in this run" subtitle="the options each repository's scan actually used, after the operator's ceiling (VM-UI-F-1206)">
          <table>
            <thead>
              <tr>
                <th scope="col">Repository</th>
                <th scope="col">Options used</th>
              </tr>
            </thead>
            <tbody>
              {data.nuguard.map((n) => (
                <tr key={n.repo}>
                  <td className="mono">
                    <Link to={`/repos/${n.repo}`}>{n.repo}</Link>
                  </td>
                  <td>
                    <EffectiveText e={n.effective} />
                    <ClipNotes clips={n.effective.clips} />
                    <NotRequestedList items={n.not_requested} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}

function signed(n: number): string {
  return n > 0 ? `+${n}` : String(n);
}

function Figure({
  label,
  value,
  to,
  hint,
  tone,
  caveat,
}: {
  label: string;
  value: number | string;
  to?: string;
  hint?: string;
  tone?: 'warn';
  caveat?: string;
}) {
  const body = (
    <>
      <span className="figure-value">{value}</span>
      <span className="figure-label">{label}</span>
    </>
  );
  return (
    <div className={`figure${tone ? ` figure-${tone}` : ''}`} title={hint}>
      {to ? <Link to={to}>{body}</Link> : body}
      {caveat && <Caveat text={caveat} short="provisional" />}
      {hint && <span className="sr-only">{hint}</span>}
    </div>
  );
}

/** Breakdown renders a count map, each row linking to its filtered list. */
function Breakdown({
  title,
  counts,
  param,
}: {
  title: string;
  counts: Record<string, number>;
  param: string;
}) {
  const entries = Object.entries(counts).filter(([, n]) => n > 0);
  entries.sort((a, b) => b[1] - a[1]);
  return (
    <div className="breakdown">
      {title && <h3>{title}</h3>}
      <ul>
        {entries.map(([key, n]) => (
          <li key={key}>
            <Link to={`/findings?scope=open&${param}=${encodeURIComponent(key)}`}>
              <span>{key}</span>
              <span className="count">{n}</span>
            </Link>
          </li>
        ))}
        {entries.length === 0 && <li className="muted">none</li>}
      </ul>
    </div>
  );
}
