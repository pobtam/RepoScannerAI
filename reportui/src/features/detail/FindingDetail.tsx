/**
 * The finding detail (U2, VM-UI-F-5xx).
 *
 * The gate for this view is that EVERY field in the record is either rendered
 * or deliberately excluded with a note. That is the interface's half of the
 * Producer-Coverage Audit: the API proves every field has a producer, and this
 * view proves every field has a reader. A field written by the pipeline and
 * shown nowhere is work nobody can see.
 *
 * Three panels exist to prevent a specific wrong conclusion:
 *
 *   THE SCORE DECOMPOSITION (VM-UI-F-510). "P1" is an assertion; "base 7.5, in
 *   the known-exploited catalogue, reachable, production dependency, tier 1"
 *   is an argument someone can disagree with. Where the recomputed band
 *   differs from the stored one, both are shown: the calibration moved since
 *   the finding was scored, and hiding either would present a number as
 *   current that no pass produced.
 *
 *   THE OBSERVATION HISTORY (VM-UI-F-503). Including the runs that did NOT see
 *   it, and whether those runs qualified. A list of only the runs that
 *   observed it cannot show a gap, and the gap is the interesting part.
 *
 *   THE ATTEMPT HISTORY (VM-UI-F-508/509). Every attempt, with its outcome —
 *   not just the open one, which would hide that two earlier attempts were
 *   declined.
 */
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { Finding } from '../../api/schemas';
import { Absent, Badge, Caveat, CopyButton, ErrorState, Loading, Panel } from '../../components/primitives';
import { Link } from '../../lib/router';
import {
  epssLabel,
  formatDate,
  formatDateTime,
  kevLabel,
  reachableLabel,
  severityMark,
  slaLabel,
  stateMark,
} from '../../lib/format';

export function FindingDetail({ fingerprint }: { fingerprint: string }) {
  const finding = useQuery({
    queryKey: ['finding', fingerprint],
    queryFn: () => api.finding(fingerprint),
  });
  const timeline = useQuery({
    queryKey: ['timeline', fingerprint],
    queryFn: () => api.timeline(fingerprint),
    enabled: finding.isSuccess,
  });
  const attempts = useQuery({
    queryKey: ['attempts', fingerprint],
    queryFn: () => api.attempts(fingerprint),
    enabled: finding.isSuccess,
  });

  if (finding.isLoading) return <Loading what="the finding" />;
  if (finding.error != null) return <ErrorState error={finding.error} what="the finding" />;
  const f = finding.data!;

  return (
    <div className="detail">
      <Header finding={f} />
      <Description finding={f} />

      {f.observation.not_reobserved && (
        <Panel tone="warning" title="The last run did not observe this finding">
          <p>{f.observation.not_reobserved_note}</p>
          {f.observation.gap_repo_scan && (
            <p>
              <Link to={`/coverage`}>
                A coverage gap is recorded for this repository in run {f.observation.gap_repo_scan} —
                read it before concluding this was fixed.
              </Link>
            </p>
          )}
        </Panel>
      )}

      {f.observation.residual_possible && (
        <Panel tone="warning" title="A same-file occurrence may remain">
          <p>{f.observation.residual_detail}</p>
        </Panel>
      )}

      <div className="detail-grid">
        <Panel title="Record">
          <dl className="record">
            <Field label="Fingerprint">
              <span className="mono">{f.fingerprint}</span>
              <CopyButton value={f.fingerprint} label="the fingerprint" />
            </Field>
            <Field label="Identifier">{f.identity.primary_id || <Absent why="this tool reports no advisory identifier" />}</Field>
            <Field label="Aliases">
              {f.identity.aliases && f.identity.aliases.length > 0 ? (
                <span className="mono small">{f.identity.aliases.join(', ')}</span>
              ) : (
                <Absent why="no other identifier is known for this vulnerability" />
              )}
            </Field>
            <Field label="Rule">{f.identity.rule_id || <Absent why="not a rule-based finding" />}</Field>
            <Field label="Repository">
              <Link to={`/repos/${f.repo}`}>{f.repo}</Link>
            </Field>
            <Field label="Category">{f.category}</Field>
            <Field label="Module">
              {f.location.module ? (
                <span className="mono">
                  {f.location.module} {f.location.module_major && `(${f.location.module_major})`}
                </span>
              ) : (
                <Absent why="this category of finding is not located in a module" />
              )}
            </Field>
            <Field label="File">
              {f.location.file ? (
                <span className="mono">
                  {f.location.file}
                  {f.location.line ? `:${f.location.line}` : ''}
                </span>
              ) : (
                <Absent why="a dependency finding is located by module, not by file" />
              )}
            </Field>
            <Field label="Package / function">
              {f.location.package || f.location.function ? (
                <span className="mono small">
                  {f.location.package}
                  {f.location.function ? ` · ${f.location.function}` : ''}
                </span>
              ) : (
                <Absent why="no pinned tool reports the enclosing symbol, so findings are located to a FILE (OQ-AUDIT-02). This is a known limitation, not a missing value" />
              )}
            </Field>
            <Field label="Versions">
              {f.versions?.current || f.versions?.fixed ? (
                <span className="mono">
                  {f.versions?.current || '?'} → {f.versions?.fixed || 'no fix published'}
                  {f.versions?.introduced && ` (introduced ${f.versions.introduced})`}
                </span>
              ) : (
                <Absent why="not a versioned dependency" />
              )}
            </Field>
            <Field label="Credential class">
              {f.credential_type ? (
                <>
                  {f.credential_type}
                  <span className="muted small">
                    {' '}
                    — the value itself is never stored, shown or transmitted (VM-F-263)
                  </span>
                </>
              ) : (
                <Absent why="not a secret finding" />
              )}
            </Field>
            <Field label="Dependency class">
              {f.classification.dep_class || <Absent why="not a dependency finding" />}
            </Field>
            <Field label="Transitive">{f.classification.transitive ? 'yes' : 'no'}</Field>
            <Field label="First-party path">
              {f.classification.first_party_path ? (
                <span className="mono small">{f.classification.first_party_path}</span>
              ) : (
                <Absent why="the vulnerable path does not traverse a module this organisation owns" />
              )}
            </Field>
            <Field label="Annotations">
              {f.annotations && Object.keys(f.annotations).length > 0 ? (
                <span className="mono small">
                  {Object.entries(f.annotations)
                    .map(([k, v]) => `${k}=${v}`)
                    .join(' ')}
                </span>
              ) : (
                <Absent why="the tools that reported this finding supplied no extra fields" />
              )}
            </Field>
          </dl>
        </Panel>

        <Panel title="Risk">
          <dl className="record">
            <Field label="Severity">
              <Badge mark={severityMark(f.classification.severity)} tone={`sev-${f.classification.severity}`}>
                {f.classification.severity}
              </Badge>
            </Field>
            <Field label="CVSS">
              {f.classification.cvss ? f.classification.cvss.toFixed(1) : <Absent why="the advisory publishes no CVSS score" />}
            </Field>
            <Field label="Reachability">
              <span className={`reach reach-${f.classification.reachable}`} title={reachableLabel(f.classification.reachable).hint}>
                {reachableLabel(f.classification.reachable).text}
              </span>
              <p className="muted small">{reachableLabel(f.classification.reachable).hint}</p>
            </Field>
            <Field label="Known exploited (KEV)">
              <Exploitation
                label={kevLabel(f.classification.kev).text}
                known={kevLabel(f.classification.kev).known}
                asOf={f.classification.kev_as_of}
                unknownWhy="the catalogue was not consulted for this finding's identifiers. That is NOT a determination that it is unexploited"
              />
            </Field>
            <Field label="Exploit prediction (EPSS)">
              <Exploitation
                label={epssLabel(f.classification.epss).text}
                known={epssLabel(f.classification.epss).known}
                asOf={f.classification.epss_as_of}
                unknownWhy="nothing answered for this finding's identifiers. That is NOT a score of zero"
              />
            </Field>
            {f.classification.exploit_intel_unavailable?.map((note) => (
              <p key={note} className="muted small inline-caveat">
                {note}
              </p>
            ))}
          </dl>
        </Panel>

        <Panel title="Priority" subtitle="the argument behind the band, not just the band">
          {f.score ? <ScorePanel score={f.score} storedPriority={f.priority} /> : <Absent why="this finding has not been scored" />}
        </Panel>

        <Panel title="State and SLA">
          <dl className="record">
            <Field label="State">
              <Badge mark={stateMark(f.state)} tone={`state-${f.partition}`}>
                {f.state}
              </Badge>
              <span className="muted small"> · {f.partition}</span>
            </Field>
            <Field label="Reason">
              {f.reason_code || <Absent why="no reason code is recorded; for an unresolved finding that is itself a gap in the pipeline" />}
            </Field>
            <Field label="Verified because">
              {f.verified_reason ? (
                <span title="attribution matters: a report that claimed credit for a fix it did not make would be a false record">
                  {f.verified_reason}
                </span>
              ) : (
                <Absent why="not verified" />
              )}
            </Field>
            <Field label="SLA">
              <span className={`sla sla-${slaLabel(f.sla).tone}`}>{slaLabel(f.sla).text}</span>
              {f.sla.caveat && <Caveat text={f.sla.caveat} short={f.sla.computed ? 'provisional windows' : 'not computed'} />}
              <span className="muted small"> · age {f.sla.age_days}d</span>
            </Field>
            <Field label="First / last seen">
              <span className="mono small">
                {f.observation.first_seen_run || formatDate(f.observation.first_seen_at)} →{' '}
                {f.observation.last_seen_run || formatDate(f.observation.last_seen_at)}
              </span>
            </Field>
            <Field label="Resolved">
              {f.observation.resolved_at ? formatDateTime(f.observation.resolved_at) : <Absent why="not resolved" />}
            </Field>
          </dl>
        </Panel>

        <Panel title="Links">
          <ul className="links">
            <li>
              Ticket:{' '}
              {f.refs.ticket ? (
                <a href={f.refs.ticket} target="_blank" rel="noreferrer">
                  {f.refs.ticket}
                </a>
              ) : (
                <Absent why="no ticket was opened: low-priority findings are aggregated into the run's parent ticket rather than ticketed individually (VM-F-808)" />
              )}
            </li>
            <li>
              Pull request:{' '}
              {f.refs.pull_request ? (
                <a href={f.refs.pull_request} target="_blank" rel="noreferrer">
                  {f.refs.pull_request}
                </a>
              ) : (
                <Absent why="no remediation attempt is open" />
              )}
            </li>
            <li>
              Advisory:{' '}
              {f.refs.advisory_url ? (
                <a href={f.refs.advisory_url} target="_blank" rel="noreferrer">
                  {f.refs.advisory_url}
                </a>
              ) : (
                <Absent why="the tool reported no advisory link" />
              )}
            </li>
            <li>
              Upstream finding:{' '}
              {f.refs.upstream_finding ? (
                <Link to={`/findings/${f.refs.upstream_finding}`}>{f.refs.upstream_finding}</Link>
              ) : (
                <Absent why="not blocked on a first-party fix elsewhere" />
              )}
            </li>
          </ul>
        </Panel>

        <Panel title="Triage" subtitle="produced by a model, and never the source of the priority (VM-F-305)">
          {f.triage ? (
            <dl className="record">
              <Field label="Description">{f.triage.description || <Absent why="the model returned none" />}</Field>
              <Field label="Impact">{f.triage.impact || <Absent why="the model returned none" />}</Field>
              <Field label="Remediation">{f.triage.remediation || <Absent why="the model returned none" />}</Field>
              <Field label="False-positive candidate">
                {f.triage.false_positive_candidate ? `yes — ${f.triage.fp_reasoning ?? 'no reasoning given'}` : 'no'}
              </Field>
              <Field label="Model">{f.triage.model || <Absent why="not recorded" />}</Field>
              <Field label="Triaged at">{formatDateTime(f.triage.triaged_at)}</Field>
            </dl>
          ) : (
            <Absent why="this finding has not been triaged; the run is never blocked on triage (VM-AD §9.3), so a finding can be scored and routed without a narrative" />
          )}
        </Panel>

        <Panel title="Tools">
          <p>
            {f.provenance.tools && f.provenance.tools.length > 0 ? (
              f.provenance.tools.join(', ')
            ) : (
              <Absent why="no tool provenance recorded" />
            )}
          </p>
          <p className="muted small">
            {f.provenance.tool_versions && Object.keys(f.provenance.tool_versions).length > 0 ? (
              Object.entries(f.provenance.tool_versions)
                .map(([t, v]) => `${t} ${v}`)
                .join(' · ')
            ) : (
              <>
                Versions are recorded per RUN rather than per finding (OQ-AUDIT-03), so they are
                shown on the run overview. This field is deliberately empty rather than filled in
                from the run, which would duplicate a fact that could then disagree with itself.
              </>
            )}
          </p>
        </Panel>
      </div>

      <Panel title="Lifecycle" subtitle="every state change, with who made it and why (VM-UI-F-502)">
        {timeline.isLoading && <Loading what="the timeline" />}
        {timeline.error != null && <ErrorState error={timeline.error} what="the timeline" />}
        {timeline.data && (
          <table className="timeline">
            <thead>
              <tr>
                <th scope="col">When</th>
                <th scope="col">From</th>
                <th scope="col">To</th>
                <th scope="col">Actor</th>
                <th scope="col">Cause</th>
              </tr>
            </thead>
            <tbody>
              {timeline.data.transitions.map((t, i) => (
                <tr key={`${t.at}-${i}`}>
                  <td className="mono small">{formatDateTime(t.at)}</td>
                  <td>{t.from || <span className="muted">created</span>}</td>
                  <td>
                    <Badge mark={stateMark(t.to)}>{t.to}</Badge>
                  </td>
                  <td>{t.actor}</td>
                  <td className="small">{t.cause}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel
        title="Observations"
        subtitle="including the runs that did NOT see it — a list of only the runs that did cannot show a gap (VM-UI-F-503)"
      >
        {timeline.data && (
          <table className="observations">
            <thead>
              <tr>
                <th scope="col">Run</th>
                <th scope="col">When</th>
                <th scope="col">Observed</th>
                <th scope="col">Scan outcome</th>
                <th scope="col">What that means</th>
              </tr>
            </thead>
            <tbody>
              {timeline.data.observations.map((o) => (
                <tr key={o.run_id} className={o.observed ? undefined : 'not-observed'}>
                  <td className="mono small">
                    <Link to={`/runs/${o.run_id}`}>{o.run_id}</Link>
                  </td>
                  <td className="mono small">{formatDate(o.at)}</td>
                  <td>{o.observed ? 'yes' : 'no'}</td>
                  <td>{o.outcome}</td>
                  <td className="small">{o.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel
        title="Remediation attempts"
        subtitle="every attempt, not only the open one — otherwise two declined attempts are invisible (VM-UI-F-508)"
      >
        {attempts.isLoading && <Loading what="the attempts" />}
        {attempts.error != null && <ErrorState error={attempts.error} what="the attempts" />}
        {attempts.data && attempts.data.length === 0 && (
          <p className="muted">
            No remediation has been attempted. For a repository with no test suite that is
            deliberate: there is no signal to verify a fix against.
          </p>
        )}
        {attempts.data && attempts.data.length > 0 && (
          <table className="attempts">
            <thead>
              <tr>
                <th scope="col">Branch</th>
                <th scope="col">Pull request</th>
                <th scope="col">State</th>
                <th scope="col">Opened</th>
                <th scope="col">Closed</th>
                <th scope="col">Confirmed by</th>
              </tr>
            </thead>
            <tbody>
              {attempts.data.map((a) => (
                <tr key={a.branch}>
                  <td className="mono small">{a.branch}</td>
                  <td>
                    {a.url ? (
                      <a href={a.url} target="_blank" rel="noreferrer">
                        #{a.number}
                      </a>
                    ) : (
                      <Absent why="no pull request was opened for this attempt" />
                    )}
                  </td>
                  <td>
                    {a.state}
                    {a.merged && ' (merged)'}
                  </td>
                  <td className="mono small">{formatDate(a.opened_at)}</td>
                  <td className="mono small">
                    {a.closed_at ? formatDate(a.closed_at) : <Absent why="still open" />}
                  </td>
                  <td className="small">
                    {a.confirmed_at ? (
                      <span title="a verified webhook delivery or a query established this state">
                        {formatDateTime(a.confirmed_at)}
                      </span>
                    ) : (
                      <Absent why="nothing has vouched for this pull request's state yet, so the bounded reconciliation pass will ask the remote about it" />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

function Header({ finding: f }: { finding: Finding }) {
  return (
    <header className="detail-head">
      <h1>
        {f.identity.primary_id || f.fingerprint}
        {f.priority && (
          <Badge tone={`prio-${f.priority}`}>{f.priority}</Badge>
        )}
        <Badge mark={severityMark(f.classification.severity)} tone={`sev-${f.classification.severity}`}>
          {f.classification.severity}
        </Badge>
        <Badge mark={stateMark(f.state)} tone={`state-${f.partition}`}>
          {f.state}
        </Badge>
      </h1>
      <p className="muted">
        <Link to={`/repos/${f.repo}`}>{f.repo}</Link> · {f.category} ·{' '}
        <span className="mono small">{f.fingerprint}</span>
        <CopyButton value={f.fingerprint} label="the fingerprint" />
      </p>
    </header>
  );
}

/** What the problem is, and whose words those are. */
function Description({ finding: f }: { finding: Finding }) {
  if (!f.description) {
    return (
      <section className="finding-description" aria-label="Description">
        <Absent why="the server sent no description for this finding" />
      </section>
    );
  }
  const derived = f.description_source === 'derived';
  return (
    <section className="finding-description" aria-label="Description">
      <p>{f.description}</p>
      <p className="muted small">
        {derived
          ? 'Built from this record\'s fields: no scanner supplied a description.'
          : `In the words of ${f.description_source}.`}
        {f.triage?.description && ' The AI triage narrative is below, under Triage.'}
      </p>
    </section>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  );
}

function Exploitation({
  label,
  known,
  asOf,
  unknownWhy,
}: {
  label: string;
  known: boolean;
  asOf?: string;
  unknownWhy: string;
}) {
  if (!known) {
    return (
      <span className="absent" title={unknownWhy}>
        {label}
        <span className="sr-only"> — {unknownWhy}</span>
      </span>
    );
  }
  return (
    <>
      {label}
      {asOf && <span className="muted small"> · as of {formatDate(asOf)}</span>}
    </>
  );
}

/**
 * ScorePanel renders the decomposition, and says when it disagrees with the
 * band the scoring pass recorded.
 */
function ScorePanel({
  score,
  storedPriority,
}: {
  score: NonNullable<Finding['score']>;
  storedPriority?: string;
}) {
  return (
    <div className="score">
      <p className="score-headline">
        <strong>{score.priority}</strong> — score {score.score.toFixed(2)}
        {score.caveat && <Caveat text={score.caveat} short="partial inputs" />}
        {!score.thresholds_calibrated && (
          <Caveat
            text="the priority bands behind this figure have not been calibrated against a shadow run (VM-OQ-06)"
            short="uncalibrated bands"
          />
        )}
      </p>

      {score.disagrees_with_stored && (
        <p className="state state-warning">
          The scoring pass recorded <strong>{score.stored_priority}</strong> and recomputing now
          gives <strong>{score.priority}</strong>. The calibration has changed since this finding was
          scored; both are shown because presenting either alone would be presenting a number as
          current that no pass produced.
        </p>
      )}

      <p className="muted small">
        Computed from {score.inputs.available} of {score.inputs.declared} declared inputs.
        {score.inputs.unavailable && score.inputs.unavailable.length > 0 && (
          <> Missing: {score.inputs.unavailable.join('; ')}.</>
        )}
        {score.inputs.stale && score.inputs.stale.length > 0 && (
          <> Not current: {score.inputs.stale.join('; ')}.</>
        )}
      </p>

      <table className="score-table">
        <tbody>
          <tr>
            <th scope="row">base</th>
            <td>{score.base.toFixed(2)}</td>
          </tr>
          <tr>
            <th scope="row">known-exploited boost</th>
            <td>{score.kev_boost ? `+${score.kev_boost.toFixed(2)}` : '—'}</td>
          </tr>
          <tr>
            <th scope="row">exploit-prediction boost</th>
            <td>{score.epss_boost ? `+${score.epss_boost.toFixed(3)}` : '—'}</td>
          </tr>
          <tr>
            <th scope="row">reachability</th>
            <td>×{score.reach_multiplier.toFixed(2)}</td>
          </tr>
          <tr>
            <th scope="row">dependency class</th>
            <td>×{score.dep_multiplier.toFixed(2)}</td>
          </tr>
          <tr>
            <th scope="row">repository tier</th>
            <td>×{score.tier_multiplier.toFixed(2)}</td>
          </tr>
          <tr>
            <th scope="row">blast radius</th>
            <td>×{score.fanout_multiplier.toFixed(2)}</td>
          </tr>
        </tbody>
      </table>

      {score.explain && score.explain.length > 0 && (
        <details>
          <summary>The arithmetic, as the scorer recorded it</summary>
          <pre className="verbatim">{score.explain.join('\n')}</pre>
        </details>
      )}
    </div>
  );
}
