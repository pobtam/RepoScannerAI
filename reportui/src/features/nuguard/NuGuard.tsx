/**
 * AI scanning (NuGuard): status, settings, overrides and history
 * (VM-UI-F-1201..1212).
 *
 * Security owners turn NuGuard on or off for the fleet, a repository or one
 * scan, and choose its tools and posture, within the ceiling the operator set
 * on the scan worker. Engineers see the same pages read-only; the public is
 * refused by the API and sees none of it.
 *
 * Every value that was not measured is shown as absent with the reason. A
 * status the scan worker has not refreshed for fifteen minutes is shown as
 * unknown, never as current. And turning NuGuard off is never presented as
 * closing anything: its findings stay open, flagged not re-observed.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';
import { api, ApiRequestError } from '../../api/client';
import type {
  EffectiveNuGuard,
  NotRequested,
  NuGuardAuditEntry,
  NuGuardDetail,
  NuGuardView,
  ScanNuGuardOptions,
} from '../../api/schemas';
import { Absent, Badge, CopyButton, ErrorState, Loading, Panel } from '../../components/primitives';
import { Link } from '../../lib/router';
import { formatDateTime } from '../../lib/format';

/** The plain-language account of what NuGuard is for (VM-UI-F-1201). */
export const NUGUARD_NOTE =
  'NuGuard adds AI code rules and an AI component inventory. Dependency, IaC and container ' +
  "scanning stay with this project's own tools. Turning NuGuard off does not close its findings: " +
  'they stay open and are flagged not re-observed until a scan with NuGuard looks again.';

const FROM: Record<string, string> = {
  scan: 'set for this scan',
  repository: 'set for this repository',
  fleet: 'inherited from the fleet setting',
  'worker default': "the scan worker's default (the fleet setting has never been changed here)",
  deployment: 'NuGuard is not configured on this deployment',
};

export function fromText(from: string): string {
  return FROM[from] ?? from;
}

function errorText(err: unknown): string {
  if (err instanceof ApiRequestError) {
    return [err.message, err.detail, err.remedy].filter(Boolean).join(': ');
  }
  return err instanceof Error ? err.message : String(err);
}

export function useNuGuard() {
  return useQuery({ queryKey: ['nuguard'], queryFn: api.nuguard, staleTime: 30_000 });
}

/** Whether the caller may see NuGuard at all: engineers and up. */
export function useNuGuardVisible(): boolean {
  const q = useNuGuard();
  return q.isSuccess;
}

/** The one line a deployment without NuGuard shows, and nothing else. */
export function NotConfigured({ note }: { note?: string }) {
  return (
    <p className="muted" data-testid="nuguard-not-configured">
      {note ?? 'NuGuard is not configured on this deployment'}
    </p>
  );
}

/** One scan's effective options, in words. */
export function EffectiveText({ e }: { e: EffectiveNuGuard }) {
  if (!e.enabled) {
    return (
      <span>
        <Badge tone="sev-UNKNOWN">off</Badge> {e.reason ?? fromText(e.from)}
      </span>
    );
  }
  return (
    <span>
      <Badge tone="state-resolved">on</Badge> {e.tools.join(', ')}
      {' · '}
      {e.include_posture ? 'posture counted into the inventory' : 'no posture'}
      {' · '}
      {e.timeout_s} s limit
      {e.keep_sbom && ' · AI-SBOM kept'}
      <span className="muted"> — {fromText(e.from)}</span>
    </span>
  );
}

/** Tools not requested, distinct from failed ones, with the reason. */
export function NotRequestedList({ items }: { items?: NotRequested[] }) {
  if (!items || items.length === 0) return null;
  return (
    <ul className="small not-requested">
      {items.map((n) => (
        <li key={n.tool}>
          <Badge tone="sev-UNKNOWN" title="neither ok nor failed: its findings keep their state and are flagged not re-observed">
            not requested
          </Badge>{' '}
          <span className="mono">{n.tool}</span> — {n.reason}
        </li>
      ))}
    </ul>
  );
}

/** Values the operator's ceiling did not allow, and what was used. */
export function ClipNotes({ clips }: { clips?: EffectiveNuGuard['clips'] }) {
  if (!clips || clips.length === 0) return null;
  return (
    <ul className="small clip-notes" aria-label="Clipped to the operator's ceiling">
      {clips.map((c) => (
        <li key={`${c.field}:${c.asked}`} className="warn-text">
          {c.field}: {c.asked} → {c.used} ({c.why})
        </li>
      ))}
    </ul>
  );
}

/** The scanned commit, short, with the full SHA on hover and copy. */
export function CommitSHA({ sha }: { sha?: string }) {
  if (!sha) return <Absent why="no commit was recorded for the latest scan (a copied tree, or a scan before commits were recorded)" />;
  return (
    <span className="mono" title={sha}>
      {sha.slice(0, 7)} <CopyButton value={sha} label="the full commit SHA" />
    </span>
  );
}

// --- the page ------------------------------------------------------------------

export function NuGuardPage() {
  const q = useNuGuard();
  if (q.isLoading) return <Loading what="NuGuard" />;
  if (q.error) return <ErrorState error={q.error} what="NuGuard" />;
  const v = q.data!;
  return (
    <div className="page">
      <header className="page-head">
        <h1>AI scanning (NuGuard)</h1>
        <p className="subtitle">{NUGUARD_NOTE}</p>
      </header>
      {!v.configured ? (
        <Panel>
          <NotConfigured note={v.note} />
        </Panel>
      ) : (
        <>
          <StatusCard v={v} />
          <FleetSettings v={v} />
          <OverridesTable v={v} />
          <History entries={v.audit} />
        </>
      )}
    </div>
  );
}

function StatusCard({ v }: { v: NuGuardView }) {
  const s = v.status;
  return (
    <Panel title="Status" subtitle="as the scan worker last reported it; the interface never talks to NuGuard">
      {s.stale ? (
        <p className="warn-text" role="status">
          {s.stale_note}
        </p>
      ) : (
        <dl className="record">
          <dt>Reachable</dt>
          <dd>{s.reachable == null ? <Absent why="not reported" /> : s.reachable ? 'yes' : 'no'}</dd>
          <dt>Version</dt>
          <dd>
            {s.service_version ? (
              <>
                service {s.service_version}, pinned {s.pinned_version}{' '}
                {s.version_ok ? (
                  <Badge tone="state-resolved">matches</Badge>
                ) : (
                  <Badge tone="sev-HIGH">does not match: results are refused</Badge>
                )}
              </>
            ) : (
              <>
                <Absent why="the service could not be asked" /> pinned {s.pinned_version}
              </>
            )}
          </dd>
          <dt>Last checked</dt>
          <dd>{formatDateTime(s.checked_at)}</dd>
          {s.last_error && (
            <>
              <dt>Last error</dt>
              <dd className="warn-text">{s.last_error}</dd>
            </>
          )}
        </dl>
      )}
      {v.ceiling && (
        <p className="muted small">
          The operator allows {v.ceiling.allow_tools.join(', ') || 'no tool'}; posture{' '}
          {v.ceiling.allow_posture ? 'allowed' : 'not allowed'}; at most {v.ceiling.max_timeout_s} s.
        </p>
      )}
    </Panel>
  );
}

/** Why a tool may not be chosen, or "" when it may. */
function toolBlocked(v: NuGuardView, tool: string): string {
  const c = v.ceiling;
  if (!c || !c.allow_tools.includes(tool)) return 'not allowed by the operator';
  if (c.service_tools && !c.service_tools.includes(tool)) return 'not offered by the service';
  return '';
}

/** Tool checkboxes, with the options outside the ceiling disabled and saying why. */
function ToolChoice({
  v,
  chosen,
  onChange,
  disabled,
  legend = 'Tools',
}: {
  v: NuGuardView;
  chosen: string[];
  onChange: (next: string[]) => void;
  disabled?: boolean;
  legend?: string;
}) {
  return (
    <fieldset className="filter-group">
      <legend>{legend}</legend>
      <ul>
        {v.selectable.map((tool) => {
          const why = toolBlocked(v, tool);
          const checked = chosen.includes(tool);
          return (
            <li key={tool}>
              <label className={why ? 'disabled' : undefined} title={why || undefined}>
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={disabled || (why !== '' && !checked)}
                  onChange={() => onChange(checked ? chosen.filter((t) => t !== tool) : [...chosen, tool])}
                />
                <span className="filter-value mono">{tool}</span>
                {why && <span className="muted small"> — {why}</span>}
              </label>
            </li>
          );
        })}
      </ul>
    </fieldset>
  );
}

function FleetSettings({ v }: { v: NuGuardView }) {
  const qc = useQueryClient();
  const s = v.fleet.settings;
  const [enabled, setEnabled] = useState(s.enabled);
  const [tools, setTools] = useState<string[]>(s.tools);
  const [posture, setPosture] = useState(s.include_posture);
  const [timeout, setTimeout] = useState(s.timeout_s);
  const [reason, setReason] = useState('');
  const [confirming, setConfirming] = useState(false);
  const repos = useQuery({ queryKey: ['repos'], queryFn: api.repos, enabled: confirming });
  const save = useMutation({
    mutationFn: () =>
      api.putNuGuardSettings({ enabled, tools, include_posture: posture, timeout_s: timeout, reason: reason || undefined }),
    onSuccess: (next) => {
      qc.setQueryData(['nuguard'], next);
      void qc.invalidateQueries({ queryKey: ['repo-nuguard'] });
      setConfirming(false);
      setReason('');
    },
  });
  const ro = !v.can_edit;
  const max = v.ceiling?.max_timeout_s ?? 0;
  const pinned = new Set(v.overrides.filter((o) => o.mode !== 'inherit').map((o) => o.repo));
  const total = repos.data?.filter((r) => !r.archived).length;

  return (
    <Panel
      title="Fleet settings"
      subtitle={
        v.fleet.set
          ? `last changed by ${v.fleet.changed_by} at ${formatDateTime(v.fleet.changed_at)}`
          : "never changed here: these are the scan worker's defaults"
      }
    >
      {ro && <p className="muted small">Read-only: changing NuGuard's settings needs the security-owner level.</p>}
      <form
        className="nuguard-form"
        onSubmit={(e) => {
          e.preventDefault();
          setConfirming(true);
        }}
      >
        <label className="switch-row">
          <input type="checkbox" role="switch" checked={enabled} disabled={ro} onChange={(e) => setEnabled(e.target.checked)} />
          <span>NuGuard on for the fleet</span>
        </label>
        <ToolChoice v={v} chosen={tools} onChange={setTools} disabled={ro} />
        <label className="switch-row" title={v.ceiling?.allow_posture ? undefined : 'not allowed by the operator'}>
          <input
            type="checkbox"
            checked={posture}
            disabled={ro || (!v.ceiling?.allow_posture && !posture)}
            onChange={(e) => setPosture(e.target.checked)}
          />
          <span>Posture observations</span>
          <span className="muted small"> — counted into the inventory, never findings</span>
          {!v.ceiling?.allow_posture && <span className="muted small"> (not allowed by the operator)</span>}
        </label>
        <label className="field">
          <span>Time limit, seconds (30–{max})</span>
          <input
            type="number"
            min={30}
            max={max || undefined}
            value={timeout}
            disabled={ro}
            onChange={(e) => setTimeout(Number(e.target.value))}
          />
        </label>
        {!ro && (
          <>
            <label className="field">
              <span>Reason (optional, kept in the history)</span>
              <input type="text" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} />
            </label>
            <button type="submit">Save</button>
          </>
        )}
      </form>
      {confirming && (
        <div className="confirm" role="alertdialog" aria-label="Confirm the fleet setting">
          <p>
            <strong>Change NuGuard for the fleet?</strong>
          </p>
          <ul>
            <li>
              {s.enabled ? 'on' : 'off'} → <strong>{enabled ? 'on' : 'off'}</strong>
            </li>
            <li>
              tools {s.tools.join(', ') || 'none'} → <strong>{tools.join(', ') || 'none'}</strong>
            </li>
            <li>
              posture {s.include_posture ? 'counted' : 'not counted'} → <strong>{posture ? 'counted' : 'not counted'}</strong>
            </li>
            <li>
              time limit {s.timeout_s} s → <strong>{timeout} s</strong>
            </li>
          </ul>
          <p>
            {total == null ? (
              'Counting the repositories it affects…'
            ) : (
              <>
                Affects the <strong>{total - pinned.size}</strong> of {total} included repositories that inherit the
                fleet setting; {pinned.size} have their own on/off override and keep it.
              </>
            )}
          </p>
          {!enabled && s.enabled && <p className="warn-text">{NUGUARD_NOTE.split('. ').slice(-1)[0]}</p>}
          {save.isError && (
            <p className="warn-text" role="alert">
              {errorText(save.error)}
            </p>
          )}
          <div className="panel-actions">
            <button type="submit" onClick={() => save.mutate()} disabled={save.isPending}>
              Confirm
            </button>
            <button type="button" onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </Panel>
  );
}

function OverridesTable({ v }: { v: NuGuardView }) {
  return (
    <Panel title="Repository overrides" subtitle={`${v.override_count} repositories set their own NuGuard setting`}>
      {v.overrides.length === 0 ? (
        <p className="muted">No repository overrides the fleet setting.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Repository</th>
              <th scope="col">Mode</th>
              <th scope="col">Tools</th>
              <th scope="col">Posture</th>
              <th scope="col">Last changed</th>
            </tr>
          </thead>
          <tbody>
            {v.overrides.map((o) => (
              <tr key={o.repo}>
                <td className="mono">
                  <Link to={`/repos/${o.repo}`}>{o.repo}</Link>
                </td>
                <td>{o.mode}</td>
                <td>{o.tools ? o.tools.join(', ') : <span className="muted">inherited</span>}</td>
                <td>{o.include_posture == null ? <span className="muted">inherited</span> : o.include_posture ? 'counted' : 'not counted'}</td>
                <td>
                  {o.changed_by}, {formatDateTime(o.changed_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}

function settingsText(doc?: Record<string, unknown>): ReactNode {
  if (!doc) return <span className="muted">not set</span>;
  const parts: string[] = [];
  if (typeof doc.enabled === 'boolean') parts.push(doc.enabled ? 'on' : 'off');
  if (typeof doc.mode === 'string') parts.push(doc.mode);
  if (Array.isArray(doc.tools)) parts.push(`tools ${(doc.tools as string[]).join(', ') || 'none'}`);
  if (typeof doc.include_posture === 'boolean') parts.push(doc.include_posture ? 'posture counted' : 'no posture');
  if (typeof doc.timeout_s === 'number') parts.push(`${doc.timeout_s} s`);
  return parts.join(' · ');
}

/** The settings history: every change, kept forever (VM-UI-F-1205). */
export function History({ entries, repo }: { entries: NuGuardAuditEntry[]; repo?: string }) {
  const [more, setMore] = useState<NuGuardAuditEntry[]>([]);
  const [next, setNext] = useState<string | undefined>(entries.length >= 20 ? String(entries[entries.length - 1]?.id) : undefined);
  const load = useMutation({
    mutationFn: () => api.nuguardAudit(next, repo),
    onSuccess: (page) => {
      setMore((m) => [...m, ...page.entries.filter((e) => !entries.some((x) => x.id === e.id))]);
      setNext(page.next);
    },
  });
  const rows = [...entries, ...more];
  return (
    <Panel title="Settings history" subtitle="every change, who made it, and why; kept forever">
      {rows.length === 0 ? (
        <p className="muted">No change has been made here yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">When</th>
              <th scope="col">Who</th>
              <th scope="col">What</th>
              <th scope="col">Before</th>
              <th scope="col">After</th>
              <th scope="col">Reason</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id}>
                <td>{formatDateTime(e.changed_at)}</td>
                <td>{e.changed_by}</td>
                <td>{e.scope === 'fleet' ? 'fleet' : <span className="mono">{e.repo}</span>}</td>
                <td>{settingsText(e.before)}</td>
                <td>{e.after ? settingsText(e.after) : <span className="muted">cleared</span>}</td>
                <td>{e.reason || <span className="muted">none given</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {next && (
        <button type="button" className="link-button" onClick={() => load.mutate()} disabled={load.isPending}>
          Show older changes
        </button>
      )}
    </Panel>
  );
}

// --- the repository page ---------------------------------------------------------

/** A repository's NuGuard setting and the last ten scans' options (VM-UI-F-1203). */
export function RepoNuGuardSection({ repo }: { repo: string }) {
  const q = useQuery({ queryKey: ['repo-nuguard', repo], queryFn: () => api.repoNuGuard(repo), retry: false });
  const view = useNuGuard();
  if (q.error instanceof ApiRequestError && q.error.status === 403) return null; // the public sees none of it
  if (q.isLoading) return <Loading what="NuGuard's setting" />;
  if (q.error) return <ErrorState error={q.error} what="NuGuard's setting" />;
  const r = q.data!;
  return (
    <Panel title="NuGuard" subtitle="AI code rules and the AI component inventory, for this repository">
      {!r.configured ? (
        <NotConfigured note={r.note} />
      ) : (
        <>
          <dl className="record">
            <dt>A scan now would use</dt>
            <dd>
              <EffectiveText e={r.effective} />
              <ClipNotes clips={r.effective.clips} />
            </dd>
            <dt>Override</dt>
            <dd>
              {r.override ? (
                <>
                  {r.override.mode}
                  {r.override.tools && <> · tools {r.override.tools.join(', ')}</>}
                  <span className="muted small">
                    {' '}
                    — {r.override.changed_by}, {formatDateTime(r.override.changed_at)}
                  </span>
                </>
              ) : (
                <span className="muted">none: the fleet setting applies</span>
              )}
            </dd>
          </dl>
          {r.can_edit && view.data && <OverrideControl repo={repo} v={view.data} current={r.override} />}
          <h3 className="small">Last ten scans</h3>
          {r.recent.length === 0 ? (
            <p className="muted">Not scanned yet.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th scope="col">Run</th>
                  <th scope="col">NuGuard options</th>
                </tr>
              </thead>
              <tbody>
                {r.recent.map((s) => (
                  <tr key={s.run_id}>
                    <td className="mono">
                      <Link to={`/runs/${encodeURIComponent(s.run_id)}`}>{s.run_id}</Link>
                    </td>
                    <td>
                      {s.effective ? <EffectiveText e={s.effective} /> : <Absent why={s.note ?? 'not recorded'} />}
                      <ClipNotes clips={s.effective?.clips} />
                      <NotRequestedList items={s.not_requested} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </Panel>
  );
}

function OverrideControl({
  repo,
  v,
  current,
}: {
  repo: string;
  v: NuGuardView;
  current?: { mode: string; tools?: string[]; include_posture?: boolean };
}) {
  const qc = useQueryClient();
  const [mode, setMode] = useState<'inherit' | 'on' | 'off'>((current?.mode as 'inherit' | 'on' | 'off') ?? 'inherit');
  const [ownTools, setOwnTools] = useState(current?.tools != null);
  const [tools, setTools] = useState<string[]>(current?.tools ?? v.fleet.settings.tools);
  const [reason, setReason] = useState('');
  const save = useMutation({
    mutationFn: () =>
      api.putRepoNuGuard(repo, { mode, tools: ownTools && mode !== 'off' ? tools : undefined, reason: reason || undefined }),
    onSuccess: (next) => {
      qc.setQueryData(['repo-nuguard', repo], next);
      void qc.invalidateQueries({ queryKey: ['nuguard'] });
      setReason('');
    },
  });
  return (
    <form
      className="nuguard-form"
      aria-label="NuGuard override for this repository"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      <label className="field">
        <span>Override</span>
        <select value={mode} onChange={(e) => setMode(e.target.value as 'inherit' | 'on' | 'off')}>
          <option value="inherit">inherit the fleet setting</option>
          <option value="on">on for this repository</option>
          <option value="off">off for this repository</option>
        </select>
      </label>
      {mode !== 'off' && (
        <label className="switch-row">
          <input type="checkbox" checked={ownTools} onChange={(e) => setOwnTools(e.target.checked)} />
          <span>Choose this repository's own tools</span>
        </label>
      )}
      {mode !== 'off' && ownTools && <ToolChoice v={v} chosen={tools} onChange={setTools} />}
      {mode === 'off' && <p className="muted small">{NUGUARD_NOTE.split('. ').slice(-1)[0]}</p>}
      <label className="field">
        <span>Reason (optional, kept in the history)</span>
        <input type="text" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} />
      </label>
      <button type="submit" disabled={save.isPending}>
        Save override
      </button>
      {save.isError && (
        <p className="warn-text" role="alert">
          {errorText(save.error)}
        </p>
      )}
    </form>
  );
}

// --- scan options ----------------------------------------------------------------

/**
 * The NuGuard options of one scan request, collapsed by default (VM-UI-F-1204).
 * With nothing chosen, onChange reports undefined and the request is exactly
 * today's. With options chosen, the preview shows what the scan worker will
 * use, clips included, before anything is submitted.
 */
export function ScanOptions({
  repo,
  value,
  onChange,
}: {
  /** The repository to preview against; for "scan all", any one of them. */
  repo?: string;
  value?: ScanNuGuardOptions;
  onChange: (next?: ScanNuGuardOptions) => void;
}) {
  const view = useNuGuard();
  const preview = useQuery({
    queryKey: ['nuguard-preview', repo, value],
    queryFn: () => api.nuguardPreview(repo!, value),
    enabled: repo != null && value != null,
    retry: false,
  });
  if (!view.data?.configured || !view.data.can_edit) return null;
  const v = view.data;
  const mode = value?.mode ?? 'default';
  const set = (patch: Partial<ScanNuGuardOptions>) => {
    const next = { mode, ...value, ...patch } as ScanNuGuardOptions;
    if (next.mode === 'off') {
      delete next.tools;
      delete next.include_posture;
      delete next.keep_sbom;
    }
    onChange(next.mode === 'default' && !next.tools && next.include_posture == null && !next.keep_sbom ? undefined : next);
  };
  return (
    <details className="scan-options">
      <summary>NuGuard options</summary>
      <fieldset className="filter-group">
        <legend>NuGuard for this scan</legend>
        {(['default', 'on', 'off'] as const).map((m) => (
          <label key={m} className="switch-row">
            <input type="radio" name={`nuguard-mode-${repo ?? 'all'}`} checked={mode === m} onChange={() => set({ mode: m })} />
            <span>{m === 'default' ? 'default (the repository and fleet settings)' : m}</span>
          </label>
        ))}
      </fieldset>
      {mode !== 'off' && (
        <>
          <label className="switch-row">
            <input
              type="checkbox"
              checked={value?.tools != null}
              onChange={(e) => set({ tools: e.target.checked ? v.fleet.settings.tools : undefined })}
            />
            <span>Choose the tools for this scan</span>
          </label>
          {value?.tools && <ToolChoice v={v} chosen={value.tools} onChange={(tools) => set({ tools })} legend="Tools for this scan" />}
          <label className="switch-row">
            <input
              type="checkbox"
              checked={value?.include_posture === true}
              disabled={!v.ceiling?.allow_posture}
              onChange={(e) => set({ include_posture: e.target.checked ? true : undefined })}
            />
            <span>Count posture into the inventory</span>
            {!v.ceiling?.allow_posture && <span className="muted small"> (not allowed by the operator)</span>}
          </label>
          <label className="switch-row">
            <input type="checkbox" checked={value?.keep_sbom === true} onChange={(e) => set({ keep_sbom: e.target.checked || undefined })} />
            <span>Keep the AI-SBOM</span>
          </label>
        </>
      )}
      {value && (
        <div className="preview" role="status" aria-live="polite">
          {preview.isLoading && <span className="muted">Checking what the scan would use…</span>}
          {preview.isError && <span className="warn-text">{errorText(preview.error)}</span>}
          {preview.data && (
            <>
              <span className="small">
                {repo ? `A scan of ${repo} would use: ` : 'Would use: '}
                <EffectiveText e={preview.data.effective} />
              </span>
              <ClipNotes clips={preview.data.clips} />
              {preview.data.note && <p className="muted small">{preview.data.note}</p>}
            </>
          )}
        </div>
      )}
    </details>
  );
}

/** What a scan request asked of NuGuard, in words. */
export function requestText(n?: ScanNuGuardOptions): string {
  if (!n) return '';
  if (n.mode === 'off') return 'NuGuard off for this scan';
  const parts = [n.mode === 'on' ? 'NuGuard on' : 'NuGuard default'];
  if (n.tools) parts.push(n.tools.join(', '));
  if (n.include_posture) parts.push('posture');
  if (n.keep_sbom) parts.push('keep AI-SBOM');
  return parts.join(' · ');
}

// --- the finding page ----------------------------------------------------------------

/** A NuGuard finding's own section, instead of raw annotations (VM-UI-F-1208). */
export function NuGuardFindingSection({ d }: { d: NuGuardDetail }) {
  const missing = (what: string) => <Absent why={`NuGuard ${d.version} gave no ${what} for this finding`} />;
  return (
    <Panel title="NuGuard" subtitle={`reported by NuGuard ${d.version}`}>
      <dl className="record">
        <dt>Rule</dt>
        <dd className="mono">{d.rule}</dd>
        <dt>NuGuard tool</dt>
        <dd>{d.sub_tool ?? missing('tool')}</dd>
        <dt>OWASP LLM</dt>
        <dd>{d.owasp_llm_ref ?? missing('OWASP LLM reference')}</dd>
        <dt>OWASP agentic (ASI)</dt>
        <dd>{d.owasp_asi_ref ?? missing('OWASP ASI reference')}</dd>
        <dt>MITRE ATLAS</dt>
        <dd>{d.mitre_atlas_technique ?? missing('MITRE ATLAS technique')}</dd>
        <dt>Enclosing function</dt>
        <dd className="mono">{d.function ?? missing('enclosing function')}</dd>
        <dt>Last observed by</dt>
        <dd>
          {d.last_run ? <Link to={`/runs/${encodeURIComponent(d.last_run)}`}>{d.last_run}</Link> : <Absent why="no run recorded" />}
          {d.effective ? (
            <>
              {' — '}
              <EffectiveText e={d.effective} />
              <ClipNotes clips={d.effective.clips} />
            </>
          ) : (
            <p className="muted small">{d.note}</p>
          )}
        </dd>
      </dl>
    </Panel>
  );
}

/** The kept AI-SBOM's download, on the AI components panel (VM-UI-F-1210). */
export function AISBOMDownload({
  repo,
  runID,
  sbom,
}: {
  repo: string;
  runID?: string;
  sbom?: { stored: boolean; size_bytes: number; sha256: string; withheld?: string };
}) {
  if (!sbom || !runID) return null;
  if (!sbom.stored) return <p className="muted small">AI-SBOM not kept: {sbom.withheld}</p>;
  return (
    <p className="small">
      <a href={api.aiSbomURL(repo, runID)} download>
        Download AI-SBOM
      </a>{' '}
      <span className="muted">
        (JSON, {Math.max(1, Math.round(sbom.size_bytes / 1024))} KB, sha256 {sbom.sha256.slice(0, 12)})
      </span>
    </p>
  );
}
