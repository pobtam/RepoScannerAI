/**
 * Requesting scans: "Scan now" on a repository, "Scan all included
 * repositories" on the index, and the status of each request.
 *
 * A click only queues a request; the scan worker does the work, so the status
 * is polled while anything is queued or running. Every state the queue can
 * hold is shown as itself: a timed-out or interrupted scan is never shown as
 * finished, and a refused one says why.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiRequestError } from '../../api/client';
import type { ScanRequest } from '../../api/schemas';
import { Badge, Panel } from '../../components/primitives';
import { Link } from '../../lib/router';
import { formatDate } from '../../lib/format';

const ACTIVE = new Set(['queued', 'running']);

function useScansEnabled(): boolean {
  const health = useQuery({ queryKey: ['health'], queryFn: api.health, staleTime: 60_000 });
  return health.data?.scan_requests === true;
}

function errorText(err: unknown): string {
  if (err instanceof ApiRequestError) {
    return [err.message, err.detail].filter(Boolean).join(': ');
  }
  return err instanceof Error ? err.message : String(err);
}

const TONE: Record<ScanRequest['status'], string> = {
  queued: 'state-unresolved',
  running: 'state-pending_verification',
  finished: 'state-resolved',
  failed: 'sev-CRITICAL',
  timed_out: 'sev-HIGH',
  interrupted: 'sev-MEDIUM',
  refused: 'sev-UNKNOWN',
};

const LABEL: Record<ScanRequest['status'], string> = {
  queued: 'queued',
  running: 'running',
  finished: 'finished',
  failed: 'failed',
  timed_out: 'timed out',
  interrupted: 'interrupted',
  refused: 'refused',
};

/** One request's status, as a sentence with its links. */
export function ScanStatus({ r, onRetry }: { r: ScanRequest; onRetry?: () => void }) {
  return (
    <span className="scan-status">
      <Badge tone={TONE[r.status]}>{LABEL[r.status]}</Badge>{' '}
      {r.status === 'queued' && <span className="muted">since {formatDate(r.requested_at)}</span>}
      {r.status === 'running' && <span className="muted">since {formatDate(r.started_at ?? r.requested_at)}</span>}
      {r.status === 'finished' && (
        <>
          {r.run_id && <Link to={`/runs/${encodeURIComponent(r.run_id)}`}>run {r.run_id}</Link>}
          {' · '}
          <Link to={`/findings?scope=open&repo=${encodeURIComponent(r.repo)}`}>findings</Link>
          {r.reason && <span className="muted"> · {r.reason}</span>}
        </>
      )}
      {(r.status === 'failed' || r.status === 'timed_out' || r.status === 'interrupted' || r.status === 'refused') && (
        <span className={r.status === 'refused' ? 'muted' : 'warn-text'}>{r.reason}</span>
      )}
      {(r.status === 'timed_out' || r.status === 'failed') && r.run_id && (
        <>
          {' · '}
          <Link to="/coverage">recorded as a coverage gap</Link>
        </>
      )}
      {r.status === 'interrupted' && onRetry && (
        <>
          {' '}
          <button type="button" className="link-button" onClick={onRetry}>
            Retry
          </button>
        </>
      )}
      <span className="muted small"> · requested by {r.requested_by}</span>
    </span>
  );
}

/** "Scan now" and the latest request, on a repository's page. */
export function ScanNow({ repo }: { repo: string }) {
  const enabled = useScansEnabled();
  const qc = useQueryClient();
  const latest = useQuery({
    queryKey: ['scans', repo],
    queryFn: () => api.scans(repo, 1),
    enabled,
    refetchInterval: (q) => (q.state.data?.some((r) => ACTIVE.has(r.status)) ? 5000 : false),
  });
  const request = useMutation({
    mutationFn: () => api.requestScan(repo),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  });
  if (!enabled) return null;

  const last = latest.data?.[0];
  const busy = request.isPending || (last != null && ACTIVE.has(last.status));
  return (
    <div className="scan-now">
      <button type="submit" onClick={() => request.mutate()} disabled={busy} aria-describedby="scan-now-status">
        {busy ? 'Scan queued' : 'Scan now'}
      </button>
      <span id="scan-now-status" role="status" aria-live="polite">
        {request.isError && <span className="warn-text">{errorText(request.error)}</span>}
        {!request.isError && request.data?.merged && <span className="muted">Already queued; this request was merged into it. </span>}
        {last ? <ScanStatus r={last} onRetry={() => request.mutate()} /> : <span className="muted">No scan requested yet.</span>}
      </span>
    </div>
  );
}

/** "Scan all included repositories" and the queue, on the repositories index. */
export function ScanQueue() {
  const enabled = useScansEnabled();
  const qc = useQueryClient();
  const recent = useQuery({
    queryKey: ['scans', 'all'],
    queryFn: () => api.scans(undefined, 10),
    enabled,
    refetchInterval: (q) => (q.state.data?.some((r) => ACTIVE.has(r.status)) ? 5000 : false),
  });
  const all = useMutation({
    mutationFn: () => api.requestScanAll(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  });
  const retry = useMutation({
    mutationFn: (repo: string) => api.requestScan(repo),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  });
  if (!enabled) return null;

  const rows = recent.data ?? [];
  return (
    <Panel
      title="Scans"
      subtitle="requested here, with vfctl, or by the daily timer; the scan worker runs them one at a time"
      actions={
        <button type="submit" onClick={() => all.mutate()} disabled={all.isPending}>
          Scan all included repositories
        </button>
      }
    >
      <div role="status" aria-live="polite">
        {all.isError && <p className="warn-text">{errorText(all.error)}</p>}
        {retry.isError && <p className="warn-text">{errorText(retry.error)}</p>}
        {all.data && (
          <p className="muted">
            {all.data.queued} queued, {all.data.merged} already queued or running.
          </p>
        )}
      </div>
      {rows.length === 0 ? (
        <p className="muted">No scans requested yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Repository</th>
              <th scope="col">Status</th>
              <th scope="col">Requested</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="mono">
                  <Link to={`/repos/${r.repo}`}>{r.repo}</Link>
                </td>
                <td>
                  <ScanStatus r={r} onRetry={() => retry.mutate(r.repo)} />
                </td>
                <td>{formatDate(r.requested_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
