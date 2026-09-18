/**
 * Presentation helpers.
 *
 * The rule throughout: nothing here invents a value. A helper that turned an
 * absent number into "0" or an absent date into "never" would be making a
 * claim the data does not support, and the whole point of the interface is
 * that it does not do that. Absent renders as "—" with a title explaining
 * what absent means in that place.
 */

export const ABSENT = '—';

/** A severity's display order and its non-colour encoding (VM-UI-F-901). */
export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const;

export function severityMark(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return '▲▲';
    case 'HIGH':
      return '▲';
    case 'MEDIUM':
      return '●';
    case 'LOW':
      return '▽';
    default:
      return '?';
  }
}

/** A state's partition, for grouping and for the non-colour marker. */
export function stateMark(state: string): string {
  switch (state) {
    case 'VERIFIED':
      return '✓';
    case 'MERGED':
      return '⇢';
    case 'REGRESSED':
      return '↺';
    case 'PR_OPEN':
    case 'AUTO_REMEDIATING':
      return '⚙';
    case 'NEEDS_HUMAN':
      return '☞';
    case 'BLOCKED_UPSTREAM':
      return '⤒';
    case 'SUPPRESSED':
    case 'DECLINED':
    case 'WONT_FIX':
      return '∅';
    default:
      return '·';
  }
}

/** reachableLabel renders the tri-state, never as a boolean (VM-F-243). */
export function reachableLabel(value: string): { text: string; hint: string } {
  switch (value) {
    case 'true':
      return { text: 'reachable', hint: 'a tool determined the vulnerable code is reached' };
    case 'false':
      return { text: 'not reachable', hint: 'a tool determined the vulnerable code is NOT reached' };
    default:
      return {
        text: 'unknown',
        hint:
          'nobody has determined whether the vulnerable code is reached. This is NOT ' +
          '"not reachable": it is the absence of a determination, and it is the common case',
      };
  }
}

export function formatDate(iso: string | undefined): string {
  if (!iso) return ABSENT;
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return ABSENT;
  return at.toISOString().slice(0, 10);
}

export function formatDateTime(iso: string | undefined): string {
  if (!iso) return ABSENT;
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return ABSENT;
  return at.toISOString().replace('T', ' ').slice(0, 16) + 'Z';
}

/** formatHours renders an elapsed span. */
export function formatHours(hours: number | undefined): string {
  if (hours === undefined) return ABSENT;
  if (hours < 48) return `${Math.round(hours)}h`;
  return `${Math.round(hours / 24)}d`;
}

/**
 * formatNanoseconds renders a Go duration, which arrives as nanoseconds.
 *
 * The coverage staleness figures come from the store's own type and are
 * serialised as Go durations. Rendering the raw number would be honest and
 * unreadable; this converts without rounding away the distinction between
 * "two days" and "two weeks".
 */
export function formatNanoseconds(ns: number | undefined): string {
  if (ns === undefined || ns === 0) return ABSENT;
  const hours = ns / 1e9 / 3600;
  return formatHours(hours);
}

/** pct renders a percentage with one decimal, never rounding 99.9 to 100. */
export function pct(value: number): string {
  return `${Math.floor(value * 10) / 10}%`;
}

/**
 * epssLabel renders an exploit-prediction score, or says nothing answered.
 *
 * The distinction is the point: an absent score is not a low one
 * (OQ-AUDIT-01). A client that rendered `undefined` as 0.00 would convert a
 * feed outage into reassurance.
 */
export function epssLabel(value: number | undefined): { text: string; known: boolean } {
  if (value === undefined) return { text: 'not looked up', known: false };
  return { text: value.toFixed(2), known: true };
}

export function kevLabel(value: boolean | undefined): { text: string; known: boolean } {
  if (value === undefined) return { text: 'not checked', known: false };
  return { text: value ? 'known exploited' : 'not listed', known: true };
}

/** slaLabel renders the SLA position, keeping "not computed" distinct. */
export function slaLabel(sla: {
  computed: boolean;
  status?: string;
  breach_days?: number;
  window_days?: number;
}): { text: string; tone: 'breached' | 'approaching' | 'within' | 'paused' | 'none' } {
  if (!sla.computed) return { text: 'not computed', tone: 'none' };
  switch (sla.status) {
    case 'breached':
      return { text: `breached by ${sla.breach_days ?? 0}d`, tone: 'breached' };
    case 'approaching':
      return { text: `approaching (${sla.window_days ?? 0}d window)`, tone: 'approaching' };
    case 'paused':
      return { text: 'paused', tone: 'paused' };
    case 'stopped':
      return { text: 'stopped', tone: 'none' };
    default:
      return { text: `within ${sla.window_days ?? 0}d`, tone: 'within' };
  }
}

/** csvEscape renders one CSV field (VM-UI-F-415). */
export function csvEscape(value: string): string {
  if (/[",\n]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
  return value;
}

/** toCSV renders rows with a header. */
export function toCSV(header: string[], rows: string[][]): string {
  return [header, ...rows].map((r) => r.map(csvEscape).join(',')).join('\n');
}
