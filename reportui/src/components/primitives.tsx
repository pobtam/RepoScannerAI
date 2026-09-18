/**
 * The primitives.
 *
 * Every view defines a loading, empty, error and partial-data state
 * (VM-UI-F-902), and the empty state distinguishes "no results for this
 * filter" from "no data yet" (VM-UI-F-904) — because those call for opposite
 * actions and look identical if you render them the same way.
 */
import type { ReactNode } from 'react';

export function Panel({
  title,
  subtitle,
  actions,
  children,
  tone,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  tone?: 'warning' | 'urgent';
}) {
  return (
    <section className={`panel${tone ? ` panel-${tone}` : ''}`}>
      {(title || actions) && (
        <header className="panel-head">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <p className="subtitle">{subtitle}</p>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Loading({ what }: { what: string }) {
  return (
    <p className="state state-loading" role="status" aria-live="polite">
      Loading {what}…
    </p>
  );
}

/**
 * Empty distinguishes an empty FILTER from an empty SYSTEM.
 *
 * "No findings match this filter" invites narrowing differently; "nothing has
 * been scanned yet" invites running a scan. Rendering both as "no results"
 * sends half the readers to the wrong place.
 */
export function Empty({
  filtered,
  what,
  hint,
}: {
  filtered: boolean;
  what: string;
  hint?: ReactNode;
}) {
  return (
    <div className="state state-empty">
      <p>
        <strong>{filtered ? `No ${what} match this filter.` : `No ${what} recorded yet.`}</strong>
      </p>
      <p className="muted">
        {filtered
          ? 'The corpus and the filters are both in the address bar, so you can widen either and share the result.'
          : 'This is not a clean fleet — it is a system with no data. The two look identical in every aggregate, which is why this says which it is.'}
      </p>
      {hint}
    </div>
  );
}

/**
 * ErrorState says what failed and what to do about it (VM-UI-F-903).
 *
 * A bare "something went wrong" teaches the reader that the system is broken
 * and there is nothing they can do, which is almost never true.
 */
export function ErrorState({ error, what }: { error: unknown; what: string }) {
  const { title, detail, remedy } = describeError(error);
  return (
    <div className="state state-error" role="alert">
      <p>
        <strong>Could not load {what}: {title}</strong>
      </p>
      {detail && <pre className="error-detail">{detail}</pre>}
      <p className="muted">{remedy}</p>
    </div>
  );
}

export function describeError(error: unknown): { title: string; detail: string; remedy: string } {
  if (error && typeof error === 'object' && 'name' in error) {
    const err = error as { name: string; message: string; remedy?: string; detail?: string };
    switch (err.name) {
      case 'CredentialDisclosureError':
        return {
          title: 'the response was rejected',
          detail: err.message,
          remedy:
            'Nothing was rendered. This is a defect in the producer, not in your query, and it ' +
            'must be fixed where the value is written.',
        };
      case 'ShapeDriftError':
        return {
          title: 'the response did not match this interface',
          detail: err.message,
          remedy: 'Regenerate the API types and rebuild the interface (npm run gen && npm run build).',
        };
      case 'ApiRequestError':
        return {
          title: err.message,
          detail: err.detail ?? '',
          remedy: err.remedy || 'Check the address bar; the query is encoded in it.',
        };
      default:
        return { title: err.message, detail: '', remedy: 'Retry, or reload the page.' };
    }
  }
  return { title: String(error), detail: '', remedy: 'Retry, or reload the page.' };
}

/**
 * Caveat renders a qualification INLINE, next to the number it qualifies.
 *
 * Not in a page header. A priority, a breach count and a coverage percentage
 * are quoted onward — into a ticket, a slide, a status mail — and a caveat
 * that stays behind on the page is a caveat nobody quoting the number ever
 * saw (OQ-P5-02, OQ-P7b-03, OQ-AUDIT-01).
 */
export function Caveat({ text, short }: { text: string; short?: string }) {
  if (!text) return null;
  return (
    <span className="caveat" title={text}>
      <span aria-hidden="true">⚠ </span>
      {short ?? 'provisional'}
      <span className="sr-only"> — {text}</span>
    </span>
  );
}

/** Chip is a removable active filter (VM-UI-F-409). */
export function Chip({
  label,
  onRemove,
  tone,
}: {
  label: ReactNode;
  onRemove?: () => void;
  tone?: string;
}) {
  return (
    <span className={`chip${tone ? ` chip-${tone}` : ''}`}>
      {label}
      {onRemove && (
        <button type="button" className="chip-remove" onClick={onRemove} aria-label={`Remove filter ${String(label)}`}>
          ×
        </button>
      )}
    </span>
  );
}

/** Badge encodes a value by shape and text as well as colour (VM-UI-F-901). */
export function Badge({
  mark,
  children,
  tone,
  title,
}: {
  mark?: string;
  children: ReactNode;
  tone?: string;
  title?: string;
}) {
  return (
    <span className={`badge${tone ? ` badge-${tone}` : ''}`} title={title}>
      {mark && <span className="badge-mark" aria-hidden="true">{mark}</span>}
      {children}
    </span>
  );
}

/** Absent renders a value that does not exist, with what that means here. */
export function Absent({ why }: { why: string }) {
  return (
    <span className="absent" title={why}>
      —<span className="sr-only"> absent: {why}</span>
    </span>
  );
}

/** CopyButton copies one value in a single action (VM-UI-F-207b, VM-UI-F-512). */
export function CopyButton({ value, label }: { value: string; label: string }) {
  return (
    <button
      type="button"
      className="copy"
      onClick={() => {
        void navigator.clipboard?.writeText(value);
      }}
      title={`Copy ${label}`}
      aria-label={`Copy ${label}`}
    >
      ⧉
    </button>
  );
}
