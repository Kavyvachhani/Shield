/**
 * Presentation helpers shared across screens.
 *
 * Kept apart from the components in `components/ui.tsx` because a module that
 * exports both components and plain functions breaks React Fast Refresh — the
 * whole module reloads instead of the component, losing state on every save.
 * The split is also the right one on its own terms: none of this renders
 * anything.
 */

import type { Severity } from '../types';

/**
 * The single mapping from severity to its badge class.
 *
 * Every screen imports this rather than writing its own. It was written out
 * four times before, and two of those disagreed — a severity that renders amber
 * on one screen and orange on another is a report the reader learns to
 * distrust.
 */
export const SEVERITY_CLASS: Record<Severity, string> = {
  Critical: 'badge-critical',
  High: 'badge-high',
  Medium: 'badge-medium',
  Low: 'badge-low',
  Info: 'badge-info',
};

/** Highest first — the order every list, chart and summary uses. */
export const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];

/** A duration in the largest unit that keeps it readable. */
export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.max(seconds, 0)}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

/**
 * How long ago, in the terms a person would use.
 *
 * An absolute timestamp is right in a report and wrong in a list being
 * scanned: "3 min ago" answers the question the reader actually has.
 */
export function formatRelative(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const seconds = Math.floor((Date.now() - then) / 1000);
  if (seconds < 45) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)} d ago`;
  return new Date(iso).toLocaleDateString();
}

/** Count findings by severity, with every band present so a chart has no holes. */
export function countBySeverity(items: { severity: Severity }[]): Record<Severity, number> {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 } as Record<Severity, number>;
  for (const item of items) counts[item.severity] = (counts[item.severity] ?? 0) + 1;
  return counts;
}
