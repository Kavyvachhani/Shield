/**
 * The shared vocabulary every screen is built from.
 *
 * These exist so that a button, a badge and an empty state look the same
 * wherever they appear. Before this, each screen wrote its own inline styles
 * and the same idea arrived in four slightly different forms — most damagingly
 * severity colour, which was defined in four places and disagreed between two
 * of them. A severity that renders amber on one screen and orange on another
 * is a report the reader learns to distrust.
 *
 * Nothing here is speculative. Each component is used by at least two screens;
 * a one-off stays in the screen that needs it.
 */

import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import {
  AlertTriangle, CheckCircle2, Info, Loader2, Moon, Sun, X, XCircle,
} from 'lucide-react';
import type { Severity } from '../types';
import type { Theme } from '../lib/useTheme';
import { SEVERITY_CLASS, SEVERITY_ORDER } from '../lib/presentation';

// ── Severity ────────────────────────────────────────────────────────────────

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge ${SEVERITY_CLASS[severity]}`}>{severity}</span>;
}

/**
 * Severity proportions as one stacked bar.
 *
 * Deliberately not a pie chart. The question a reader asks of this is "how much
 * of the total is serious", which is a part-to-whole comparison along one axis —
 * exactly what a stacked bar answers and what a circle makes harder.
 */
export function SeverityBar({ counts }: { counts: Record<Severity, number> }) {
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + (counts[s] ?? 0), 0);
  if (total === 0) {
    return <div className="severity-bar" aria-label="No findings" />;
  }
  return (
    <div
      className="severity-bar"
      role="img"
      aria-label={SEVERITY_ORDER.filter((s) => counts[s])
        .map((s) => `${counts[s]} ${s.toLowerCase()}`)
        .join(', ')}
    >
      {SEVERITY_ORDER.map((s) =>
        counts[s] ? (
          <span
            key={s}
            className={`seg-${s.toLowerCase()}`}
            style={{ flexGrow: counts[s] }}
            title={`${counts[s]} ${s}`}
          />
        ) : null,
      )}
    </div>
  );
}

// ── Primitives ──────────────────────────────────────────────────────────────

export function Stat({
  label, value, note, tone = 'accent',
}: {
  label: string;
  value: ReactNode;
  note?: ReactNode;
  tone?: 'accent' | 'critical' | 'high' | 'medium' | 'low' | 'info';
}) {
  return (
    <div className={`stat ${tone === 'accent' ? '' : `stat-${tone}`}`}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {note && <span className="stat-note">{note}</span>}
    </div>
  );
}

export function Callout({
  tone = 'info', icon, children,
}: {
  tone?: 'info' | 'success' | 'warning' | 'danger';
  icon?: ReactNode;
  children: ReactNode;
}) {
  const fallback = {
    info: <Info size={15} />,
    success: <CheckCircle2 size={15} />,
    warning: <AlertTriangle size={15} />,
    danger: <XCircle size={15} />,
  }[tone];
  return (
    <div className={`callout callout-${tone}`}>
      {icon ?? fallback}
      <div className="grow">{children}</div>
    </div>
  );
}

/**
 * What a screen shows when it has nothing to show.
 *
 * An empty region with no explanation is read as a bug. Every one of these
 * says what would put something here, and offers the action that does it.
 */
export function EmptyState({
  icon, title, children, action,
}: {
  icon?: ReactNode;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      {icon}
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function Spinner({ size = 15 }: { size?: number }) {
  return <Loader2 size={size} className="spin" />;
}

export function Modal({
  title, onClose, children, footer, wide,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  // Escape closes it. A modal that can only be dismissed by finding the small
  // button in its corner is one people learn to dread.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="overlay" onClick={onClose} role="presentation">
      <div
        className={`modal ${wide ? 'modal-wide' : ''}`}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="modal-header">
          <h2 className="h2">{title}</h2>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={onClose} aria-label="Close">
            <X size={15} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  );
}

// ── Toasts ──────────────────────────────────────────────────────────────────

type Toast = { id: number; tone: 'info' | 'success' | 'error'; message: string };

const ToastContext = createContext<(tone: Toast['tone'], message: string) => void>(() => {});

/** Raise a transient message. Used for outcomes the analyst should notice but
 *  need not acknowledge — a profile saved, a finding dismissed, an export
 *  written. Anything that needs a decision gets a modal instead. */
export const useToast = () => useContext(ToastContext);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const push = useCallback((tone: Toast['tone'], message: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, tone, message }]);
    // Errors stay longer: they are more likely to be read after the fact, and
    // more likely to matter.
    const ms = tone === 'error' ? 8000 : 4000;
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), ms);
  }, []);

  const icons = {
    info: <Info size={14} />,
    success: <CheckCircle2 size={14} />,
    error: <XCircle size={14} />,
  };

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.tone}`}>
            {icons[t.tone]}
            <span className="grow">{t.message}</span>
            <button
              className="btn btn-ghost btn-icon btn-sm"
              onClick={() => setToasts((all) => all.filter((x) => x.id !== t.id))}
              aria-label="Dismiss"
            >
              <X size={13} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

// ── Theme ───────────────────────────────────────────────────────────────────

export function ThemeToggle({ theme, onToggle }: { theme: Theme; onToggle: () => void }) {
  return (
    <button
      className="btn btn-ghost btn-icon btn-sm"
      onClick={onToggle}
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
      aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
    >
      {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
    </button>
  );
}
