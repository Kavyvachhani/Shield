import { useEffect, useMemo, useState } from 'react';
import { Loader2, Search } from 'lucide-react';
import type { CheckResult, CheckStatus, CoverageReport } from '../types';
import { api } from '../lib/tauri';

interface Props {
  scanId: string;
}

const STATUS_META: Record<CheckStatus, { label: string; color: string }> = {
  passed: { label: 'Passed', color: '#16a34a' },
  issues_found: { label: 'Issues found', color: '#dc2626' },
  manual_required: { label: 'Manual review', color: '#d97706' },
  not_tested: { label: 'Not tested', color: '#94a3b8' },
};

const STATUS_ORDER: CheckStatus[] = ['issues_found', 'manual_required', 'not_tested', 'passed'];

export function CoverageScreen({ scanId }: Props) {
  const [coverage, setCoverage] = useState<CoverageReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [statusFilter, setStatusFilter] = useState<CheckStatus | 'all'>('all');
  const [search, setSearch] = useState('');

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    api
      .getCoverage(scanId)
      .then((c) => {
        if (active) setCoverage(c);
      })
      .catch((e) => {
        if (active) setError(String(e));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [scanId]);

  const visible = useMemo(() => {
    if (!coverage) return [];
    const needle = search.trim().toLowerCase();
    return coverage.results.filter((r) => {
      if (statusFilter !== 'all' && r.status !== statusFilter) return false;
      if (!needle) return true;
      return (
        r.id.toLowerCase().includes(needle) ||
        r.name.toLowerCase().includes(needle) ||
        r.category.toLowerCase().includes(needle) ||
        r.cwe.toLowerCase().includes(needle) ||
        r.owasp2025.toLowerCase().includes(needle)
      );
    });
  }, [coverage, statusFilter, search]);

  const grouped = useMemo(() => {
    const map = new Map<string, CheckResult[]>();
    for (const r of visible) {
      const list = map.get(r.category) ?? [];
      list.push(r);
      map.set(r.category, list);
    }
    return [...map.entries()];
  }, [visible]);

  if (loading) {
    return (
      <Centered>
        <Loader2 size={20} className="spin" />
        <span style={{ marginLeft: 10 }}>Building the coverage matrix…</span>
      </Centered>
    );
  }

  if (error || !coverage) {
    return <Centered>{error || 'No coverage data is available for this scan.'}</Centered>;
  }

  return (
    <div className="fade-in" style={{ padding: '24px 28px', height: '100%', overflow: 'auto' }}>
      <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>Assessment Coverage</h2>
      <div style={{ color: 'var(--text-muted)', fontSize: 12, marginBottom: 18, maxWidth: 720, lineHeight: 1.6 }}>
        Every test case from the OWASP Web Security Testing Guide considered during this assessment.
        A check only counts as passed when an engine covering it actually ran — checks needing a tool that
        was unavailable are shown as not tested, not as clean.
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 20 }}>
        <Kpi label="Total checks" value={coverage.totalChecks} />
        <Kpi label="Passed" value={coverage.passed} color={STATUS_META.passed.color} />
        <Kpi label="Issues found" value={coverage.issuesFound} color={STATUS_META.issues_found.color} />
        <Kpi label="Manual review" value={coverage.manualRequired} color={STATUS_META.manual_required.color} />
        <Kpi label="Not tested" value={coverage.notTested} color={STATUS_META.not_tested.color} />
      </div>

      <div
        style={{
          border: '1px solid var(--border-strong)',
          borderRadius: 'var(--radius-sm)',
          padding: 14,
          marginBottom: 20,
          background: 'var(--bg-elevated)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 8 }}>
          <strong>{coverage.automatedCoveragePct.toFixed(0)}% of automatable checks exercised</strong>
          <span style={{ color: 'var(--text-muted)' }}>
            Engines: {coverage.enginesExecuted.join(', ') || 'none'}
          </span>
        </div>
        <div style={{ display: 'flex', height: 12, borderRadius: 6, overflow: 'hidden', background: '#1e293b' }}>
          {STATUS_ORDER.map((status) => {
            const value =
              status === 'passed'
                ? coverage.passed
                : status === 'issues_found'
                  ? coverage.issuesFound
                  : status === 'manual_required'
                    ? coverage.manualRequired
                    : coverage.notTested;
            if (!value) return null;
            return (
              <div
                key={status}
                title={`${STATUS_META[status].label}: ${value}`}
                style={{
                  flex: value,
                  background: STATUS_META[status].color,
                }}
              />
            );
          })}
        </div>
        {coverage.enginesUnavailable.length > 0 && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 10, lineHeight: 1.6 }}>
            Install {coverage.enginesUnavailable.join(', ')} and re-run to close the remaining gaps.
          </div>
        )}
      </div>

      <div style={{ display: 'flex', gap: 10, marginBottom: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: '1 1 240px', minWidth: 200 }}>
          <Search
            size={13}
            style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', opacity: 0.5 }}
          />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by reference, name, CWE or OWASP category"
            style={{
              width: '100%',
              padding: '8px 10px 8px 30px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-strong)',
              background: 'var(--bg-base)',
              color: 'inherit',
              fontSize: 12,
            }}
          />
        </div>
        <FilterChip active={statusFilter === 'all'} onClick={() => setStatusFilter('all')} label="All" />
        {STATUS_ORDER.map((s) => (
          <FilterChip
            key={s}
            active={statusFilter === s}
            onClick={() => setStatusFilter(s)}
            label={STATUS_META[s].label}
            color={STATUS_META[s].color}
          />
        ))}
      </div>

      {grouped.length === 0 && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: 20 }}>
          No checks match the current filter.
        </div>
      )}

      {grouped.map(([category, items]) => (
        <section key={category} style={{ marginBottom: 26 }}>
          <h3 style={{ fontSize: 13, fontWeight: 700, marginBottom: 8 }}>
            {category} <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>({items.length})</span>
          </h3>
          <div style={{ border: '1px solid var(--border-strong)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
            {items.map((r, i) => (
              <div
                key={r.id}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '120px 1fr 130px 150px',
                  gap: 12,
                  padding: '10px 14px',
                  fontSize: 12,
                  alignItems: 'start',
                  borderTop: i === 0 ? 'none' : '1px solid var(--border)',
                }}
              >
                <code style={{ fontSize: 11, opacity: 0.75 }}>{r.id}</code>
                <div>
                  <div style={{ fontWeight: 500 }}>{r.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, lineHeight: 1.5 }}>
                    {r.clientSummary}
                  </div>
                </div>
                <div>
                  <span
                    style={{
                      display: 'inline-block',
                      padding: '2px 9px',
                      borderRadius: 99,
                      fontSize: 10,
                      fontWeight: 700,
                      color: '#fff',
                      background: STATUS_META[r.status].color,
                    }}
                  >
                    {r.statusLabel}
                  </span>
                  {r.findingCount > 0 && (
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
                      {r.findingCount} finding{r.findingCount === 1 ? '' : 's'}
                    </div>
                  )}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  {r.enginesExecuted.length > 0 ? r.enginesExecuted.join(', ') : '—'}
                  {r.enginesMissing.length > 0 && (
                    <div style={{ opacity: 0.7 }}>missing: {r.enginesMissing.join(', ')}</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

function Kpi({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div
      style={{
        border: '1px solid var(--border-strong)',
        borderRadius: 'var(--radius-sm)',
        padding: '14px 12px',
        textAlign: 'center',
        background: 'var(--bg-elevated)',
      }}
    >
      <div style={{ fontSize: 24, fontWeight: 700, color: color ?? 'inherit' }}>{value}</div>
      <div
        style={{
          fontSize: 10,
          letterSpacing: 0.6,
          textTransform: 'uppercase',
          color: 'var(--text-muted)',
          marginTop: 2,
        }}
      >
        {label}
      </div>
    </div>
  );
}

function FilterChip({
  active,
  onClick,
  label,
  color,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  color?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        padding: '6px 12px',
        borderRadius: 99,
        fontSize: 11,
        fontWeight: 600,
        cursor: 'pointer',
        color: 'inherit',
        border: `1px solid ${active ? color ?? 'rgba(34,211,238,0.5)' : 'var(--border-strong)'}`,
        background: active ? `${color ?? '#22d3ee'}22` : 'var(--bg-elevated)',
      }}
    >
      {label}
    </button>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'var(--text-muted)',
        fontSize: 13,
      }}
    >
      {children}
    </div>
  );
}
