import { useEffect, useMemo, useState } from 'react';
import { Loader2, Search, ShieldQuestion } from 'lucide-react';
import type { CheckResult, CheckStatus, CoverageReport } from '../types';
import { api } from '../lib/tauri';
import { EmptyState, RingChart, PillFilter } from '../components/ui';

interface Props {
  scanId: string;
}

// Literal hex here meant the coverage matrix was painted in four colours that
// took no notice of the theme — fine on navy, muddy on paper, and a fifth
// opinion about what "issues found" red is. These reference the palette, so a
// status reads the same here as its severity does everywhere else.
const STATUS_META: Record<CheckStatus, { label: string; color: string; stat: string }> = {
  passed:          { label: 'Passed',        color: 'var(--success)', stat: 'stat-low' },
  issues_found:    { label: 'Issues found',  color: 'var(--danger)',  stat: 'stat-critical' },
  manual_required: { label: 'Manual review', color: 'var(--warning)', stat: 'stat-medium' },
  not_tested:      { label: 'Not tested',    color: 'var(--info)',    stat: 'stat-info' },
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
      <div className="empty">
        <Loader2 size={20} className="spin" />
        <p>Building the coverage matrix…</p>
      </div>
    );
  }

  if (error || !coverage) {
    return (
      <EmptyState icon={<ShieldQuestion size={22} />} title="No coverage data">
        {error || 'This scan recorded no coverage matrix. Re-run it to produce one.'}
      </EmptyState>
    );
  }

  return (
    <div className="page fade-in scroll" style={{ height: '100%' }}>
      <h2 className="h2">Assessment Coverage</h2>
      <div className="hint" style={{ maxWidth: 720, marginBottom: 'var(--s-5)' }}>
        Every test case from the OWASP Web Security Testing Guide considered during this assessment.
        A check only counts as passed when an engine covering it actually ran — checks needing a tool that
        was unavailable are shown as not tested, not as clean.
      </div>

      <div className="grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', marginBottom: 'var(--s-5)' }}>
        <Kpi label="Total checks" value={coverage.totalChecks} />
        <Kpi label="Passed" value={coverage.passed} status="passed" />
        <Kpi label="Issues found" value={coverage.issuesFound} status="issues_found" />
        <Kpi label="Manual review" value={coverage.manualRequired} status="manual_required" />
        <Kpi label="Not tested" value={coverage.notTested} status="not_tested" />
      </div>

      <div className="card card-tight" style={{ marginBottom: 'var(--s-5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--s-5)' }}>
          <RingChart
            value={coverage.automatedCoveragePct}
            size={84}
            strokeWidth={8}
            sub="Coverage"
          />
          <div className="grow col" style={{ gap: 'var(--s-2)' }}>
            <div className="between wrap" style={{ gap: 'var(--s-3)' }}>
              <strong>{coverage.automatedCoveragePct.toFixed(0)}% of automatable checks exercised</strong>
              <span className="dim small">
                Engines: {coverage.enginesExecuted.join(', ') || 'none'}
              </span>
            </div>
            <div className="severity-bar">
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
                    style={{ flexGrow: value, background: STATUS_META[status].color }}
                  />
                );
              })}
            </div>
            {coverage.enginesUnavailable.length > 0 && (
              <div className="hint" style={{ marginTop: 'var(--s-1)' }}>
                Install {coverage.enginesUnavailable.join(', ')} and re-run to close the remaining gaps.
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="row wrap" style={{ marginBottom: 'var(--s-4)', gap: 'var(--s-3)', alignItems: 'center' }}>
        <div className="search" style={{ flex: '1 1 260px', minWidth: 220 }}>
          <Search size={14} />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by reference, name, CWE or OWASP category"
            aria-label="Search coverage checks"
          />
        </div>
        <PillFilter
          options={[
            { id: 'all', label: 'All', count: coverage.totalChecks },
            { id: 'passed', label: 'Passed', count: coverage.passed, tone: 'low' },
            { id: 'issues_found', label: 'Issues found', count: coverage.issuesFound, tone: 'critical' },
            { id: 'manual_required', label: 'Manual review', count: coverage.manualRequired, tone: 'medium' },
            { id: 'not_tested', label: 'Not tested', count: coverage.notTested, tone: 'info' },
          ]}
          value={statusFilter}
          onChange={(val) => setStatusFilter(val as CheckStatus | 'all')}
        />
      </div>

      {grouped.length === 0 && (
        <EmptyState icon={<Search size={22} />} title="No checks match this filter">
          Clear the search or choose a different status to see the rest of the matrix.
        </EmptyState>
      )}

      {grouped.map(([category, items]) => (
        <section key={category} style={{ marginBottom: 'var(--s-5)' }}>
          <div className="row" style={{ gap: 'var(--s-2)', marginBottom: 'var(--s-2)' }}>
            <h3 className="h3" style={{ fontSize: 13.5 }}>{category}</h3>
            <span className="badge badge-outline tabular" style={{ fontSize: 10 }}>{items.length} checks</span>
          </div>
          <div className="card card-flush">
            {items.map((r, i) => (
              <div
                key={r.id}
                className="grid"
                style={{
                  gridTemplateColumns: '120px 1fr 130px 150px',
                  padding: 'var(--s-3) var(--s-4)',
                  alignItems: 'start',
                  borderTop: i === 0 ? 'none' : '1px solid var(--border)',
                }}
              >
                <code className="code-inline">{r.id}</code>
                <div>
                  <div style={{ fontWeight: 500 }}>{r.name}</div>
                  <div className="hint">{r.clientSummary}</div>
                </div>
                <div>
                  {/* The status colour goes on the border and the text rather
                      than as a white-on-colour fill: four saturated pills per
                      row is what made this table hard to read. */}
                  <span
                    className="badge"
                    style={{
                      color: STATUS_META[r.status].color,
                      border: `1px solid ${STATUS_META[r.status].color}`,
                    }}
                  >
                    {r.statusLabel}
                  </span>
                  {r.findingCount > 0 && (
                    <div className="dim small" style={{ marginTop: 4 }}>
                      {r.findingCount} finding{r.findingCount === 1 ? '' : 's'}
                    </div>
                  )}
                </div>
                <div className="dim small">
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

function Kpi({ label, value, status }: { label: string; value: number; status?: CheckStatus }) {
  return (
    <div className={`stat ${status ? STATUS_META[status].stat : ''}`}>
      <span className="stat-value">{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

