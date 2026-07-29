import { useState, useEffect, useCallback } from 'react';
import { Search, SlidersHorizontal, ChevronRight, X, AlertOctagon, Flag } from 'lucide-react';
import type { Finding, FindingStatus, FindingFilter, TriageInput } from '../types';
import { api } from '../lib/tauri';

interface Props {
  scanId: string;
  targetId: string;
}

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const STATUSES: FindingStatus[] = ['Open', 'In Progress', 'Remediated', 'Accepted Risk', 'False Positive'];
const SEV_COLORS: Record<string, string> = {
  Critical: 'badge-critical', High: 'badge-high', Medium: 'badge-medium', Low: 'badge-low', Info: 'badge-info',
};

export function FindingsWorkbench({ scanId }: Props) {
  const [findings, setFindings]       = useState<Finding[]>([]);
  const [selected, setSelected]       = useState<Finding | null>(null);
  const [loading, setLoading]         = useState(true);
  const [showFilters, setShowFilters] = useState(false);

  // Filters
  const [search, setSearch]         = useState('');
  const [sevFilter, setSevFilter]   = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [toolFilter, setToolFilter] = useState('');

  // Triage
  const [triageStatus, setTriageStatus] = useState<FindingStatus>('Open');
  const [triageNote, setTriageNote]     = useState('');
  const [analystName, setAnalystName]   = useState('');
  const [triaging, setTriaging]         = useState(false);
  const [triageError, setTriageError]   = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    const filter: FindingFilter = {
      scanId,
      severity: sevFilter || undefined,
      status: statusFilter || undefined,
      sourceTool: toolFilter || undefined,
    };
    const data = await api.listFindings(filter);
    setFindings(data);
    setLoading(false);
  }, [scanId, sevFilter, statusFilter, toolFilter]);

  useEffect(() => { load(); }, [load]);

  const displayed = findings.filter(f =>
    !search || f.title.toLowerCase().includes(search.toLowerCase()) ||
    f.affectedComponent.toLowerCase().includes(search.toLowerCase()) ||
    (f.cweId ?? '').toLowerCase().includes(search.toLowerCase())
  );

  async function submitTriage() {
    if (!selected) return;
    if (!triageNote.trim() || !analystName.trim()) {
      setTriageError('Both analyst name and triage note are required.'); return;
    }
    setTriaging(true); setTriageError('');
    try {
      const input: TriageInput = {
        findingId: selected.id,
        newStatus: triageStatus,
        triageNote: triageNote.trim(),
        analystName: analystName.trim(),
      };
      const updated = await api.triageFinding(input);
      setSelected(updated);
      setFindings(prev => prev.map(f => f.id === updated.id ? updated : f));
      setTriageNote('');
    } catch (err) { setTriageError(String(err)); }
    finally { setTriaging(false); }
  }

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>
      {/* LEFT: Findings table */}
      <div style={{ flex: '0 0 55%', display: 'flex', flexDirection: 'column', borderRight: '1px solid var(--border)', overflow: 'hidden' }}>
        {/* Filter bar */}
        <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, position: 'relative', minWidth: 180 }}>
            <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input value={search} onChange={(e) => setSearch(e.target.value)}
              placeholder="Search title, component, CWE..."
              style={{ width: '100%', paddingLeft: 30, paddingRight: 10, paddingTop: 7, paddingBottom: 7, background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: 12, outline: 'none' }}
            />
          </div>

          <button onClick={() => setShowFilters(v => !v)} style={{ padding: '7px 12px', background: showFilters ? 'rgba(34,211,238,0.1)' : 'var(--bg-elevated)', border: `1px solid ${showFilters ? 'rgba(34,211,238,0.3)' : 'var(--border)'}`, borderRadius: 'var(--radius-sm)', color: showFilters ? 'var(--cyan)' : 'var(--text-secondary)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
            <SlidersHorizontal size={13} /> Filters
          </button>

          <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>
            {displayed.length} / {findings.length} findings
          </span>
        </div>

        {showFilters && (
          <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <FilterSelect label="Severity" value={sevFilter} onChange={setSevFilter} options={SEVERITIES} />
            <FilterSelect label="Status" value={statusFilter} onChange={setStatusFilter} options={STATUSES} />
            <FilterSelect label="Tool" value={toolFilter} onChange={setToolFilter} options={['Semgrep', 'Trivy', 'Gitleaks', 'OWASP ZAP', 'Nuclei']} />
            {(sevFilter || statusFilter || toolFilter) && (
              <button onClick={() => { setSevFilter(''); setStatusFilter(''); setToolFilter(''); }}
                style={{ padding: '5px 12px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 'var(--radius-sm)', color: 'var(--red)', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', gap: 6 }}>
                <X size={11} /> Clear
              </button>
            )}
          </div>
        )}

        {/* Table */}
        <div style={{ flex: 1, overflow: 'auto' }}>
          {loading ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading findings...</div>
          ) : displayed.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
              No findings match the current filters.
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ position: 'sticky', top: 0, background: 'var(--bg-surface)', zIndex: 1 }}>
                  {['Severity', 'Title', 'Component', 'Priority', 'Status', ''].map(h => (
                    <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayed.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => { setSelected(f); setTriageStatus(f.status); setTriageNote(''); setTriageError(''); }}
                    style={{
                      cursor: 'pointer',
                      background: selected?.id === f.id ? 'rgba(34,211,238,0.05)' : 'transparent',
                      borderBottom: '1px solid var(--border)',
                      transition: 'background 0.12s',
                    }}
                    onMouseEnter={(e) => { if (selected?.id !== f.id) (e.currentTarget as HTMLElement).style.background = 'var(--bg-elevated)'; }}
                    onMouseLeave={(e) => { if (selected?.id !== f.id) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
                  >
                    <td style={{ padding: '9px 12px', whiteSpace: 'nowrap' }}>
                      <span className={`badge ${SEV_COLORS[f.severity] || 'badge-info'}`}>{f.severity}</span>
                    </td>
                    <td style={{ padding: '9px 12px', maxWidth: 200 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</div>
                      {f.cweId && <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>{f.cweId}</div>}
                    </td>
                    <td style={{ padding: '9px 12px', maxWidth: 160 }}>
                      <div style={{ fontSize: 11, color: 'var(--text-code)', fontFamily: "'JetBrains Mono', monospace", overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {f.affectedComponent}
                      </div>
                    </td>
                    <td style={{ padding: '9px 12px', textAlign: 'center' }}>
                      <span style={{ fontSize: 13, fontWeight: 800, color: f.priorityScore >= 9 ? 'var(--red)' : f.priorityScore >= 7 ? 'var(--amber)' : 'var(--emerald)' }}>
                        {f.priorityScore.toFixed(1)}
                      </span>
                    </td>
                    <td style={{ padding: '9px 12px' }}>
                      <StatusPill status={f.status} />
                    </td>
                    <td style={{ padding: '9px 12px' }}>
                      <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* RIGHT: Detail panel */}
      <div style={{ flex: 1, overflow: 'auto', padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 20 }}>
        {!selected ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', textAlign: 'center' }}>
            <div>
              <AlertOctagon size={40} style={{ opacity: 0.2, marginBottom: 12 }} />
              <p>Select a finding to view details,<br />evidence, and remediation guidance.</p>
            </div>
          </div>
        ) : (
          <div className="fade-in">
            {/* Finding header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16, paddingBottom: 16, borderBottom: '1px solid var(--border)' }}>
              <div style={{ flex: 1, marginRight: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                  <span className={`badge ${SEV_COLORS[selected.severity] || 'badge-info'}`}>{selected.severity}</span>
                  {selected.cweId && <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-code)' }}>{selected.cweId}</span>}
                  {selected.kevListed && (
                    <span style={{ padding: '2px 8px', borderRadius: 99, background: 'rgba(239,68,68,0.15)', color: '#fca5a5', fontSize: 10, fontWeight: 700, border: '1px solid rgba(239,68,68,0.3)' }}>
                      CISA KEV
                    </span>
                  )}
                  <StatusPill status={selected.status} />
                </div>
                <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.3 }}>{selected.title}</h3>
                <div style={{ marginTop: 6, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--text-code)' }}>{selected.affectedComponent}</div>
              </div>
              <div style={{ textAlign: 'right', flexShrink: 0 }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Priority</div>
                <div style={{ fontSize: 28, fontWeight: 800, color: selected.priorityScore >= 9 ? 'var(--red)' : 'var(--cyan)', lineHeight: 1 }}>{selected.priorityScore.toFixed(1)}</div>
              </div>
            </div>

            {/* Tags row */}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
              {selected.owasp2025 && <Tag label={selected.owasp2025} color="purple" />}
              {selected.wstgId && <Tag label={selected.wstgId} color="cyan" />}
              {selected.sourceTools.map(t => <Tag key={t} label={t} color="slate" />)}
            </div>

            {/* Scoring breakdown */}
            <DetailSection title="Priority Scoring">
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 10 }}>
                <ScoreCard label="CVSS 4.0" value={selected.cvss4Score?.toFixed(1) ?? '—'} />
                <ScoreCard label="EPSS" value={selected.epssScore ? `${(selected.epssScore * 100).toFixed(1)}%` : '—'} />
                <ScoreCard label="KEV" value={selected.kevListed ? 'YES ⚡' : 'No'} highlight={selected.kevListed} />
              </div>
              {selected.priorityRationale && (
                <div style={{ padding: '10px 12px', background: 'rgba(34,211,238,0.06)', border: '1px solid rgba(34,211,238,0.2)', borderRadius: 'var(--radius-sm)', fontSize: 11, color: 'var(--cyan)', fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.5 }}>
                  💡 <strong>Rationale:</strong> {selected.priorityRationale}
                </div>
              )}
            </DetailSection>

            {/* Description */}
            <DetailSection title="Technical Description">
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{selected.description}</p>
            </DetailSection>

            {/* Repro steps */}
            {selected.reproSteps.length > 0 && (
              <DetailSection title="Reproduction Steps">
                <div style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '12px 14px', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
                  {selected.reproSteps.map((s, i) => <div key={i}>{s}</div>)}
                </div>
              </DetailSection>
            )}

            {/* Remediation */}
            <DetailSection title="Remediation Guidance">
              <div style={{ padding: '12px 14px', background: 'rgba(52,211,153,0.06)', border: '1px solid rgba(52,211,153,0.2)', borderRadius: 'var(--radius-sm)', fontSize: 12, color: 'var(--emerald)', lineHeight: 1.6 }}>
                {selected.remediation}
              </div>
            </DetailSection>

            {/* Triage panel */}
            <DetailSection title="Triage & Status Override">
              <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
                {STATUSES.map(s => (
                  <button key={s} type="button" onClick={() => setTriageStatus(s)} style={{
                    padding: '5px 12px', borderRadius: 99, fontSize: 11, fontWeight: 600,
                    cursor: 'pointer', border: '1px solid',
                    borderColor: triageStatus === s ? 'var(--cyan)' : 'var(--border)',
                    background: triageStatus === s ? 'rgba(34,211,238,0.1)' : 'var(--bg-elevated)',
                    color: triageStatus === s ? 'var(--cyan)' : 'var(--text-muted)',
                    transition: 'all 0.12s',
                  }}>
                    {s}
                  </button>
                ))}
              </div>
              <input
                value={analystName} onChange={(e) => setAnalystName(e.target.value)}
                placeholder="Analyst name (required)"
                style={{ width: '100%', marginBottom: 8, padding: '8px 10px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: 12, outline: 'none' }}
              />
              <textarea
                value={triageNote} onChange={(e) => setTriageNote(e.target.value)}
                placeholder="Triage rationale (required — written to audit trail)"
                rows={3}
                style={{ width: '100%', padding: '8px 10px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: 12, outline: 'none', resize: 'vertical', fontFamily: 'inherit' }}
              />
              {triageError && <div style={{ fontSize: 11, color: 'var(--red)', marginTop: 6 }}>{triageError}</div>}
              <button
                onClick={submitTriage} disabled={triaging}
                style={{ marginTop: 10, padding: '8px 20px', background: 'rgba(34,211,238,0.1)', border: '1px solid rgba(34,211,238,0.3)', borderRadius: 'var(--radius-sm)', color: 'var(--cyan)', cursor: 'pointer', fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Flag size={13} /> {triaging ? 'Saving...' : 'Save Triage Decision'}
              </button>
            </DetailSection>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function FilterSelect({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: readonly string[] }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}
      style={{ padding: '6px 10px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: value ? 'var(--text-primary)' : 'var(--text-muted)', fontSize: 12, outline: 'none', cursor: 'pointer' }}>
      <option value="">{label}: All</option>
      {options.map(o => <option key={o} value={o}>{o}</option>)}
    </select>
  );
}

function StatusPill({ status }: { status: string }) {
  const colors: Record<string, { bg: string; color: string }> = {
    'Open': { bg: 'rgba(239,68,68,0.1)', color: '#fca5a5' },
    'In Progress': { bg: 'rgba(251,191,36,0.1)', color: '#fde68a' },
    'Remediated': { bg: 'rgba(52,211,153,0.1)', color: '#6ee7b7' },
    'Accepted Risk': { bg: 'rgba(148,163,184,0.1)', color: '#94a3b8' },
    'False Positive': { bg: 'rgba(148,163,184,0.08)', color: '#64748b' },
  };
  const c = colors[status] ?? colors['Open'];
  return (
    <span style={{ padding: '2px 8px', borderRadius: 99, fontSize: 10, fontWeight: 600, background: c.bg, color: c.color }}>
      {status}
    </span>
  );
}

function DetailSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>{title}</div>
      {children}
    </div>
  );
}

function Tag({ label, color }: { label: string; color: string }) {
  const c = color === 'purple' ? { bg: 'rgba(167,139,250,0.12)', border: 'rgba(167,139,250,0.3)', text: '#c4b5fd' }
           : color === 'cyan'   ? { bg: 'rgba(34,211,238,0.08)', border: 'rgba(34,211,238,0.2)', text: '#67e8f9' }
           : { bg: 'rgba(148,163,184,0.08)', border: 'rgba(148,163,184,0.2)', text: '#94a3b8' };
  return (
    <span style={{ padding: '3px 10px', borderRadius: 99, fontSize: 10, fontWeight: 600, background: c.bg, border: `1px solid ${c.border}`, color: c.text }}>
      {label}
    </span>
  );
}

function ScoreCard({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div style={{ padding: '10px 14px', background: 'var(--bg-elevated)', border: `1px solid ${highlight ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`, borderRadius: 'var(--radius-sm)', textAlign: 'center' }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 16, fontWeight: 800, color: highlight ? 'var(--red)' : 'var(--text-primary)' }}>{value}</div>
    </div>
  );
}
