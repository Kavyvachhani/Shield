import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Search, SlidersHorizontal, ChevronRight, X, AlertOctagon, Flag,
  ShieldOff, Undo2, CalendarClock, FileUp,
} from 'lucide-react';
import type {
  Finding, FindingStatus, FindingFilter, TriageInput, ExceptionRecord, Evidence,
} from '../types';
import { api } from '../lib/tauri';
import { Callout, Modal, EmptyState, Spinner, SeverityBadge } from '../components/ui';

interface Props {
  scanId: string;
  targetId: string;
}

/** The two statuses that record a standing decision against the target. */
const EXCEPTION_STATUSES: FindingStatus[] = ['Accepted Risk', 'False Positive'];

/** The band a priority score falls in. One definition, so the colour a score
 *  gets in the table is the colour it gets in the detail pane. */
function priorityColor(score: number): string {
  if (score >= 9) return 'var(--danger)';
  if (score >= 7) return 'var(--warning)';
  return 'var(--success)';
}

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const STATUSES: FindingStatus[] = ['Open', 'In Progress', 'Remediated', 'Accepted Risk', 'False Positive'];
const SEV_COLORS: Record<string, string> = {
  Critical: 'badge-critical', High: 'badge-high', Medium: 'badge-medium', Low: 'badge-low', Info: 'badge-info',
};

export function FindingsWorkbench({ scanId, targetId }: Props) {
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
  const [reviewDate, setReviewDate]     = useState('');
  const [triageEffect, setTriageEffect] = useState('');

  // The standing decisions for this target. Kept alongside the findings because
  // they are what governs the *next* scan: a row here is the reason a weakness
  // will not be raised again, and withdrawing it is how you get it back.
  const [exceptions, setExceptions] = useState<ExceptionRecord[]>([]);
  const [showRegister, setShowRegister] = useState(false);

  // SARIF import. Anything that emits SARIF — CodeQL, Snyk, Grype, GitHub code
  // scanning — can be brought into this scan's results rather than living in a
  // second report nobody reconciles against this one.
  const importInput = useRef<HTMLInputElement>(null);
  const [importing, setImporting] = useState(false);
  const [importMsg, setImportMsg] = useState('');

  // The evidence bodies. `listFindings` returns a count but not the content —
  // and the count is not what an analyst deciding whether something is a false
  // positive actually needs. Fetched per finding rather than for the whole
  // table, because an evidence block can be kilobytes and most rows are never
  // opened.
  const [evidences, setEvidences] = useState<Evidence[]>([]);
  const [evidenceFor, setEvidenceFor] = useState<string | null>(null);

  // Dismissing a false positive from the row, without first opening the detail
  // panel and filling in the full triage form. This is the most frequent single
  // action in a triage pass and it was six interactions deep — which is how an
  // analyst ends up not recording dismissals at all, and re-triaging the same
  // noise on every re-scan.
  //
  // It still demands a reason and a name. An exception with no rationale is not
  // auditable, and this one governs every future scan of the target: the speed
  // is in getting to the form, not in skipping it.
  const [quickDismiss, setQuickDismiss] = useState<Finding | null>(null);
  const [quickReason, setQuickReason] = useState('');
  const [quickAnalyst, setQuickAnalyst] = useState('');
  const [quickError, setQuickError] = useState('');
  const [quickBusy, setQuickBusy] = useState(false);

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

  const loadExceptions = useCallback(async () => {
    try {
      setExceptions(await api.listExceptions(targetId));
    } catch {
      // The register is supporting context, not the screen's reason to exist:
      // failing to load it must not blank out the findings table.
      setExceptions([]);
    }
  }, [targetId]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadExceptions(); }, [loadExceptions]);

  const displayed = findings.filter(f =>
    !search || f.title.toLowerCase().includes(search.toLowerCase()) ||
    f.affectedComponent.toLowerCase().includes(search.toLowerCase()) ||
    (f.cweId ?? '').toLowerCase().includes(search.toLowerCase())
  );

  /** Whether the chosen status records a decision that outlives this scan. */
  const recordsException = EXCEPTION_STATUSES.includes(triageStatus);

  /** Record a false positive against the target, straight from the row. */
  async function submitQuickDismiss() {
    if (!quickDismiss) return;
    if (!quickReason.trim() || !quickAnalyst.trim()) {
      setQuickError('Both a reason and your name are required — this decision is recorded against the target and applies to every future scan.');
      return;
    }
    setQuickBusy(true);
    setQuickError('');
    try {
      await api.triageFinding({
        findingId: quickDismiss.id,
        newStatus: 'False Positive',
        triageNote: quickReason.trim(),
        analystName: quickAnalyst.trim(),
      });
      setQuickDismiss(null);
      setQuickReason('');
      await load();
      await loadExceptions();
    } catch (err) {
      setQuickError(String(err));
    }
    setQuickBusy(false);
  }

  async function submitTriage() {
    if (!selected) return;
    if (!triageNote.trim() || !analystName.trim()) {
      setTriageError('Both analyst name and triage note are required.'); return;
    }
    setTriaging(true); setTriageError(''); setTriageEffect('');
    try {
      const input: TriageInput = {
        findingId: selected.id,
        newStatus: triageStatus,
        triageNote: triageNote.trim(),
        analystName: analystName.trim(),
        // A date input gives a bare day; the backend wants a full timestamp, and
        // end-of-day is the reading that matches "review by this date".
        expiresAt: triageStatus === 'Accepted Risk' && reviewDate
          ? new Date(`${reviewDate}T23:59:59Z`).toISOString()
          : undefined,
      };
      const outcome = await api.triageFinding(input);
      setSelected(outcome.finding);
      setFindings(prev => prev.map(f => (f.id === outcome.finding.id ? outcome.finding : f)));
      setTriageNote('');
      setReviewDate('');
      setTriageEffect(outcome.effect);
      await loadExceptions();
    } catch (err) { setTriageError(String(err)); }
    finally { setTriaging(false); }
  }

  async function withdraw(exceptionId: string) {
    try {
      await api.revokeException(exceptionId);
      await loadExceptions();
    } catch (err) { setTriageError(String(err)); }
  }

  async function importSarif(file: File) {
    setImporting(true);
    setImportMsg('');
    setTriageError('');
    try {
      const outcome = await api.importFindings({
        scanId,
        content: await file.text(),
        sourceName: file.name,
      });
      setImportMsg(outcome.summary);
      await load();
    } catch (err) {
      setTriageError(String(err));
    } finally {
      setImporting(false);
    }
  }

  // Load evidence when the selected finding changes.
  useEffect(() => {
    if (!selected || selected.evidenceCount === 0) {
      setEvidences([]);
      setEvidenceFor(null);
      return;
    }
    let active = true;
    const id = selected.id;
    api
      .getFindingDetail(id)
      .then((detail) => {
        if (active) {
          setEvidences(detail.evidences);
          setEvidenceFor(id);
        }
      })
      .catch(() => {
        // Evidence is supporting detail, not the reason the panel exists: a
        // failure here must not blank out the finding the analyst is reading.
        if (active) {
          setEvidences([]);
          setEvidenceFor(id);
        }
      });
    return () => { active = false; };
  }, [selected]);

  /** The standing decision covering a finding, if there is one. */
  function exceptionFor(f: Finding): ExceptionRecord | undefined {
    return exceptions.find(e => e.fingerprint === f.fingerprint && e.active);
  }

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>
      {/* LEFT: Findings table */}
      <div style={{ flex: '0 0 55%', display: 'flex', flexDirection: 'column', borderRight: '1px solid var(--border)', overflow: 'hidden' }}>
        {/* Filter bar */}
        <div className="row wrap" style={{ padding: 'var(--s-3) var(--s-4)', borderBottom: '1px solid var(--border)', gap: 'var(--s-2)' }}>
          <div className="search grow" style={{ minWidth: 180 }}>
            <Search size={13} />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search title, component, CWE…"
              aria-label="Search findings"
            />
          </div>

          {/* aria-pressed carries the on/off state to assistive technology, and
              is also what the stylesheet keys the active appearance off — so the
              two cannot drift apart the way a hand-set colour does. */}
          <button
            className="btn btn-sm"
            aria-pressed={showFilters}
            onClick={() => setShowFilters(v => !v)}
          >
            <SlidersHorizontal size={13} /> Filters
          </button>

          <input
            ref={importInput}
            type="file"
            accept=".sarif,.json"
            style={{ display: 'none' }}
            onChange={(e) => {
              const file = e.target.files?.[0];
              // Reset first, so re-picking the same file fires onChange again.
              e.target.value = '';
              if (file) void importSarif(file);
            }}
          />
          <button
            className="btn btn-sm"
            onClick={() => importInput.current?.click()}
            disabled={importing}
            title="Import findings from another tool's SARIF output (CodeQL, Snyk, Grype, GitHub code scanning)"
          >
            {importing ? <Spinner size={13} /> : <FileUp size={13} />}
            {importing ? 'Importing…' : 'Import SARIF'}
          </button>

          <button
            className="btn btn-sm"
            aria-pressed={showRegister}
            onClick={() => setShowRegister(v => !v)}
            title="Decisions that carry forward to every later scan of this target"
          >
            <ShieldOff size={13} /> Exceptions
            {exceptions.length > 0 && <span className="badge badge-outline">{exceptions.length}</span>}
          </button>

          <span className="dim small tabular" style={{ marginLeft: 'auto' }}>
            {displayed.length} / {findings.length} findings
          </span>
        </div>

        {importMsg && (
          <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', background: 'rgba(52,211,153,0.06)', fontSize: 11, color: 'var(--success)', lineHeight: 1.6 }}>
            {importMsg}
          </div>
        )}

        {showRegister && (
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-base)' }}>
            <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 8 }}>
              Exception register — applied automatically to every scan of this target
            </div>
            {exceptions.length === 0 ? (
              <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Nothing recorded yet. Marking a finding <strong>False Positive</strong> or{' '}
                <strong>Accepted Risk</strong> adds it here, and the decision is then re-applied on
                every later scan — so you triage each weakness once, not once per run.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {exceptions.map(e => (
                  <div key={e.id} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', padding: '8px 10px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', opacity: e.active ? 1 : 0.55 }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                        <span style={{ padding: '1px 7px', borderRadius: 99, fontSize: 9, fontWeight: 700, background: e.kind === 'Accepted Risk' ? 'rgba(251,191,36,0.14)' : 'rgba(148,163,184,0.14)', color: e.kind === 'Accepted Risk' ? '#fde68a' : '#94a3b8' }}>
                          {e.kind}
                        </span>
                        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {e.title}
                        </span>
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3, lineHeight: 1.5 }}>
                        {e.justification} — {e.raisedBy}
                        {e.daysUntilExpiry !== null && (
                          <span style={{ marginLeft: 6, color: !e.active ? 'var(--danger)' : e.daysUntilExpiry <= 30 ? 'var(--warning)' : 'var(--text-muted)' }}>
                            · {e.active ? `review in ${e.daysUntilExpiry} days` : 'lapsed — reported again on the next scan'}
                          </span>
                        )}
                      </div>
                    </div>
                    <button
                      onClick={() => withdraw(e.id)}
                      title="Withdraw: this weakness is reported again on the next scan"
                      style={{ flexShrink: 0, padding: '4px 9px', background: 'transparent', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 10, display: 'flex', alignItems: 'center', gap: 5 }}>
                      <Undo2 size={11} /> Withdraw
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {showFilters && (
          <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <FilterSelect label="Severity" value={sevFilter} onChange={setSevFilter} options={SEVERITIES} />
            <FilterSelect label="Status" value={statusFilter} onChange={setStatusFilter} options={STATUSES} />
            <FilterSelect label="Tool" value={toolFilter} onChange={setToolFilter} options={['Semgrep', 'Trivy', 'Gitleaks', 'OWASP ZAP', 'Nuclei']} />
            {(sevFilter || statusFilter || toolFilter) && (
              <button onClick={() => { setSevFilter(''); setStatusFilter(''); setToolFilter(''); }}
                style={{ padding: '5px 12px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 'var(--radius-sm)', color: 'var(--danger)', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', gap: 6 }}>
                <X size={11} /> Clear
              </button>
            )}
          </div>
        )}

        {/* Table */}
        <div style={{ flex: 1, overflow: 'auto' }}>
          {loading ? (
            <div className="empty">
              <Spinner size={20} />
              <p>Loading findings…</p>
            </div>
          ) : displayed.length === 0 ? (
            <EmptyState
              icon={findings.length === 0 ? <AlertOctagon size={22} /> : <Search size={22} />}
              title={findings.length === 0 ? 'No findings in this scan' : 'Nothing matches these filters'}
            >
              {findings.length === 0
                ? 'The engines completed without raising anything. Check the coverage record on the scan console to see what was actually read before reporting this as a clean result.'
                : 'Every finding in this scan is filtered out. Clear the search, or widen the severity and status filters, to see them again.'}
            </EmptyState>
          ) : (
            <table className="table table-clickable">
              <thead>
                <tr>
                  {['Severity', 'Title', 'Component', 'Priority', 'Status', ''].map(h => (
                    <th key={h} scope="col">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayed.map((f) => (
                  <tr
                    key={f.id}
                    className={selected?.id === f.id ? 'selected' : undefined}
                    onClick={() => { setSelected(f); setTriageStatus(f.status); setTriageNote(''); setTriageError(''); setTriageEffect(''); setReviewDate(''); }}
                  >
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td style={{ maxWidth: 200 }}>
                      <div className="truncate" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{f.title}</div>
                      {f.cweId && <div className="mono dim small">{f.cweId}</div>}
                    </td>
                    <td style={{ maxWidth: 160 }}>
                      <div className="mono small truncate" style={{ color: 'var(--text-secondary)' }}>
                        {f.affectedComponent}
                      </div>
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <span
                        className="tabular"
                        style={{ fontSize: 13, fontWeight: 800, color: priorityColor(f.priorityScore) }}
                      >
                        {f.priorityScore.toFixed(1)}
                      </span>
                    </td>
                    <td>
                      <StatusPill status={f.status} />
                      {exceptionFor(f) && (
                        <div className="row dim" style={{ gap: 3, fontSize: 9, marginTop: 3 }} title="Carried forward from a standing exception">
                          <ShieldOff size={9} /> standing
                        </div>
                      )}
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <div className="row" style={{ gap: 2 }}>
                        {f.status !== 'False Positive' && (
                          <button
                            className="btn btn-ghost btn-icon btn-sm"
                            title="Not a real issue — dismiss it, and keep it dismissed on every future scan"
                            aria-label={`Dismiss "${f.title}" as a false positive`}
                            onClick={(e) => {
                              e.stopPropagation();
                              setQuickDismiss(f);
                              setQuickReason('');
                              setQuickError('');
                            }}
                          >
                            <ShieldOff size={13} />
                          </button>
                        )}
                        <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />
                      </div>
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
                  {selected.cweId && <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-secondary)' }}>{selected.cweId}</span>}
                  {selected.kevListed && (
                    <span style={{ padding: '2px 8px', borderRadius: 99, background: 'rgba(239,68,68,0.15)', color: '#fca5a5', fontSize: 10, fontWeight: 700, border: '1px solid rgba(239,68,68,0.3)' }}>
                      CISA KEV
                    </span>
                  )}
                  <StatusPill status={selected.status} />
                </div>
                <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.3 }}>{selected.title}</h3>
                <div style={{ marginTop: 6, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--text-secondary)' }}>{selected.affectedComponent}</div>
              </div>
              <div style={{ textAlign: 'right', flexShrink: 0 }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Priority</div>
                <div style={{ fontSize: 28, fontWeight: 800, color: selected.priorityScore >= 9 ? 'var(--danger)' : 'var(--accent)', lineHeight: 1 }}>{selected.priorityScore.toFixed(1)}</div>
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
                <div style={{ padding: '10px 12px', background: 'rgba(34,211,238,0.06)', border: '1px solid rgba(34,211,238,0.2)', borderRadius: 'var(--radius-sm)', fontSize: 11, color: 'var(--accent)', fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.5 }}>
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
              <div style={{ padding: '12px 14px', background: 'rgba(52,211,153,0.06)', border: '1px solid rgba(52,211,153,0.2)', borderRadius: 'var(--radius-sm)', fontSize: 12, color: 'var(--success)', lineHeight: 1.6 }}>
                {selected.remediation}
              </div>
            </DetailSection>

            {/* Evidence — what the finding is actually based on. Placed above
                triage because the decision depends on reading it. */}
            {selected.evidenceCount > 0 && (
              <DetailSection title={`Evidence (${selected.evidenceCount}, sanitized)`}>
                {evidenceFor !== selected.id ? (
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Loading evidence…</div>
                ) : evidences.length === 0 ? (
                  <div style={{ fontSize: 11, color: 'var(--warning)', lineHeight: 1.6 }}>
                    This finding records {selected.evidenceCount} artefact
                    {selected.evidenceCount === 1 ? '' : 's'}, but they could not be loaded.
                    Verify by hand before triaging.
                  </div>
                ) : (
                  evidences.map((e, i) => (
                    <div key={i} style={{ marginBottom: 10 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 8, marginBottom: 4 }}>
                        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)' }}>{e.title}</span>
                        <span style={{ fontSize: 9, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>{e.evidenceType}</span>
                      </div>
                      <pre style={{ margin: 0, padding: '10px 12px', background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: 10.5, lineHeight: 1.6, color: 'var(--text-secondary)', fontFamily: "'JetBrains Mono', monospace", whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 260, overflow: 'auto' }}>
                        {e.content}
                      </pre>
                      {e.hash && (
                        <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 3, fontFamily: "'JetBrains Mono', monospace" }}>
                          SHA-256 {e.hash.slice(0, 32)}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </DetailSection>
            )}

            {/* Validation confidence — the developer report shows the same figure,
                so a reviewer here and a reader there start from the same claim. */}
            <DetailSection title="Validation Confidence">
              <ConfidencePanel finding={selected} />
            </DetailSection>

            {/* Triage panel */}
            <DetailSection title="Triage & Status Override">
              <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
                {STATUSES.map(s => (
                  <button key={s} type="button" onClick={() => setTriageStatus(s)} style={{
                    padding: '5px 12px', borderRadius: 99, fontSize: 11, fontWeight: 600,
                    cursor: 'pointer', border: '1px solid',
                    borderColor: triageStatus === s ? 'var(--accent)' : 'var(--border)',
                    background: triageStatus === s ? 'rgba(34,211,238,0.1)' : 'var(--bg-elevated)',
                    color: triageStatus === s ? 'var(--accent)' : 'var(--text-muted)',
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
                placeholder={recordsException
                  ? 'Justification (required — printed in the report and kept for audit)'
                  : 'Triage rationale (required — written to audit trail)'}
                rows={3}
                style={{ width: '100%', padding: '8px 10px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: 12, outline: 'none', resize: 'vertical', fontFamily: 'inherit' }}
              />

              {triageStatus === 'Accepted Risk' && (
                <div style={{ marginTop: 8 }}>
                  <label style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: 5, marginBottom: 5 }}>
                    <CalendarClock size={11} /> Review date (optional)
                  </label>
                  <input
                    type="date" value={reviewDate} onChange={(e) => setReviewDate(e.target.value)}
                    style={{ padding: '7px 10px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: 12, outline: 'none' }}
                  />
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 5, lineHeight: 1.5 }}>
                    On this date the acceptance lapses and the weakness returns to the open list.
                    Leave it blank for an acceptance that stands until you withdraw it.
                  </div>
                </div>
              )}

              {recordsException && (
                <div style={{ marginTop: 10, padding: '9px 11px', background: 'rgba(148,163,184,0.08)', border: '1px solid rgba(148,163,184,0.25)', borderRadius: 'var(--radius-sm)', fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  <strong>This carries forward.</strong>{' '}
                  {triageStatus === 'False Positive'
                    ? 'The finding is removed from every report, and the same dismissal is applied to every later scan of this target — you will not be asked about it again.'
                    : 'The finding leaves the open counts and the posture score, and is disclosed instead in the client report’s accepted-risk register with this justification.'}
                </div>
              )}

              {triageError && <div style={{ fontSize: 11, color: 'var(--danger)', marginTop: 6 }}>{triageError}</div>}
              {triageEffect && (
                <div style={{ fontSize: 11, color: 'var(--success)', marginTop: 8, padding: '8px 10px', background: 'rgba(52,211,153,0.06)', border: '1px solid rgba(52,211,153,0.2)', borderRadius: 'var(--radius-sm)', lineHeight: 1.6 }}>
                  {triageEffect}
                </div>
              )}
              <button
                onClick={submitTriage} disabled={triaging}
                style={{ marginTop: 10, padding: '8px 20px', background: 'rgba(34,211,238,0.1)', border: '1px solid rgba(34,211,238,0.3)', borderRadius: 'var(--radius-sm)', color: 'var(--accent)', cursor: 'pointer', fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Flag size={13} /> {triaging ? 'Saving...' : 'Save Triage Decision'}
              </button>
            </DetailSection>
          </div>
        )}
      </div>
      {quickDismiss && (
        <Modal
          title="Dismiss as a false positive"
          onClose={() => setQuickDismiss(null)}
          footer={
            <>
              <button className="btn" onClick={() => setQuickDismiss(null)}>Cancel</button>
              <button className="btn btn-primary" onClick={submitQuickDismiss} disabled={quickBusy}>
                <ShieldOff size={14} /> Dismiss and remember
              </button>
            </>
          }
        >
          <div className="stack">
            <div className="card card-tight">
              <div className="row" style={{ marginBottom: 6 }}>
                <span className={`badge ${SEV_COLORS[quickDismiss.severity] || 'badge-info'}`}>
                  {quickDismiss.severity}
                </span>
                <strong>{quickDismiss.title}</strong>
              </div>
              <div className="mono dim small truncate">{quickDismiss.affectedComponent}</div>
            </div>

            <Callout tone="warning">
              This removes the finding from <strong>every</strong> deliverable — the counts, the
              posture score and the remediation roadmap — and the report discloses only that a
              dismissal was made, not what it was. The decision is recorded against the target
              rather than this scan, so the next assessment applies it automatically instead of
              raising the same finding with a new id. Withdraw it from the exception register if
              you change your mind.
            </Callout>

            <div className="field">
              <label className="label" htmlFor="quick-reason">Why is this not a real issue?</label>
              <textarea
                id="quick-reason"
                className="textarea"
                value={quickReason}
                onChange={(e) => { setQuickReason(e.target.value); setQuickError(''); }}
                placeholder="The value is a compile-time constant read from a build flag, not from a request — traced in src/config.ts:14."
                autoFocus
              />
              <span className="hint">
                Required. This is what an auditor reads when they ask why a finding is absent from
                the report, and what you read when the same finding appears again in six months.
              </span>
            </div>

            <div className="field">
              <label className="label" htmlFor="quick-analyst">Your name</label>
              <input
                id="quick-analyst"
                className="input"
                value={quickAnalyst}
                onChange={(e) => { setQuickAnalyst(e.target.value); setQuickError(''); }}
                placeholder="A. Analyst"
              />
            </div>

            {quickError && <Callout tone="danger">{quickError}</Callout>}
          </div>
        </Modal>
      )}
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

/**
 * How much of this finding is direct observation and how much is inference.
 *
 * Mirrors the developer report's panel deliberately: the analyst triaging here
 * and the engineer reading the PDF have to be looking at the same claim, or the
 * conversation between them starts from two different numbers.
 */
function ConfidencePanel({ finding }: { finding: Finding }) {
  const confidence = Math.round((1 - (finding.falsePositiveConfidence ?? 0.25)) * 100);
  const [label, color] =
      confidence >= 90 ? ['Confirmed', '#34d399']
    : confidence >= 70 ? ['High confidence', '#6ee7b7']
    : confidence >= 45 ? ['Needs verification', '#fbbf24']
    :                    ['Likely false positive', '#f87171'];

  const tools = finding.sourceTools.map(t => t.toLowerCase());
  const runtime = tools.some(t => ['native', 'zap', 'nuclei', 'dast'].some(k => t.includes(k)));
  const dependency = tools.some(t => t.includes('trivy'));
  const staticOnly = !runtime && tools.some(t => ['semgrep', 'sast', 'gitleaks'].some(k => t.includes(k)));

  const basis =
      finding.sourceTools.length >= 2
        ? `Reported independently by ${finding.sourceTools.length} engines.`
    : dependency
        ? 'Derived from a declared dependency version. Whether the vulnerable code path is reachable is not established here.'
    : staticOnly
        ? 'Matched by static analysis against the source. Runtime reachability is not confirmed.'
    : runtime
        ? 'Observed directly in a live response from the target.'
        : 'Reported by the engine listed above.';

  return (
    <div style={{ display: 'flex', gap: 12, alignItems: 'stretch' }}>
      <div style={{ flex: '0 0 96px', padding: '10px 8px', borderRadius: 'var(--radius-sm)', background: `${color}22`, border: `1px solid ${color}55`, textAlign: 'center' }}>
        <div style={{ fontSize: 22, fontWeight: 800, color, lineHeight: 1.1 }}>{confidence}%</div>
        <div style={{ fontSize: 9, color, textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: 2 }}>{label}</div>
      </div>
      <div style={{ flex: 1, fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
        <div>{basis}</div>
        <div style={{ marginTop: 5, color: 'var(--text-muted)' }}>
          {finding.evidenceCount > 0
            ? `${finding.evidenceCount} hashed evidence artefact${finding.evidenceCount === 1 ? '' : 's'} captured at the time of testing.`
            : 'No evidence artefact was captured — verify by hand before scheduling work.'}
        </div>
      </div>
    </div>
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
      <div style={{ fontSize: 16, fontWeight: 800, color: highlight ? 'var(--danger)' : 'var(--text-primary)' }}>{value}</div>
    </div>
  );
}
