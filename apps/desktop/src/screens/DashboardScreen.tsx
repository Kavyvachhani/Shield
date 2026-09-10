/**
 * The screen the application opens on.
 *
 * Before this existed the first thing an analyst saw was an empty project form,
 * which answers the question "what do I do first" exactly once and is in the
 * way every time after. What somebody returning to an engagement actually needs
 * is the state of it: what the last scan found, how much of the catalogue it
 * covered, which engines are missing, and the one action that moves the work
 * forward from here.
 *
 * The posture number is deliberately not the first thing on the page. A single
 * score is the easiest thing to over-read — it compresses "eleven criticals" and
 * "one critical and good hygiene everywhere else" into numbers that look
 * comparable — so the severity breakdown sits above it, and the score carries
 * the sentence that says what it is derived from.
 */

import { useCallback, useEffect, useState } from 'react';
import {
  Activity, AlertOctagon, ArrowRight, FileBarChart2, FolderOpen, ListChecks,
  PlayCircle, Plug, ShieldCheck, ShieldAlert, Sparkles,
} from 'lucide-react';
import type {
  CoverageReport, EngineDescriptor, Finding, Project, ScanRun, Severity, Target,
} from '../types';
import { api } from '../lib/tauri';
import {
  Callout, EmptyState, SeverityBadge, SeverityBar, Spinner, Stat,
} from '../components/ui';
import { SEVERITY_ORDER, countBySeverity, formatRelative } from '../lib/presentation';

interface Props {
  project: Project | null;
  target: Target | null;
  scanId: string | null;
  roeSigned: boolean;
  onNavigate: (screen: 'setup' | 'auth' | 'console' | 'findings' | 'coverage' | 'reports' | 'profiles') => void;
}

export function DashboardScreen({ project, target, scanId, roeSigned, onNavigate }: Props) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [coverage, setCoverage] = useState<CoverageReport | null>(null);
  const [engines, setEngines] = useState<EngineDescriptor[]>([]);
  const [run, setRun] = useState<ScanRun | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    // The engine roster does not depend on a scan, so it loads either way —
    // "which engines can this machine run" is worth answering before the first
    // scan, not only after.
    const [engineList] = await Promise.all([api.listEngines().catch(() => [])]);
    setEngines(engineList);

    if (scanId) {
      const [f, c, r] = await Promise.all([
        api.listFindings({ scanId }).catch(() => [] as Finding[]),
        api.getCoverage(scanId).catch(() => null),
        api.getScanStatus(scanId).catch(() => null),
      ]);
      setFindings(f);
      setCoverage(c);
      setRun(r);
    }
    setLoading(false);
  }, [scanId]);

  useEffect(() => {
    load();
  }, [load]);

  // Only open weaknesses count. A dismissed false positive is not a finding,
  // and an accepted risk has been moved into the register by a decision
  // somebody signed — putting either back into the headline would misrepresent
  // both the posture and the work remaining.
  const open = findings.filter(
    (f) => f.status !== 'False Positive' && f.status !== 'Accepted Risk',
  );
  const counts = countBySeverity(open);
  const dismissed = findings.filter((f) => f.status === 'False Positive').length;
  const accepted = findings.filter((f) => f.status === 'Accepted Risk').length;

  const topFindings = [...open]
    .sort((a, b) => b.priorityScore - a.priorityScore)
    .slice(0, 5);

  const available = engines.filter((e) => e.builtIn).length;
  const missing = engines.filter((e) => !e.builtIn && e.requiresBinary);

  if (loading) {
    return (
      <div className="page">
        <div className="empty">
          <Spinner size={22} />
          <p className="muted">Loading the engagement…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page stack">
      <div className="between">
        <div>
          <h1 className="h1">{project ? project.companyName : 'SentinelVAPT'}</h1>
          <p className="muted small">
            {target
              ? <>Assessing <span className="mono">{target.baseUrl}</span></>
              : 'No target selected yet.'}
          </p>
        </div>
        <div className="row">
          {target && (
            <button className="btn" onClick={() => onNavigate('profiles')}>
              <Sparkles size={14} /> Scan profiles
            </button>
          )}
          <button className="btn btn-primary" onClick={() => onNavigate(target ? 'console' : 'setup')}>
            <PlayCircle size={15} />
            {target ? 'Run a scan' : 'Set up a target'}
          </button>
        </div>
      </div>

      {!target && (
        <EmptyState
          icon={<FolderOpen size={34} />}
          title="Start with a project and a target"
          action={
            <button className="btn btn-primary" onClick={() => onNavigate('setup')}>
              Create a project <ArrowRight size={14} />
            </button>
          }
        >
          A project holds the client's details and branding for the report; a target is the
          application being assessed — its URL, and optionally a local checkout of its source.
          Supplying the checkout is what turns on the four static engines, which is most of what
          this tool finds.
        </EmptyState>
      )}

      {target && !roeSigned && (
        <Callout tone="warning">
          <strong>No signed Rules of Engagement for this target.</strong> The static engines will
          run — they read local files and send nothing — but every engine that would make a
          request to {target.baseUrl} stays blocked until an authorisation is recorded.{' '}
          <button className="btn btn-sm" style={{ marginTop: 8 }} onClick={() => onNavigate('auth')}>
            <ShieldCheck size={13} /> Record authorisation
          </button>
        </Callout>
      )}

      {scanId && (
        <>
          <section className="stack">
            <div className="between">
              <h2 className="h2">Findings</h2>
              {run?.completedAt && (
                <span className="dim small">
                  Last scan {formatRelative(run.completedAt)} ·{' '}
                  {run.enginesExecuted.length} engine{run.enginesExecuted.length === 1 ? '' : 's'} ran
                </span>
              )}
            </div>

            <SeverityBar counts={counts} />

            <div className="grid grid-4">
              {SEVERITY_ORDER.map((s) => (
                <Stat
                  key={s}
                  label={s}
                  value={counts[s]}
                  tone={s.toLowerCase() as Lowercase<Severity>}
                  note={s === 'Critical' && counts.Critical > 0 ? 'Fix before release' : undefined}
                />
              ))}
            </div>

            {(dismissed > 0 || accepted > 0) && (
              <p className="dim small">
                Not counted above:{' '}
                {dismissed > 0 && (
                  <>
                    <strong>{dismissed}</strong> dismissed as false positives — excluded from every
                    deliverable, with the count disclosed in the report so the silence is accounted
                    for
                  </>
                )}
                {dismissed > 0 && accepted > 0 && '; '}
                {accepted > 0 && (
                  <>
                    <strong>{accepted}</strong> accepted risks — moved to the register with their
                    justification and review date, not deleted
                  </>
                )}
                .
              </p>
            )}
          </section>

          <div className="grid grid-2">
            <section className="card card-flush">
              <div className="card-header">
                <h2 className="h2">Highest priority</h2>
                <button className="btn btn-ghost btn-sm" onClick={() => onNavigate('findings')}>
                  All findings <ArrowRight size={13} />
                </button>
              </div>
              {topFindings.length === 0 ? (
                <EmptyState icon={<ShieldCheck size={28} />} title="Nothing open">
                  No open weaknesses in this scan. Read the coverage matrix before treating that as
                  a clean result — it says which checks actually ran.
                </EmptyState>
              ) : (
                <div>
                  {topFindings.map((f) => (
                    <button
                      key={f.id}
                      className="nav-item"
                      style={{
                        borderRadius: 0,
                        padding: 'var(--s-3) var(--s-5)',
                        borderBottom: '1px solid var(--border)',
                        alignItems: 'flex-start',
                      }}
                      onClick={() => onNavigate('findings')}
                    >
                      <SeverityBadge severity={f.severity} />
                      <span className="grow col" style={{ gap: 2 }}>
                        <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                          {f.title}
                        </span>
                        <span className="dim mono small truncate">{f.affectedComponent}</span>
                      </span>
                      <span className="nav-count tabular">{f.priorityScore.toFixed(1)}</span>
                    </button>
                  ))}
                </div>
              )}
            </section>

            <section className="card stack">
              <div className="between">
                <h2 className="h2">Coverage</h2>
                <button className="btn btn-ghost btn-sm" onClick={() => onNavigate('coverage')}>
                  Full matrix <ArrowRight size={13} />
                </button>
              </div>

              {coverage ? (
                <>
                  <div className="col" style={{ gap: 6 }}>
                    <div className="between">
                      <span className="small muted">Automated coverage of the WSTG catalogue</span>
                      <span className="h2 tabular">{coverage.automatedCoveragePct.toFixed(0)}%</span>
                    </div>
                    <div className="meter">
                      <span style={{ width: `${Math.min(coverage.automatedCoveragePct, 100)}%` }} />
                    </div>
                  </div>

                  <div className="grid grid-4">
                    <Stat label="Passed" value={coverage.passed} tone="low" />
                    <Stat label="Issues" value={coverage.issuesFound} tone="high" />
                    <Stat label="Manual" value={coverage.manualRequired} tone="info" />
                    <Stat label="Not tested" value={coverage.notTested} tone="medium" />
                  </div>

                  {coverage.enginesUnavailable.length > 0 && (
                    <Callout tone="warning">
                      {coverage.enginesUnavailable.length} engine
                      {coverage.enginesUnavailable.length === 1 ? ' was' : 's were'} unavailable, so
                      the checks they answer are recorded as untested rather than passed:{' '}
                      <span className="mono">{coverage.enginesUnavailable.join(', ')}</span>.
                    </Callout>
                  )}
                </>
              ) : (
                <p className="muted small">
                  Coverage is computed once a scan has finished. It records every check that ran,
                  including the ones that passed and the ones that need a person — which is what
                  makes a clean result interpretable.
                </p>
              )}
            </section>
          </div>
        </>
      )}

      {target && !scanId && (
        <EmptyState
          icon={<Activity size={34} />}
          title="No scan has been run for this target yet"
          action={
            <button className="btn btn-primary" onClick={() => onNavigate('console')}>
              Open the scan console <ArrowRight size={14} />
            </button>
          }
        >
          Pick a profile and start. "Quick triage" runs only the engines compiled into the
          application and finishes in a couple of minutes; "Full assessment" adds every external
          scanner you have installed and a deep crawl.
        </EmptyState>
      )}

      <section className="card stack">
        <div className="between">
          <h2 className="h2">
            <Plug size={14} style={{ verticalAlign: -2, marginRight: 6 }} />
            Engines on this machine
          </h2>
          <span className="dim small">
            {available} built in · {missing.length} optional
          </span>
        </div>

        <p className="muted small">
          {available} engine{available === 1 ? '' : 's'} ship inside the application and always run.
          The rest are used when their binary is on PATH and skipped with the gap recorded when it
          is not — a missing engine never silently becomes a pass.
        </p>

        <div className="row wrap" style={{ gap: 'var(--s-2)' }}>
          {engines.map((e) => (
            <span
              key={e.stage}
              className={`badge ${e.builtIn ? 'badge-accent' : 'badge-outline'}`}
              title={e.description}
            >
              {e.builtIn ? <ShieldCheck size={11} /> : <span className="dot" style={{ background: 'var(--text-muted)' }} />}
              {e.label}
            </span>
          ))}
        </div>

        {missing.length > 0 && (
          <p className="dim small">
            Install any of{' '}
            <span className="mono">{missing.map((e) => e.requiresBinary).join(', ')}</span>{' '}
            to widen coverage. None is required: the built-in engines cover code, dependencies,
            secrets, infrastructure and live checks on their own.
          </p>
        )}
      </section>

      {scanId && (
        <div className="row wrap">
          <button className="btn" onClick={() => onNavigate('findings')}>
            <AlertOctagon size={14} /> Triage findings
          </button>
          <button className="btn" onClick={() => onNavigate('coverage')}>
            <ListChecks size={14} /> Coverage matrix
          </button>
          <button className="btn" onClick={() => onNavigate('reports')}>
            <FileBarChart2 size={14} /> Build the report
          </button>
          {run?.status === 'failed' && (
            <span className="badge badge-critical">
              <ShieldAlert size={11} /> The last scan failed
            </span>
          )}
        </div>
      )}
    </div>
  );
}
