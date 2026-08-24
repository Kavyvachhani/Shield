import { useState, useEffect, useRef } from 'react';
import { Play, Square, CheckCircle2, XCircle, SkipForward, Clock, Loader2, ShieldOff, Shield } from 'lucide-react';
import type { Target, AuthorizationRecord, ScanLogPayload } from '../types';
import { api, events } from '../lib/tauri';
import type { UnlistenFn } from '@tauri-apps/api/event';

interface Props {
  target: Target;
  authRecord: AuthorizationRecord | null;
  onScanComplete: (scanRunId: string) => void;
}

type StageState = 'pending' | 'running' | 'done' | 'skipped' | 'failed';
type ScanStage = 'semgrep' | 'trivy' | 'gitleaks' | 'native' | 'zap_dast' | 'nuclei_dast';

interface StageStatus {
  stage: ScanStage;
  label: string;
  stageType: 'static' | 'builtin' | 'dast';
  state: StageState;
  findings: number;
  message: string;
}

// Must stay in step with BASELINE_STAGES / DAST_STAGES in commands/scan.rs. A
// stage the backend runs but this list omits emits events that match no row, so
// its progress and its failures are both invisible — which is exactly how the
// native engine came to look like it was doing nothing.
const STAGE_DEFS: StageStatus[] = [
  { stage: 'semgrep',     label: 'Semgrep SAST',      stageType: 'static',  state: 'pending', findings: 0, message: 'Waiting...' },
  { stage: 'trivy',       label: 'Trivy SCA',          stageType: 'static',  state: 'pending', findings: 0, message: 'Waiting...' },
  { stage: 'gitleaks',    label: 'Gitleaks Secrets',   stageType: 'static',  state: 'pending', findings: 0, message: 'Waiting...' },
  { stage: 'native',      label: 'Sentinel Native',    stageType: 'builtin', state: 'pending', findings: 0, message: 'Waiting...' },
  { stage: 'zap_dast',    label: 'OWASP ZAP DAST',     stageType: 'dast',    state: 'pending', findings: 0, message: 'Requires signed RoE' },
  { stage: 'nuclei_dast', label: 'Nuclei Templates',   stageType: 'dast',    state: 'pending', findings: 0, message: 'Requires signed RoE' },
];

// How long to wait for the first engine event before warning. The pipeline
// emits its first log line immediately on spawn, so silence past this point
// means the events are not arriving rather than that a stage is slow.
const WATCHDOG_SECONDS = 20;

const STAGE_TAG: Record<StageStatus['stageType'], string> = {
  static:  '🔍 STATIC',
  builtin: '🛡 BUILT-IN',
  dast:    '⚡ DAST',
};

const STATE_ICON: Record<StageState, React.ReactNode> = {
  pending: <Clock size={14} style={{ color: 'var(--text-muted)' }} />,
  running: <Loader2 size={14} className="pulse" style={{ color: 'var(--cyan)' }} />,
  done:    <CheckCircle2 size={14} style={{ color: 'var(--emerald)' }} />,
  skipped: <SkipForward size={14} style={{ color: 'var(--amber)' }} />,
  failed:  <XCircle size={14} style={{ color: 'var(--red)' }} />,
};

export function ScanConsoleScreen({ target, authRecord, onScanComplete }: Props) {
  const [stages, setStages] = useState<StageStatus[]>(STAGE_DEFS);
  const [logs, setLogs] = useState<ScanLogPayload[]>([]);
  const [scanRunId, setScanRunId] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [runDast, setRunDast] = useState(false);
  const [totalFindings, setTotalFindings] = useState(0);
  // Reported by the engine alongside the total. This was rendered as a literal
  // `0` regardless of what the scan found, so a run that turned up criticals
  // still displayed "0 Critical+High" beside a non-zero total.
  const [criticalHigh, setCriticalHigh] = useState(0);
  const [error, setError] = useState('');
  // False until all four engine event subscriptions are live. A scan launched
  // without them would run to completion in the backend while this console
  // showed nothing, so the launch button stays disabled until they are up.
  const [listenersReady, setListenersReady] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  // Tracks whether any backend event has arrived for the current run, so a
  // pipeline that never reports in can be told apart from one that is simply
  // slow. Kept in a ref because the watchdog timer closes over it.
  const sawEventRef = useRef(false);
  const watchdogRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Holds the latest callback so the mount-once listener effect below never
  // closes over a stale `onScanComplete` without having to re-run itself.
  const onScanCompleteRef = useRef(onScanComplete);
  onScanCompleteRef.current = onScanComplete;
  // Same reason: the mount-once listener effect writes a summary line when a
  // scan completes, and must not capture a stale closure to do it.
  const localLogRef = useRef<(m: string, l?: 'info' | 'warn' | 'error') => void>(() => {});

  const isAuthorized = !!authRecord;

  /// Append a line the console itself produced, so the log distinguishes
  /// "the UI never asked for a scan" from "the engine never answered".
  function localLog(message: string, level: 'info' | 'warn' | 'error' = 'info') {
    setLogs((prev) => [
      ...prev.slice(-199),
      { scanRunId: '', stage: 'console', level, message, timestamp: new Date().toISOString() },
    ]);
  }
  localLogRef.current = localLog;

  // Subscribe to Tauri scan events exactly once per mount. This used to
  // depend on `[onScanComplete]`, a callback App.tsx recreates on every
  // render — if App re-rendered while a scan was in flight, this effect tore
  // down and re-registered all four listeners. Registering once and reading
  // the callback through a ref removes that churn entirely.
  //
  // Registration is also awaited as a unit and its failure is surfaced.
  // `listen()` is a core-plugin call, so it goes through Tauri's ACL and
  // rejects outright when the window holds no capability granting
  // `core:event:allow-listen`. The old code registered with a bare
  // `.then(u => unlisteners.push(u))`: a rejection there is an unhandled
  // promise nobody sees, so the console simply never received a single event
  // and blamed the silence on a stray second instance twenty seconds later.
  // A subscription that cannot be established is a hard failure and now says
  // so immediately, before any scan is launched.
  useEffect(() => {
    let cancelled = false;
    let unlisteners: UnlistenFn[] = [];

    // `listen()` resolves asynchronously, so a cleanup that runs before these
    // promises settle would otherwise orphan every listener it could not yet
    // see. Collecting them in one `Promise.all` and honouring `cancelled`
    // guarantees each one is either stored for teardown or torn down here.
    (async () => {
      try {
        const registered = await Promise.all([
          events.onStageUpdate((p) => {
            sawEventRef.current = true;
            const stage = p.stage as ScanStage;
            setTotalFindings(p.totalFindings);
            setCriticalHigh(p.criticalHigh);
            setStages(prev => prev.map(s =>
              s.stage === stage ? { ...s, state: p.state as StageState, findings: p.stageFindings, message: p.message } : s
            ));
          }),
          events.onLog((p) => {
            sawEventRef.current = true;
            setLogs(prev => [...prev.slice(-199), p]);
            setTimeout(() => { logRef.current?.scrollTo({ top: 99999, behavior: 'smooth' }); }, 50);
          }),
          events.onComplete((p) => {
            sawEventRef.current = true;
            if (watchdogRef.current) clearTimeout(watchdogRef.current);
            setIsRunning(false);
            setScanRunId(p.scanRunId);
            setTotalFindings(p.totalFindings);
            setCriticalHigh(p.criticalHigh);
            localLogRef.current(
              `Scan finished in ${p.durationSeconds}s — ${p.totalFindings} finding` +
              `${p.totalFindings === 1 ? '' : 's'}, ${p.criticalHigh} Critical/High.`,
            );
            onScanCompleteRef.current(p.scanRunId);
          }),
          events.onError((p) => {
            sawEventRef.current = true;
            if (watchdogRef.current) clearTimeout(watchdogRef.current);
            setIsRunning(false);
            setError(p.error);
          }),
        ]);

        if (cancelled) {
          registered.forEach(u => u());
          return;
        }
        unlisteners = registered;
        setListenersReady(true);
      } catch (err) {
        if (cancelled) return;
        setListenersReady(false);
        setError(
          'Could not subscribe to the scan engine event stream: ' + String(err) +
          ' — scan progress cannot be displayed. This is a build/permissions ' +
          'fault in this installation, not a problem with the target.',
        );
      }
    })();

    return () => {
      cancelled = true;
      unlisteners.forEach(u => u());
      if (watchdogRef.current) clearTimeout(watchdogRef.current);
    };
    // Intentionally mount-once — see the comment above.
  }, []);

  async function startScan() {
    // Without live subscriptions the engine's events go nowhere. Refuse rather
    // than launching a scan whose progress and findings could not be shown.
    if (!listenersReady) {
      setError(
        'Not subscribed to the scan engine event stream — refusing to launch a ' +
        'scan whose progress could not be reported. Restart SentinelVAPT; if this ' +
        'persists, the installation is missing its event permissions.',
      );
      return;
    }
    setError('');
    setLogs([]);
    setStages(STAGE_DEFS.map(s => ({ ...s, state: 'pending', findings: 0, message: s.stageType !== 'static' && !isAuthorized ? 'Requires signed RoE' : 'Waiting...' })));
    setTotalFindings(0);
    setCriticalHigh(0);
    setIsRunning(true);
    sawEventRef.current = false;
    if (watchdogRef.current) clearTimeout(watchdogRef.current);

    const dast = runDast && isAuthorized;
    localLog(`Requesting scan of ${target.baseUrl} (DAST ${dast ? 'on' : 'off'})...`);

    // If the engine has said nothing at all after this long, the run is not
    // merely slow — the command never returned or its events are not reaching
    // this window. Say so, instead of leaving six cards reading "Waiting...".
    watchdogRef.current = setTimeout(() => {
      if (!sawEventRef.current) {
        localLog(
          `No engine event received ${WATCHDOG_SECONDS}s after the scan was accepted. ` +
          'The run may still be progressing in the background — this warning means only ' +
          'that its events are not reaching this window. Check the run status before ' +
          'relaunching, and report this with the scan run id if it repeats.',
          'warn',
        );
        setError(
          `No progress from the scan engine after ${WATCHDOG_SECONDS}s. The scan may ` +
          'still be running; its events are not reaching this window.',
        );
      }
    }, WATCHDOG_SECONDS * 1000);

    try {
      const id = await api.triggerScan(target.id, dast);
      setScanRunId(id);
      localLog(`Scan accepted by the engine — run id ${id}`);
    } catch (err) {
      if (watchdogRef.current) clearTimeout(watchdogRef.current);
      localLog(`Engine refused the scan: ${String(err)}`, 'error');
      setError(String(err));
      setIsRunning(false);
    }
  }

  async function cancelScan() {
    if (!scanRunId) return;
    await api.cancelScan(scanRunId);
    setIsRunning(false);
    setStages(prev => prev.map(s => s.state === 'running' ? { ...s, state: 'failed', message: 'Cancelled by user' } : s));
  }

  return (
    <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20, height: '100%' }} className="fade-in">
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h2 style={{ fontSize: 16, fontWeight: 700 }}>Scan Console</h2>
          <div style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 2, fontFamily: "'JetBrains Mono', monospace" }}>{target.baseUrl}</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {/* DAST toggle — only if authorized */}
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: isAuthorized ? 'pointer' : 'not-allowed', opacity: isAuthorized ? 1 : 0.45 }}>
            <input
              type="checkbox" checked={runDast} disabled={!isAuthorized}
              onChange={(e) => setRunDast(e.target.checked)}
              style={{ accentColor: 'var(--cyan)', width: 14, height: 14 }}
            />
            <span style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
              {isAuthorized ? <Shield size={13} style={{ color: 'var(--emerald)' }} /> : <ShieldOff size={13} style={{ color: 'var(--amber)' }} />}
              Include DAST {!isAuthorized && '(sign RoE first)'}
            </span>
          </label>

          {isRunning ? (
            <button onClick={cancelScan} style={cancelBtnStyle}>
              <Square size={14} /> Cancel
            </button>
          ) : (
            <button
              onClick={startScan}
              disabled={isRunning || !listenersReady}
              title={listenersReady ? undefined : 'Connecting to the scan engine event stream...'}
              style={{ ...startBtnStyle, opacity: listenersReady ? 1 : 0.5, cursor: listenersReady ? 'pointer' : 'wait' }}
            >
              <Play size={14} /> {listenersReady ? 'Launch Scan' : 'Connecting...'}
            </button>
          )}
        </div>
      </div>

      {/* Auth banner */}
      {!isAuthorized && (
        <div style={{ padding: '10px 14px', background: 'rgba(251,191,36,0.08)', border: '1px solid rgba(251,191,36,0.25)', borderRadius: 'var(--radius-sm)', fontSize: 12, color: 'var(--amber)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <ShieldOff size={14} /> DAST stages are disabled — complete the Authorization Gate to unlock ZAP and Nuclei.
        </div>
      )}

      {error && (
        <div style={{ padding: '10px 14px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 'var(--radius-sm)', fontSize: 12, color: '#fca5a5' }}>
          {error}
        </div>
      )}

      {/* Stage cards grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
        {stages.map((s) => {
          // The native engine is auth-gated too — it makes real requests to the
          // target, so it needs the same signed RoE the DAST stages do.
          const isDastLocked = s.stageType !== 'static' && !isAuthorized;
          return (
            <div key={s.stage} className="card" style={{
              padding: '14px 16px',
              opacity: isDastLocked ? 0.5 : 1,
              borderColor: s.state === 'running' ? 'rgba(34,211,238,0.3)' : s.state === 'done' ? 'rgba(52,211,153,0.2)' : s.state === 'failed' ? 'rgba(239,68,68,0.2)' : 'var(--border)',
              transition: 'all 0.3s',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                {STATE_ICON[s.state]}
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {STAGE_TAG[s.stageType]}
                </span>
              </div>
              <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)', marginBottom: 4 }}>{s.label}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, lineHeight: 1.4 }}>{s.message}</div>
              {s.findings > 0 && (
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--cyan)', background: 'rgba(34,211,238,0.1)', padding: '3px 8px', borderRadius: 99, display: 'inline-block' }}>
                  {s.findings} finding{s.findings !== 1 ? 's' : ''}
                </div>
              )}
              {isDastLocked && (
                <div style={{ fontSize: 11, color: 'var(--amber)', marginTop: 6, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <ShieldOff size={11} /> Locked
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Totals */}
      {totalFindings > 0 && (
        <div style={{ display: 'flex', gap: 16 }}>
          <StatPill label="Total Findings" value={totalFindings} color="var(--cyan)" />
          <StatPill label="Critical+High" value={criticalHigh} color="var(--red)" />
        </div>
      )}

      {/* Log console */}
      <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 220 }}>
        <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: isRunning ? 'var(--emerald)' : 'var(--text-muted)' }} className={isRunning ? 'pulse' : ''} />
          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Engine Log Stream
          </span>
        </div>
        <div
          ref={logRef}
          style={{ flex: 1, overflow: 'auto', padding: '12px 14px', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, lineHeight: 1.7, color: 'var(--text-muted)' }}
        >
          {logs.length === 0 ? (
            <span style={{ color: 'var(--text-muted)', opacity: 0.5 }}>Scan output will appear here when the engine runs...</span>
          ) : (
            logs.map((log, i) => (
              <div key={i} style={{ marginBottom: 2 }}>
                <span style={{ color: 'var(--text-muted)', marginRight: 8 }}>{new Date(log.timestamp).toISOString().split('T')[1].slice(0, 8)}</span>
                <span style={{
                  marginRight: 8, fontWeight: 700,
                  color: log.level === 'error' ? 'var(--red)' : log.level === 'warn' ? 'var(--amber)' : 'var(--cyan)',
                }}>
                  [{log.level.toUpperCase()}]
                </span>
                <span style={{ color: 'var(--text-secondary)', marginRight: 8 }}>[{log.stage}]</span>
                <span>{log.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function StatPill({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ padding: '8px 16px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', display: 'flex', alignItems: 'center', gap: 10 }}>
      <span style={{ fontWeight: 800, fontSize: 22, color }}>{value}</span>
      <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 500 }}>{label}</span>
    </div>
  );
}

const startBtnStyle: React.CSSProperties = {
  padding: '9px 20px', background: 'var(--cyan)', color: '#020817',
  border: 'none', borderRadius: 'var(--radius-sm)', fontWeight: 700, fontSize: 13,
  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
  boxShadow: '0 0 16px rgba(34,211,238,0.2)',
};

const cancelBtnStyle: React.CSSProperties = {
  padding: '9px 20px', background: 'rgba(239,68,68,0.12)', color: 'var(--red)',
  border: '1px solid rgba(239,68,68,0.3)', borderRadius: 'var(--radius-sm)', fontWeight: 700, fontSize: 13,
  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
};
