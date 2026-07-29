import { useState, useEffect, useRef } from 'react';
import { Play, Square, CheckCircle2, XCircle, SkipForward, Clock, Loader2, ShieldOff, Shield } from 'lucide-react';
import type { Target, AuthorizationRecord, ScanLogPayload } from '../types';
import { api, events } from '../lib/tauri';

interface Props {
  target: Target;
  authRecord: AuthorizationRecord | null;
  onScanComplete: (scanRunId: string) => void;
}

type StageState = 'pending' | 'running' | 'done' | 'skipped' | 'failed';
type ScanStage = 'semgrep' | 'trivy' | 'gitleaks' | 'zap_dast' | 'nuclei_dast';

interface StageStatus {
  stage: ScanStage;
  label: string;
  stageType: 'static' | 'dast';
  state: StageState;
  findings: number;
  message: string;
}

const STAGE_DEFS: StageStatus[] = [
  { stage: 'semgrep',     label: 'Semgrep SAST',      stageType: 'static', state: 'pending', findings: 0, message: 'Waiting...' },
  { stage: 'trivy',       label: 'Trivy SCA',          stageType: 'static', state: 'pending', findings: 0, message: 'Waiting...' },
  { stage: 'gitleaks',    label: 'Gitleaks Secrets',   stageType: 'static', state: 'pending', findings: 0, message: 'Waiting...' },
  { stage: 'zap_dast',    label: 'OWASP ZAP DAST',     stageType: 'dast',   state: 'pending', findings: 0, message: 'Requires signed RoE' },
  { stage: 'nuclei_dast', label: 'Nuclei Templates',   stageType: 'dast',   state: 'pending', findings: 0, message: 'Requires signed RoE' },
];

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
  const [error, setError] = useState('');
  const logRef = useRef<HTMLDivElement>(null);

  const isAuthorized = !!authRecord;

  // Subscribe to Tauri scan events
  useEffect(() => {
    const unlisteners: (() => void)[] = [];

    events.onStageUpdate((p) => {
      const stage = p.stage as ScanStage;
      setTotalFindings(p.totalFindings);
      setStages(prev => prev.map(s =>
        s.stage === stage ? { ...s, state: p.state as StageState, findings: p.stageFindings, message: p.message } : s
      ));
    }).then(u => unlisteners.push(u));

    events.onLog((p) => {
      setLogs(prev => [...prev.slice(-199), p]);
      setTimeout(() => { logRef.current?.scrollTo({ top: 99999, behavior: 'smooth' }); }, 50);
    }).then(u => unlisteners.push(u));

    events.onComplete((p) => {
      setIsRunning(false);
      setScanRunId(p.scanRunId);
      setTotalFindings(p.totalFindings);
      onScanComplete(p.scanRunId);
    }).then(u => unlisteners.push(u));

    events.onError((p) => {
      setIsRunning(false);
      setError(p.error);
    }).then(u => unlisteners.push(u));

    return () => { unlisteners.forEach(u => u()); };
  }, [onScanComplete]);

  async function startScan() {
    setError('');
    setLogs([]);
    setStages(STAGE_DEFS.map(s => ({ ...s, state: 'pending', findings: 0, message: s.stageType === 'dast' && !isAuthorized ? 'Requires signed RoE' : 'Waiting...' })));
    setTotalFindings(0);
    setIsRunning(true);
    try {
      const id = await api.triggerScan(target.id, runDast && isAuthorized);
      setScanRunId(id);
    } catch (err) {
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
            <button onClick={startScan} disabled={isRunning} style={startBtnStyle}>
              <Play size={14} /> Launch Scan
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
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10 }}>
        {stages.map((s) => {
          const isDastLocked = s.stageType === 'dast' && !isAuthorized;
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
                  {s.stageType === 'dast' ? '⚡ DAST' : '🔍 STATIC'}
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
          <StatPill label="Critical+High" value={0} color="var(--red)" />
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
