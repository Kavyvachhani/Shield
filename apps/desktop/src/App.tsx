import { useState } from 'react';
import {
  Shield, FolderOpen, ShieldCheck, Activity,
  AlertOctagon, FileBarChart2, ChevronRight,
} from 'lucide-react';
import type { Project, Target, AuthorizationRecord } from './types';
import { ProjectSetupScreen } from './screens/ProjectSetupScreen';
import { AuthGateScreen } from './screens/AuthGateScreen';
import { ScanConsoleScreen } from './screens/ScanConsoleScreen';
import { FindingsWorkbench } from './screens/FindingsWorkbench';
import { ReportBuilderScreen } from './screens/ReportBuilderScreen';
import './index.css';

type Screen = 'setup' | 'auth' | 'console' | 'findings' | 'reports';

const NAV_ITEMS: { id: Screen; label: string; icon: typeof Shield }[] = [
  { id: 'setup',    label: 'Project Setup',   icon: FolderOpen },
  { id: 'auth',     label: 'Auth Gate',        icon: ShieldCheck },
  { id: 'console',  label: 'Scan Console',     icon: Activity },
  { id: 'findings', label: 'Findings',         icon: AlertOctagon },
  { id: 'reports',  label: 'Reports',          icon: FileBarChart2 },
];

export function App() {
  const [screen, setScreen] = useState<Screen>('setup');
  const [project, setProject]     = useState<Project | null>(null);
  const [target, setTarget]       = useState<Target | null>(null);
  const [authRecord, setAuthRecord] = useState<AuthorizationRecord | null>(null);
  const [scanRunId, setScanRunId] = useState<string | null>(null);

  const canNav = (id: Screen): boolean => {
    if (id === 'setup') return true;
    if (id === 'auth') return !!project && !!target;
    if (id === 'console') return !!project && !!target;
    if (id === 'findings') return !!scanRunId;
    if (id === 'reports') return !!scanRunId;
    return false;
  };

  const handleProjectTargetReady = (p: Project, t: Target) => {
    setProject(p); setTarget(t); setScreen('auth');
  };

  const handleRoESigned = (record: AuthorizationRecord) => {
    setAuthRecord(record); setScreen('console');
  };

  const handleScanComplete = (id: string) => {
    setScanRunId(id); setScreen('findings');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden', background: 'var(--bg-base)' }}>
      {/* Top bar */}
      <header style={{
        display: 'flex', alignItems: 'center', gap: 14,
        padding: '0 20px', height: 52,
        background: 'var(--bg-surface)',
        borderBottom: '1px solid var(--border)',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ padding: '6px', background: 'rgba(34,211,238,0.1)', borderRadius: 8, border: '1px solid rgba(34,211,238,0.15)' }}>
            <Shield size={16} style={{ color: 'var(--cyan)' }} />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>SentinelVAPT</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>Local Engine • Offline • v0.2.0</div>
          </div>
        </div>

        {/* Breadcrumb context */}
        {project && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginLeft: 16, padding: '4px 12px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 99 }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{project.companyName}</span>
            {target && <><ChevronRight size={11} style={{ color: 'var(--text-muted)' }} /><span style={{ fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600 }}>{target.name}</span></>}
            {authRecord && (
              <><ChevronRight size={11} style={{ color: 'var(--text-muted)' }} />
              <span style={{ fontSize: 10, color: 'var(--emerald)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                <ShieldCheck size={11} /> RoE Signed
              </span></>
            )}
          </div>
        )}

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--emerald)' }} className="pulse" />
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Local core ready</span>
        </div>
      </header>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Left nav */}
        <nav style={{
          width: 180, flexShrink: 0,
          background: 'var(--bg-surface)',
          borderRight: '1px solid var(--border)',
          padding: '12px 8px',
          display: 'flex', flexDirection: 'column', gap: 2,
        }}>
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => {
            const active = screen === id;
            const enabled = canNav(id);
            return (
              <button
                key={id}
                disabled={!enabled}
                onClick={() => enabled && setScreen(id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '9px 12px', borderRadius: 'var(--radius-sm)',
                  border: 'none', cursor: enabled ? 'pointer' : 'not-allowed',
                  background: active ? 'rgba(34,211,238,0.1)' : 'transparent',
                  color: active ? 'var(--cyan)' : enabled ? 'var(--text-secondary)' : 'var(--text-muted)',
                  opacity: enabled ? 1 : 0.4,
                  fontWeight: active ? 700 : 500, fontSize: 13,
                  textAlign: 'left', width: '100%',
                  transition: 'all 0.12s',
                  borderLeft: `2px solid ${active ? 'var(--cyan)' : 'transparent'}`,
                }}
              >
                <Icon size={15} />
                {label}
              </button>
            );
          })}

          {/* Lock indicators */}
          <div style={{ marginTop: 'auto', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: authRecord ? 'var(--emerald)' : 'var(--amber)' }} />
              {authRecord ? 'RoE Signed' : 'RoE Pending'}
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'rgba(148,163,184,0.15)' }} />
              No telemetry
            </div>
          </div>
        </nav>

        {/* Main content area */}
        <main style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          {screen === 'setup' && (
            <div style={{ flex: 1, overflow: 'auto' }}>
              <ProjectSetupScreen onProjectTargetReady={handleProjectTargetReady} />
            </div>
          )}
          {screen === 'auth' && target && (
            <div style={{ flex: 1, overflow: 'auto' }}>
              <AuthGateScreen target={target} onRoESigned={handleRoESigned} />
            </div>
          )}
          {screen === 'console' && target && (
            <ScanConsoleScreen
              target={target}
              authRecord={authRecord}
              onScanComplete={handleScanComplete}
            />
          )}
          {screen === 'findings' && scanRunId && target && (
            <FindingsWorkbench scanId={scanRunId} targetId={target.id} />
          )}
          {screen === 'reports' && project && scanRunId && target && (
            <ReportBuilderScreen
              project={project}
              scanId={scanRunId}
              targetName={target.name}
            />
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
