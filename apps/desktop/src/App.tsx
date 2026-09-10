/**
 * The application shell: navigation, engagement context, and the theme.
 *
 * Two changes from the shape this had before, both about the same thing —
 * making the tool usable on the fifth visit rather than only on the first.
 *
 * It opens on a dashboard rather than an empty project form. The form answers
 * "what do I do first" exactly once and is in the way every time after; the
 * dashboard answers "where is this engagement" every time.
 *
 * And the navigation is grouped rather than a flat list of six. The steps that
 * set an engagement up are done once; the ones that carry the work are returned
 * to constantly, and mixing them made the second group harder to find. Items
 * that genuinely cannot work yet stay disabled with a reason attached, rather
 * than failing when clicked.
 */

import { useEffect, useState } from 'react';
import { getVersion } from '@tauri-apps/api/app';
import {
  Activity, AlertOctagon, ChevronRight, FileBarChart2, FolderOpen, LayoutDashboard,
  ListChecks, ShieldCheck, Sparkles, WifiOff,
} from 'lucide-react';
import type { AuthorizationRecord, Project, ScanProfile, Target } from './types';
import brandMark from './assets/hero.png';
import { ProjectSetupScreen } from './screens/ProjectSetupScreen';
import { AuthGateScreen } from './screens/AuthGateScreen';
import { ScanConsoleScreen } from './screens/ScanConsoleScreen';
import { FindingsWorkbench } from './screens/FindingsWorkbench';
import { ReportBuilderScreen } from './screens/ReportBuilderScreen';
import { CoverageScreen } from './screens/CoverageScreen';
import { DashboardScreen } from './screens/DashboardScreen';
import { ScanProfilesScreen } from './screens/ScanProfilesScreen';
import { ThemeToggle, ToastProvider } from './components/ui';
import { useTheme } from './lib/useTheme';
import './styles/design-system.css';

export type Screen =
  | 'dashboard' | 'setup' | 'auth' | 'profiles' | 'console'
  | 'findings' | 'coverage' | 'reports';

interface NavEntry {
  id: Screen;
  label: string;
  icon: typeof LayoutDashboard;
  section: 'work' | 'setup';
}

const NAV: NavEntry[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, section: 'work' },
  { id: 'console',   label: 'Scan',      icon: Activity,        section: 'work' },
  { id: 'findings',  label: 'Findings',  icon: AlertOctagon,    section: 'work' },
  { id: 'coverage',  label: 'Coverage',  icon: ListChecks,      section: 'work' },
  { id: 'reports',   label: 'Reports',   icon: FileBarChart2,   section: 'work' },
  { id: 'setup',     label: 'Project & target', icon: FolderOpen, section: 'setup' },
  { id: 'auth',      label: 'Authorisation',    icon: ShieldCheck, section: 'setup' },
  { id: 'profiles',  label: 'Scan profiles',    icon: Sparkles,    section: 'setup' },
];

function Shell() {
  const [screen, setScreen] = useState<Screen>('dashboard');
  const [project, setProject] = useState<Project | null>(null);
  const [target, setTarget] = useState<Target | null>(null);
  const [authRecord, setAuthRecord] = useState<AuthorizationRecord | null>(null);
  const [scanRunId, setScanRunId] = useState<string | null>(null);
  const [profile, setProfile] = useState<ScanProfile | null>(null);
  const [theme, toggleTheme] = useTheme();

  // Read from the bundle rather than hardcoded. A literal here went stale
  // across two releases and reported v0.2.0 on every build, which made "which
  // version am I running?" unanswerable while diagnosing an empty scan.
  const [version, setVersion] = useState('…');
  useEffect(() => {
    getVersion().then(setVersion).catch(() => setVersion('unknown'));
  }, []);

  /**
   * Why a screen is not reachable yet.
   *
   * Returning the reason rather than a boolean is what lets the item explain
   * itself on hover instead of just being greyed out — a disabled control with
   * no explanation is the most common way an interface stalls somebody.
   */
  function blockedBecause(id: Screen): string | null {
    switch (id) {
      case 'dashboard':
      case 'setup':
      case 'profiles':
        return null;
      case 'auth':
      case 'console':
        return project && target
          ? null
          : 'Create a project and a target first.';
      case 'findings':
      case 'coverage':
      case 'reports':
        return scanRunId ? null : 'Run a scan first — there is nothing to show yet.';
      default:
        return null;
    }
  }

  const sections: { key: 'work' | 'setup'; title: string }[] = [
    { key: 'work', title: 'Assessment' },
    { key: 'setup', title: 'Configuration' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
      <header
        className="row"
        style={{
          height: 52,
          padding: '0 var(--s-5)',
          gap: 'var(--s-4)',
          background: 'var(--bg-surface)',
          borderBottom: '1px solid var(--border)',
          flexShrink: 0,
        }}
      >
        <div className="row">
          <img
            src={brandMark}
            alt=""
            width={28}
            height={28}
            style={{ borderRadius: 7, display: 'block', objectFit: 'cover' }}
          />
          <div className="col" style={{ gap: 0 }}>
            <span style={{ fontSize: 13, fontWeight: 750, letterSpacing: '-0.01em' }}>
              SentinelVAPT
            </span>
            <span className="dim mono" style={{ fontSize: 9.5 }}>v{version}</span>
          </div>
        </div>

        {project && (
          <div
            className="row"
            style={{
              padding: '4px var(--s-3)',
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-full)',
              gap: 6,
            }}
          >
            <span className="dim small">{project.companyName}</span>
            {target && (
              <>
                <ChevronRight size={11} className="dim" />
                <span className="small" style={{ fontWeight: 600 }}>{target.name}</span>
              </>
            )}
            {authRecord && (
              <>
                <ChevronRight size={11} className="dim" />
                <span className="badge badge-low">
                  <ShieldCheck size={10} /> Authorised
                </span>
              </>
            )}
          </div>
        )}

        <div className="grow" />

        {profile && (
          <span className="badge badge-outline" title={profile.description}>
            <Sparkles size={10} /> {profile.name}
          </span>
        )}
        <span className="badge badge-outline" title="No telemetry, no account, no cloud dependency">
          <WifiOff size={10} /> Local only
        </span>
        <ThemeToggle theme={theme} onToggle={toggleTheme} />
      </header>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <nav
          style={{
            width: 196,
            flexShrink: 0,
            padding: 'var(--s-2)',
            background: 'var(--bg-surface)',
            borderRight: '1px solid var(--border)',
            overflowY: 'auto',
          }}
        >
          {sections.map(({ key, title }) => (
            <div key={key}>
              <div className="nav-section">{title}</div>
              {NAV.filter((n) => n.section === key).map(({ id, label, icon: Icon }) => {
                const blocked = blockedBecause(id);
                return (
                  <button
                    key={id}
                    className={`nav-item ${screen === id ? 'nav-item-active' : ''}`}
                    disabled={!!blocked}
                    title={blocked ?? label}
                    onClick={() => !blocked && setScreen(id)}
                  >
                    <Icon size={15} />
                    {label}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        <main style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column' }}>
          {screen === 'dashboard' && (
            <DashboardScreen
              project={project}
              target={target}
              scanId={scanRunId}
              roeSigned={!!authRecord}
              onNavigate={setScreen}
            />
          )}

          {screen === 'setup' && (
            <ProjectSetupScreen
              onProjectTargetReady={(p, t) => {
                setProject(p);
                setTarget(t);
                setScreen('auth');
              }}
            />
          )}

          {screen === 'auth' && target && (
            <AuthGateScreen
              target={target}
              onRoESigned={(record) => {
                setAuthRecord(record);
                setScreen('console');
              }}
            />
          )}

          {screen === 'profiles' && (
            <ScanProfilesScreen
              selectedId={profile?.id ?? null}
              onSelect={setProfile}
            />
          )}

          {screen === 'console' && target && (
            <ScanConsoleScreen
              target={target}
              authRecord={authRecord}
              profile={profile}
              onChooseProfile={() => setScreen('profiles')}
              onScanComplete={(id) => {
                setScanRunId(id);
                setScreen('findings');
              }}
            />
          )}

          {screen === 'findings' && scanRunId && target && (
            <FindingsWorkbench scanId={scanRunId} targetId={target.id} />
          )}

          {screen === 'coverage' && scanRunId && <CoverageScreen scanId={scanRunId} />}

          {screen === 'reports' && project && scanRunId && target && (
            <ReportBuilderScreen
              project={project}
              scanId={scanRunId}
              targetName={target.name}
              targetUrl={target.baseUrl}
            />
          )}
        </main>
      </div>
    </div>
  );
}

export function App() {
  return (
    <ToastProvider>
      <Shell />
    </ToastProvider>
  );
}

export default App;
