import { useState, useEffect, useRef } from 'react';
import { Play, Square, CheckCircle2, XCircle, SkipForward, Clock, Loader2, ShieldOff, Shield, SlidersHorizontal, Sparkles, KeyRound, Trash2, FolderGit2 } from 'lucide-react';
import type {
  Target, AuthorizationRecord, ScanLogPayload, ScanProfile, ScanStage, StageState,
  EngineDescriptor, CredentialStatus,
} from '../types';
import { api, events } from '../lib/tauri';
import type { UnlistenFn } from '@tauri-apps/api/event';

interface Props {
  target: Target;
  authRecord: AuthorizationRecord | null;
  /**
   * The saved configuration this run should use.
   *
   * `null` runs every engine, which is what the console did before profiles
   * existed and remains the right default for somebody who has not chosen one.
   */
  profile: ScanProfile | null;
  onChooseProfile: () => void;
  onScanComplete: (scanRunId: string) => void;
}

interface StageStatus {
  stage: ScanStage;
  label: string;
  /** How the engine is obtained, which is what the tag on the card says. */
  stageType: 'static' | 'builtin' | 'dast';
  /**
   * Whether this engine sends requests to the target and is therefore behind
   * the authorisation gate.
   *
   * Carried explicitly rather than inferred from `stageType`. It was inferred,
   * and the inference was "anything not external is gated" — which was right
   * while the only built-in engine was the live one, and became wrong the
   * moment four built-in engines that read local files were added. They would
   * have rendered permanently locked behind an authorisation they do not need.
   */
  gated: boolean;
  state: StageState;
  findings: number;
  message: string;
}

// Must stay in step with BASELINE_STAGES / DAST_STAGES in commands/scan.rs. A
// stage the backend runs but this list omits emits events that match no row, so
// its progress and its failures are both invisible — which is exactly how the
// native engine came to look like it was doing nothing.
/** Stage state to the class that colours its card. */
const STAGE_STATE_CLASS: Record<StageState, string> = {
  pending: '',
  running: 'stage-running',
  done: 'stage-done',
  skipped: '',
  failed: 'stage-failed',
};

/** Log level to the class that colours the line. */
const LOG_LEVEL_CLASS: Record<string, string> = {
  info: 'log-info',
  warn: 'log-warn',
  error: 'log-error',
  done: 'log-done',
};

/**
 * Build the console's stage list from the engine list the backend serves.
 *
 * This was a hardcoded table carrying the comment "must stay in step with
 * BASELINE_STAGES / DAST_STAGES in commands/scan.rs" — the same drift the Rust
 * side is now guarded against, except across a boundary no test can reach. It
 * fails silently in both directions: an engine the pipeline runs but this list
 * omits emits stage, log and completion events matching no row, so its progress
 * and its failures are equally invisible; and a row here for a stage the
 * pipeline does not run sits on "Waiting…" for the whole scan, which reads as a
 * hang. The native engine was invisible this way once already.
 *
 * `list_engines` is derived from ALL_STAGES, which the Rust tests now hold equal
 * to what the pipeline actually runs. Deriving from it makes this console
 * correct by construction rather than by remembering to edit two files.
 */
function stageFromEngine(e: EngineDescriptor): StageStatus {
  return {
    stage: e.stage as ScanStage,
    label: e.label,
    // Built-in is about where the engine comes from; gated is about whether it
    // reaches the target. Sentinel Native is both, and the tag should say the
    // former while the lock follows the latter.
    stageType: e.builtIn ? 'builtin' : e.reachesTarget ? 'dast' : 'static',
    gated: e.reachesTarget,
    state: 'pending',
    findings: 0,
    message: e.reachesTarget ? 'Requires signed RoE' : 'Waiting…',
  };
}

// How long to wait for the first engine event before warning. The pipeline
// emits its first log line immediately on spawn, so silence past this point
// means the events are not arriving rather than that a stage is slow.
/// Starting points for the engine-config box.
///
/// Each is a complete, valid document rather than a fragment, so a preset can
/// be used as-is without the analyst having to know which fields pair with
/// which. Field names are camelCase because serde renames on the way in.
const CONFIG_PRESETS: { label: string; json: string }[] = [
  {
    label: 'Gentle',
    json: JSON.stringify(
      {
        rateLimitRps: 1,
        timeoutSeconds: 3600,
        nuclei: { severityFilter: 'critical,high' },
      },
      null,
      2,
    ),
  },
  {
    label: 'Thorough',
    json: JSON.stringify(
      {
        rateLimitRps: 5,
        timeoutSeconds: 3600,
        zapSpider: {
          runTraditionalSpider: true,
          runAjaxSpider: true,
          traditionalSpiderDurationSecs: 300,
          ajaxSpiderDurationSecs: 300,
        },
        nuclei: { severityFilter: 'critical,high,medium,low' },
      },
      null,
      2,
    ),
  },
  {
    label: 'Remote ZAP',
    json: JSON.stringify({ zapApiUrl: 'http://127.0.0.1:8090', zapApiKey: '' }, null, 2),
  },
];

const CONFIG_PLACEHOLDER = `{
  "rateLimitRps": 3,
  "timeoutSeconds": 1800,
  "zapApiUrl": "http://localhost:8090",
  "nuclei": { "severityFilter": "critical,high,medium" }
}`;

const WATCHDOG_SECONDS = 20;

const STAGE_TAG: Record<StageStatus['stageType'], string> = {
  static:  '🔍 STATIC',
  builtin: '🛡 BUILT-IN',
  dast:    '⚡ DAST',
};

const STATE_ICON: Record<StageState, React.ReactNode> = {
  pending: <Clock size={14} style={{ color: 'var(--text-muted)' }} />,
  running: <Loader2 size={14} className="pulse" style={{ color: 'var(--accent)' }} />,
  done:    <CheckCircle2 size={14} style={{ color: 'var(--success)' }} />,
  skipped: <SkipForward size={14} style={{ color: 'var(--warning)' }} />,
  failed:  <XCircle size={14} style={{ color: 'var(--danger)' }} />,
};

export function ScanConsoleScreen({
  target, authRecord, profile, onChooseProfile, onScanComplete,
}: Props) {
  const [stages, setStages] = useState<StageStatus[]>([]);
  const [enginesError, setEnginesError] = useState('');
  // Whether a credential is sitting in the OS keychain for this target.
  const [credStatus, setCredStatus] = useState<CredentialStatus | null>(null);
  const [credBusy, setCredBusy] = useState(false);
  const [credError, setCredError] = useState('');
  // The source checkout the static engines read. Editable here because a wrong
  // path was previously only fixable by recreating the target, which discards
  // its findings and its signed authorisation along with the mistake.
  const [repoRef, setRepoRef] = useState(target.repoRef ?? '');
  const [repoSaved, setRepoSaved] = useState(target.repoRef ?? '');
  const [repoBusy, setRepoBusy] = useState(false);
  const [repoError, setRepoError] = useState('');
  // A card for an engine the profile has switched off would sit on "Waiting…"
  // for the whole run, which reads as a stalled stage rather than an excluded
  // one. With no profile chosen everything runs, so everything is shown.
  const visibleStages = profile
    ? stages.filter((s) => profile.enabledStages.includes(s.stage))
    : stages;
  const [logs, setLogs] = useState<ScanLogPayload[]>([]);
  const [scanRunId, setScanRunId] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [runDast, setRunDast] = useState(false);


  // Per-scan engine configuration, sent to the pipeline as `configJson`.
  //
  // Left blank the backend applies DastConfig::default(), which is what every
  // scan used to get with no way to influence it. Note that `rateLimitRps` is a
  // ceiling request, not an override: the engine takes min(config, RoE), so
  // this can lower the rate agreed in the Rules of Engagement but never raise
  // it — the signed limit is a safety guarantee, not a default.
  const [showConfig, setShowConfig] = useState(false);
  const [configText, setConfigText] = useState('');
  const [configError, setConfigError] = useState('');
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
  // A credential for this target lives in the OS keychain, not in the
  // engagement file. It could be written from the setup wizard and then never
  // seen again: nothing in the interface said whether one was stored, and
  // nothing could remove it. That is the wrong shape for a secret — an analyst
  // finishing an engagement had no way to revoke what they had left behind
  // except to go into Credential Manager and find it by hand.
  useEffect(() => {
    let active = true;
    api.getTargetCredentialStatus(target.id)
      .then((st) => { if (active) setCredStatus(st); })
      .catch((err) => { if (active) setCredError(String(err)); });
    return () => { active = false; };
  }, [target.id]);

  async function saveRepo() {
    setRepoBusy(true);
    setRepoError('');
    try {
      const updated = await api.updateTargetRepo(target.id, repoRef.trim());
      setRepoSaved(updated.repoRef ?? '');
      setRepoRef(updated.repoRef ?? '');
    } catch (err) {
      setRepoError(String(err));
    }
    setRepoBusy(false);
  }

  async function clearCredentials() {
    setCredBusy(true);
    setCredError('');
    try {
      setCredStatus(await api.clearTargetCredentials(target.id));
    } catch (err) {
      setCredError(String(err));
    }
    setCredBusy(false);
  }

  // Load the engine list once. A failure here is worth surfacing rather than
  // rendering an empty grid: no cards beside a working Launch button looks like
  // a scan with nothing to run, which is indistinguishable from a scan that ran
  // and found nothing.
  useEffect(() => {
    let active = true;
    api.listEngines()
      .then((engines) => {
        if (!active) return;
        setStages(engines.map(stageFromEngine));
        setEnginesError('');
      })
      .catch((err) => {
        if (!active) return;
        setEnginesError(String(err));
      });
    return () => { active = false; };
  }, []);

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
    // Parsed before the console is reset: a malformed config should leave the
    // previous run's output on screen with an explanation, not wipe it and then
    // report a failure against an empty console.
    if (configText.trim()) {
      try {
        const parsed: unknown = JSON.parse(configText);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          setConfigError('Scan configuration must be a JSON object, e.g. {"rateLimitRps": 2}.');
          setShowConfig(true);
          return;
        }
      } catch (err) {
        setConfigError(`Scan configuration is not valid JSON: ${String(err)}`);
        setShowConfig(true);
        return;
      }
    }
    setConfigError('');
    setError('');
    setLogs([]);
    setStages(prev => prev.map(s => ({
      ...s,
      state: 'pending',
      findings: 0,
      message: s.gated && !isAuthorized ? 'Requires signed RoE' : 'Waiting…',
    })));
    setTotalFindings(0);
    setCriticalHigh(0);
    setIsRunning(true);
    sawEventRef.current = false;
    if (watchdogRef.current) clearTimeout(watchdogRef.current);

    // A profile that does not enable dynamic testing must not have it turned on
    // by a switch left set from a previous run.
    const dast = runDast && isAuthorized && (profile ? profile.runDast : true);
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
      // The profile decides which engines run and supplies the configuration;
      // anything typed into the box below overrides the profile's own JSON, so
      // a one-off adjustment does not require saving a new profile.
      const id = await api.triggerScan(
        target.id,
        dast,
        configText.trim() || profile?.configJson || undefined,
        profile?.enabledStages,
      );
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
    <div className="page col fade-in" style={{ gap: 'var(--s-5)', height: '100%' }}>
      {/* Engine configuration panel */}
      {showConfig && (
        <div className="card card-tight">
          <div className="between wrap" style={{ marginBottom: 'var(--s-2)', gap: 'var(--s-3)' }}>
            <label className="label" htmlFor="engine-config">Engine configuration (JSON) — optional</label>
            <div className="row" style={{ gap: 'var(--s-1)' }}>
              {CONFIG_PRESETS.map(preset => (
                <button
                  key={preset.label}
                  className="btn btn-sm"
                  onClick={() => { setConfigText(preset.json); setConfigError(''); }}>
                  {preset.label}
                </button>
              ))}
              {configText && (
                <button className="btn btn-ghost btn-sm" onClick={() => { setConfigText(''); setConfigError(''); }}>
                  Clear
                </button>
              )}
            </div>
          </div>

          <textarea
            id="engine-config"
            className="textarea input-mono"
            value={configText}
            onChange={(e) => { setConfigText(e.target.value); setConfigError(''); }}
            spellCheck={false}
            rows={7}
            placeholder={CONFIG_PLACEHOLDER}
            aria-invalid={configError ? true : undefined}
          />

          {configError && <div className="error-text">{configError}</div>}

          <div className="hint" style={{ marginTop: 'var(--s-2)' }}>
            Left blank, the engine defaults apply: <code>5</code> requests/sec, a <code>1800</code>s job
            budget, ZAP at <code>http://localhost:8090</code>, Nuclei filtered to
            <code> critical,high,medium</code>.{' '}
            <strong>rateLimitRps is a ceiling request, not an override</strong> — the engine takes the lower
            of this and the rate in the signed Rules of Engagement
            {authRecord ? <> (currently <code>{authRecord.scope.rateLimitRps}</code>/sec)</> : null}, so it
            can slow a scan down but never speed it past what was agreed.
          </div>
        </div>
      )}

      {/* Which configuration this run uses. Shown before the launch button
          rather than buried in a settings panel: "which profile was that scan
          run with" is the first question asked of an unexpected result. */}
      <div className="card card-tight between wrap">
        <div className="col" style={{ gap: 2 }}>
          <div className="row">
            <Sparkles size={14} style={{ color: 'var(--accent)' }} />
            <strong>{profile ? profile.name : 'Every engine'}</strong>
            {profile?.builtin && <span className="badge badge-outline">Built in</span>}
            <span className="badge badge-outline tabular">
              {(profile ? profile.enabledStages.length : stages.length)} engines
            </span>
          </div>
          <span className="hint">
            {profile
              ? profile.description
              : 'No profile selected, so every engine runs. Pick one to shorten the run, or to keep live traffic off entirely.'}
          </span>
        </div>
        <button className="btn btn-sm" onClick={onChooseProfile} disabled={isRunning}>
          {profile ? 'Change profile' : 'Choose a profile'}
        </button>
      </div>

      {/* Source checkout. The static engines read this directory; with it unset
          they skip cleanly and the scan reports only what the live engines saw,
          which is easy to mistake for a clean result. */}
      <div className="card card-tight">
        <div className="between wrap" style={{ gap: 'var(--s-2)', marginBottom: 'var(--s-2)' }}>
          <div className="row">
            <FolderGit2 size={14} style={{ color: repoSaved ? 'var(--success)' : 'var(--warning)' }} />
            <strong>{repoSaved ? 'Source repository' : 'No source repository set'}</strong>
          </div>
          {repoRef.trim() !== repoSaved && (
            <button className="btn btn-sm btn-primary" onClick={saveRepo} disabled={repoBusy || isRunning}>
              {repoBusy ? <Loader2 size={13} className="spin" /> : null}
              {repoBusy ? 'Saving…' : 'Save path'}
            </button>
          )}
        </div>
        <input
          className="input input-mono"
          value={repoRef}
          onChange={(e) => { setRepoRef(e.target.value); setRepoError(''); }}
          placeholder="/path/to/the/checkout"
          aria-label="Source repository path"
          disabled={isRunning}
        />
        <span className="hint">
          {repoError
            ? repoError
            : repoSaved
              ? 'The code, dependency, secret and infrastructure engines read this directory. Change it and save to point the next scan at a different checkout.'
              : 'Without a checkout the source engines skip, and the scan reports only what the live engines saw — which reads the same as a clean result. Set it before relying on this assessment.'}
        </span>
      </div>

      {/* Scan credentials. Shown here because "will this scan reach the pages
          behind the login" is decided at launch, not at setup. */}
      <div className="card card-tight between wrap">
        <div className="col" style={{ gap: 2 }}>
          <div className="row">
            <KeyRound size={14} style={{ color: credStatus?.configured ? 'var(--success)' : 'var(--text-muted)' }} />
            <strong>{credStatus?.configured ? 'Credential stored' : 'No credential stored'}</strong>
            {credStatus?.configured && <span className="badge badge-outline">OS keychain</span>}
          </div>
          <span className="hint">
            {credError
              ? credError
              : credStatus?.configured
                ? `${credStatus.description ?? 'A credential is held for this target'} — the engine will assess the authenticated pages. It is never written to the engagement file or a report.`
                : 'The scan will only reach pages a signed-out visitor can see. Add a credential in Project & target to assess what sits behind the login.'}
          </span>
        </div>
        {credStatus?.configured && (
          <button className="btn btn-sm" onClick={clearCredentials} disabled={credBusy || isRunning}>
            {credBusy ? <Loader2 size={13} className="spin" /> : <Trash2 size={13} />}
            {credBusy ? 'Removing…' : 'Remove from keychain'}
          </button>
        )}
      </div>

      {/* Header row */}
      <div className="between wrap" style={{ gap: 'var(--s-3)' }}>
        <div>
          <h2 className="h2">Scan Console</h2>
          <div className="mono dim small">{target.baseUrl}</div>
        </div>
        <div className="row" style={{ gap: 'var(--s-3)' }}>
          {/* DAST toggle — only if authorized */}
          {/* A profile that declares itself source-only must not have live
              testing switched on by a control left set from a previous run. */}
          {(!profile || profile.runDast) && (
            <label className={`checkline ${runDast && isAuthorized ? 'checkline-on' : ''}`}>
              <input
                type="checkbox" checked={runDast} disabled={!isAuthorized}
                onChange={(e) => setRunDast(e.target.checked)}
              />
              <span className="row" style={{ gap: 'var(--s-1)' }}>
                {isAuthorized
                  ? <Shield size={13} style={{ color: 'var(--success)' }} />
                  : <ShieldOff size={13} style={{ color: 'var(--warning)' }} />}
                Include DAST {!isAuthorized && '(record authorisation first)'}
              </span>
            </label>
          )}
          {profile && !profile.runDast && (
            <span className="badge badge-outline" title="This profile reads local files and public sources only">
              <ShieldOff size={10} /> No live traffic
            </span>
          )}

          <button
            className="btn"
            aria-pressed={showConfig}
            onClick={() => setShowConfig(v => !v)}
            disabled={isRunning}
            title="Per-scan engine configuration (JSON)">
            <SlidersHorizontal size={13} /> Engine config
            {/* A dot, so a configuration left over from a previous run is
                visible without opening the panel. */}
            {configText.trim() && <span className="dot" style={{ background: 'var(--accent)' }} />}
          </button>

          {isRunning ? (
            <button className="btn btn-danger btn-lg" onClick={cancelScan}>
              <Square size={14} /> Cancel
            </button>
          ) : (
            <button
              className="btn btn-primary btn-lg"
              onClick={startScan}
              disabled={isRunning || !listenersReady}
              title={listenersReady ? undefined : 'Connecting to the scan engine event stream...'}
            >
              {listenersReady ? <Play size={14} /> : <Loader2 size={14} className="spin" />}
              {listenersReady ? 'Launch Scan' : 'Connecting…'}
            </button>
          )}
        </div>
      </div>

      {/* Auth banner */}
      {!isAuthorized && (
        <div className="callout callout-warning">
          <ShieldOff size={14} />
          <span>DAST stages are disabled — complete the Authorization Gate to unlock ZAP and Nuclei.</span>
        </div>
      )}

      {error && (
        <div className="callout callout-danger"><span>{error}</span></div>
      )}

      {enginesError && (
        <div className="callout callout-danger">
          <span>
            The engine list could not be loaded, so this console cannot show what a scan
            will run: {enginesError}
          </span>
        </div>
      )}

      {/* Stage cards. Only the engines this profile runs: a card that will
          never move is worse than no card, because it reads as a stall. */}
      <div className="grid grid-3">
        {visibleStages.map((s) => {
          // The native engine is gated like the external DAST ones: it makes
          // real requests to the target. The built-in *static* engines are not
          // — they read local files and reach no network the gate governs.
          const isDastLocked = s.gated && !isAuthorized;
          return (
            <div
              key={s.stage}
              className={`stage ${STAGE_STATE_CLASS[s.state]}`}
              style={isDastLocked ? { opacity: 0.5 } : undefined}
            >
              {STATE_ICON[s.state]}
              <div className="col grow" style={{ gap: 2, minWidth: 0 }}>
                <div className="row between" style={{ gap: 'var(--s-2)' }}>
                  <span className="stage-name truncate">{s.label}</span>
                  <span className="badge badge-outline">{STAGE_TAG[s.stageType]}</span>
                </div>
                <span className="stage-state">{s.message}</span>
                <div className="row" style={{ gap: 'var(--s-2)' }}>
                  {s.findings > 0 && (
                    <span className="badge badge-accent tabular">
                      {s.findings} finding{s.findings !== 1 ? 's' : ''}
                    </span>
                  )}
                  {isDastLocked && (
                    <span className="row small" style={{ gap: 4, color: 'var(--warning)' }}>
                      <ShieldOff size={11} /> Locked
                    </span>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Totals */}
      {totalFindings > 0 && (
        <div className="grid grid-2">
          <div className="stat">
            <span className="stat-value">{totalFindings}</span>
            <span className="stat-label">Total findings</span>
          </div>
          <div className="stat stat-critical">
            <span className="stat-value">{criticalHigh}</span>
            <span className="stat-label">Critical + High</span>
          </div>
        </div>
      )}

      {/* Log console */}
      <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 220 }}>
        <div className="card-header row" style={{ gap: 'var(--s-2)' }}>
          <span
            className={`dot ${isRunning ? 'pulse' : ''}`}
            style={{ background: isRunning ? 'var(--success)' : 'var(--text-muted)' }}
          />
          <span className="label">Engine log stream</span>
        </div>
        <div ref={logRef} className="log grow" style={{ border: 'none', borderRadius: 0 }}>
          {logs.length === 0 ? (
            <span className="dim">Scan output will appear here when the engine runs…</span>
          ) : (
            logs.map((log, i) => (
              <div key={i} className="log-line">
                <span className="log-time">
                  {new Date(log.timestamp).toISOString().split('T')[1].slice(0, 8)}
                </span>
                <span className={LOG_LEVEL_CLASS[log.level] ?? 'log-info'} style={{ fontWeight: 700 }}>
                  [{log.level.toUpperCase()}]
                </span>
                <span className="dim">[{log.stage}]</span>
                <span className="grow">{log.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}


