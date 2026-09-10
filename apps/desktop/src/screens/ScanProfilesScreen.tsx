/**
 * Saved scan configurations.
 *
 * Configuring a scan means deciding which of sixteen engines to run, how hard
 * to crawl, and how fast to send requests. Those decisions are not per-target —
 * they are per kind of work — and making them from scratch every time is how an
 * analyst ends up leaving dynamic testing off by accident on the run that
 * mattered.
 *
 * Six profiles ship built in and are read-only. The editor starts from whichever
 * one is selected, so "Full assessment but without ZAP" is two clicks and a
 * name rather than sixteen checkboxes from nothing.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle, Check, Copy, FileCog, Globe, HardDrive, Lock, Plus, Save,
  Server, Trash2,
} from 'lucide-react';
import type { EngineDescriptor, ScanProfile } from '../types';
import { api } from '../lib/tauri';
import { Callout, EmptyState, Modal, Spinner, useToast } from '../components/ui';

interface Props {
  /** The profile currently chosen for the next scan, if any. */
  selectedId: string | null;
  onSelect: (profile: ScanProfile) => void;
}

const CATEGORY_LABEL: Record<EngineDescriptor['category'], string> = {
  builtin: 'Built in — always available',
  external: 'External — used when installed',
  live: 'Live — sends requests to the target',
};

const CATEGORY_ICON: Record<EngineDescriptor['category'], typeof Server> = {
  builtin: HardDrive,
  external: FileCog,
  live: Globe,
};

export function ScanProfilesScreen({ selectedId, onSelect }: Props) {
  const toast = useToast();
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [engines, setEngines] = useState<EngineDescriptor[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<ScanProfile | null>(null);
  const [isNew, setIsNew] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [p, e] = await Promise.all([api.listScanProfiles(), api.listEngines()]);
      setProfiles(p);
      setEngines(e);
    } catch (err) {
      toast('error', `Could not load scan profiles: ${err}`);
    }
    setLoading(false);
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const grouped = useMemo(() => {
    const order: EngineDescriptor['category'][] = ['builtin', 'external', 'live'];
    return order
      .map((category) => ({ category, engines: engines.filter((e) => e.category === category) }))
      .filter((g) => g.engines.length > 0);
  }, [engines]);

  function startNew() {
    setIsNew(true);
    setEditing({
      id: '',
      name: '',
      description: '',
      builtin: false,
      runDast: false,
      // A new profile starts with the engines that need nothing installed, so
      // it does something useful before a single box is ticked.
      enabledStages: engines.filter((e) => e.builtIn && !e.reachesTarget).map((e) => e.stage),
      configJson: '{\n  "crawl": { "enabled": false }\n}',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }

  /** Start a new profile from an existing one — including a built-in. */
  function duplicate(profile: ScanProfile) {
    setIsNew(true);
    setEditing({
      ...profile,
      id: '',
      builtin: false,
      name: `${profile.name} (copy)`,
    });
  }

  async function remove(profile: ScanProfile) {
    try {
      await api.deleteScanProfile(profile.id);
      toast('success', `Deleted "${profile.name}".`);
      load();
    } catch (err) {
      toast('error', String(err));
    }
  }

  if (loading) {
    return (
      <div className="page">
        <div className="empty">
          <Spinner size={22} />
          <p className="muted">Loading profiles…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page stack">
      <div className="between">
        <div>
          <h1 className="h1">Scan profiles</h1>
          <p className="muted small">
            A named set of engines and settings. Pick one on the scan console instead of
            re-deciding sixteen switches every run.
          </p>
        </div>
        <button className="btn btn-primary" onClick={startNew}>
          <Plus size={14} /> New profile
        </button>
      </div>

      <div className="grid grid-2">
        {profiles.map((profile) => {
          const live = profile.enabledStages.filter((s) =>
            engines.find((e) => e.stage === s)?.reachesTarget,
          ).length;
          const selected = profile.id === selectedId;

          return (
            <article
              key={profile.id}
              className={`card card-interactive ${selected ? 'card-selected' : ''}`}
              onClick={() => onSelect(profile)}
            >
              <div className="between" style={{ marginBottom: 'var(--s-2)' }}>
                <div className="row">
                  <h2 className="h2">{profile.name}</h2>
                  {profile.builtin && (
                    <span className="badge badge-outline" title="Ships with the application and cannot be edited">
                      <Lock size={10} /> Built in
                    </span>
                  )}
                  {selected && (
                    <span className="badge badge-accent">
                      <Check size={10} /> Selected
                    </span>
                  )}
                </div>
                <span className="dim small tabular">
                  {profile.enabledStages.length} engine{profile.enabledStages.length === 1 ? '' : 's'}
                </span>
              </div>

              <p className="muted small" style={{ marginBottom: 'var(--s-3)' }}>
                {profile.description}
              </p>

              <div className="row wrap" style={{ gap: 6, marginBottom: 'var(--s-3)' }}>
                {profile.enabledStages.slice(0, 8).map((stage) => (
                  <span key={stage} className="badge badge-outline">
                    {engines.find((e) => e.stage === stage)?.label ?? stage}
                  </span>
                ))}
                {profile.enabledStages.length > 8 && (
                  <span className="badge badge-outline">
                    +{profile.enabledStages.length - 8} more
                  </span>
                )}
              </div>

              <div className="between">
                <span className="dim small">
                  {profile.runDast && live > 0 ? (
                    <>
                      <AlertTriangle size={11} style={{ verticalAlign: -1 }} /> Sends requests to
                      the target — needs a signed authorisation
                    </>
                  ) : (
                    <>Reads local files and public sources only</>
                  )}
                </span>
                <div className="row" onClick={(e) => e.stopPropagation()}>
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() => duplicate(profile)}
                    title="Start a new profile from this one"
                  >
                    <Copy size={13} />
                  </button>
                  {!profile.builtin && (
                    <>
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => {
                          setIsNew(false);
                          setEditing(profile);
                        }}
                      >
                        Edit
                      </button>
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => remove(profile)}
                        title="Delete this profile"
                      >
                        <Trash2 size={13} />
                      </button>
                    </>
                  )}
                </div>
              </div>
            </article>
          );
        })}
      </div>

      {profiles.length === 0 && (
        <EmptyState icon={<FileCog size={30} />} title="No profiles">
          Even the built-in presets could not be loaded, which usually means the backend is not
          responding. Restart the application.
        </EmptyState>
      )}

      {editing && (
        <ProfileEditor
          profile={editing}
          isNew={isNew}
          grouped={grouped}
          onClose={() => setEditing(null)}
          onSaved={(saved) => {
            setEditing(null);
            load();
            onSelect(saved);
            toast('success', `Saved "${saved.name}".`);
          }}
        />
      )}
    </div>
  );
}

function ProfileEditor({
  profile, isNew, grouped, onClose, onSaved,
}: {
  profile: ScanProfile;
  isNew: boolean;
  grouped: { category: EngineDescriptor['category']; engines: EngineDescriptor[] }[];
  onClose: () => void;
  onSaved: (p: ScanProfile) => void;
}) {
  const [name, setName] = useState(profile.name);
  const [description, setDescription] = useState(profile.description);
  const [stages, setStages] = useState<string[]>(profile.enabledStages);
  const [runDast, setRunDast] = useState(profile.runDast);
  const [configJson, setConfigJson] = useState(profile.configJson);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const liveSelected = grouped
    .flatMap((g) => g.engines)
    .filter((e) => e.reachesTarget && stages.includes(e.stage));

  // Caught here as well as in the backend so the analyst sees it while they are
  // still looking at the checkboxes, rather than on save.
  const wouldRunNothing = stages.length > 0 && !runDast && liveSelected.length === stages.length;

  function toggle(stage: string) {
    setStages((s) => (s.includes(stage) ? s.filter((x) => x !== stage) : [...s, stage]));
  }

  async function save() {
    setSaving(true);
    setError('');
    try {
      const saved = await api.saveScanProfile({
        id: isNew ? undefined : profile.id,
        name,
        description,
        runDast,
        enabledStages: stages,
        configJson,
      });
      onSaved(saved);
    } catch (err) {
      setError(String(err));
    }
    setSaving(false);
  }

  return (
    <Modal
      wide
      title={isNew ? 'New scan profile' : `Edit "${profile.name}"`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            onClick={save}
            disabled={saving || !name.trim() || stages.length === 0 || wouldRunNothing}
          >
            {saving ? <Spinner size={14} /> : <Save size={14} />} Save profile
          </button>
        </>
      }
    >
      <div className="stack">
        <div className="field">
          <label className="label" htmlFor="profile-name">Name</label>
          <input
            id="profile-name"
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Pre-release check"
          />
        </div>

        <div className="field">
          <label className="label" htmlFor="profile-description">Description</label>
          <textarea
            id="profile-description"
            className="textarea"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What this profile is for, and what it will not find."
          />
          <span className="hint">
            Worth writing. A profile whose limits are not stated produces a report whose silence
            gets over-read.
          </span>
        </div>

        <div className="field">
          <span className="label">Engines</span>
          {grouped.map(({ category, engines }) => {
            const Icon = CATEGORY_ICON[category];
            return (
              <div key={category} className="stack" style={{ marginTop: 'var(--s-3)' }}>
                <div className="row dim small">
                  <Icon size={13} />
                  {CATEGORY_LABEL[category]}
                </div>
                {engines.map((e) => (
                  <label
                    key={e.stage}
                    className={`checkline ${stages.includes(e.stage) ? 'checkline-on' : ''}`}
                  >
                    <input
                      type="checkbox"
                      checked={stages.includes(e.stage)}
                      onChange={() => toggle(e.stage)}
                    />
                    <span className="grow col" style={{ gap: 2 }}>
                      <span className="row">
                        <strong>{e.label}</strong>
                        {e.builtIn && <span className="badge badge-accent">no install needed</span>}
                        {e.requiresBinary && (
                          <span className="badge badge-outline mono">{e.requiresBinary}</span>
                        )}
                      </span>
                      <span className="hint">{e.description}</span>
                    </span>
                  </label>
                ))}
              </div>
            );
          })}
        </div>

        <label className={`checkline ${runDast ? 'checkline-on' : ''}`}>
          <input type="checkbox" checked={runDast} onChange={(e) => setRunDast(e.target.checked)} />
          <span className="grow col" style={{ gap: 2 }}>
            <strong>Allow dynamic testing</strong>
            <span className="hint">
              Required for any engine that reaches the target. The authorisation gate still applies
              on top of this: with no signed Rules of Engagement the live engines are refused
              whatever this switch says.
            </span>
          </span>
        </label>

        {wouldRunNothing && (
          <Callout tone="danger">
            Every engine selected is a live one, but dynamic testing is off — this profile would
            run nothing and report a clean result. Enable dynamic testing, or add a static engine.
          </Callout>
        )}

        {liveSelected.length > 0 && runDast && (
          <Callout tone="warning">
            This profile sends requests to the target through{' '}
            <strong>{liveSelected.map((e) => e.label).join(', ')}</strong>. Only run it against a
            system you are authorised to test.
          </Callout>
        )}

        <div className="field">
          <label className="label" htmlFor="profile-config">Scan configuration (JSON)</label>
          <textarea
            id="profile-config"
            className="textarea input-mono"
            rows={8}
            value={configJson}
            onChange={(e) => setConfigJson(e.target.value)}
            spellCheck={false}
          />
          <span className="hint">
            Crawl bounds, request rate and timeouts. <span className="code-inline">crawl.maxPages</span>,{' '}
            <span className="code-inline">crawl.maxDepth</span>,{' '}
            <span className="code-inline">crawl.budgetSeconds</span>,{' '}
            <span className="code-inline">requestsPerSecond</span>,{' '}
            <span className="code-inline">offline</span>. Validated as parseable on save, so a
            typo cannot fail the scan after the authorisation has been signed.
          </span>
        </div>

        {error && <Callout tone="danger">{error}</Callout>}
      </div>
    </Modal>
  );
}
