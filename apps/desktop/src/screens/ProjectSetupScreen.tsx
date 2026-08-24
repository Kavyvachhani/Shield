import { useState } from 'react';
import { FolderOpen, Globe, Code2, Cpu, ChevronRight, Plus, CheckCircle2, KeyRound } from 'lucide-react';
import type { Project, Target, CreateProjectInput, CreateTargetInput, CredentialKind } from '../types';
import { api } from '../lib/tauri';

interface Props {
  onProjectTargetReady: (project: Project, target: Target) => void;
}

const TARGET_TYPES = ['Web App', 'REST API', 'GraphQL', 'Host', 'Mobile API'] as const;
const TARGET_ICONS = {
  'Web App':    Globe,
  'REST API':   Code2,
  'GraphQL':    Cpu,
  'Host':       Cpu,
  'Mobile API': Cpu,
};

/// Returns a human-readable problem with `raw`, or null if it is usable as a
/// target base URL. Mirrors `validate_base_url` in commands/targets.rs.
function describeBaseUrlProblem(raw: string): string | null {
  if (!raw) return 'Base URL is required.';
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return `'${raw}' is not a valid URL. Expected something like https://app.example.com`;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return `Base URL must use http or https, not '${parsed.protocol.replace(':', '')}'.`;
  }
  if (!parsed.hostname) return `'${raw}' has no host.`;
  return null;
}

export function ProjectSetupScreen({ onProjectTargetReady }: Props) {
  const [step, setStep] = useState<1 | 2>(1);
  const [project, setProject] = useState<Project | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  // Project form state
  const [companyName, setCompanyName]     = useState('');
  const [engagementName, setEngagementName] = useState('');

  // Target form state
  const [targetName, setTargetName]       = useState('');
  const [targetType, setTargetType]       = useState<string>('Web App');
  const [baseUrl, setBaseUrl]             = useState('');
  const [repoRef, setRepoRef]             = useState('');
  const [stackDesc, setStackDesc]         = useState('');

  // Optional scan credentials. Kept out of the target payload entirely: the
  // secret is sent on its own to the keychain after the target exists.
  const [credKind, setCredKind]             = useState<CredentialKind | 'none'>('none');
  const [credUsername, setCredUsername]     = useState('');
  const [credSecret, setCredSecret]         = useState('');
  const [credHeaderName, setCredHeaderName] = useState('');

  async function handleCreateProject(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (!companyName.trim() || !engagementName.trim()) {
      setError('Company name and engagement name are required.'); return;
    }
    setSaving(true);
    try {
      const input: CreateProjectInput = {
        companyName: companyName.trim(),
        name: engagementName.trim(),
      };
      const p = await api.createProject(input);
      setProject(p);
      setStep(2);
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  }

  async function handleCreateTarget(e: React.FormEvent) {
    e.preventDefault();
    if (!project) return;
    setError('');
    if (!targetName.trim() || !baseUrl.trim()) {
      setError('Target name and base URL are required.'); return;
    }
    // `startsWith('https://')` is not validation — it accepts `https://` with
    // no host at all. Parse it, and let the backend's validator (which also
    // canonicalizes) have the final say.
    const urlError = describeBaseUrlProblem(baseUrl.trim());
    if (urlError) { setError(urlError); return; }
    setSaving(true);
    try {
      const input: CreateTargetInput = {
        projectId: project.id,
        name: targetName.trim(),
        targetType,
        baseUrl: baseUrl.trim(),
        repoRef: repoRef.trim() || undefined,
        stackDescription: stackDesc.trim() || undefined,
      };
      const t = await api.createTarget(input);

      // Credentials are stored against the target, so this can only happen once
      // the target exists. A rejected credential must not strand the analyst on
      // a target that was already created, so report it and continue.
      if (credKind !== 'none' && credSecret.trim()) {
        try {
          await api.setTargetCredentials({
            targetId: t.id,
            kind: credKind,
            username: credUsername.trim() || undefined,
            secret: credSecret,
            headerName: credHeaderName.trim() || undefined,
          });
        } catch (credErr) {
          setError(
            `The target was created, but the credential was not saved: ${credErr}. ` +
            `You can add it again from the scan console.`
          );
          setSaving(false);
          return;
        }
      }

      onProjectTargetReady(project, t);
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div style={{ maxWidth: 600, margin: '0 auto', padding: '40px 20px' }} className="fade-in">
      {/* Progress */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 32 }}>
        {[1, 2].map((s) => (
          <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%', display: 'flex', alignItems: 'center',
              justifyContent: 'center', fontSize: 12, fontWeight: 700,
              background: step >= s ? 'var(--cyan)' : 'var(--bg-elevated)',
              color: step >= s ? '#020817' : 'var(--text-muted)',
              border: step >= s ? 'none' : '1px solid var(--border-strong)',
              transition: 'all 0.2s',
            }}>
              {step > s ? <CheckCircle2 size={14} /> : s}
            </div>
            <span style={{ fontSize: 12, color: step >= s ? 'var(--text-primary)' : 'var(--text-muted)', fontWeight: step === s ? 600 : 400 }}>
              {s === 1 ? 'Project' : 'Target & Scope'}
            </span>
            {s < 2 && <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />}
          </div>
        ))}
      </div>

      {step === 1 && (
        <form onSubmit={handleCreateProject}>
          <SectionHeader icon={<FolderOpen size={18} />} title="New Engagement Project" subtitle="Defines the client context and report branding" />

          <FieldGroup>
            <Field label="Client / Company Name" required>
              <Input value={companyName} onChange={setCompanyName} placeholder="Acme Corporation" />
            </Field>
            <Field label="Engagement Name" required>
              <Input value={engagementName} onChange={setEngagementName} placeholder="Q3 2025 External Pentest" />
            </Field>
          </FieldGroup>

          {error && <ErrorBox msg={error} />}

          <SubmitButton loading={saving} label="Create Project & Continue →" />
        </form>
      )}

      {step === 2 && project && (
        <form onSubmit={handleCreateTarget}>
          <SectionHeader
            icon={<Globe size={18} />}
            title="Define Scan Target"
            subtitle={`Project: ${project.name} — ${project.companyName}`}
          />

          <FieldGroup>
            <Field label="Target Name" required>
              <Input value={targetName} onChange={setTargetName} placeholder="Production API Gateway" />
            </Field>

            <Field label="Target Type" required>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                {TARGET_TYPES.map((t) => {
                  const Icon = TARGET_ICONS[t];
                  return (
                    <button
                      key={t} type="button"
                      onClick={() => setTargetType(t)}
                      style={{
                        padding: '10px 8px', borderRadius: 'var(--radius-sm)',
                        border: `1px solid ${targetType === t ? 'var(--cyan)' : 'var(--border-strong)'}`,
                        background: targetType === t ? 'rgba(34,211,238,0.08)' : 'var(--bg-elevated)',
                        color: targetType === t ? 'var(--cyan)' : 'var(--text-secondary)',
                        cursor: 'pointer', fontSize: 12, fontWeight: 500,
                        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                        transition: 'all 0.15s',
                      }}
                    >
                      <Icon size={14} /> {t}
                    </button>
                  );
                })}
              </div>
            </Field>

            <Field label="Base URL" required>
              <Input
                value={baseUrl} onChange={setBaseUrl}
                placeholder="https://api.acme-corp.internal"
                mono
              />
            </Field>

            <Field label="Repository Path (for SAST/SCA)" hint="Local path or remote ref">
              <Input value={repoRef} onChange={setRepoRef} placeholder="/home/user/repos/acme-portal or github.com/acme/portal" mono />
            </Field>

            <Field label="Technology Stack (optional)" hint="Helps contextualize findings">
              <Input value={stackDesc} onChange={setStackDesc} placeholder="Node.js 18 / Express / PostgreSQL / Docker" />
            </Field>

            <CredentialsFields
              kind={credKind} setKind={setCredKind}
              username={credUsername} setUsername={setCredUsername}
              secret={credSecret} setSecret={setCredSecret}
              headerName={credHeaderName} setHeaderName={setCredHeaderName}
            />
          </FieldGroup>

          {error && <ErrorBox msg={error} />}

          <div style={{ display: 'flex', gap: 10 }}>
            <button type="button" onClick={() => setStep(1)} style={secondaryBtnStyle}>← Back</button>
            <SubmitButton loading={saving} label={<><Plus size={14} /> Add Target & Continue →</>} />
          </div>
        </form>
      )}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

const CRED_OPTIONS: { value: CredentialKind | 'none'; label: string; hint: string }[] = [
  { value: 'none',   label: 'None',          hint: 'Scan only what is reachable without signing in.' },
  { value: 'cookie', label: 'Session cookie', hint: 'Log in with your browser, copy the session cookie from DevTools → Application → Cookies, and paste it here. This is the one that works for a normal login form.' },
  { value: 'basic',  label: 'Username & password', hint: 'HTTP Basic auth — the browser popup style, not a login page.' },
  { value: 'bearer', label: 'Bearer token',  hint: 'Sent as Authorization: Bearer <token>. For APIs and JWT-based apps.' },
  { value: 'header', label: 'API key header', hint: 'Any custom header, e.g. X-API-Key.' },
];

/**
 * Credentials let the engine assess pages behind a login, which is most of an
 * application. The secret goes to the OS keychain, never to the engagement
 * database, and the engine still only issues GET, HEAD and OPTIONS — signing in
 * widens what can be read, never what can be changed.
 */
function CredentialsFields({
  kind, setKind, username, setUsername, secret, setSecret, headerName, setHeaderName,
}: {
  kind: CredentialKind | 'none';
  setKind: (v: CredentialKind | 'none') => void;
  username: string; setUsername: (v: string) => void;
  secret: string;   setSecret: (v: string) => void;
  headerName: string; setHeaderName: (v: string) => void;
}) {
  const selected = CRED_OPTIONS.find((o) => o.value === kind);

  return (
    <div style={{
      border: '1px solid var(--border-strong)', borderRadius: 'var(--radius-sm)',
      padding: 14, background: 'rgba(255,255,255,0.02)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
        <KeyRound size={14} style={{ color: 'var(--cyan)' }} />
        <span style={{
          fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)',
          letterSpacing: '0.03em', textTransform: 'uppercase',
        }}>
          Scan Credentials (optional)
        </span>
      </div>
      <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>
        Most of an application sits behind a login. Supply credentials and the engine
        assesses the authenticated pages too. Stored in your OS keychain — never in the
        engagement file, never in a report.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6, marginBottom: 10 }}>
        {CRED_OPTIONS.map((o) => (
          <button
            key={o.value} type="button"
            onClick={() => setKind(o.value)}
            style={{
              padding: '8px 6px', borderRadius: 'var(--radius-sm)',
              border: `1px solid ${kind === o.value ? 'var(--cyan)' : 'var(--border-strong)'}`,
              background: kind === o.value ? 'rgba(34,211,238,0.08)' : 'var(--bg-elevated)',
              color: kind === o.value ? 'var(--cyan)' : 'var(--text-secondary)',
              cursor: 'pointer', fontSize: 11, fontWeight: 500, transition: 'all 0.15s',
            }}
          >
            {o.label}
          </button>
        ))}
      </div>

      {selected && (
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: kind === 'none' ? 0 : 12 }}>
          {selected.hint}
        </div>
      )}

      {kind === 'basic' && (
        <Field label="Username" required>
          <Input value={username} onChange={setUsername} placeholder="admin" />
        </Field>
      )}

      {kind === 'header' && (
        <Field label="Header Name" hint="Defaults to X-API-Key">
          <Input value={headerName} onChange={setHeaderName} placeholder="X-API-Key" mono />
        </Field>
      )}

      {kind !== 'none' && (
        <div style={{ marginTop: kind === 'basic' || kind === 'header' ? 12 : 0 }}>
          <Field
            label={
              kind === 'basic'  ? 'Password' :
              kind === 'bearer' ? 'Token' :
              kind === 'cookie' ? 'Cookie' : 'API Key'
            }
            required
          >
            <Input
              value={secret} onChange={setSecret}
              placeholder={kind === 'cookie' ? 'session=abc123; csrf=xyz' : '••••••••'}
              mono={kind !== 'basic'}
              secret={kind === 'basic'}
            />
          </Field>
        </div>
      )}
    </div>
  );
}

function SectionHeader({ icon, title, subtitle }: { icon: React.ReactNode; title: string; subtitle: string }) {
  return (
    <div style={{ marginBottom: 28 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
        <div style={{ color: 'var(--cyan)' }}>{icon}</div>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>{title}</h2>
      </div>
      <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>{subtitle}</p>
    </div>
  );
}

function FieldGroup({ children }: { children: React.ReactNode }) {
  return <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginBottom: 24 }}>{children}</div>;
}

function Field({ label, children, required, hint }: { label: string; children: React.ReactNode; required?: boolean; hint?: string }) {
  return (
    <div>
      <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6, letterSpacing: '0.03em', textTransform: 'uppercase' }}>
        {label} {required && <span style={{ color: 'var(--red)' }}>*</span>}
      </label>
      {children}
      {hint && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{hint}</div>}
    </div>
  );
}

function Input({ value, onChange, placeholder, mono, secret }: { value: string; onChange: (v: string) => void; placeholder?: string; mono?: boolean; secret?: boolean }) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      type={secret ? 'password' : 'text'}
      autoComplete={secret ? 'new-password' : undefined}
      style={{
        width: '100%', padding: '9px 12px',
        background: 'var(--bg-elevated)', border: '1px solid var(--border-strong)',
        borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)',
        fontSize: mono ? 12 : 13, fontFamily: mono ? "'JetBrains Mono', monospace" : 'inherit',
        outline: 'none', transition: 'border-color 0.15s',
      }}
      onFocus={(e) => { e.currentTarget.style.borderColor = 'var(--cyan-dim)'; }}
      onBlur={(e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.13)'; }}
    />
  );
}

function ErrorBox({ msg }: { msg: string }) {
  return (
    <div style={{
      padding: '10px 14px', marginBottom: 16,
      background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
      borderRadius: 'var(--radius-sm)', color: '#fca5a5', fontSize: 12,
    }}>
      {msg}
    </div>
  );
}

function SubmitButton({ loading, label }: { loading: boolean; label: React.ReactNode }) {
  return (
    <button
      type="submit" disabled={loading}
      style={{
        width: '100%', padding: '11px 20px',
        background: loading ? 'var(--bg-elevated)' : 'var(--cyan)',
        color: loading ? 'var(--text-muted)' : '#020817',
        border: 'none', borderRadius: 'var(--radius-sm)',
        fontWeight: 700, fontSize: 13, cursor: loading ? 'not-allowed' : 'pointer',
        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
        transition: 'all 0.15s',
      }}
    >
      {loading ? 'Saving...' : label}
    </button>
  );
}

const secondaryBtnStyle: React.CSSProperties = {
  padding: '11px 18px', background: 'var(--bg-elevated)',
  border: '1px solid var(--border-strong)', color: 'var(--text-secondary)',
  borderRadius: 'var(--radius-sm)', cursor: 'pointer', fontSize: 13, fontWeight: 500,
};
