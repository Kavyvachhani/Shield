import { useState } from 'react';
import { FolderOpen, Globe, Code2, Cpu, ChevronRight, Plus, CheckCircle2 } from 'lucide-react';
import type { Project, Target, CreateProjectInput, CreateTargetInput } from '../types';
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
    if (!baseUrl.startsWith('http://') && !baseUrl.startsWith('https://')) {
      setError('Base URL must start with http:// or https://'); return;
    }
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

function Input({ value, onChange, placeholder, mono }: { value: string; onChange: (v: string) => void; placeholder?: string; mono?: boolean }) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
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
