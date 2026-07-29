import { useState } from 'react';
import { ShieldCheck, AlertTriangle, Lock, FileSignature, ChevronDown, ChevronUp } from 'lucide-react';
import type { Target, AuthorizationRecord, ScopeDefinition, CreateRoEInput } from '../types';
import { api } from '../lib/tauri';

interface Props {
  target: Target;
  onRoESigned: (record: AuthorizationRecord) => void;
}

const DEFAULT_SCOPE: ScopeDefinition = {
  allowedDomains: [],
  allowedIpsCidrs: [],
  outOfScopePaths: [],
  rateLimitRps: 5,
  prohibitedActions: ['DoS', 'Destructive payloads', 'Data exfiltration beyond evidence captures'],
};

export function AuthGateScreen({ target, onRoESigned }: Props) {
  const [scope, setScope] = useState<ScopeDefinition>({ ...DEFAULT_SCOPE });
  const [reviewerName, setReviewerName]   = useState('');
  const [domainInput, setDomainInput]     = useState('');
  const [ipInput, setIpInput]             = useState('');
  const [pathInput, setPathInput]         = useState('');
  const [roeText, setRoeText]             = useState(generateDefaultRoE(target));
  const [checklist, setChecklist]         = useState({ c1: false, c2: false, c3: false, c4: false });
  const [showRoeDoc, setShowRoeDoc]       = useState(false);
  const [saving, setSaving]               = useState(false);
  const [error, setError]                 = useState('');

  const allChecked = Object.values(checklist).every(Boolean);
  const canSign = allChecked && reviewerName.trim() && scope.allowedDomains.length > 0;

  function addDomain() {
    const d = domainInput.trim().replace(/^https?:\/\//, '');
    if (d && !scope.allowedDomains.includes(d)) {
      setScope(s => ({ ...s, allowedDomains: [...s.allowedDomains, d] }));
      setDomainInput('');
    }
  }

  function addIp() {
    const ip = ipInput.trim();
    if (ip && !scope.allowedIpsCidrs.includes(ip)) {
      setScope(s => ({ ...s, allowedIpsCidrs: [...s.allowedIpsCidrs, ip] }));
      setIpInput('');
    }
  }

  function addPath() {
    const p = pathInput.trim();
    if (p && !scope.outOfScopePaths.includes(p)) {
      setScope(s => ({ ...s, outOfScopePaths: [...s.outOfScopePaths, p] }));
      setPathInput('');
    }
  }

  async function handleSign(e: React.FormEvent) {
    e.preventDefault();
    if (!canSign) return;
    setError('');
    setSaving(true);
    try {
      const input: CreateRoEInput = {
        targetId: target.id,
        scope,
        acknowledgedBy: reviewerName.trim(),
        roeDocumentText: roeText,
      };
      const record = await api.createScopeAndRoe(input);
      onRoESigned(record);
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div style={{ maxWidth: 680, margin: '0 auto', padding: '32px 20px' }} className="fade-in">
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8,
        padding: '14px 18px',
        background: 'rgba(251,191,36,0.06)', border: '1px solid rgba(251,191,36,0.2)',
        borderRadius: 'var(--radius)',
      }}>
        <AlertTriangle size={20} style={{ color: 'var(--amber)', flexShrink: 0 }} />
        <div>
          <div style={{ fontWeight: 700, color: 'var(--amber)', fontSize: 13 }}>Authorization Gate — Mandatory Before Any Dynamic Scan</div>
          <div style={{ color: 'var(--text-secondary)', fontSize: 12, marginTop: 2 }}>
            DAST capabilities are locked until a signed Rules of Engagement is stored. This action writes to the tamper-evident audit ledger.
          </div>
        </div>
      </div>

      <form onSubmit={handleSign} style={{ marginTop: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Target summary */}
        <Section title="Engagement Target">
          <InfoRow label="Target Name" value={target.name} />
          <InfoRow label="Base URL" value={target.baseUrl} mono />
          <InfoRow label="Type" value={target.targetType} />
        </Section>

        {/* Scope definition */}
        <Section title="Scope Definition">
          <TagInput
            label="Allowed Domains" required
            tags={scope.allowedDomains}
            input={domainInput} setInput={setDomainInput}
            onAdd={addDomain}
            onRemove={(d) => setScope(s => ({ ...s, allowedDomains: s.allowedDomains.filter(x => x !== d) }))}
            placeholder="portal.acme-corp.internal"
          />
          <TagInput
            label="Allowed IPs / CIDRs"
            tags={scope.allowedIpsCidrs}
            input={ipInput} setInput={setIpInput}
            onAdd={addIp}
            onRemove={(ip) => setScope(s => ({ ...s, allowedIpsCidrs: s.allowedIpsCidrs.filter(x => x !== ip) }))}
            placeholder="10.0.0.0/16"
          />
          <TagInput
            label="Out-of-Scope Paths"
            tags={scope.outOfScopePaths}
            input={pathInput} setInput={setPathInput}
            onAdd={addPath}
            onRemove={(p) => setScope(s => ({ ...s, outOfScopePaths: s.outOfScopePaths.filter(x => x !== p) }))}
            placeholder="/admin/danger"
          />
          <div>
            <label style={labelStyle}>Rate Limit (req/sec) — Max: {scope.rateLimitRps}</label>
            <input
              type="range" min={1} max={20} value={scope.rateLimitRps}
              onChange={(e) => setScope(s => ({ ...s, rateLimitRps: Number(e.target.value) }))}
              style={{ width: '100%', accentColor: 'var(--cyan)' }}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
              <span>1 rps (safest)</span><span style={{ color: 'var(--cyan)', fontWeight: 600 }}>{scope.rateLimitRps} rps</span><span>20 rps</span>
            </div>
          </div>
        </Section>

        {/* RoE Document */}
        <Section title="Rules of Engagement Document">
          <button
            type="button"
            onClick={() => setShowRoeDoc(v => !v)}
            style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'none', border: 'none', color: 'var(--cyan)', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}
          >
            <FileSignature size={14} />
            {showRoeDoc ? 'Collapse' : 'Review RoE Document'}
            {showRoeDoc ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
          {showRoeDoc && (
            <textarea
              value={roeText}
              onChange={(e) => setRoeText(e.target.value)}
              rows={10}
              style={{
                width: '100%', marginTop: 10, padding: '10px 12px',
                background: 'var(--bg-base)', border: '1px solid var(--border-strong)',
                borderRadius: 'var(--radius-sm)', color: 'var(--text-secondary)',
                fontFamily: "'JetBrains Mono', monospace", fontSize: 11, resize: 'vertical',
                outline: 'none',
              }}
            />
          )}
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
            <Lock size={10} style={{ display: 'inline', marginRight: 4 }} />
            Only the SHA-256 hash of this document is stored. The plaintext is never persisted.
          </div>
        </Section>

        {/* Attestation checklist */}
        <Section title="Attestation Checklist">
          {[
            { key: 'c1', text: 'I have written authorization from the system owner to perform security testing on the defined scope.' },
            { key: 'c2', text: 'I will NOT test URLs, IPs, or paths outside the explicitly defined in-scope list above.' },
            { key: 'c3', text: 'I will NOT perform denial-of-service, destructive, or data-exfiltrating actions.' },
            { key: 'c4', text: 'I understand that this acknowledgement is recorded in a tamper-evident, hash-chained audit ledger.' },
          ].map(({ key, text }) => (
            <label key={key} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer', marginBottom: 10 }}>
              <input
                type="checkbox"
                checked={checklist[key as keyof typeof checklist]}
                onChange={(e) => setChecklist(c => ({ ...c, [key]: e.target.checked }))}
                style={{ marginTop: 2, accentColor: 'var(--emerald)', width: 15, height: 15, flexShrink: 0 }}
              />
              <span style={{ color: 'var(--text-secondary)', fontSize: 12, lineHeight: 1.5 }}>{text}</span>
            </label>
          ))}
        </Section>

        {/* Reviewer signature */}
        <Section title="Reviewer / Lead Analyst">
          <input
            value={reviewerName}
            onChange={(e) => setReviewerName(e.target.value)}
            placeholder="Full name of the lead analyst signing this RoE"
            style={{
              width: '100%', padding: '10px 12px',
              background: 'var(--bg-elevated)', border: '1px solid var(--border-strong)',
              borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)',
              fontSize: 13, outline: 'none',
            }}
          />
        </Section>

        {error && (
          <div style={{ padding: '10px 14px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 'var(--radius-sm)', color: '#fca5a5', fontSize: 12 }}>
            {error}
          </div>
        )}

        <button
          type="submit" disabled={!canSign || saving}
          style={{
            padding: '13px 24px', borderRadius: 'var(--radius-sm)', border: 'none',
            background: canSign && !saving ? 'linear-gradient(135deg, #059669, #0d9488)' : 'var(--bg-elevated)',
            color: canSign && !saving ? 'white' : 'var(--text-muted)',
            fontWeight: 700, fontSize: 14, cursor: canSign && !saving ? 'pointer' : 'not-allowed',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
            transition: 'all 0.2s',
            boxShadow: canSign && !saving ? '0 4px 20px rgba(5,150,105,0.25)' : 'none',
          }}
        >
          <ShieldCheck size={18} />
          {saving ? 'Signing & Committing to Audit Ledger...' : 'Sign Rules of Engagement & Unlock Scan Engine'}
        </button>

        {!canSign && (
          <p style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 11 }}>
            Complete all checklist items, add ≥1 allowed domain, and enter reviewer name to sign.
          </p>
        )}
      </form>
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="card" style={{ padding: '18px 20px' }}>
      <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 14 }}>
        {title}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>{children}</div>
    </div>
  );
}

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>{label}</span>
      <span style={{ color: 'var(--text-primary)', fontSize: 12, fontFamily: mono ? "'JetBrains Mono', monospace" : 'inherit', fontWeight: 500 }}>{value}</span>
    </div>
  );
}

function TagInput({ label, required, tags, input, setInput, onAdd, onRemove, placeholder }: {
  label: string; required?: boolean; tags: string[]; input: string;
  setInput: (v: string) => void; onAdd: () => void; onRemove: (v: string) => void; placeholder?: string;
}) {
  return (
    <div>
      <label style={labelStyle}>{label} {required && <span style={{ color: 'var(--red)' }}>*</span>}</label>
      <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
        <input
          value={input} onChange={(e) => setInput(e.target.value)}
          placeholder={placeholder}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); onAdd(); } }}
          style={{
            flex: 1, padding: '7px 10px', background: 'var(--bg-base)',
            border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
            color: 'var(--text-primary)', fontSize: 12, fontFamily: "'JetBrains Mono', monospace",
            outline: 'none',
          }}
        />
        <button type="button" onClick={onAdd} style={{ padding: '7px 14px', background: 'var(--bg-elevated)', border: '1px solid var(--border-strong)', borderRadius: 'var(--radius-sm)', color: 'var(--cyan)', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
          Add
        </button>
      </div>
      {tags.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {tags.map((t) => (
            <span key={t} style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              padding: '3px 10px', borderRadius: 99,
              background: 'rgba(34,211,238,0.08)', border: '1px solid rgba(34,211,238,0.2)',
              color: 'var(--cyan)', fontSize: 11, fontFamily: "'JetBrains Mono', monospace",
            }}>
              {t}
              <button type="button" onClick={() => onRemove(t)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', lineHeight: 1, padding: 0, opacity: 0.6 }}>×</button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

const labelStyle: React.CSSProperties = {
  display: 'block', fontSize: 11, fontWeight: 600,
  color: 'var(--text-muted)', marginBottom: 6,
  letterSpacing: '0.05em', textTransform: 'uppercase',
};

function generateDefaultRoE(target: Target): string {
  return `RULES OF ENGAGEMENT
══════════════════

Engagement: Security Assessment
Target: ${target.name} (${target.baseUrl})
Date: ${new Date().toISOString().split('T')[0]}
Tool: SentinelVAPT Workbench (local-first, offline, defensive)

AUTHORIZED ACTIVITIES
─────────────────────
• Automated static analysis (SAST/SCA/secrets) on the project source repository
• Dynamic application scanning (DAST) limited to domains/IPs defined in the scope
• Passive reconnaissance and traffic interception

PROHIBITED ACTIVITIES
─────────────────────
• Denial-of-service or availability-impacting tests
• Data exfiltration beyond minimum proof-of-concept captures
• Modification or deletion of production data
• Testing systems outside defined scope
• Social engineering or physical security tests

SAFETY CONSTRAINTS
──────────────────
• Rate limiting: enforced per RoE record (configurable above)
• All scan actions logged to tamper-evident hash-chained ledger
• Credentials stored only in OS keychain — never in DB, logs, or reports
• Non-destructive DAST defaults only

ACKNOWLEDGEMENT
───────────────
The undersigned analyst confirms they have written authorization from the
system owner to perform this assessment and will operate within the above constraints.
`;
}
