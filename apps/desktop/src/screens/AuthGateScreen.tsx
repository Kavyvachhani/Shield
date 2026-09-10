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
    <div className="page fade-in" style={{ maxWidth: 680, margin: '0 auto' }}>
      <div className="callout callout-warning">
        <AlertTriangle size={20} />
        <div>
          <div style={{ fontWeight: 700 }}>Authorization Gate — mandatory before any dynamic scan</div>
          <div style={{ color: 'var(--text-secondary)', marginTop: 2 }}>
            DAST capabilities are locked until a signed Rules of Engagement is stored. This action
            writes to the tamper-evident audit ledger.
          </div>
        </div>
      </div>

      <form onSubmit={handleSign} className="col" style={{ marginTop: 'var(--s-6)', gap: 'var(--s-5)' }}>
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
            <label className="label" htmlFor="rate-limit">Rate limit (req/sec) — max: {scope.rateLimitRps}</label>
            <input
              type="range" min={1} max={20} value={scope.rateLimitRps}
              onChange={(e) => setScope(s => ({ ...s, rateLimitRps: Number(e.target.value) }))}
              id="rate-limit"
              style={{ width: '100%', accentColor: 'var(--accent)' }}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
              <span>1 rps (safest)</span><span style={{ color: 'var(--accent)', fontWeight: 600 }}>{scope.rateLimitRps} rps</span><span>20 rps</span>
            </div>
          </div>
        </Section>

        {/* RoE Document */}
        <Section title="Rules of Engagement Document">
          <button
            type="button"
            onClick={() => setShowRoeDoc(v => !v)}
            className="btn btn-ghost btn-sm"
            style={{ color: 'var(--accent)' }}
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
              className="textarea input-mono"
              style={{ marginTop: 'var(--s-2)' }}
              aria-label="Rules of Engagement document"
            />
          )}
          <div className="hint row" style={{ gap: 4, marginTop: 'var(--s-1)' }}>
            <Lock size={10} />
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
            <label
              key={key}
              className={`checkline ${checklist[key as keyof typeof checklist] ? 'checkline-on' : ''}`}
              style={{ alignItems: 'flex-start' }}
            >
              <input
                type="checkbox"
                checked={checklist[key as keyof typeof checklist]}
                onChange={(e) => setChecklist(c => ({ ...c, [key]: e.target.checked }))}
                style={{ marginTop: 2 }}
              />
              <span>{text}</span>
            </label>
          ))}
        </Section>

        {/* Reviewer signature */}
        <Section title="Reviewer / Lead Analyst">
          <input
            value={reviewerName}
            onChange={(e) => setReviewerName(e.target.value)}
            placeholder="Full name of the lead analyst signing this RoE"
            className="input"
            aria-label="Reviewer name"
          />
        </Section>

        {error && (
          <div className="callout callout-danger"><span>{error}</span></div>
        )}

        <button type="submit" className="btn btn-primary btn-lg btn-block" disabled={!canSign || saving}>
          <ShieldCheck size={18} />
          {saving ? 'Signing and committing to the audit ledger…' : 'Sign Rules of Engagement and unlock the scan engine'}
        </button>

        {!canSign && (
          <p className="hint" style={{ textAlign: 'center' }}>
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
    <div className="card">
      <div className="label" style={{ marginBottom: 'var(--s-4)' }}>
        {title}
      </div>
      <div className="col" style={{ gap: 'var(--s-3)' }}>{children}</div>
    </div>
  );
}

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="between">
      <span className="dim">{label}</span>
      <span className={mono ? 'mono' : ''} style={{ fontWeight: 500 }}>{value}</span>
    </div>
  );
}

function TagInput({ label, required, tags, input, setInput, onAdd, onRemove, placeholder }: {
  label: string; required?: boolean; tags: string[]; input: string;
  setInput: (v: string) => void; onAdd: () => void; onRemove: (v: string) => void; placeholder?: string;
}) {
  return (
    <div>
      <label className="label">{label} {required && <span style={{ color: 'var(--danger)' }}>*</span>}</label>
      <div className="row" style={{ marginBottom: 'var(--s-2)', gap: 'var(--s-2)' }}>
        <input
          value={input} onChange={(e) => setInput(e.target.value)}
          placeholder={placeholder}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); onAdd(); } }}
          className="input input-mono grow"
          aria-label={label}
        />
        <button type="button" className="btn" onClick={onAdd}>Add</button>
      </div>
      {tags.length > 0 && (
        <div className="row wrap" style={{ gap: 'var(--s-1)' }}>
          {tags.map((t) => (
            <span key={t} className="badge badge-accent mono">
              {t}
              <button
                type="button"
                onClick={() => onRemove(t)}
                aria-label={`Remove ${t}`}
                style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', lineHeight: 1, padding: 0, opacity: 0.6 }}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

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
