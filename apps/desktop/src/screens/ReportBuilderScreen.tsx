import { useEffect, useState } from 'react';
import { Download, Eye, Loader2, FileText } from 'lucide-react';
import type { GenerateReportInput, GenerateReportOutput, Project, ReportType } from '../types';
import { api } from '../lib/tauri';

interface Props {
  project: Project;
  scanId: string;
  targetName: string;
  targetUrl?: string;
}

interface ReportOption {
  value: ReportType;
  label: string;
  audience: string;
  desc: string;
  icon: string;
}

const REPORT_OPTIONS: ReportOption[] = [
  {
    value: 'client',
    label: 'Client Report',
    audience: 'For the business',
    desc: 'Posture score, plain-language risks, remediation roadmap, compliance alignment, and the full coverage matrix showing every check performed — including the ones that passed.',
    icon: '📊',
  },
  {
    value: 'developer',
    label: 'Developer Report',
    audience: 'For the engineers',
    desc: 'One section per finding: exact location, CVSS 4.0 vector, CWE/OWASP/WSTG mapping, reproduction steps, sanitized evidence, the fix, and how to verify it.',
    icon: '🔧',
  },
  {
    value: 'markdown',
    label: 'Markdown Export',
    audience: 'For your tracker',
    desc: 'The developer report as Markdown, one heading per finding — paste straight into Jira, Linear or a GitHub issue.',
    icon: '📝',
  },
  {
    value: 'sarif',
    label: 'SARIF 2.1.0',
    audience: 'For CI/CD',
    desc: 'Machine-readable results for GitHub code scanning, Azure DevOps and any SARIF-consuming pipeline.',
    icon: '⚙️',
  },
  {
    value: 'json',
    label: 'Full JSON Export',
    audience: 'For archival',
    desc: 'Complete assessment data: engagement metadata, every finding, and the coverage matrix.',
    icon: '🗄️',
  },
];

export function ReportBuilderScreen({ project, scanId, targetName, targetUrl }: Props) {
  const [reportType, setReportType] = useState<ReportType>('client');
  const [companyName, setCompanyName] = useState(project.companyName);
  const [analyst, setAnalyst] = useState('');
  const [generating, setGenerating] = useState(false);
  const [report, setReport] = useState<GenerateReportOutput | null>(null);
  const [preview, setPreview] = useState(false);
  const [exportDir, setExportDir] = useState('');
  const [exporting, setExporting] = useState(false);
  const [exportMsg, setExportMsg] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    api.defaultExportDir().then(setExportDir).catch(() => setExportDir(''));
  }, []);

  // A newly chosen report type invalidates whatever was generated before.
  useEffect(() => {
    setReport(null);
    setPreview(false);
    setExportMsg('');
  }, [reportType]);

  const isHtml = report?.contentType === 'text/html';

  async function generate() {
    setError('');
    setReport(null);
    setPreview(false);
    setExportMsg('');
    setGenerating(true);
    try {
      const input: GenerateReportInput = {
        scanId,
        reportType,
        companyName: companyName.trim() || project.companyName,
        targetName,
        targetUrl,
        analyst: analyst.trim() || undefined,
      };
      setReport(await api.generateReport(input));
    } catch (err) {
      setError(String(err));
    } finally {
      setGenerating(false);
    }
  }

  async function saveToDisk() {
    if (!report) return;
    setExporting(true);
    setExportMsg('');
    setError('');
    try {
      const separator = exportDir.includes('\\') ? '\\' : '/';
      const path = exportDir
        ? `${exportDir.replace(/[\\/]+$/, '')}${separator}${report.suggestedFilename}`
        : report.suggestedFilename;
      setExportMsg(await api.exportReport(report.reportId, path));
    } catch (err) {
      setError(String(err));
    } finally {
      setExporting(false);
    }
  }

  return (
    <div
      className="fade-in"
      style={{ padding: '24px 28px', display: 'flex', gap: 24, height: '100%', overflow: 'hidden' }}
    >
      <div style={{ flex: '0 0 360px', display: 'flex', flexDirection: 'column', gap: 20, overflow: 'auto' }}>
        <div>
          <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>Report Builder</h2>
          <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>
            Two deliverables from one assessment — one for the client, one for the engineers.
          </div>
        </div>

        <Section title="Deliverable">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {REPORT_OPTIONS.map((o) => {
              const selected = reportType === o.value;
              return (
                <button
                  key={o.value}
                  type="button"
                  onClick={() => setReportType(o.value)}
                  style={{
                    padding: '12px 14px',
                    borderRadius: 'var(--radius-sm)',
                    cursor: 'pointer',
                    textAlign: 'left',
                    border: `1px solid ${selected ? 'rgba(34,211,238,0.4)' : 'var(--border-strong)'}`,
                    background: selected ? 'rgba(34,211,238,0.06)' : 'var(--bg-elevated)',
                    transition: 'all 0.15s',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span aria-hidden="true">{o.icon}</span>
                    <span style={{ fontWeight: 600, fontSize: 13 }}>{o.label}</span>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                      {o.audience}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>{o.desc}</div>
                </button>
              );
            })}
          </div>
        </Section>

        <Section title="Branding & Attribution">
          <Field label="Client name">
            <input
              value={companyName}
              onChange={(e) => setCompanyName(e.target.value)}
              placeholder={project.companyName}
              style={inputStyle}
            />
          </Field>
          <Field label="Assessed by (optional)">
            <input
              value={analyst}
              onChange={(e) => setAnalyst(e.target.value)}
              placeholder="Your name or team"
              style={inputStyle}
            />
          </Field>
        </Section>

        <button
          type="button"
          onClick={generate}
          disabled={generating}
          style={{
            ...primaryButton,
            opacity: generating ? 0.6 : 1,
            cursor: generating ? 'wait' : 'pointer',
          }}
        >
          {generating ? <Loader2 size={15} className="spin" /> : <FileText size={15} />}
          {generating ? 'Generating…' : 'Generate report'}
        </button>

        {report && (
          <Section title="Export">
            <Field label="Destination folder">
              <input
                value={exportDir}
                onChange={(e) => setExportDir(e.target.value)}
                placeholder="Folder to save into"
                style={inputStyle}
              />
            </Field>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
              Saves as <code>{report.suggestedFilename}</code>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="button"
                onClick={saveToDisk}
                disabled={exporting}
                style={{ ...primaryButton, flex: 1, opacity: exporting ? 0.6 : 1 }}
              >
                {exporting ? <Loader2 size={15} className="spin" /> : <Download size={15} />}
                Save
              </button>
              {isHtml && (
                <button
                  type="button"
                  onClick={() => setPreview((p) => !p)}
                  style={{ ...secondaryButton, flex: 1 }}
                >
                  <Eye size={15} />
                  {preview ? 'Hide' : 'Preview'}
                </button>
              )}
            </div>
            {isHtml && (
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 10, lineHeight: 1.6 }}>
                To produce a PDF, open the saved HTML file in your browser and choose
                Print → Save as PDF. The report is styled for A4 with page breaks already set.
              </div>
            )}
          </Section>
        )}

        {exportMsg && <Notice tone="ok">{exportMsg}</Notice>}
        {error && <Notice tone="error">{error}</Notice>}
      </div>

      <div
        style={{
          flex: 1,
          minWidth: 0,
          border: '1px solid var(--border-strong)',
          borderRadius: 'var(--radius-sm)',
          background: 'var(--bg-elevated)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {!report && (
          <Placeholder>
            Choose a deliverable and select <strong>Generate report</strong> to see it here.
          </Placeholder>
        )}

        {report && !isHtml && (
          <pre
            style={{
              margin: 0,
              padding: 18,
              overflow: 'auto',
              fontSize: 11,
              lineHeight: 1.6,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
            }}
          >
            {report.content}
          </pre>
        )}

        {report && isHtml && !preview && (
          <Placeholder>
            {report.findingCount} finding{report.findingCount === 1 ? '' : 's'} included.
            Select <strong>Preview</strong> to render the report, or <strong>Save</strong> to write it to disk.
          </Placeholder>
        )}

        {report && isHtml && preview && (
          // The report is rendered in a sandboxed frame with no allow-scripts:
          // report content is derived from the assessed target and must never
          // execute inside the application.
          <iframe
            title="Report preview"
            sandbox=""
            srcDoc={report.content}
            style={{ border: 'none', width: '100%', height: '100%', background: '#fff' }}
          />
        )}
      </div>
    </div>
  );
}

// ── Small presentational helpers ─────────────────────────────────────────────

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '8px 10px',
  borderRadius: 'var(--radius-sm)',
  border: '1px solid var(--border-strong)',
  background: 'var(--bg-base)',
  color: 'inherit',
  fontSize: 12,
};

const primaryButton: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  gap: 8,
  padding: '10px 14px',
  borderRadius: 'var(--radius-sm)',
  border: '1px solid rgba(34,211,238,0.4)',
  background: 'rgba(34,211,238,0.12)',
  color: 'inherit',
  fontSize: 13,
  fontWeight: 600,
  cursor: 'pointer',
};

const secondaryButton: React.CSSProperties = {
  ...primaryButton,
  border: '1px solid var(--border-strong)',
  background: 'var(--bg-elevated)',
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div
        style={{
          fontSize: 10,
          fontWeight: 700,
          letterSpacing: 0.8,
          textTransform: 'uppercase',
          color: 'var(--text-muted)',
          marginBottom: 8,
        }}
      >
        {title}
      </div>
      {children}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label style={{ display: 'block', marginBottom: 10 }}>
      <span style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
        {label}
      </span>
      {children}
    </label>
  );
}

function Notice({ tone, children }: { tone: 'ok' | 'error'; children: React.ReactNode }) {
  const ok = tone === 'ok';
  return (
    <div
      role={ok ? 'status' : 'alert'}
      style={{
        padding: '10px 12px',
        borderRadius: 'var(--radius-sm)',
        fontSize: 11,
        lineHeight: 1.6,
        wordBreak: 'break-word',
        border: `1px solid ${ok ? 'rgba(22,163,74,0.4)' : 'rgba(220,38,38,0.4)'}`,
        background: ok ? 'rgba(22,163,74,0.08)' : 'rgba(220,38,38,0.08)',
      }}
    >
      {children}
    </div>
  );
}

function Placeholder({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        flex: 1,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 40,
        textAlign: 'center',
        fontSize: 12,
        lineHeight: 1.7,
        color: 'var(--text-muted)',
      }}
    >
      <div style={{ maxWidth: 380 }}>{children}</div>
    </div>
  );
}
