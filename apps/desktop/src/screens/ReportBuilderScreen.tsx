import { useState } from 'react';
import { FileText, Download, Eye, Building2, Palette, Loader2 } from 'lucide-react';
import type { Project, GenerateReportInput, GenerateReportOutput } from '../types';
import { api } from '../lib/tauri';

interface Props {
  project: Project;
  scanId: string;
  targetName: string;
}

type Audience = 'executive' | 'developer' | 'sarif';

const AUDIENCE_OPTS: { value: Audience; label: string; desc: string; icon: string }[] = [
  { value: 'executive', label: 'Executive / Client Summary', desc: 'Business-language, ≤4 pages, severity heatmap, compliance snapshot. No CVSS vectors.', icon: '📊' },
  { value: 'developer', label: 'Developer Remediation Guide', desc: 'Full technical detail: CVSS4 vectors, CWE/OWASP/WSTG IDs, repro steps, code fixes.', icon: '🔧' },
  { value: 'sarif', label: 'SARIF 2.1.0 JSON', desc: 'Machine-readable for CI/CD integration, GitHub Advanced Security, and toolchain import.', icon: '⚙️' },
];

export function ReportBuilderScreen({ project, scanId, targetName }: Props) {
  const [audience, setAudience]       = useState<Audience>('executive');
  const [companyName, setCompanyName] = useState(project.companyName);
  const [primaryColor, setPrimaryColor] = useState(project.primaryColor ?? '#22d3ee');
  const [generating, setGenerating]   = useState(false);
  const [report, setReport]           = useState<GenerateReportOutput | null>(null);
  const [preview, setPreview]         = useState(false);
  const [exporting, setExporting]     = useState(false);
  const [exportMsg, setExportMsg]     = useState('');
  const [error, setError]             = useState('');

  async function generate() {
    setError(''); setReport(null); setPreview(false);
    setGenerating(true);
    try {
      const input: GenerateReportInput = {
        scanId,
        reportType: audience,
        companyName: companyName.trim() || project.companyName,
        targetName,
        logoPath: project.logoPath,
      };
      const out = await api.generateReport(input);
      setReport(out);
    } catch (err) { setError(String(err)); }
    finally { setGenerating(false); }
  }

  async function exportReport(format: string) {
    if (!report) return;
    setExporting(true); setExportMsg('');
    const ext = format === 'json' ? '.json' : format === 'sarif' ? '.sarif' : '.html';
    const filename = `SentinelVAPT_${audience}_${Date.now()}${ext}`;
    // In a real Tauri app we'd use dialog.save() — for now use a known path
    const exportPath = `/tmp/${filename}`;
    try {
      const msg = await api.exportReport(report.reportId, exportPath, format);
      setExportMsg(msg);
    } catch (err) { setError(String(err)); }
    finally { setExporting(false); }
  }

  return (
    <div style={{ padding: '24px 28px', display: 'flex', gap: 24, height: '100%', overflow: 'hidden' }} className="fade-in">
      {/* LEFT: Builder controls */}
      <div style={{ flex: '0 0 340px', display: 'flex', flexDirection: 'column', gap: 20, overflow: 'auto' }}>
        <div>
          <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>Report Builder</h2>
          <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>Generate branded deliverables from the scan findings</div>
        </div>

        {/* Audience selector */}
        <BuilderSection title="Report Audience">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {AUDIENCE_OPTS.map((o) => (
              <button key={o.value} type="button" onClick={() => setAudience(o.value)} style={{
                padding: '12px 14px', borderRadius: 'var(--radius-sm)', cursor: 'pointer', textAlign: 'left',
                border: `1px solid ${audience === o.value ? 'rgba(34,211,238,0.4)' : 'var(--border-strong)'}`,
                background: audience === o.value ? 'rgba(34,211,238,0.06)' : 'var(--bg-elevated)',
                transition: 'all 0.15s',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 16 }}>{o.icon}</span>
                  <span style={{ fontWeight: 700, fontSize: 13, color: audience === o.value ? 'var(--cyan)' : 'var(--text-primary)' }}>{o.label}</span>
                </div>
                <p style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>{o.desc}</p>
              </button>
            ))}
          </div>
        </BuilderSection>

        {/* Branding */}
        {audience !== 'sarif' && (
          <BuilderSection title="Branding">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={labelStyle}><Building2 size={11} style={{ display: 'inline', marginRight: 4 }} /> Client Name</label>
                <input value={companyName} onChange={(e) => setCompanyName(e.target.value)}
                  style={inputStyle} placeholder={project.companyName} />
              </div>
              <div>
                <label style={labelStyle}><Palette size={11} style={{ display: 'inline', marginRight: 4 }} /> Brand Accent Color</label>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <input type="color" value={primaryColor} onChange={(e) => setPrimaryColor(e.target.value)}
                    style={{ width: 36, height: 36, border: '1px solid var(--border-strong)', borderRadius: 'var(--radius-sm)', padding: 3, background: 'var(--bg-elevated)', cursor: 'pointer' }} />
                  <input value={primaryColor} onChange={(e) => setPrimaryColor(e.target.value)}
                    style={{ ...inputStyle, fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }} />
                </div>
              </div>
            </div>
          </BuilderSection>
        )}

        {error && (
          <div style={{ padding: '10px 14px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 'var(--radius-sm)', color: '#fca5a5', fontSize: 12 }}>
            {error}
          </div>
        )}

        <button
          onClick={generate} disabled={generating}
          style={{ padding: '13px 20px', background: generating ? 'var(--bg-elevated)' : 'var(--cyan)', color: generating ? 'var(--text-muted)' : '#020817', border: 'none', borderRadius: 'var(--radius-sm)', fontWeight: 700, fontSize: 14, cursor: generating ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, transition: 'all 0.15s', boxShadow: generating ? 'none' : '0 4px 16px rgba(34,211,238,0.2)' }}
        >
          {generating ? <><Loader2 size={16} className="pulse" /> Generating...</> : <><FileText size={16} /> Generate Report</>}
        </button>

        {/* Export actions */}
        {report && (
          <BuilderSection title="Export">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {audience === 'sarif' ? (
                <ExportBtn label="Export SARIF JSON" format="json" onExport={exportReport} loading={exporting} />
              ) : (
                <>
                  <ExportBtn label="Export HTML" format="html" onExport={exportReport} loading={exporting} />
                  <ExportBtn label="Export JSON" format="json" onExport={exportReport} loading={exporting} />
                </>
              )}
              {exportMsg && (
                <div style={{ padding: '8px 12px', background: 'rgba(52,211,153,0.1)', border: '1px solid rgba(52,211,153,0.2)', borderRadius: 'var(--radius-sm)', color: 'var(--emerald)', fontSize: 11 }}>
                  ✓ {exportMsg}
                </div>
              )}
            </div>
          </BuilderSection>
        )}
      </div>

      {/* RIGHT: Preview pane */}
      <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Eye size={14} style={{ color: 'var(--cyan)' }} />
          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>
            {report ? `Preview: ${AUDIENCE_OPTS.find(o => o.value === report.reportType)?.label ?? report.reportType}` : 'Report Preview'}
          </span>
          {report && (
            <button onClick={() => setPreview(v => !v)} style={{ marginLeft: 'auto', padding: '4px 12px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 11 }}>
              {preview ? 'Show HTML' : 'Show Rendered'}
            </button>
          )}
        </div>

        <div style={{ flex: 1, overflow: 'auto' }}>
          {!report ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', gap: 12 }}>
              <FileText size={48} style={{ opacity: 0.15 }} />
              <p style={{ textAlign: 'center', fontSize: 12 }}>
                Configure report settings<br />and click <strong style={{ color: 'var(--text-secondary)' }}>Generate Report</strong> to preview.
              </p>
            </div>
          ) : preview ? (
            <iframe
              srcDoc={report.htmlContent}
              style={{ width: '100%', height: '100%', border: 'none', background: 'white' }}
              title="Report Preview"
              sandbox="allow-same-origin"
            />
          ) : (
            <pre style={{ padding: '16px', fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: 'var(--text-secondary)', lineHeight: 1.6, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
              {report.htmlContent}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}

function BuilderSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>{title}</div>
      {children}
    </div>
  );
}

function ExportBtn({ label, format, onExport, loading }: { label: string; format: string; onExport: (f: string) => void; loading: boolean }) {
  return (
    <button
      onClick={() => onExport(format)} disabled={loading}
      style={{ padding: '9px 16px', background: 'var(--bg-elevated)', border: '1px solid var(--border-strong)', borderRadius: 'var(--radius-sm)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8 }}>
      <Download size={13} /> {loading ? 'Exporting...' : label}
    </button>
  );
}

const labelStyle: React.CSSProperties = {
  display: 'block', fontSize: 11, fontWeight: 600,
  color: 'var(--text-muted)', marginBottom: 6,
  letterSpacing: '0.04em', textTransform: 'uppercase',
};

const inputStyle: React.CSSProperties = {
  width: '100%', padding: '8px 10px',
  background: 'var(--bg-elevated)', border: '1px solid var(--border-strong)',
  borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)',
  fontSize: 13, outline: 'none',
};
