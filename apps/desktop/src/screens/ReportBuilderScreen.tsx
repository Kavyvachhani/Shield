import { useEffect, useRef, useState } from 'react';
import { Download, Eye, Loader2, FileText, ImagePlus, Printer, X } from 'lucide-react';
import type { GenerateReportInput, GenerateReportOutput, Project, ReportType } from '../types';
import { api } from '../lib/tauri';

/**
 * Logo formats the report engine will actually embed. SVG is deliberately
 * absent — it can carry script, so the engine rejects it.
 */
const LOGO_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
const MAX_LOGO_BYTES = 2 * 1024 * 1024;

/**
 * Send a report to the platform print pipeline, which is what turns it into a
 * PDF.
 *
 * The report stylesheet already carries a full `@media print` block — A4 page
 * size, margins, repeated table headers and per-block page-break rules — so the
 * printed result is the intended document rather than a screenshot of a web
 * page. All this has to do is hand that document to the printer.
 *
 * The frame is sandboxed. `allow-same-origin` is required for this window to
 * reach `contentWindow` at all, and `allow-modals` for the print dialog to
 * open; `allow-scripts` is deliberately withheld, so report content — which is
 * derived from the assessed target — still cannot execute inside the
 * application. That is the same guarantee the on-screen preview makes.
 *
 * Resolves once the frame has been torn down, so the caller can restore the
 * button. `afterprint` fires whether the user saved or cancelled; the timeout
 * is a backstop for platforms that do not emit it.
 */
function printReport(html: string): Promise<void> {
  return new Promise((resolve) => {
    const frame = document.createElement('iframe');
    frame.setAttribute('sandbox', 'allow-same-origin allow-modals');
    frame.setAttribute('aria-hidden', 'true');
    // Kept on-page but out of sight: `display:none` stops some engines
    // laying the document out, and an unlaid-out document prints blank.
    frame.style.cssText = 'position:fixed;right:0;bottom:0;width:1px;height:1px;opacity:0;border:0';

    let settled = false;
    const cleanup = () => {
      if (settled) return;
      settled = true;
      frame.remove();
      resolve();
    };

    frame.onload = () => {
      const view = frame.contentWindow;
      if (!view) {
        cleanup();
        return;
      }
      view.addEventListener('afterprint', cleanup);
      // A backstop only: if `afterprint` never arrives the frame would leak.
      const backstop = window.setTimeout(cleanup, 120_000);
      view.addEventListener('afterprint', () => window.clearTimeout(backstop));
      try {
        view.focus();
        view.print();
      } catch {
        cleanup();
      }
    };

    document.body.appendChild(frame);
    frame.srcdoc = html;
  });
}

/** Read a picked file as a `data:image/...;base64,` URI. */
function readAsDataUri(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error('Could not read that file.'));
    reader.readAsDataURL(file);
  });
}

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
  const [printing, setPrinting] = useState(false);
  const [exportMsg, setExportMsg] = useState('');
  const [error, setError] = useState('');
  const [logo, setLogo] = useState<string | undefined>(project.logoDataUri);
  const [logoBusy, setLogoBusy] = useState(false);
  const logoInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api.defaultExportDir().then(setExportDir).catch(() => setExportDir(''));
  }, []);

  // A different engagement brings its own branding.
  useEffect(() => {
    setLogo(project.logoDataUri);
  }, [project.id, project.logoDataUri]);

  // A newly chosen report type invalidates whatever was generated before.
  useEffect(() => {
    setReport(null);
    setPreview(false);
    setExportMsg('');
  }, [reportType]);

  const isHtml = report?.contentType === 'text/html';

  /**
   * Validate a picked image, then save it against the project so every report
   * for this engagement is branded — not just the one generated right now.
   */
  async function pickLogo(file: File) {
    setError('');
    setExportMsg('');

    if (!LOGO_TYPES.includes(file.type)) {
      setError('Use a PNG, JPEG, GIF or WebP image. SVG is not accepted, because it can carry script.');
      return;
    }
    if (file.size > MAX_LOGO_BYTES) {
      setError(`That image is ${Math.round(file.size / 1024)} KB. Please use one under ${MAX_LOGO_BYTES / 1024} KB.`);
      return;
    }

    setLogoBusy(true);
    try {
      const dataUri = await readAsDataUri(file);
      await api.setProjectLogo({ projectId: project.id, logoDataUri: dataUri });
      setLogo(dataUri);
      // The generated report predates this logo, so it no longer reflects settings.
      setReport(null);
      setPreview(false);
    } catch (err) {
      setError(String(err));
    } finally {
      setLogoBusy(false);
    }
  }

  async function clearLogo() {
    setError('');
    setLogoBusy(true);
    try {
      await api.setProjectLogo({ projectId: project.id, logoDataUri: undefined });
      setLogo(undefined);
      setReport(null);
      setPreview(false);
    } catch (err) {
      setError(String(err));
    } finally {
      setLogoBusy(false);
    }
  }

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
        logoDataUri: logo,
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

  async function saveAsPdf() {
    if (!report) return;
    setPrinting(true);
    setExportMsg('');
    setError('');
    try {
      await printReport(report.content);
      // This resolves once the dialog has closed, and the dialog does not say
      // whether the user saved or cancelled or where the file went — so the
      // message can only confirm the hand-off, never claim a file was written.
      setExportMsg('Report sent to the print dialog. If you chose a PDF destination, it saved there.');
    } catch (err) {
      setError(String(err));
    } finally {
      setPrinting(false);
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

          <Field label="Company logo (optional)">
            <input
              ref={logoInput}
              type="file"
              accept={LOGO_TYPES.join(',')}
              style={{ display: 'none' }}
              onChange={(e) => {
                const file = e.target.files?.[0];
                // Reset first, so re-picking the same file fires onChange again.
                e.target.value = '';
                if (file) void pickLogo(file);
              }}
            />

            {logo ? (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: 10,
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-strong)',
                  background: 'var(--bg-base)',
                }}
              >
                <img
                  src={logo}
                  alt="Company logo preview"
                  style={{
                    maxHeight: 40,
                    maxWidth: 130,
                    objectFit: 'contain',
                    // Most client logos are dark artwork on transparency, which
                    // would vanish against the dark UI.
                    background: '#fff',
                    borderRadius: 4,
                    padding: 4,
                  }}
                />
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginLeft: 'auto' }}>
                  <button
                    type="button"
                    onClick={() => logoInput.current?.click()}
                    disabled={logoBusy}
                    style={{ ...miniButton, opacity: logoBusy ? 0.6 : 1 }}
                  >
                    Replace
                  </button>
                  <button
                    type="button"
                    onClick={clearLogo}
                    disabled={logoBusy}
                    style={{ ...miniButton, opacity: logoBusy ? 0.6 : 1 }}
                  >
                    <X size={11} /> Remove
                  </button>
                </div>
              </div>
            ) : (
              <button
                type="button"
                onClick={() => logoInput.current?.click()}
                disabled={logoBusy}
                style={{ ...secondaryButton, width: '100%', opacity: logoBusy ? 0.6 : 1 }}
              >
                {logoBusy ? <Loader2 size={14} className="spin" /> : <ImagePlus size={14} />}
                {logoBusy ? 'Saving…' : 'Upload logo'}
              </button>
            )}

            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 6, lineHeight: 1.5 }}>
              PNG, JPEG, GIF or WebP, up to 2 MB. Embedded in the report itself, so it
              still displays offline. Saved with the engagement — upload it once.
            </div>
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
              <>
                <button
                  type="button"
                  onClick={saveAsPdf}
                  disabled={printing}
                  style={{ ...secondaryButton, width: '100%', marginTop: 8, opacity: printing ? 0.6 : 1 }}
                >
                  {printing ? <Loader2 size={15} className="spin" /> : <Printer size={15} />}
                  Save as PDF
                </button>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 10, lineHeight: 1.6 }}>
                  Opens your print dialog with the report already laid out for A4.
                  Choose <strong>Save as PDF</strong> as the destination — on Windows
                  that is <strong>Microsoft Print to PDF</strong>.
                </div>
              </>
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

const miniButton: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  gap: 4,
  padding: '4px 8px',
  borderRadius: 'var(--radius-sm)',
  border: '1px solid var(--border-strong)',
  background: 'var(--bg-elevated)',
  color: 'inherit',
  fontSize: 10,
  fontWeight: 600,
  cursor: 'pointer',
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
