import { useState } from 'react';
import type { Finding, Target } from '../types';
import { FileText, Download, X } from 'lucide-react';

interface ReportModalProps {
  target: Target;
  findings: Finding[];
  onClose: () => void;
}

export const ReportModal = ({ target, findings, onClose }: ReportModalProps) => {
  const [reportType, setReportType] = useState<'client' | 'developer'>('client');
  const [companyName, setCompanyName] = useState('Acme Corporation');

  const generateClientReportHTML = () => {
    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Executive VAPT Report — ${companyName}</title>
  <style>
    body { font-family: 'Helvetica Neue', Arial, sans-serif; padding: 30px; color: #0f172a; background-color: #f8fafc; }
    .header { border-bottom: 3px solid #0284c7; padding-bottom: 15px; margin-bottom: 25px; }
    .title { font-size: 24px; font-weight: bold; }
    .metric-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }
    .metric-card { background: white; padding: 15px; border-radius: 8px; border: 1px solid #e2e8f0; text-align: center; }
    .metric-value { font-size: 24px; font-weight: bold; margin-top: 4px; }
  </style>
</head>
<body>
  <div class="header">
    <div class="title">Executive Vulnerability Assessment Report</div>
    <div>Client: <strong>${companyName}</strong> | Target: <strong>${target.baseUrl}</strong></div>
  </div>
  <div class="metric-grid">
    <div class="metric-card"><div>TOTAL FINDINGS</div><div class="metric-value">${findings.length}</div></div>
    <div class="metric-card"><div>CRITICAL</div><div class="metric-value" style="color:#ef4444;">${findings.filter(f => f.severity === 'Critical').length}</div></div>
    <div class="metric-card"><div>HIGH</div><div class="metric-value" style="color:#f97316;">${findings.filter(f => f.severity === 'High').length}</div></div>
    <div class="metric-card"><div>MEDIUM</div><div class="metric-value" style="color:#eab308;">${findings.filter(f => f.severity === 'Medium').length}</div></div>
  </div>
  <p>This assessment was conducted using SentinelVAPT offline scanner orchestration under signed Rules of Engagement (RoE).</p>
</body>
</html>`;
  };

  const generateDeveloperReportHTML = () => {
    const findingsList = findings.map(f => `
      <div style="background:white; border:1px solid #e2e8f0; border-radius:8px; padding:16px; margin-bottom:16px;">
        <div style="font-weight:bold; color:#0284c7;">${f.cweId || 'VAPT'} — ${f.title} (Priority Score: ${f.priorityScore})</div>
        <div style="font-family:monospace; font-size:12px; color:#64748b; margin-top:4px;">Component: ${f.affectedComponent}</div>
        <div style="margin-top:10px; font-size:13px; color:#334155;">${f.description}</div>
        <div style="margin-top:10px; background:#f0fdf4; border:1px solid #bbf7d0; padding:10px; border-radius:6px; font-size:12px; color:#15803d;">
          <strong>Remediation:</strong> ${f.remediation}
        </div>
      </div>
    `).join('');

    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Developer Technical VAPT Report — ${target.name}</title>
  <style>
    body { font-family: system-ui, sans-serif; padding: 30px; color: #0f172a; background: #f8fafc; }
    .header { border-bottom: 3px solid #0f172a; padding-bottom: 15px; margin-bottom: 25px; }
  </style>
</head>
<body>
  <div class="header">
    <h2 style="margin:0;">Developer Technical Remediation Guide</h2>
    <div style="color:#64748b; font-size:13px; margin-top:4px;">Target: ${target.baseUrl}</div>
  </div>
  ${findingsList}
</body>
</html>`;
  };

  const currentHTML = reportType === 'client' ? generateClientReportHTML() : generateDeveloperReportHTML();

  const handleDownloadHTML = () => {
    const blob = new Blob([currentHTML], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel_${reportType}_report_${target.name.toLowerCase().replace(/\s+/g, '_')}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
          <div className="flex items-center gap-3">
            <div className="bg-cyan-500/10 p-2 rounded-lg border border-cyan-500/20">
              <FileText className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h3 className="font-bold text-slate-100 text-sm">Dual-Audience Report Generator</h3>
              <div className="text-xs text-slate-400 font-mono">Branded PDF / HTML Exporter</div>
            </div>
          </div>

          <button onClick={onClose} className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Controls Bar */}
        <div className="p-6 border-b border-slate-800 bg-slate-950/40 flex flex-wrap gap-4 items-center justify-between">
          <div className="flex gap-2 bg-slate-950 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => setReportType('client')}
              className={`px-4 py-2 rounded-lg text-xs font-semibold transition ${
                reportType === 'client' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Report A (Client Executive)
            </button>
            <button
              onClick={() => setReportType('developer')}
              className={`px-4 py-2 rounded-lg text-xs font-semibold transition ${
                reportType === 'developer' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Report B (Developer Technical)
            </button>
          </div>

          {reportType === 'client' && (
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-400">Client Name:</label>
              <input
                type="text"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>
          )}

          <button
            onClick={handleDownloadHTML}
            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs px-4 py-2 rounded-lg transition shadow-lg"
          >
            <Download className="w-4 h-4" />
            Export HTML Report
          </button>
        </div>

        {/* Live Report Preview Area */}
        <div className="flex-1 p-6 overflow-y-auto bg-slate-950/60">
          <div className="border border-slate-800 rounded-xl overflow-hidden shadow-inner bg-white min-h-[400px]">
            <iframe
              srcDoc={currentHTML}
              title="Report Preview"
              className="w-full h-[450px] border-0"
            />
          </div>
        </div>
      </div>
    </div>
  );
};
