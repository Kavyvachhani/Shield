import type { Finding } from '../types';
import { Shield, CheckCircle2, Layers } from 'lucide-react';

interface FindingTableProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
}

export const FindingTable = ({ findings, onSelectFinding }: FindingTableProps) => {
  const getSeverityBadge = (severity: Finding['severity']) => {
    switch (severity) {
      case 'Critical': return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'High': return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
      case 'Medium': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
      case 'Low': return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      default: return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      <div className="px-6 py-4 border-b border-slate-800 flex justify-between items-center bg-slate-900/50">
        <h3 className="font-semibold text-slate-100 flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          Deduplicated Vulnerability Findings ({findings.length})
        </h3>
        <span className="text-xs text-slate-400">Sorted by Priority Score</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider text-[10px]">
            <tr>
              <th className="px-6 py-3">Priority</th>
              <th className="px-6 py-3">Title & Component</th>
              <th className="px-6 py-3">Severity</th>
              <th className="px-6 py-3">Taxonomy (CWE/OWASP)</th>
              <th className="px-6 py-3">Scanners</th>
              <th className="px-6 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {findings.map((finding) => (
              <tr 
                key={finding.id}
                onClick={() => onSelectFinding(finding)}
                className="hover:bg-slate-800/40 cursor-pointer transition"
              >
                <td className="px-6 py-4">
                  <div className="flex items-center gap-1.5 font-bold text-sm text-cyan-400">
                    {finding.priorityScore.toFixed(1)}
                  </div>
                  {finding.kevListed && (
                    <span className="inline-block mt-0.5 text-[9px] bg-red-950 text-red-400 border border-red-800/60 px-1.5 py-0.5 rounded font-mono">
                      CISA KEV
                    </span>
                  )}
                </td>
                <td className="px-6 py-4">
                  <div className="font-medium text-slate-100">{finding.title}</div>
                  <div className="text-slate-400 font-mono text-[11px] mt-0.5 truncate max-w-xs">
                    {finding.affectedComponent}
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span className={`px-2.5 py-1 rounded-full border text-[11px] font-semibold ${getSeverityBadge(finding.severity)}`}>
                    {finding.severity}
                  </span>
                </td>
                <td className="px-6 py-4 text-slate-400 font-mono text-[11px]">
                  <div>{finding.cweId || 'N/A'}</div>
                  <div className="text-[10px] text-slate-500">{finding.owasp2025}</div>
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-1">
                    <Layers className="w-3.5 h-3.5 text-slate-400" />
                    <span className="text-slate-300 font-medium">{finding.sourceTools.join(', ')}</span>
                  </div>
                  {finding.sourceTools.length > 1 && (
                    <span className="text-[9px] text-emerald-400 font-mono">SAST+DAST Unified</span>
                  )}
                </td>
                <td className="px-6 py-4">
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] bg-slate-800 text-slate-300">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                    {finding.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
