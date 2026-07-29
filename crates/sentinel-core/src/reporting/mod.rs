use crate::models::finding::{Finding, Severity};
use crate::scoring::priority::PriorityScoringEngine;
use serde_json::json;

pub struct ReportEngine;

impl ReportEngine {
    /// Helper to sort findings by priority score descending before rendering
    fn sort_findings(findings: &[Finding]) -> Vec<Finding> {
        let mut sorted = findings.to_vec();
        sorted.sort_by(|a, b| {
            b.priority_score.partial_cmp(&a.priority_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.severity.cmp(&b.severity))
                .then(b.created_at.cmp(&a.created_at))
        });
        sorted
    }

    /// Generates Report A (Executive / Client Report) HTML: <=4 pages, business language,
    /// severity heatmap, posture verdict, compliance snapshot, NO raw CVSS vectors, NO stack traces.
    /// Leads with Top N findings sorted by Priority Score, accompanied by plain-language rationale.
    pub fn generate_client_report_html(
        company_name: &str,
        logo_path: Option<&str>,
        target_name: &str,
        findings: &[Finding]
    ) -> String {
        let sorted = Self::sort_findings(findings);
        let total = sorted.len();
        let critical = sorted.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = sorted.iter().filter(|f| f.severity == Severity::High).count();
        let medium = sorted.iter().filter(|f| f.severity == Severity::Medium).count();
        let _low = sorted.iter().filter(|f| f.severity == Severity::Low).count();

        let logo_html = logo_path
            .map(|p| format!(r#"<img src="{}" alt="Company Logo" style="height: 40px; margin-bottom: 10px;" />"#, p))
            .unwrap_or_default();

        let top_findings_html: String = sorted.iter().take(5).enumerate().map(|(idx, f)| {
            let exec_rationale = PriorityScoringEngine::explain_executive(f);
            format!(
                r#"<div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 14px; box-shadow: 0 1px 2px rgba(0,0,0,0.03);">
                    <div style="display: flex; justify-space-between; align-items: center; border-bottom: 1px solid #f1f5f9; padding-bottom: 8px; margin-bottom: 10px;">
                        <div style="font-weight: bold; color: #0f172a; font-size: 15px;">#{rank} • {title}</div>
                        <div style="background: #0284c7; color: white; font-weight: bold; font-size: 12px; padding: 3px 10px; border-radius: 99px;">Priority {score:.1}/10</div>
                    </div>
                    <div style="font-size: 13px; color: #334155; margin-bottom: 8px;"><strong>Risk Rationale:</strong> {rationale}</div>
                    <div style="font-size: 13px; color: #475569; margin-top: 4px;"><strong>Impact Summary:</strong> {desc}</div>
                    <div style="font-size: 12px; color: #166534; background: #f0fdf4; border: 1px solid #bbf7d0; padding: 8px 12px; border-radius: 6px; margin-top: 10px;"><strong>Strategic Action:</strong> {remediation}</div>
                </div>"#,
                rank = idx + 1,
                title = f.title,
                score = f.priority_score,
                rationale = exec_rationale,
                desc = f.description,
                remediation = f.remediation
            )
        }).collect();

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Executive Security Posture Report — {company_name}</title>
    <style>
        body {{ font-family: 'Helvetica Neue', Arial, sans-serif; margin: 40px; color: #1e293b; background: #f8fafc; line-height: 1.6; }}
        .confidential-header {{ background: #dc2626; color: white; text-align: center; font-weight: bold; font-size: 11px; letter-spacing: 1px; padding: 6px; border-radius: 4px; margin-bottom: 20px; }}
        .header {{ border-bottom: 3px solid #0284c7; padding-bottom: 20px; margin-bottom: 30px; }}
        .title {{ font-size: 26px; font-weight: bold; color: #0f172a; }}
        .subtitle {{ font-size: 14px; color: #64748b; margin-top: 5px; }}
        .verdict {{ background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; padding: 16px; border-radius: 8px; font-weight: 500; margin: 20px 0; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 25px 0; }}
        .metric-card {{ background: white; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; text-align: center; }}
        .metric-value {{ font-size: 32px; font-weight: bold; margin-top: 5px; }}
        .section-title {{ font-size: 18px; font-weight: bold; color: #0f172a; margin-top: 30px; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }}
        .compliance-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; background: white; border-radius: 8px; overflow: hidden; }}
        .compliance-table th, .compliance-table td {{ border: 1px solid #e2e8f0; padding: 10px 15px; text-align: left; font-size: 13px; }}
        .compliance-table th {{ background: #f1f5f9; font-weight: bold; color: #334155; }}
    </style>
</head>
<body>
    <div class="confidential-header">STRICTLY CONFIDENTIAL — FOR AUTHORIZED CLIENT REVIEW ONLY</div>

    <div class="header">
        {logo_html}
        <div class="title">Executive Security Posture & Vulnerability Report</div>
        <div class="subtitle">Client: <strong>{company_name}</strong> | Target Application: <strong>{target_name}</strong></div>
    </div>

    <div class="verdict">
        ✓ <strong>Security Posture Verdict:</strong> Comprehensive offline multi-engine assessment completed under signed Rules of Engagement (RoE). Findings are prioritized by SentinelVAPT Integrated Priority Score (CVSS4 × EPSS × KEV × Reachability × Exposure).
    </div>

    <div class="section-title">Risk Severity Breakdown & Heatmap</div>
    <div class="metrics-grid">
        <div class="metric-card"><div style="color: #64748b; font-size: 11px;">TOTAL FINDINGS</div><div class="metric-value">{total}</div></div>
        <div class="metric-card"><div style="color: #ef4444; font-size: 11px;">CRITICAL</div><div class="metric-value" style="color: #ef4444;">{critical}</div></div>
        <div class="metric-card"><div style="color: #f97316; font-size: 11px;">HIGH</div><div class="metric-value" style="color: #f97316;">{high}</div></div>
        <div class="metric-card"><div style="color: #eab308; font-size: 11px;">MEDIUM</div><div class="metric-value" style="color: #eab308;">{medium}</div></div>
    </div>

    <div class="section-title">Strategic Business Risk Priorities (Top {top_count} by Priority Score)</div>
    {top_findings_html}

    <div class="section-title">Compliance Framework Alignment Snapshot</div>
    <table class="compliance-table">
        <thead>
            <tr>
                <th>Compliance Framework</th>
                <th>Relevant Control Area</th>
                <th>Current Status</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><strong>PCI DSS v4.0.1</strong></td>
                <td>Requirement 6.3 (Software Security & Patching)</td>
                <td><span style="color: #ea580c; font-weight: bold;">Attention Required ({critical} Critical / {high} High)</span></td>
            </tr>
            <tr>
                <td><strong>SOC 2 Type II</strong></td>
                <td>CC7.1 (Vulnerability Management & Monitoring)</td>
                <td><span style="color: #16a34a; font-weight: bold;">Evidence Logged in Audit Ledger</span></td>
            </tr>
            <tr>
                <td><strong>ISO/IEC 27001:2022</strong></td>
                <td>Control A.8.8 (Management of Technical Vulnerabilities)</td>
                <td><span style="color: #16a34a; font-weight: bold;">Assessment Conducted</span></td>
            </tr>
        </tbody>
    </table>
</body>
</html>"#,
            company_name = company_name,
            target_name = target_name,
            logo_html = logo_html,
            total = total,
            critical = critical,
            high = high,
            medium = medium,
            top_count = sorted.len().min(5),
            top_findings_html = top_findings_html
        )
    }

    /// Generates Report B (Developer / Technical Report) HTML: per-finding blocks with title,
    /// priority rationale breakdown, CVSS4 vector, CWE + OWASP Top 10:2025 + WSTG ID, affected component,
    /// reproduction steps, sanitized evidence, precise remediation, and references.
    pub fn generate_developer_report_html(target_name: &str, findings: &[Finding]) -> String {
        let sorted = Self::sort_findings(findings);

        let findings_html: String = sorted.iter().enumerate().map(|(idx, f)| {
            let cwe = f.cwe_id.as_deref().unwrap_or("N/A");
            let owasp = f.owasp_2025.as_deref().unwrap_or("N/A");
            let wstg = f.wstg_id.as_deref().unwrap_or("N/A");
            let cvss_vec = f.cvss4.as_ref().map(|c| c.vector_string.as_str()).unwrap_or("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H");

            let rationale = if !f.priority_rationale.is_empty() {
                f.priority_rationale.clone()
            } else {
                PriorityScoringEngine::explain(f)
            };

            let repro_html: String = f.repro_steps.iter().map(|step| format!("<li><code>{}</code></li>", step)).collect();
            let evidences_html: String = f.evidences.iter().map(|ev| {
                format!(
                    r#"<div style="background: #0f172a; color: #f8fafc; font-family: monospace; font-size: 11px; padding: 12px; border-radius: 6px; margin-top: 6px;">
                        <div style="color: #38bdf8; font-weight: bold; margin-bottom: 4px;">[{}] {}</div>
                        <pre style="margin: 0; white-space: pre-wrap;">{}</pre>
                    </div>"#,
                    ev.evidence_type, ev.title, ev.content
                )
            }).collect();

            format!(
                r#"<div style="background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 22px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                    <div style="display: flex; justify-content: space-between; align-items: start; border-bottom: 1px solid #e2e8f0; padding-bottom: 14px;">
                        <div>
                            <span style="font-family: monospace; font-size: 12px; color: #0284c7; font-weight: bold;">#{rank} • {cwe} • {owasp} • {wstg}</span>
                            <h3 style="margin: 6px 0 0 0; font-size: 19px; color: #0f172a;">{title}</h3>
                            <div style="font-family: monospace; font-size: 12px; color: #64748b; margin-top: 4px;">Component / Endpoint: {affected}</div>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-size: 10px; color: #64748b;">PRIORITY SCORE</div>
                            <div style="font-size: 26px; font-weight: bold; color: #0284c7;">{score:.1}</div>
                        </div>
                    </div>

                    <div style="margin-top: 12px; font-size: 12px; color: #0369a1; background: #e0f2fe; border: 1px solid #bae6fd; padding: 8px 12px; border-radius: 6px; font-weight: 500;">
                        💡 <strong>Why this ranks here:</strong> {rationale}
                    </div>

                    <div style="margin-top: 10px; font-family: monospace; font-size: 11px; color: #475569; background: #f1f5f9; padding: 6px 10px; border-radius: 4px;">
                        Vector: {cvss_vec}
                    </div>
                    
                    <div style="margin-top: 16px;">
                        <h4 style="font-size: 12px; text-transform: uppercase; color: #475569; margin: 0 0 4px 0;">Technical Description</h4>
                        <p style="font-size: 13px; color: #334155; margin: 0; line-height: 1.5;">{desc}</p>
                    </div>

                    <div style="margin-top: 16px;">
                        <h4 style="font-size: 12px; text-transform: uppercase; color: #475569; margin: 0 0 6px 0;">Reproduction Steps</h4>
                        <ol style="font-size: 13px; color: #334155; margin: 0; padding-left: 20px;">{repro}</ol>
                    </div>

                    <div style="margin-top: 16px;">
                        <h4 style="font-size: 12px; text-transform: uppercase; color: #475569; margin: 0 0 6px 0;">Sanitized Proof Evidence Payload</h4>
                        {evidences}
                    </div>

                    <div style="margin-top: 16px; background: #f0fdf4; border: 1px solid #bbf7d0; padding: 14px; border-radius: 6px;">
                        <h4 style="font-size: 12px; text-transform: uppercase; color: #166534; margin: 0 0 4px 0;">Precise Remediation Guidance</h4>
                        <div style="font-size: 13px; color: #15803d; font-weight: 500;">{remediation}</div>
                    </div>
                </div>"#,
                rank = idx + 1,
                cwe = cwe,
                owasp = owasp,
                wstg = wstg,
                title = f.title,
                affected = f.affected_component,
                score = f.priority_score,
                rationale = rationale,
                cvss_vec = cvss_vec,
                desc = f.description,
                repro = repro_html,
                evidences = evidences_html,
                remediation = f.remediation
            )
        }).collect();

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Developer Technical VAPT Report — {target_name}</title>
    <style>
        body {{ font-family: 'Helvetica Neue', Arial, sans-serif; margin: 40px; color: #1e293b; background: #f8fafc; line-height: 1.5; }}
        .header {{ border-bottom: 3px solid #0f172a; padding-bottom: 20px; margin-bottom: 30px; }}
        .title {{ font-size: 26px; font-weight: bold; color: #0f172a; }}
        .subtitle {{ font-size: 14px; color: #64748b; margin-top: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">Developer Technical Remediation Guide</div>
        <div class="subtitle">Target Application: <strong>{target_name}</strong> | SentinelVAPT Multi-Engine Audit (Sorted by Integrated Priority Score)</div>
    </div>
    {findings_html}
</body>
</html>"#
        )
    }

    /// Generates machine-readable SARIF 2.1.0 JSON format for developer pipelines
    pub fn generate_sarif_json(findings: &[Finding]) -> String {
        let sorted = Self::sort_findings(findings);

        let rules: Vec<serde_json::Value> = sorted.iter().map(|f| {
            json!({
                "id": f.cwe_id.as_deref().unwrap_or("VAPT-GENERIC"),
                "name": f.title,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.description },
                "help": { "text": format!("{}\n\nRemediation: {}", f.priority_rationale, f.remediation) }
            })
        }).collect();

        let results: Vec<serde_json::Value> = sorted.iter().map(|f| {
            json!({
                "ruleId": f.cwe_id.as_deref().unwrap_or("VAPT-GENERIC"),
                "message": { "text": format!("[Priority {:.1}] {}", f.priority_score, f.title) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.affected_component }
                    }
                }]
            })
        }).collect();

        let sarif = json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SentinelVAPT",
                        "version": "0.1.0",
                        "rules": rules
                    }
                },
                "results": results
            }]
        });

        serde_json::to_string_pretty(&sarif).unwrap_or_default()
    }
}
