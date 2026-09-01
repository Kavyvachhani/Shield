//! Report generation.
//!
//! Two audiences, two documents, one dataset:
//!
//!   • **Client / executive report** — what was assessed, how healthy the
//!     application is, what it means commercially, and what to do next. Leads
//!     with the full coverage matrix so the client can see every check that was
//!     performed, including the ones that passed.
//!
//!   • **Developer / technical report** — one section per finding with the exact
//!     location, reproduction steps, sanitized evidence, a concrete fix and
//!     verification steps.
//!
//! Both are self-contained HTML with inline styles and inline SVG: no scripts,
//! no external fonts, no network requests. They render identically offline and
//! print to clean PDF via the browser's "Save as PDF".

pub mod charts;
pub mod client;
pub mod developer;
pub mod escape;
pub mod owasp;

use crate::checklist::CoverageReport;
use crate::exceptions::ExceptionRecord;
use crate::models::finding::{Finding, FindingStatus, Severity, FindingKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Everything the reports need about the engagement itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportContext {
    pub company_name: String,
    pub target_name: String,
    pub target_url: String,
    /// Optional base64 `data:image/...` logo. Anything else is ignored.
    pub logo_data_uri: Option<String>,
    pub analyst: String,
    pub assessment_start: DateTime<Utc>,
    pub assessment_end: DateTime<Utc>,
    /// Engines that genuinely executed.
    pub engines_executed: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub out_of_scope_paths: Vec<String>,
    pub rate_limit_rps: u32,
    /// SHA-256 of the signed Rules of Engagement, for the attestation block.
    pub roe_hash: Option<String>,
    pub report_reference: String,
    /// Exceptions in force for this target, printed as the report's register.
    ///
    /// `default` keeps engagement JSON written before the register existed
    /// deserialisable.
    #[serde(default)]
    pub exceptions: Vec<ExceptionRecord>,
    /// Document classification shown on the cover and in the footer.
    #[serde(default = "default_classification")]
    pub classification: String,
    /// Who reviewed the report before issue, for the document-control table.
    #[serde(default)]
    pub reviewed_by: Option<String>,
    /// Report revision, e.g. "1.0". Shown in document control.
    #[serde(default = "default_revision")]
    pub revision: String,
}

fn default_classification() -> String {
    "Confidential".to_string()
}

fn default_revision() -> String {
    "1.0".to_string()
}

impl ReportContext {
    /// A context with sensible defaults, for tests and for callers that only
    /// have partial engagement metadata.
    pub fn new(company_name: &str, target_name: &str, target_url: &str) -> Self {
        let now = Utc::now();
        Self {
            company_name: company_name.to_string(),
            target_name: target_name.to_string(),
            target_url: target_url.to_string(),
            logo_data_uri: None,
            analyst: "SentinelVAPT".to_string(),
            assessment_start: now,
            assessment_end: now,
            engines_executed: Vec::new(),
            allowed_domains: Vec::new(),
            out_of_scope_paths: Vec::new(),
            rate_limit_rps: 5,
            roe_hash: None,
            report_reference: format!("SV-{}", now.format("%Y%m%d-%H%M")),
            exceptions: Vec::new(),
            classification: default_classification(),
            reviewed_by: None,
            revision: default_revision(),
        }
    }

    /// How long the assessment window was, in whole days (minimum one).
    pub fn duration_days(&self) -> i64 {
        let days = (self.assessment_end - self.assessment_start).num_days();
        days.max(1)
    }

    /// Accepted-risk exceptions still in force, newest first.
    pub fn active_acceptances(&self) -> Vec<&ExceptionRecord> {
        let now = Utc::now();
        let mut records: Vec<&ExceptionRecord> = self
            .exceptions
            .iter()
            .filter(|e| e.kind == crate::exceptions::ExceptionKind::AcceptedRisk)
            .filter(|e| e.is_active_at(now))
            .collect();
        records.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        records
    }

    /// False-positive dismissals still in force, newest first.
    pub fn active_dismissals(&self) -> Vec<&ExceptionRecord> {
        let now = Utc::now();
        let mut records: Vec<&ExceptionRecord> = self
            .exceptions
            .iter()
            .filter(|e| e.kind == crate::exceptions::ExceptionKind::FalsePositive)
            .filter(|e| e.is_active_at(now))
            .collect();
        records.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        records
    }
}

/// A report's findings split by how the document must treat them.
///
/// The split is what makes an exception mean anything. Everything the client
/// still carries as open exposure drives the counts, the posture score and the
/// remediation roadmap; a weakness the business has formally accepted does not
/// — it is disclosed in its own register, with the justification and the owner,
/// rather than sitting in the roadmap as work nobody intends to do.
///
/// False positives never reach here: they are removed at selection time,
/// because a report that asks the reader to discount something that was never
/// real has wasted their attention and inflated its own numbers.
#[derive(Debug, Clone, Default)]
pub struct ReportFindings {
    /// Open, in-progress and remediated findings — the live picture.
    pub active: Vec<Finding>,
    /// Findings carried under a formal acceptance.
    pub accepted: Vec<Finding>,
    /// Records about the assessment's own reach rather than the target's
    /// security. Never counted, never scored, never in the remediation queue —
    /// they belong in the coverage narrative.
    pub information: Vec<Finding>,
}

impl ReportFindings {
    /// Split `findings` into the live set and the accepted set, each sorted
    /// highest-risk first.
    pub fn partition(findings: &[Finding]) -> Self {
        let sorted = sort_by_priority(findings);
        // Scan information comes out first: it is not a weakness, so it must
        // not reach the counts, the posture score or the remediation queue.
        let (information, weaknesses): (Vec<Finding>, Vec<Finding>) = sorted
            .into_iter()
            .partition(|f| f.kind == FindingKind::ScanInformation);
        let (accepted, active): (Vec<Finding>, Vec<Finding>) = weaknesses
            .into_iter()
            .partition(|f| f.status == FindingStatus::AcceptedRisk);
        Self { active, accepted, information }
    }

    /// Render the assessment-surface records as report prose, if any exist.
    ///
    /// Returns the description and every evidence block, so the caller decides
    /// where in its own document the coverage narrative belongs.
    pub fn surface_notes(&self) -> Vec<(&str, Vec<(&str, &str)>)> {
        self.information
            .iter()
            .map(|f| {
                (
                    f.description.as_str(),
                    f.evidences
                        .iter()
                        .map(|e| (e.title.as_str(), e.content.as_str()))
                        .collect(),
                )
            })
            .collect()
    }

    /// Severity tallies over the live set only.
    pub fn counts(&self) -> SeverityCounts {
        SeverityCounts::of(&self.active)
    }
}

/// Severity tallies used across both reports.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn of(findings: &[Finding]) -> Self {
        let mut c = Self::default();
        for f in findings {
            match f.severity {
                Severity::Critical => c.critical += 1,
                Severity::High => c.high += 1,
                Severity::Medium => c.medium += 1,
                Severity::Low => c.low += 1,
                Severity::Info => c.info += 1,
            }
        }
        c
    }

    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }

    /// Findings that require action, i.e. everything above informational.
    pub fn actionable(&self) -> usize {
        self.critical + self.high + self.medium + self.low
    }
}

/// Overall posture band derived from the findings and coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostureBand {
    Strong,
    Adequate,
    NeedsImprovement,
    AtRisk,
    Critical,
}

impl PostureBand {
    pub fn label(&self) -> &'static str {
        match self {
            PostureBand::Strong => "Strong",
            PostureBand::Adequate => "Adequate",
            PostureBand::NeedsImprovement => "Needs Improvement",
            PostureBand::AtRisk => "At Risk",
            PostureBand::Critical => "Critical",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            PostureBand::Strong => "#16a34a",
            PostureBand::Adequate => "#0284c7",
            PostureBand::NeedsImprovement => "#ca8a04",
            PostureBand::AtRisk => "#ea580c",
            PostureBand::Critical => "#b91c1c",
        }
    }

    /// The one-paragraph verdict shown at the top of the client report.
    pub fn verdict(&self) -> &'static str {
        match self {
            PostureBand::Strong =>
                "The assessment found no high-impact weaknesses. The controls that were tested behaved as expected, and the issues raised are refinements rather than exposures. Maintain the current standard and re-test after significant changes.",
            PostureBand::Adequate =>
                "The application's core protections are in place. A number of lower-impact weaknesses were identified that should be scheduled into normal development work; none of them require emergency action.",
            PostureBand::NeedsImprovement =>
                "Several weaknesses were identified that a motivated attacker could combine to meaningful effect. None represents an immediate breach, but the pattern suggests security review is not consistently applied. Address the medium and high items over the coming weeks.",
            PostureBand::AtRisk =>
                "High-impact weaknesses were confirmed on the live application. These are directly exploitable by an external attacker without credentials, and should be treated as an active risk to customer data and service availability. Remediation should begin within days, not weeks.",
            PostureBand::Critical =>
                "Critical weaknesses were confirmed that expose sensitive data or grant unauthorised control of the application. These require immediate action: an attacker who finds them needs no special access and no unusual skill. Treat this as an incident-grade priority and remediate before the next release.",
        }
    }
}

/// A 0–100 posture score plus its band.
///
/// The score starts at 100 and deducts per finding weighted by severity, then
/// applies a penalty proportional to how much of the checklist could not be
/// exercised — a scan that tested very little must not score as "Strong".
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PostureScore {
    pub score: f64,
    pub band: PostureBand,
}

impl PostureScore {
    pub fn compute(counts: &SeverityCounts, coverage: Option<&CoverageReport>) -> Self {
        let deductions = (counts.critical as f64 * 22.0)
            + (counts.high as f64 * 12.0)
            + (counts.medium as f64 * 5.0)
            + (counts.low as f64 * 1.5);

        let mut score = (100.0 - deductions).max(0.0);

        // An assessment that exercised little of the catalog cannot claim a high
        // score: the absence of findings would reflect absent testing, not health.
        if let Some(cov) = coverage {
            let confidence = (cov.automated_coverage_pct / 100.0).clamp(0.0, 1.0);
            score *= 0.55 + (0.45 * confidence);
        }

        let score = (score * 10.0).round() / 10.0;

        // Severity floors: a confirmed critical can never present as healthy,
        // regardless of how few other findings there are.
        let band = if counts.critical > 0 {
            PostureBand::Critical
        } else if counts.high > 0 && score < 70.0 {
            PostureBand::AtRisk
        } else if counts.high > 0 {
            PostureBand::NeedsImprovement
        } else if score >= 85.0 {
            PostureBand::Strong
        } else if score >= 70.0 {
            PostureBand::Adequate
        } else if score >= 50.0 {
            PostureBand::NeedsImprovement
        } else {
            PostureBand::AtRisk
        };

        Self { score, band }
    }
}

/// Remediation urgency band shown in the roadmap.
pub fn remediation_window(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "Immediate — within 24–48 hours",
        Severity::High => "Urgent — within 7 days",
        Severity::Medium => "Planned — within 30 days",
        Severity::Low => "Scheduled — within 90 days",
        Severity::Info => "Optional — at the team's discretion",
    }
}

/// Sort findings highest-risk first, with deterministic tie-breaking.
pub fn sort_by_priority(findings: &[Finding]) -> Vec<Finding> {
    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| {
        b.priority_score
            .partial_cmp(&a.priority_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.severity.cmp(&b.severity))
            .then(a.title.cmp(&b.title))
            .then(a.affected_component.cmp(&b.affected_component))
            .then(a.id.cmp(&b.id))
    });
    sorted
}

/// Shared print-ready stylesheet for both reports.
pub fn base_stylesheet() -> &'static str {
    r##"
:root{--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--bg:#ffffff;--soft:#f8fafc;--brand:#0f4c81}
*{box-sizing:border-box}
body{margin:0;background:var(--soft);color:var(--ink);
  font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;
  font-size:14px;line-height:1.6;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.page{max-width:1000px;margin:0 auto;padding:36px 44px;background:var(--bg)}
h1,h2,h3,h4{margin:0;line-height:1.25}
h2{font-size:20px;margin:38px 0 14px;padding-bottom:9px;border-bottom:2px solid var(--line)}
h3{font-size:16px;margin:22px 0 8px}
p{margin:0 0 12px}
a{color:var(--brand)}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}
th,td{border:1px solid var(--line);padding:9px 12px;text-align:left;vertical-align:top}
th{background:var(--soft);font-weight:600;color:#334155}
tbody tr:nth-child(even){background:#fcfdfe}
code,pre{font-family:'Cascadia Mono',Consolas,'SF Mono',Menlo,monospace;font-size:12px}
pre{background:#0f172a;color:#e2e8f0;padding:13px 15px;border-radius:7px;overflow-x:auto;
  white-space:pre-wrap;word-break:break-word;margin:8px 0}
.muted{color:var(--muted)}
.small{font-size:12px}
.pill{display:inline-block;padding:2px 10px;border-radius:99px;font-size:11px;
  font-weight:700;letter-spacing:.3px;color:#fff;white-space:nowrap}
.card{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:14px}
.grid{display:grid;gap:14px}
.grid-4{grid-template-columns:repeat(4,1fr)}
.grid-2{grid-template-columns:1fr 1fr}
.kpi{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:15px;text-align:center}
.kpi .n{font-size:29px;font-weight:700;line-height:1.15}
.kpi .l{font-size:10px;letter-spacing:.7px;text-transform:uppercase;color:var(--muted);margin-top:3px}
.banner{border-radius:8px;padding:11px 16px;font-size:11px;font-weight:700;
  letter-spacing:1.1px;text-transform:uppercase;text-align:center;color:#fff;background:#b91c1c}
.callout{border-left:4px solid var(--brand);background:#f0f7ff;padding:13px 16px;border-radius:0 7px 7px 0;margin:12px 0}
.fix{border-left:4px solid #16a34a;background:#f0fdf4;padding:13px 16px;border-radius:0 7px 7px 0;margin:12px 0}
.warn{border-left:4px solid #ca8a04;background:#fefce8;padding:13px 16px;border-radius:0 7px 7px 0;margin:12px 0}
.legend{display:flex;flex-wrap:wrap;gap:8px 18px;font-size:12px;margin-top:10px}
.legend span{display:flex;align-items:center;gap:6px}
.swatch{width:11px;height:11px;border-radius:3px;flex:0 0 auto}
.footer{margin-top:44px;padding-top:14px;border-top:1px solid var(--line);
  font-size:11px;color:var(--muted);display:flex;justify-content:space-between;gap:16px}
@media print{
  body{background:#fff}
  .page{max-width:none;padding:0 12mm}
  h2{page-break-after:avoid}
  /* Deliberately NOT `table{page-break-inside:avoid}`. A table longer than a
     page cannot honour it, so the browser shunts the whole table to a fresh
     page and overflows anyway — which left half-empty pages either side of the
     findings index and the 108-row coverage checklist. Break the table across
     pages, but keep each row whole and repeat the header. */
  /* `.finding` is deliberately absent for the same reason: a finding carrying
     several evidence blocks is taller than a page, so "avoid" only bought a
     mostly-empty page after each one. Findings flow across pages; the blocks
     that must never split — evidence, fix, verification, repro steps — are
     protected individually, and a heading never ends a page alone. */
  .card,pre,.fix,.warn,.callout,ol.steps li{page-break-inside:avoid}
  .finding h3,.section-label{page-break-after:avoid}
  thead{display:table-header-group}
  tfoot{display:table-footer-group}
  tr{page-break-inside:avoid;break-inside:avoid}
  .page-break{page-break-before:always}
  @page{size:A4;margin:14mm 0}
}
@media (max-width:760px){
  .page{padding:20px 16px}
  .grid-4,.grid-2{grid-template-columns:1fr 1fr}
}
"##
}

/// Standard document footer.
pub fn footer_html(ctx: &ReportContext, document_name: &str) -> String {
    format!(
        r##"<div class="footer">
  <div>{doc} · {company} · Reference {reference}</div>
  <div>Generated {generated} UTC by SentinelVAPT</div>
</div>"##,
        doc = escape::html(document_name),
        company = escape::html(&ctx.company_name),
        reference = escape::html(&ctx.report_reference),
        generated = ctx.assessment_end.format("%Y-%m-%d %H:%M"),
    )
}

/// Facade retained for callers that already depend on `ReportEngine`.
pub struct ReportEngine;

impl ReportEngine {
    /// Client-facing executive report.
    pub fn client_report(
        ctx: &ReportContext,
        findings: &[Finding],
        coverage: Option<&CoverageReport>,
    ) -> String {
        client::render(ctx, findings, coverage)
    }

    /// Developer-facing technical remediation report.
    pub fn developer_report(
        ctx: &ReportContext,
        findings: &[Finding],
        coverage: Option<&CoverageReport>,
    ) -> String {
        developer::render(ctx, findings, coverage)
    }

    /// SARIF 2.1.0 for CI pipelines and code-scanning dashboards.
    pub fn generate_sarif_json(findings: &[Finding]) -> String {
        let sorted = sort_by_priority(findings);
        // SARIF has a first-class concept for "known and deliberately not
        // acted on", so an accepted risk is emitted as a suppressed result
        // rather than silently dropped: a code-scanning dashboard then stops
        // failing the build on it without losing the record that it exists.

        // SARIF requires unique rule ids; collapse findings onto their check class.
        let mut rules: Vec<serde_json::Value> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for f in &sorted {
            let rule_id = sarif_rule_id(f);
            if seen.contains(&rule_id) {
                continue;
            }
            seen.push(rule_id.clone());
            rules.push(serde_json::json!({
                "id": rule_id,
                "name": f.title,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.description },
                "help": { "text": format!("Remediation: {}", f.remediation) },
                "properties": {
                    "tags": sarif_tags(f),
                    "security-severity": format!("{:.1}", f.cvss4.as_ref().map(|c| c.base_score).unwrap_or(0.0)),
                }
            }));
        }

        let results: Vec<serde_json::Value> = sorted
            .iter()
            .map(|f| {
                let mut result = serde_json::json!({
                    "ruleId": sarif_rule_id(f),
                    "level": sarif_level(&f.severity),
                    "message": { "text": format!("[Priority {:.1}] {}", f.priority_score, f.title) },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": f.affected_component }
                        }
                    }],
                    "properties": {
                        "priorityScore": f.priority_score,
                        "severity": format!("{:?}", f.severity),
                        "sourceTools": f.source_tools,
                        "status": format!("{:?}", f.status),
                    }
                });
                if f.status == FindingStatus::AcceptedRisk {
                    result["suppressions"] = serde_json::json!([{
                        "kind": "external",
                        "status": "accepted",
                        "justification": "Formally accepted by the risk owner; see the engagement's exception register.",
                    }]);
                }
                result
            })
            .collect();

        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": {
                    "name": "SentinelVAPT",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/sentinelvapt",
                    "rules": rules
                }},
                "results": results
            }]
        });

        serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
    }

    /// Ticket-ready Markdown, one section per finding.
    pub fn developer_markdown(ctx: &ReportContext, findings: &[Finding]) -> String {
        developer::render_markdown(ctx, findings)
    }

    /// Machine-readable export of the whole assessment.
    pub fn generate_json(
        ctx: &ReportContext,
        findings: &[Finding],
        coverage: Option<&CoverageReport>,
    ) -> String {
        // The same split the HTML reports use, so a pipeline consuming this
        // export and a human reading the PDF cannot disagree about the numbers.
        let split = ReportFindings::partition(findings);
        let counts = split.counts();
        let posture = PostureScore::compute(&counts, coverage);
        let payload = serde_json::json!({
            "schemaVersion": "1.1",
            "generator": { "name": "SentinelVAPT", "version": env!("CARGO_PKG_VERSION") },
            "engagement": ctx,
            "summary": {
                "severityCounts": counts,
                "postureScore": posture.score,
                "postureBand": posture.band.label(),
                "totalFindings": split.active.len(),
                "acceptedRiskCount": split.accepted.len(),
            },
            "coverage": coverage,
            "findings": split.active,
            "acceptedRisks": split.accepted,
            "exceptions": ctx.exceptions,
        });
        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
    }
}

fn sarif_rule_id(f: &Finding) -> String {
    f.cwe_id
        .as_deref()
        .filter(|c| !c.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "SENTINEL-GENERIC".to_string())
}

fn sarif_tags(f: &Finding) -> Vec<String> {
    let mut tags = vec!["security".to_string()];
    for v in [&f.cwe_id, &f.owasp_2025, &f.wstg_id, &f.api_top10].into_iter().flatten() {
        if !v.trim().is_empty() {
            tags.push(v.clone());
        }
    }
    tags
}

fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{CVSS4Data, FindingStatus};
    use uuid::Uuid;

    pub(crate) fn finding(title: &str, sev: Severity, score: f64) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            title: title.into(),
            description: "Description text.".into(),
            severity: sev.clone(),
            kind: FindingKind::default(),
            cvss4: Some(CVSS4Data {
                vector_string: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H".into(),
                base_score: score,
                severity_label: format!("{sev:?}"),
            }),
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.0,
            reachability_score: 1.0,
            priority_score: score,
            cwe_id: Some("CWE-79".into()),
            owasp_2025: Some("A05:2025-Injection".into()),
            wstg_id: Some("WSTG-INPV-01".into()),
            api_top10: None,
            affected_component: "https://app.test/x".into(),
            evidences: vec![],
            repro_steps: vec!["step one".into()],
            remediation: "Fix it properly.".into(),
            references: vec!["https://owasp.org/x".into()],
            status: FindingStatus::Open,
            source_tools: vec!["Sentinel Native".into()],
            ai_triage: None,
            priority_rationale: "because".into(),
            created_at: Utc::now(),
        }
    }

    /// The record exists so a clean result can be read correctly. If it were
    /// counted as a finding, every report would gain an issue nobody can fix
    /// and the informational tally would be permanently off by one.
    #[test]
    fn scan_information_is_never_counted_as_a_finding() {
        let mut note = finding("Assessment Surface", Severity::Info, 0.0);
        note.kind = crate::models::finding::FindingKind::ScanInformation;

        let split = ReportFindings::partition(&[
            finding("real", Severity::High, 8.0),
            note,
        ]);

        assert_eq!(split.active.len(), 1, "only the weakness is a finding");
        assert_eq!(split.information.len(), 1);
        assert_eq!(split.counts().total(), 1);
        assert_eq!(split.counts().info, 0, "the record must not inflate the info tally");
    }

    #[test]
    fn scan_information_does_not_move_the_posture_score() {
        let mut note = finding("Assessment Surface", Severity::Info, 0.0);
        note.kind = crate::models::finding::FindingKind::ScanInformation;

        let with_note = ReportFindings::partition(&[finding("real", Severity::Medium, 5.0), note]);
        let without = ReportFindings::partition(&[finding("real", Severity::Medium, 5.0)]);

        assert_eq!(
            PostureScore::compute(&with_note.counts(), None).score,
            PostureScore::compute(&without.counts(), None).score
        );
    }

    #[test]
    fn surface_notes_carry_the_description_and_every_evidence_block() {
        let mut note = finding("Assessment Surface", Severity::Info, 0.0);
        note.kind = crate::models::finding::FindingKind::ScanInformation;
        note.description = "87 pages were assessed.".into();
        note.evidences = vec![crate::models::finding::Evidence {
            evidence_type: "assessment_surface".into(),
            title: "Pages assessed (87)".into(),
            content: "https://app.test/".into(),
            hash: String::new(),
        }];

        let split = ReportFindings::partition(&[note]);
        let notes = split.surface_notes();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].0, "87 pages were assessed.");
        assert_eq!(notes[0].1[0].0, "Pages assessed (87)");
    }

    #[test]
    fn severity_counts_tally_correctly() {
        let f = vec![
            finding("a", Severity::Critical, 9.0),
            finding("b", Severity::High, 8.0),
            finding("c", Severity::High, 7.5),
            finding("d", Severity::Info, 0.0),
        ];
        let c = SeverityCounts::of(&f);
        assert_eq!(c.critical, 1);
        assert_eq!(c.high, 2);
        assert_eq!(c.total(), 4);
        assert_eq!(c.actionable(), 3, "informational findings are not actionable");
    }

    #[test]
    fn a_clean_fully_covered_assessment_scores_strong() {
        // Derived from the catalogue rather than hardcoded: adding an engine
        // must not leave this test asserting yesterday's full coverage.
        let engines: Vec<String> = crate::checklist::catalog::WSTG_CATALOG
            .iter()
            .flat_map(|item| item.engines.iter())
            .filter(|e| **e != crate::checklist::catalog::engine::ANALYST)
            .map(|e| (*e).to_string())
            .collect();
        let coverage = crate::checklist::ChecklistEngine::assess(&engines, &[]);
        let p = PostureScore::compute(&SeverityCounts::default(), Some(&coverage));
        assert_eq!(p.band, PostureBand::Strong);
        assert_eq!(p.score, 100.0);
    }

    #[test]
    fn a_clean_but_barely_covered_assessment_does_not_score_strong() {
        // No engines ran, so nothing was actually tested.
        let coverage = crate::checklist::ChecklistEngine::assess(&[], &[]);
        let p = PostureScore::compute(&SeverityCounts::default(), Some(&coverage));
        assert!(
            p.band != PostureBand::Strong,
            "an untested application must not be reported as strong (got {:?} at {})",
            p.band, p.score
        );
    }

    #[test]
    fn any_critical_finding_forces_the_critical_band() {
        let counts = SeverityCounts { critical: 1, ..Default::default() };
        assert_eq!(PostureScore::compute(&counts, None).band, PostureBand::Critical);
    }

    #[test]
    fn posture_score_never_goes_negative() {
        let counts = SeverityCounts { critical: 40, high: 40, medium: 40, low: 40, info: 0 };
        let p = PostureScore::compute(&counts, None);
        assert!(p.score >= 0.0, "score went negative: {}", p.score);
    }

    #[test]
    fn more_findings_never_increase_the_score() {
        let few = SeverityCounts { medium: 1, ..Default::default() };
        let many = SeverityCounts { medium: 6, ..Default::default() };
        assert!(PostureScore::compute(&many, None).score < PostureScore::compute(&few, None).score);
    }

    #[test]
    fn every_posture_band_has_a_verdict_and_colour() {
        for band in [PostureBand::Strong, PostureBand::Adequate, PostureBand::NeedsImprovement,
                     PostureBand::AtRisk, PostureBand::Critical] {
            assert!(!band.verdict().is_empty());
            assert!(band.color().starts_with('#'));
            assert!(!band.label().is_empty());
        }
    }

    #[test]
    fn sorting_is_deterministic_for_equal_scores() {
        let a = finding("aaa", Severity::High, 7.0);
        let b = finding("bbb", Severity::High, 7.0);
        let one = sort_by_priority(&[a.clone(), b.clone()]);
        let two = sort_by_priority(&[b, a]);
        assert_eq!(
            one.iter().map(|f| f.title.clone()).collect::<Vec<_>>(),
            two.iter().map(|f| f.title.clone()).collect::<Vec<_>>(),
            "sort order must not depend on input order"
        );
    }

    #[test]
    fn sorting_puts_the_highest_priority_first() {
        let sorted = sort_by_priority(&[
            finding("low", Severity::Low, 3.0),
            finding("crit", Severity::Critical, 9.8),
            finding("med", Severity::Medium, 5.5),
        ]);
        assert_eq!(sorted[0].title, "crit");
        assert_eq!(sorted[2].title, "low");
    }

    #[test]
    fn sarif_output_is_valid_json_with_unique_rules() {
        let findings = vec![
            finding("XSS one", Severity::High, 8.0),
            finding("XSS two", Severity::High, 7.0), // same CWE
        ];
        let sarif = ReportEngine::generate_sarif_json(&findings);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1, "findings sharing a CWE collapse to one SARIF rule");
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn sarif_levels_map_severity_correctly() {
        assert_eq!(sarif_level(&Severity::Critical), "error");
        assert_eq!(sarif_level(&Severity::Medium), "warning");
        assert_eq!(sarif_level(&Severity::Info), "note");
    }

    #[test]
    fn json_export_round_trips() {
        let ctx = ReportContext::new("Acme", "Portal", "https://app.test");
        let json = ReportEngine::generate_json(&ctx, &[finding("x", Severity::High, 8.0)], None);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["engagement"]["company_name"], "Acme");
        assert_eq!(parsed["summary"]["totalFindings"], 1);
        assert!(parsed["findings"].as_array().unwrap().len() == 1);
    }

    #[test]
    fn remediation_windows_are_ordered_by_urgency() {
        assert!(remediation_window(&Severity::Critical).contains("Immediate"));
        assert!(remediation_window(&Severity::High).contains("7 days"));
        assert!(remediation_window(&Severity::Low).contains("90 days"));
    }
}
