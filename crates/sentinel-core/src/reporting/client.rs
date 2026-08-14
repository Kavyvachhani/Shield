//! Client / executive report.
//!
//! Written for a reader who owns the risk but does not write the code: no CVSS
//! vectors, no stack traces, no payloads. It answers four questions — what was
//! checked, how healthy is it, what does that mean for the business, and what
//! happens next — and shows the full checklist so the client can see the checks
//! that passed, not only the ones that failed.

use super::charts::{self, Slice};
use super::escape::{html, html_multiline, image_data_uri};
use super::{
    base_stylesheet, footer_html, remediation_window, sort_by_priority, PostureScore,
    ReportContext, SeverityCounts,
};
use crate::checklist::{CheckStatus, CoverageReport};
use crate::models::finding::{Finding, Severity};
use crate::scoring::priority::PriorityScoringEngine;

/// Render the complete client report as a self-contained HTML document.
pub fn render(
    ctx: &ReportContext,
    findings: &[Finding],
    coverage: Option<&CoverageReport>,
) -> String {
    let sorted = sort_by_priority(findings);
    let counts = SeverityCounts::of(&sorted);
    let posture = PostureScore::compute(&counts, coverage);

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment Report — {company}</title>
<style>{css}</style>
</head>
<body>
<div class="page">
  <div class="banner">Confidential — prepared for {company}</div>
  {cover}
  {summary}
  {posture_section}
  {breakdown}
  {coverage_section}
  {top_risks}
  {roadmap}
  {compliance}
  {methodology}
  {scope}
  {footer}
</div>
</body>
</html>"##,
        company = html(&ctx.company_name),
        css = base_stylesheet(),
        cover = cover(ctx),
        summary = executive_summary(ctx, &counts, &posture, coverage),
        posture_section = posture_panel(&posture, &counts),
        breakdown = severity_breakdown(&counts),
        coverage_section = coverage_section(coverage),
        top_risks = top_risks(&sorted),
        roadmap = roadmap(&sorted),
        compliance = compliance(&counts, coverage),
        methodology = methodology(ctx),
        scope = scope_and_attestation(ctx),
        footer = footer_html(ctx, "Security Assessment Report"),
    )
}

fn cover(ctx: &ReportContext) -> String {
    let logo = ctx
        .logo_data_uri
        .as_deref()
        .and_then(image_data_uri)
        .map(|uri| format!(r##"<img src="{uri}" alt="" style="max-height:52px;margin-bottom:18px">"##))
        .unwrap_or_default();

    format!(
        r##"<header style="margin:26px 0 8px">
  {logo}
  <div class="small muted" style="letter-spacing:2px;text-transform:uppercase">Security Assessment Report</div>
  <h1 style="font-size:32px;margin:8px 0 6px">{target}</h1>
  <div class="muted">Prepared for <strong>{company}</strong></div>
  <table style="margin-top:22px">
    <tbody>
      <tr><th style="width:210px">Application under test</th><td>{url}</td></tr>
      <tr><th>Assessment period</th><td>{start} to {end} (UTC)</td></tr>
      <tr><th>Performed by</th><td>{analyst}</td></tr>
      <tr><th>Report reference</th><td>{reference}</td></tr>
      <tr><th>Classification</th><td>Confidential — restricted to authorised recipients</td></tr>
    </tbody>
  </table>
</header>"##,
        logo = logo,
        target = html(&ctx.target_name),
        company = html(&ctx.company_name),
        url = html(&ctx.target_url),
        start = ctx.assessment_start.format("%d %B %Y"),
        end = ctx.assessment_end.format("%d %B %Y"),
        analyst = html(&ctx.analyst),
        reference = html(&ctx.report_reference),
    )
}

fn executive_summary(
    ctx: &ReportContext,
    counts: &SeverityCounts,
    posture: &PostureScore,
    coverage: Option<&CoverageReport>,
) -> String {
    let checks_line = match coverage {
        Some(c) => format!(
            "We assessed {total} security test cases drawn from the OWASP Web Security Testing Guide. \
             {exercised} were exercised automatically, of which {passed} passed cleanly and {issues} \
             raised findings. A further {manual} require hands-on review by an analyst.",
            total = c.total_checks,
            exercised = c.passed + c.issues_found,
            passed = c.passed,
            issues = c.issues_found,
            manual = c.manual_required,
        ),
        None => "The application was assessed against the OWASP Web Security Testing Guide.".to_string(),
    };

    let findings_line = if counts.total() == 0 {
        "No security weaknesses were identified during this assessment.".to_string()
    } else {
        format!(
            "The assessment identified <strong>{total} finding{plural}</strong>: \
             {critical} critical, {high} high, {medium} medium, {low} low and {info} informational.",
            total = counts.total(),
            plural = if counts.total() == 1 { "" } else { "s" },
            critical = counts.critical,
            high = counts.high,
            medium = counts.medium,
            low = counts.low,
            info = counts.info,
        )
    };

    let urgency = if counts.critical > 0 {
        format!(
            "<div class=\"warn\"><strong>Immediate attention required.</strong> {n} critical finding{p} \
             {were} confirmed against the live application. These should be remediated before the next \
             release and, where customer data is involved, assessed against your breach-notification obligations.</div>",
            n = counts.critical,
            p = if counts.critical == 1 { "" } else { "s" },
            were = if counts.critical == 1 { "was" } else { "were" },
        )
    } else {
        String::new()
    };

    format!(
        r##"<h2>Executive Summary</h2>
<p>{intro}</p>
<p>{checks}</p>
<p>{findings}</p>
<div class="callout"><strong>Overall verdict — {band} ({score:.0}/100).</strong> {verdict}</div>
{urgency}"##,
        intro = format!(
            "This report presents the results of a security assessment of <strong>{}</strong>, \
             carried out for {} under a signed authorisation. Testing was non-destructive throughout: \
             no data was modified or removed, and no availability-affecting technique was used.",
            html(&ctx.target_name),
            html(&ctx.company_name)
        ),
        checks = checks_line,
        findings = findings_line,
        band = html(posture.band.label()),
        score = posture.score,
        verdict = posture.band.verdict(),
        urgency = urgency,
    )
}

fn posture_panel(posture: &PostureScore, counts: &SeverityCounts) -> String {
    format!(
        r##"<div class="grid grid-2" style="margin-top:20px;align-items:center">
  <div class="card" style="text-align:center">
    {gauge}
    <div class="small muted" style="margin-top:4px">Security posture score</div>
  </div>
  <div class="grid grid-2">
    <div class="kpi"><div class="n" style="color:#b91c1c">{critical}</div><div class="l">Critical</div></div>
    <div class="kpi"><div class="n" style="color:#ea580c">{high}</div><div class="l">High</div></div>
    <div class="kpi"><div class="n" style="color:#ca8a04">{medium}</div><div class="l">Medium</div></div>
    <div class="kpi"><div class="n" style="color:#0284c7">{low}</div><div class="l">Low</div></div>
  </div>
</div>"##,
        gauge = charts::posture_gauge(posture.score, posture.band.label(), posture.band.color()),
        critical = counts.critical,
        high = counts.high,
        medium = counts.medium,
        low = counts.low,
    )
}

fn severity_breakdown(counts: &SeverityCounts) -> String {
    let slices = vec![
        Slice::new("Critical", counts.critical, charts::severity_color(&Severity::Critical)),
        Slice::new("High", counts.high, charts::severity_color(&Severity::High)),
        Slice::new("Medium", counts.medium, charts::severity_color(&Severity::Medium)),
        Slice::new("Low", counts.low, charts::severity_color(&Severity::Low)),
        Slice::new("Informational", counts.info, charts::severity_color(&Severity::Info)),
    ];

    let legend: String = slices
        .iter()
        .map(|s| {
            format!(
                r##"<span><i class="swatch" style="background:{c}"></i>{l} — {v}</span>"##,
                c = s.color,
                l = html(&s.label),
                v = s.value
            )
        })
        .collect();

    format!(
        r##"<h2>Findings by Severity</h2>
<div class="grid grid-2" style="align-items:center">
  <div class="card" style="text-align:center">{donut}<div class="legend" style="justify-content:center">{legend}</div></div>
  <div class="card">{bars}</div>
</div>
<p class="small muted">Severity reflects the potential business impact if the weakness were exploited, combined with how easily an attacker could reach it.</p>"##,
        donut = charts::donut(&slices, "FINDINGS"),
        legend = legend,
        bars = charts::horizontal_bars(&slices, 460.0),
    )
}

fn coverage_section(coverage: Option<&CoverageReport>) -> String {
    let Some(cov) = coverage else {
        return String::new();
    };

    let slices = vec![
        Slice::new("Passed", cov.passed, "#16a34a"),
        Slice::new("Issues found", cov.issues_found, "#b91c1c"),
        Slice::new("Manual review required", cov.manual_required, "#d97706"),
        Slice::new("Not tested", cov.not_tested, "#94a3b8"),
    ];

    let legend: String = slices
        .iter()
        .map(|s| {
            format!(
                r##"<span><i class="swatch" style="background:{c}"></i>{l} — {v}</span>"##,
                c = s.color,
                l = html(&s.label),
                v = s.value
            )
        })
        .collect();

    let category_rows: String = cov
        .categories
        .iter()
        .map(|c| {
            format!(
                r##"<tr>
  <td><strong>{name}</strong></td>
  <td style="text-align:center">{total}</td>
  <td style="text-align:center;color:#16a34a;font-weight:600">{passed}</td>
  <td style="text-align:center;color:#b91c1c;font-weight:600">{issues}</td>
  <td style="text-align:center;color:#d97706">{manual}</td>
  <td style="text-align:center;color:#64748b">{not_tested}</td>
</tr>"##,
                name = html(&c.category),
                total = c.total,
                passed = c.passed,
                issues = c.issues_found,
                manual = c.manual_required,
                not_tested = c.not_tested,
            )
        })
        .collect();

    let engines = if cov.engines_executed.is_empty() {
        "None".to_string()
    } else {
        html(&cov.engines_executed.join(", "))
    };

    // Full itemised checklist, grouped by category.
    let mut detail = String::new();
    for category in &cov.categories {
        let rows: String = cov
            .results
            .iter()
            .filter(|r| r.category_code == category.category_code)
            .map(|r| {
                let note = if r.finding_count > 0 {
                    format!("{} finding(s) raised", r.finding_count)
                } else {
                    match r.status {
                        CheckStatus::Passed => "No issue observed".to_string(),
                        CheckStatus::ManualRequired => "Requires analyst review".to_string(),
                        CheckStatus::NotTested => {
                            if r.engines_missing.is_empty() {
                                "Not exercised in this assessment".to_string()
                            } else {
                                format!("Requires {}", html(&r.engines_missing.join(" or ")))
                            }
                        }
                        CheckStatus::IssuesFound => "Issues raised".to_string(),
                    }
                };
                format!(
                    r##"<tr>
  <td class="small" style="white-space:nowrap"><code>{id}</code></td>
  <td>{name}<div class="small muted">{summary}</div></td>
  <td style="white-space:nowrap"><span class="pill" style="background:{color}">{status}</span></td>
  <td class="small muted">{note}</td>
</tr>"##,
                    id = html(&r.id),
                    name = html(&r.name),
                    summary = html(&r.client_summary),
                    color = r.status.color(),
                    status = html(&r.status_label),
                    note = note,
                )
            })
            .collect();

        detail.push_str(&format!(
            r##"<h3>{name}</h3>
<table><thead><tr><th style="width:118px">Reference</th><th>Security check performed</th><th style="width:150px">Result</th><th style="width:190px">Notes</th></tr></thead><tbody>{rows}</tbody></table>"##,
            name = html(&category.category),
            rows = rows,
        ));
    }

    format!(
        r##"<h2 class="page-break">Assessment Coverage — Every Check We Performed</h2>
<p>The table below records the full inventory of security test cases considered during this assessment,
so you can see exactly what was examined — including the checks that passed. Test cases are drawn from the
OWASP Web Security Testing Guide, the industry-standard methodology for web application security testing.</p>
<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px">
    <strong>{total} test cases assessed</strong>
    <span class="small muted">{pct:.0}% of automatable checks exercised</span>
  </div>
  {bar}
  <div class="legend">{legend}</div>
  <div class="small muted" style="margin-top:10px">Engines used: {engines}</div>
</div>
<table>
  <thead><tr><th>Category</th><th style="text-align:center">Checks</th><th style="text-align:center">Passed</th><th style="text-align:center">Issues</th><th style="text-align:center">Manual</th><th style="text-align:center">Not tested</th></tr></thead>
  <tbody>{category_rows}</tbody>
</table>
<h3 style="margin-top:26px">Itemised Checklist</h3>
{detail}"##,
        total = cov.total_checks,
        pct = cov.automated_coverage_pct,
        bar = charts::stacked_bar(&slices, 900.0, 16.0),
        legend = legend,
        engines = engines,
        category_rows = category_rows,
        detail = detail,
    )
}

fn top_risks(sorted: &[Finding]) -> String {
    let actionable: Vec<&Finding> = sorted.iter().filter(|f| f.severity != Severity::Info).collect();

    if actionable.is_empty() {
        return r##"<h2 class="page-break">Principal Risks</h2>
<div class="fix"><strong>No actionable weaknesses were identified.</strong> Every automated check that could
be exercised either passed or returned only informational observations. We recommend maintaining the current
controls and repeating this assessment after any significant change to the application.</div>"##
            .to_string();
    }

    let cards: String = actionable
        .iter()
        .take(10)
        .enumerate()
        .map(|(i, f)| {
            format!(
                r##"<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:14px">
    <div>
      <div class="small muted">Risk {rank} of {shown}</div>
      <h3 style="margin:2px 0 0">{title}</h3>
    </div>
    <span class="pill" style="background:{color}">{severity}</span>
  </div>
  <p style="margin-top:12px"><strong>What this means:</strong> {rationale}</p>
  <p><strong>Where it applies:</strong> <span class="small">{component}</span></p>
  <div class="fix"><strong>Recommended action:</strong> {remediation}</div>
  <div class="small muted">Suggested timeframe: {window}</div>
</div>"##,
                rank = i + 1,
                shown = actionable.len().min(10),
                title = html(&f.title),
                color = charts::severity_color(&f.severity),
                severity = charts::severity_name(&f.severity),
                rationale = html(&PriorityScoringEngine::explain_executive(f)),
                component = html(&f.affected_component),
                remediation = html(&f.remediation),
                window = html(remediation_window(&f.severity)),
            )
        })
        .collect();

    let note = if actionable.len() > 10 {
        format!(
            r##"<p class="small muted">The {n} highest-priority risks are shown. All {total} findings are documented in full in the accompanying technical report.</p>"##,
            n = 10,
            total = actionable.len()
        )
    } else {
        String::new()
    };

    format!(
        r##"<h2 class="page-break">Principal Risks</h2>
<p>Risks are ordered by an integrated priority score that combines technical severity, how likely the
weakness is to be exploited in practice, whether it has been observed under active attack, and how exposed
the affected component is.</p>
{cards}
{note}"##
    )
}

fn roadmap(sorted: &[Finding]) -> String {
    let bands: [(Severity, &str); 4] = [
        (Severity::Critical, "Immediate — within 24 to 48 hours"),
        (Severity::High, "Urgent — within 7 days"),
        (Severity::Medium, "Planned — within 30 days"),
        (Severity::Low, "Scheduled — within 90 days"),
    ];

    let rows: String = bands
        .iter()
        .filter_map(|(severity, window)| {
            let items: Vec<&Finding> = sorted.iter().filter(|f| f.severity == *severity).collect();
            if items.is_empty() {
                return None;
            }
            let titles: Vec<String> = items.iter().take(6).map(|f| html(&f.title)).collect();
            let more = if items.len() > 6 {
                format!(" <span class=\"muted\">and {} more</span>", items.len() - 6)
            } else {
                String::new()
            };
            Some(format!(
                r##"<tr>
  <td style="white-space:nowrap"><span class="pill" style="background:{color}">{name}</span></td>
  <td style="text-align:center;font-weight:600">{count}</td>
  <td>{window}</td>
  <td class="small">{titles}{more}</td>
</tr>"##,
                color = charts::severity_color(severity),
                name = charts::severity_name(severity),
                count = items.len(),
                window = html(window),
                titles = titles.join("; "),
                more = more,
            ))
        })
        .collect();

    if rows.is_empty() {
        return String::new();
    }

    format!(
        r##"<h2>Remediation Roadmap</h2>
<p>Suggested sequencing. Timeframes are industry-standard service levels for each severity band; adjust
them to your own risk appetite and change-management process.</p>
<table>
  <thead><tr><th style="width:110px">Severity</th><th style="width:70px">Count</th><th style="width:230px">Target timeframe</th><th>Items</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<p class="small muted">Once remediation is complete we recommend a verification re-test of the affected
items to confirm the fixes are effective and have not introduced new weaknesses.</p>"##
    )
}

fn compliance(counts: &SeverityCounts, coverage: Option<&CoverageReport>) -> String {
    let outstanding = counts.critical + counts.high;
    let (status_text, status_color) = if outstanding > 0 {
        (
            format!("Attention required — {outstanding} high-impact finding(s) outstanding"),
            "#b91c1c",
        )
    } else if counts.medium > 0 {
        (
            format!("Minor gaps — {} medium finding(s) to address", counts.medium),
            "#ca8a04",
        )
    } else {
        ("No material gaps identified".to_string(), "#16a34a")
    };

    let coverage_note = coverage
        .map(|c| {
            format!(
                "This assessment exercised {} of {} catalogued test cases.",
                c.passed + c.issues_found,
                c.total_checks
            )
        })
        .unwrap_or_default();

    format!(
        r##"<h2>Compliance Alignment</h2>
<p>How the findings in this report relate to common assurance frameworks. This is an indicative mapping to
support your compliance programme — it is not a certification, and it does not replace a formal audit.</p>
<table>
  <thead><tr><th style="width:200px">Framework</th><th style="width:280px">Relevant control area</th><th>Status from this assessment</th></tr></thead>
  <tbody>
    <tr><td><strong>OWASP Top 10:2025</strong></td><td>Application security risk categories</td><td><span style="color:{c};font-weight:600">{s}</span></td></tr>
    <tr><td><strong>PCI DSS v4.0.1</strong></td><td>Requirement 6.2 / 6.3 — secure development and vulnerability management</td><td><span style="color:{c};font-weight:600">{s}</span></td></tr>
    <tr><td><strong>ISO/IEC 27001:2022</strong></td><td>Annex A 8.8 — management of technical vulnerabilities</td><td>Assessment performed and evidence retained</td></tr>
    <tr><td><strong>SOC 2 (Trust Services)</strong></td><td>CC7.1 — vulnerability identification and monitoring</td><td>Assessment performed and evidence retained</td></tr>
    <tr><td><strong>NIST SP 800-53 Rev. 5</strong></td><td>RA-5 — vulnerability monitoring and scanning</td><td>Assessment performed and evidence retained</td></tr>
  </tbody>
</table>
<p class="small muted">{note}</p>"##,
        c = status_color,
        s = html(&status_text),
        note = html(&coverage_note),
    )
}

fn methodology(ctx: &ReportContext) -> String {
    let engines = if ctx.engines_executed.is_empty() {
        "the built-in Sentinel Native check engine".to_string()
    } else {
        html(&ctx.engines_executed.join(", "))
    };

    format!(
        r##"<h2>Methodology</h2>
<p>Testing followed the OWASP Web Security Testing Guide (WSTG) v4.2, the recognised industry methodology
for web application security assessment. Results from each engine are normalised into a single format,
de-duplicated so the same weakness reported by two tools appears once, and then ranked.</p>
<table>
  <thead><tr><th style="width:230px">Phase</th><th>What we did</th></tr></thead>
  <tbody>
    <tr><td><strong>1. Authorisation</strong></td><td>Confirmed written permission to test, agreed the scope and exclusions, and recorded a signed Rules of Engagement before any traffic was sent.</td></tr>
    <tr><td><strong>2. Reconnaissance</strong></td><td>Identified the technologies in use, mapped the reachable surface, and reviewed publicly served metadata files.</td></tr>
    <tr><td><strong>3. Configuration review</strong></td><td>Examined transport security, security response headers, cookie handling and exposure of files that should not be public.</td></tr>
    <tr><td><strong>4. Automated testing</strong></td><td>Ran {engines} against the agreed scope, within the agreed rate limit.</td></tr>
    <tr><td><strong>5. Analysis and ranking</strong></td><td>Removed duplicates and likely false positives, then ranked each finding by technical severity, real-world exploitation likelihood, known active exploitation, and exposure of the affected component.</td></tr>
    <tr><td><strong>6. Reporting</strong></td><td>Produced this summary alongside a technical report giving developers the exact location, reproduction steps and fix for every finding.</td></tr>
  </tbody>
</table>
<div class="callout"><strong>Scope of assurance.</strong> Automated testing reliably identifies configuration
and known-pattern weaknesses. It cannot fully evaluate business logic, authorisation between user accounts, or
multi-step workflow abuse — these are marked "Manual review required" in the coverage table and need a human
analyst. A clean automated result is meaningful evidence of hygiene, not a guarantee that no weakness exists.</div>"##
    )
}

fn scope_and_attestation(ctx: &ReportContext) -> String {
    let domains = if ctx.allowed_domains.is_empty() {
        html(&ctx.target_url)
    } else {
        html(&ctx.allowed_domains.join(", "))
    };
    let exclusions = if ctx.out_of_scope_paths.is_empty() {
        "None declared".to_string()
    } else {
        html(&ctx.out_of_scope_paths.join(", "))
    };
    let roe = ctx
        .roe_hash
        .as_deref()
        .map(|h| format!(r##"<tr><th>Authorisation record</th><td class="small"><code>{}</code></td></tr>"##, html(h)))
        .unwrap_or_default();

    format!(
        r##"<h2>Scope &amp; Attestation</h2>
<table>
  <tbody>
    <tr><th style="width:230px">Systems in scope</th><td>{domains}</td></tr>
    <tr><th>Explicit exclusions</th><td>{exclusions}</td></tr>
    <tr><th>Request rate ceiling</th><td>{rps} requests per second</td></tr>
    <tr><th>Testing window</th><td>{start} to {end} (UTC)</td></tr>
    {roe}
  </tbody>
</table>
<div class="callout"><strong>Attestation.</strong> All testing was performed with written authorisation and
confined to the systems listed above. Techniques were non-destructive: no data was created, modified or
deleted, no denial-of-service or resource-exhaustion technique was used, and request rates were held within
the agreed ceiling. Any credentials or personal data encountered were redacted before inclusion in this report.</div>
<p class="small muted">This report reflects the state of the application during the testing window only.
Subsequent changes to code, configuration or infrastructure may introduce new weaknesses.</p>"##,
        rps = ctx.rate_limit_rps,
        start = ctx.assessment_start.format("%d %B %Y %H:%M"),
        end = ctx.assessment_end.format("%d %B %Y %H:%M"),
    )
}

/// Escape helper re-export used by the roadmap's inline description.
#[allow(dead_code)]
fn describe(f: &Finding) -> String {
    html_multiline(&f.description)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checklist::ChecklistEngine;
    use crate::reporting::tests::finding;

    fn ctx() -> ReportContext {
        let mut c = ReportContext::new("Acme Corp", "Customer Portal", "https://portal.acme.test");
        c.engines_executed = vec!["Sentinel Native".into(), "OWASP ZAP".into()];
        c.allowed_domains = vec!["portal.acme.test".into()];
        c.out_of_scope_paths = vec!["/admin/shutdown".into()];
        c.roe_hash = Some("abc123".into());
        c
    }

    #[test]
    fn report_is_a_complete_html_document() {
        let html_out = render(&ctx(), &[finding("XSS", Severity::High, 8.0)], None);
        assert!(html_out.starts_with("<!DOCTYPE html>"));
        assert!(html_out.trim_end().ends_with("</html>"));
        assert!(html_out.contains("<title>"));
    }

    #[test]
    fn report_contains_no_scripts_or_external_resources() {
        let cov = ChecklistEngine::assess(&["Sentinel Native".into()], &[]);
        let out = render(&ctx(), &[finding("XSS", Severity::High, 8.0)], Some(&cov));
        assert!(!out.contains("<script"), "client report must contain no script");
        assert!(!out.contains("src=\"http"), "no remote images");
        assert!(!out.contains("@import"), "no remote stylesheets");
    }

    #[test]
    fn malicious_finding_content_cannot_inject_markup() {
        let mut evil = finding("<img src=x onerror=alert(1)>", Severity::High, 8.0);
        evil.affected_component = "https://app.test/?q=</td><script>alert(1)</script>".into();
        evil.remediation = "<script>steal()</script>".into();
        let out = render(&ctx(), &[evil], None);
        assert!(!out.contains("<script>alert(1)</script>"));
        // The payload survives as inert text; what matters is that no live tag
        // can form from it — the angle brackets are escaped.
        assert!(!out.contains("<img src=x"));
        assert!(out.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(out.contains("&lt;img src=x"));
    }

    #[test]
    fn malicious_company_name_is_escaped_in_the_title() {
        let mut c = ctx();
        c.company_name = "</title><script>alert(1)</script>".into();
        let out = render(&c, &[], None);
        assert!(!out.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn executive_report_omits_developer_only_detail() {
        let out = render(&ctx(), &[finding("XSS", Severity::High, 8.0)], None);
        assert!(!out.contains("CVSS:4.0/"), "raw CVSS vectors are not for this audience");
        assert!(!out.contains("CWE-79"), "CWE identifiers are not for this audience");
    }

    #[test]
    fn coverage_section_lists_passed_checks_not_only_failures() {
        let cov = ChecklistEngine::assess(&["Sentinel Native".into()], &[]);
        let out = render(&ctx(), &[], Some(&cov));
        assert!(out.contains("Every Check We Performed"));
        assert!(out.contains("WSTG-CONF-12"), "itemised checklist must name individual checks");
        assert!(out.contains("Passed"));
        assert!(out.contains("No issue observed"));
    }

    #[test]
    fn coverage_section_is_omitted_when_no_coverage_was_computed() {
        let out = render(&ctx(), &[], None);
        assert!(!out.contains("Every Check We Performed"));
    }

    #[test]
    fn a_clean_assessment_states_so_explicitly() {
        let out = render(&ctx(), &[], None);
        assert!(out.contains("No security weaknesses were identified"));
        assert!(out.contains("No actionable weaknesses were identified"));
    }

    #[test]
    fn critical_findings_produce_an_urgency_callout() {
        let out = render(&ctx(), &[finding("RCE", Severity::Critical, 9.9)], None);
        assert!(out.contains("Immediate attention required"));
    }

    #[test]
    fn informational_findings_do_not_appear_as_principal_risks() {
        let out = render(&ctx(), &[finding("Banner", Severity::Info, 0.0)], None);
        assert!(out.contains("No actionable weaknesses were identified"));
    }

    #[test]
    fn roadmap_groups_findings_by_severity_band() {
        let findings = vec![
            finding("crit", Severity::Critical, 9.5),
            finding("high", Severity::High, 8.0),
            finding("med", Severity::Medium, 5.0),
        ];
        let out = render(&ctx(), &findings, None);
        assert!(out.contains("Remediation Roadmap"));
        assert!(out.contains("within 24 to 48 hours"));
        assert!(out.contains("within 7 days"));
    }

    #[test]
    fn scope_and_attestation_reflect_the_engagement() {
        let out = render(&ctx(), &[], None);
        assert!(out.contains("portal.acme.test"));
        assert!(out.contains("/admin/shutdown"));
        assert!(out.contains("abc123"));
        assert!(out.contains("Attestation"));
    }

    #[test]
    fn methodology_is_honest_about_automation_limits() {
        let out = render(&ctx(), &[], None);
        assert!(out.contains("Manual review required"));
        assert!(out.contains("not a guarantee"));
    }

    #[test]
    fn only_the_top_ten_risks_are_detailed() {
        let findings: Vec<Finding> = (0..15)
            .map(|i| finding(&format!("Finding {i}"), Severity::High, 8.0 - i as f64 * 0.1))
            .collect();
        let out = render(&ctx(), &findings, None);
        assert!(out.contains("Risk 10 of 10"));
        assert!(!out.contains("Risk 11 of"));
        assert!(out.contains("All 15 findings are documented"));
    }
}
