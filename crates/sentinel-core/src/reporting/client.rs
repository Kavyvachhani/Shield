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
    base_stylesheet, footer_html, remediation_window, PostureScore, ReportContext, ReportFindings,
    SeverityCounts,
};
use crate::checklist::{CheckStatus, CoverageReport};
use crate::exceptions::ExceptionRecord;
use crate::reporting::owasp;
use crate::models::finding::{Finding, Severity};
use crate::scoring::priority::PriorityScoringEngine;
use chrono::Utc;

/// Render the complete client report as a self-contained HTML document.
pub fn render(
    ctx: &ReportContext,
    findings: &[Finding],
    coverage: Option<&CoverageReport>,
) -> String {
    // Accepted risks are held out of the live picture: they are disclosed in
    // their own register with the justification and the owner, rather than
    // counted as open exposure the client is expected to act on.
    let split = ReportFindings::partition(findings);
    let counts = split.counts();
    let posture = PostureScore::compute(&counts, coverage);

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment Report — {company}</title>
<style>{css}{extra_css}</style>
</head>
<body>
<div class="page">
  <div class="banner">{classification} — prepared for {company}</div>
  {cover}
  {contents}
  {summary}
  {posture_section}
  {breakdown}
  {controls_verified}
  {coverage_section}
  {top_risks}
  {accepted}
  {progress}
  {roadmap}
  {owasp}
  {compliance}
  {methodology}
  {assurance}
  {scope}
  {signoff}
  {footer}
</div>
</body>
</html>"##,
        company = html(&ctx.company_name),
        classification = html(&ctx.classification),
        css = base_stylesheet(),
        extra_css = extra_stylesheet(),
        cover = cover(ctx),
        contents = contents(coverage, &split, ctx.comparison.is_some()),
        summary = executive_summary(ctx, &counts, &posture, coverage, &split),
        posture_section = posture_panel(&posture, &counts),
        breakdown = severity_breakdown(&counts),
        controls_verified = controls_verified(coverage),
        coverage_section = coverage_section(coverage),
        top_risks = top_risks(&split.active),
        accepted = accepted_risk_register(ctx, &split),
        progress = remediation_progress(ctx),
        roadmap = roadmap(&split.active),
        owasp = owasp_rollup(&split),
        compliance = compliance(&counts, coverage),
        methodology = methodology(ctx),
        assurance = assurance(ctx, coverage, findings, &split),
        scope = scope_and_attestation(ctx),
        signoff = signoff(ctx),
        footer = footer_html(ctx, "Security Assessment Report"),
    )
}

/// Styles used only by this document, appended to the shared sheet.
fn extra_stylesheet() -> &'static str {
    r##"
.toc{columns:2;column-gap:34px;font-size:13px;margin:6px 0 4px}
.toc div{break-inside:avoid;padding:3px 0;border-bottom:1px dotted var(--line)}
.toc .n{display:inline-block;width:24px;color:var(--muted);font-variant-numeric:tabular-nums}
.control{border:1px solid var(--line);border-left:3px solid #16a34a;border-radius:0 8px 8px 0;
  padding:11px 14px;background:#fbfefc}
.control h4{font-size:13px;margin:0 0 3px}
.control .ref{font-size:11px;color:var(--muted);font-family:'Cascadia Mono',Consolas,monospace}
.tick{color:#16a34a;font-weight:700;margin-right:5px}
.sign{border:1px solid var(--line);border-radius:9px;padding:16px 18px;background:var(--bg)}
.sign .line{border-bottom:1px solid #94a3b8;height:34px;margin-top:14px}
@media print{.toc{columns:2}.control,.sign{page-break-inside:avoid}}
"##
}

/// Contents page, so a printed report can be navigated.
fn contents(
    coverage: Option<&CoverageReport>,
    split: &ReportFindings,
    has_comparison: bool,
) -> String {
    let mut entries: Vec<&str> = vec![
        "Executive Summary",
        "Findings by Severity",
    ];
    if coverage.is_some() {
        entries.push("Controls Verified — What Is Protecting You");
        entries.push("Assessment Coverage — Every Check We Performed");
    }
    entries.push("Principal Risks");
    if !split.accepted.is_empty() {
        entries.push("Accepted Risk Register");
    }
    if has_comparison {
        entries.push("Remediation Progress");
    }
    if !split.active.is_empty() {
        entries.push("Remediation Roadmap");
    }
    entries.extend([
        "OWASP Top 10:2025 — Where the Findings Sit",
        "Compliance Alignment",
        "Methodology",
        "Assurance, Evidence &amp; Limitations",
        "Scope &amp; Attestation",
        "Sign-off",
    ]);

    let items: String = entries
        .iter()
        .enumerate()
        .map(|(i, name)| format!(r##"<div><span class="n">{}</span>{name}</div>"##, i + 1))
        .collect();

    format!(r##"<h2>Contents</h2><div class="toc">{items}</div>"##)
}

fn cover(ctx: &ReportContext) -> String {
    let logo = ctx
        .logo_data_uri
        .as_deref()
        .and_then(image_data_uri)
        // max-width matters as much as max-height: a wide banner logo bounded
        // only by height renders wider than the page and breaks the layout.
        .map(|uri| {
            format!(
                r##"<img src="{uri}" alt="" style="max-height:52px;max-width:260px;object-fit:contain;margin-bottom:18px">"##
            )
        })
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
      <tr><th>Revision</th><td>{revision} — issued {issued}</td></tr>
      <tr><th>Reviewed by</th><td>{reviewer}</td></tr>
      <tr><th>Classification</th><td>{classification} — restricted to authorised recipients</td></tr>
      <tr><th>Distribution</th><td>{company}, named recipients only. Do not forward without the issuer&#39;s consent.</td></tr>
      <tr><th>Retention</th><td>Held for the period agreed in the engagement letter, then destroyed.</td></tr>
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
        revision = html(&ctx.revision),
        issued = ctx.assessment_end.format("%d %B %Y"),
        reviewer = html(ctx.reviewed_by.as_deref().unwrap_or("Pending independent review")),
        classification = html(&ctx.classification),
    )
}

fn executive_summary(
    ctx: &ReportContext,
    counts: &SeverityCounts,
    posture: &PostureScore,
    coverage: Option<&CoverageReport>,
    split: &ReportFindings,
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

    // The intro is built first rather than nested inside the outer `format!`,
    // which clippy rightly flags: a `format!` evaluated as an argument to
    // another allocates twice and hides the escaping in the middle of a layout.
    let intro = format!(
        "This report presents the results of a security assessment of <strong>{target}</strong>, \
         carried out for {company} under a signed authorisation between {start} and {end}. \
         Testing was non-destructive throughout: no data was created, modified or removed, and \
         no availability-affecting technique was used.",
        target = html(&ctx.target_name),
        company = html(&ctx.company_name),
        start = ctx.assessment_start.format("%d %B %Y"),
        end = ctx.assessment_end.format("%d %B %Y"),
    );

    // What the client actively decided to carry, stated up front rather than
    // buried: an executive reading only this page must not mistake a suppressed
    // count for an absent risk.
    let accepted_line = if split.accepted.is_empty() {
        String::new()
    } else {
        format!(
            "<p>A further <strong>{n} weakness{plural}</strong> {is} formally accepted by {company} \
             and {is2} therefore excluded from the counts and the score above. {they} remain{s} \
             disclosed in full in the <em>Accepted Risk Register</em> later in this report, with the \
             justification recorded for each.</p>",
            n = split.accepted.len(),
            plural = if split.accepted.len() == 1 { "" } else { "es" },
            is = if split.accepted.len() == 1 { "is" } else { "are" },
            is2 = if split.accepted.len() == 1 { "is" } else { "are" },
            they = if split.accepted.len() == 1 { "It" } else { "They" },
            s = if split.accepted.len() == 1 { "s" } else { "" },
            company = html(&ctx.company_name),
        )
    };

    format!(
        r##"<h2>Executive Summary</h2>
<p>{intro}</p>
<p>{checks}</p>
<p>{findings}</p>
{accepted_line}
<div class="callout"><strong>Overall verdict — {band} ({score:.0}/100).</strong> {verdict}</div>
{urgency}"##,
        intro = intro,
        checks = checks_line,
        findings = findings_line,
        accepted_line = accepted_line,
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

/// What a clean result in each WSTG category actually buys the client.
///
/// The coverage matrix answers "was this tested"; a client also needs "and what
/// does passing it protect me from". Written for the reader who signs the
/// cheque, not the one who writes the code.
fn category_assurance(code: &str) -> &'static str {
    match code {
        "INFO" => "The application does not volunteer the details an attacker uses to plan an attack — server and framework versions, internal hostnames, source-control metadata, backup files or developer notes left in the page.",
        "CONF" => "Transport security, security response headers and file exposure are configured as expected. Traffic is encrypted, the browser is instructed to enforce the site's own security rules, and files that belong on a build server are not being served to the internet.",
        "IDNT" => "Account provisioning and role definitions behave as intended: accounts cannot be enumerated from the outside, and the roles the application defines are the roles it actually enforces.",
        "ATHN" => "The login path holds up: credentials are transmitted over an encrypted channel, the mechanism resists guessing and replay, and the application does not disclose whether a username exists.",
        "ATHZ" => "Access control decisions are made on the server. A user cannot reach another user's data or an administrative function by editing a URL, an identifier or a client-side value.",
        "SESS" => "Sessions are issued, protected and ended correctly. Cookies carry the attributes that stop them being read by scripts, sent over plaintext, or replayed from another site.",
        "INPV" => "Data supplied by a user is treated as data, not as code. The injection classes that lead to database compromise, script execution in a victim's browser or command execution on the server were exercised and not observed.",
        "ERRH" => "Failures are handled without disclosing internal detail. Stack traces, SQL fragments and file paths — the material that turns a probe into a working exploit — are not returned to the client.",
        "CRYP" => "Encryption is applied where it is needed and configured to current standards: valid certificates, modern protocol versions and strong algorithms, with no downgrade to obsolete cryptography.",
        "BUSL" => "The application's own rules were reviewed for abuse: workflows that can be completed out of order, limits that can be bypassed, and values a user should not be able to influence.",
        "CLNT" => "Code running in the user's browser does not create a way in. Third-party scripts, cross-origin policy and client-side rendering were reviewed for weaknesses that a server-side review would miss.",
        "APIT" => "Programmatic interfaces were assessed alongside the web interface, so an endpoint that the browser never calls is not left unexamined.",
        _ => "The checks in this category were exercised and returned no issue.",
    }
}

/// The controls this assessment actively confirmed to be in place.
///
/// The coverage matrix further down is exhaustive and therefore long. This
/// section is the answer to the question a client actually asks — "so what is
/// protecting us?" — expressed as the specific test cases that passed.
fn controls_verified(coverage: Option<&CoverageReport>) -> String {
    let Some(cov) = coverage else {
        return String::new();
    };

    let passed: Vec<&crate::checklist::CheckResult> = cov
        .results
        .iter()
        .filter(|r| r.status == CheckStatus::Passed)
        .collect();

    if passed.is_empty() {
        return r##"<h2 class="page-break">Controls Verified — What Is Protecting You</h2>
<div class="warn"><strong>No check completed cleanly in this assessment.</strong> That is a statement about the
assessment, not about the application: without an engine covering a test case there is no basis on which to
confirm a control is working. Install the engines listed as unavailable in the coverage table, or arrange a
manual assessment, before drawing any conclusion about the controls below.</div>"##
            .to_string();
    }

    let mut blocks = String::new();
    for category in &cov.categories {
        let items: Vec<&&crate::checklist::CheckResult> = passed
            .iter()
            .filter(|r| r.category_code == category.category_code)
            .collect();
        if items.is_empty() {
            continue;
        }

        let cards: String = items
            .iter()
            .map(|r| {
                format!(
                    r##"<div class="control">
  <h4><span class="tick">&#10003;</span>{name}</h4>
  <div class="small muted">{summary}</div>
  <div class="ref">{id} &middot; verified by {engines}</div>
</div>"##,
                    name = html(&r.name),
                    summary = html(&r.client_summary),
                    id = html(&r.id),
                    engines = html(&if r.engines_executed.is_empty() {
                        "the assessment engine".to_string()
                    } else {
                        r.engines_executed.join(", ")
                    }),
                )
            })
            .collect();

        blocks.push_str(&format!(
            r##"<h3>{name} — {n} of {total} checks passed</h3>
<p class="small">{assurance}</p>
<div class="grid grid-2">{cards}</div>"##,
            name = html(&category.category),
            n = items.len(),
            total = category.total,
            assurance = category_assurance(&category.category_code),
            cards = cards,
        ));
    }

    let engines = if cov.engines_executed.is_empty() {
        "the built-in check engine".to_string()
    } else {
        html(&cov.engines_executed.join(", "))
    };

    format!(
        r##"<h2 class="page-break">Controls Verified — What Is Protecting You</h2>
<p>A security report that lists only what is broken tells you half the story. This section records the
<strong>{n} test cases that were exercised against {target_desc} and came back clean</strong>: each one is a
control that was actively examined and found to be doing its job, not an assumption.</p>
<div class="fix"><strong>How we established this.</strong> Every entry below was tested by {engines} against
the live application inside the authorised scope. A control is only listed here when an engine capable of
answering that test case ran and returned no issue — a check nothing could exercise is reported as
&ldquo;Not tested&rdquo; in the coverage matrix, never as a pass. Evidence for each observation was captured
and hashed at the time of testing and is retained with the engagement record.</div>
{blocks}"##,
        n = passed.len(),
        target_desc = "the application",
        engines = engines,
        blocks = blocks,
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

/// The weaknesses the business has formally chosen to carry.
///
/// This section is why an exception can safely take a finding out of the score
/// above. Suppressing a risk without disclosing it would make the report
/// dishonest; disclosing it here, with who accepted it, why, and when the
/// decision is due for review, is exactly what an auditor expects to find.
fn accepted_risk_register(ctx: &ReportContext, split: &ReportFindings) -> String {
    if split.accepted.is_empty() {
        return String::new();
    }

    let now = Utc::now();
    let register = crate::exceptions::ExceptionRegister::from_records(ctx.exceptions.iter());

    let rows: String = split
        .accepted
        .iter()
        .map(|f| {
            let record: Option<&ExceptionRecord> = register.covering(f, now);
            let justification = record
                .map(|r| html(&r.justification))
                .unwrap_or_else(|| "Recorded during triage — see the engagement record.".to_string());
            let owner = record
                .map(|r| html(&r.raised_by))
                .unwrap_or_else(|| "Not recorded".to_string());
            let accepted_on = record
                .map(|r| r.created_at.format("%d %b %Y").to_string())
                .unwrap_or_else(|| "—".to_string());
            let review = match record.and_then(|r| r.expires_at) {
                Some(when) => {
                    let days = (when - now).num_days();
                    let colour = if days <= 30 { "#ea580c" } else { "#334155" };
                    format!(
                        r##"<span style="color:{colour};font-weight:600">{}</span><div class="small muted">{days} days</div>"##,
                        when.format("%d %b %Y")
                    )
                }
                None => r##"<span class="muted">Open-ended</span>"##.to_string(),
            };

            format!(
                r##"<tr>
  <td><strong>{title}</strong><div class="small muted">{component}</div></td>
  <td style="white-space:nowrap"><span class="pill" style="background:{colour}">{severity}</span></td>
  <td class="small">{justification}</td>
  <td class="small" style="white-space:nowrap">{owner}<div class="muted">{accepted_on}</div></td>
  <td class="small" style="white-space:nowrap">{review}</td>
</tr>"##,
                title = html(&f.title),
                component = html(&f.affected_component),
                colour = charts::severity_color(&f.severity),
                severity = charts::severity_name(&f.severity),
                justification = justification,
                owner = owner,
                accepted_on = accepted_on,
                review = review,
            )
        })
        .collect();

    let lapsing = split
        .accepted
        .iter()
        .filter_map(|f| register.covering(f, now))
        .filter(|r| r.days_until_expiry(now).is_some_and(|d| d <= 30))
        .count();

    let due_note = if lapsing > 0 {
        format!(
            r##"<div class="warn"><strong>{lapsing} acceptance{p} due for review within 30 days.</strong>
An acceptance that lapses is not renewed automatically: the weakness returns to the open findings list in the
next assessment, which is what stops &ldquo;accepted&rdquo; quietly becoming &ldquo;forgotten&rdquo;.</div>"##,
            p = if lapsing == 1 { "" } else { "s" },
        )
    } else {
        String::new()
    };

    format!(
        r##"<h2 class="page-break">Accepted Risk Register</h2>
<p>The weaknesses below are real and were confirmed during testing. {company} has formally accepted them,
so they are excluded from the finding counts, the posture score and the remediation roadmap — but they are
<strong>not</strong> removed from this report. Accepted exposure is disclosed, never deleted.</p>
<table>
  <thead><tr>
    <th>Weakness and location</th>
    <th style="width:88px">Severity</th>
    <th style="width:260px">Business justification</th>
    <th style="width:140px">Accepted by</th>
    <th style="width:110px">Review due</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>
{due_note}
<p class="small muted">Each entry remains the accepting party&#39;s risk to own. Should the surrounding
circumstances change — a new integration, a change of data classification, or public exploitation of the
weakness class — the acceptance should be revisited ahead of its review date.</p>"##,
        company = html(&ctx.company_name),
        rows = rows,
        due_note = due_note,
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

/// What changed since the previous assessment.
///
/// The question actually asked after a remediation cycle is not "what is wrong"
/// but "did the work land, and did anything get worse". Without this the reader
/// has to diff two PDFs by hand, which is how a regression survives a quarter.
fn remediation_progress(ctx: &ReportContext) -> String {
    let Some(delta) = ctx.comparison.as_ref() else {
        return String::new();
    };

    let row = |label: &str, count: usize, colour: &str, meaning: &str| {
        format!(
            r##"<tr>
  <td><strong>{label}</strong><div class="small muted">{meaning}</div></td>
  <td style="text-align:center;font-size:22px;font-weight:800;color:{colour}">{count}</td>
</tr>"##
        )
    };

    let resolved_list = if delta.resolved.is_empty() {
        String::new()
    } else {
        let items: String = delta
            .resolved
            .iter()
            .take(15)
            .map(|f| {
                format!(
                    r##"<li>{title} <span class="small muted">({severity} — {component})</span></li>"##,
                    title = html(&f.title),
                    severity = charts::severity_name(&f.severity),
                    component = html(&f.affected_component),
                )
            })
            .collect();
        format!(
            r##"<h3>Confirmed closed</h3>
<p class="small">Each of these was present in the previous assessment and could not be reproduced in
this one. This is the only place in the report that evidences remediation working — and it is why a
finding marked fixed by hand is still re-tested rather than taken at its word.</p>
<ul class="small">{items}</ul>"##
        )
    };

    let new_list = if delta.newly_found.is_empty() {
        String::new()
    } else {
        let items: String = delta
            .newly_found
            .iter()
            .take(15)
            .map(|f| {
                format!(
                    r##"<li><span class="pill" style="background:{colour}">{severity}</span>
                    {title} <span class="small muted">({component})</span></li>"##,
                    colour = charts::severity_color(&f.severity),
                    severity = charts::severity_name(&f.severity),
                    title = html(&f.title),
                    component = html(&f.affected_component),
                )
            })
            .collect();
        format!(
            r##"<h3>Appeared since the previous assessment</h3>
<p class="small">Either a change introduced these, or the previous assessment could not reach them.
Both are worth knowing which: the first is a regression in the development process, the second is a
gap in the previous scope.</p>
<ul class="small" style="list-style:none;padding-left:0">{items}</ul>"##
        )
    };

    format!(
        r##"<h2 class="page-break">Remediation Progress</h2>
<p>Compared against assessment <strong>{reference}</strong>, completed {when}. A weakness is treated
as the same weakness across assessments by its location and classification, not by any identifier the
scan generated, so a finding that moved from one report to the next is genuinely the same issue.</p>
<div class="callout"><strong>{verdict}</strong></div>
<table style="max-width:560px">
  <tbody>
    {resolved_row}
    {new_row}
    {open_row}
  </tbody>
</table>
{resolved_list}
{new_list}"##,
        reference = html(&delta.previous_reference),
        when = delta.previous_completed_at.format("%d %B %Y"),
        verdict = html(&delta.verdict()),
        resolved_row = row(
            "Closed", delta.resolved.len(), "#16a34a",
            "Present last time, could not be reproduced now"
        ),
        new_row = row(
            "New", delta.newly_found.len(), "#b91c1c",
            "Present now, absent last time"
        ),
        open_row = row(
            "Still open", delta.still_open.len(), "#ca8a04",
            "Present in both — scheduled work that has not landed"
        ),
        resolved_list = resolved_list,
        new_list = new_list,
    )
}

/// Where the findings sit against the framework the client's programme tracks.
///
/// A list of twenty findings cannot be reconciled with a security programme
/// that reports against the OWASP Top 10; the same twenty grouped by category
/// can. Every category is shown, including the ones with nothing against them —
/// a clean category is a result, and omitting it would turn a picture of
/// coverage into a list of failures.
fn owasp_rollup(split: &ReportFindings) -> String {
    let rows = owasp::rollup(&split.active);

    let body: String = rows
        .iter()
        .map(|r| {
            let meaning = owasp::category(&r.code)
                .map(|c| html(c.client_meaning))
                .unwrap_or_default();
            let count_cell = if r.total == 0 {
                r##"<span style="color:#16a34a;font-weight:700">None</span>"##.to_string()
            } else {
                format!(
                    r##"<span style="color:{colour};font-weight:700">{total}</span>"##,
                    colour = r.status_color(),
                    total = r.total
                )
            };
            format!(
                r##"<tr>
  <td style="white-space:nowrap"><strong>{code}</strong> {name}</td>
  <td style="text-align:center">{count_cell}</td>
  <td style="white-space:nowrap"><span class="pill" style="background:{colour}">{status}</span></td>
  <td class="small">{meaning}</td>
</tr>"##,
                code = html(&r.code),
                name = html(&r.name),
                count_cell = count_cell,
                colour = r.status_color(),
                status = r.status_label(),
                meaning = meaning,
            )
        })
        .collect();

    let clean = rows.iter().filter(|r| r.actionable() == 0).count();

    format!(
        r##"<h2 class="page-break">OWASP Top 10:2025 — Where the Findings Sit</h2>
<p>The OWASP Top 10 is the reference list of application security risk categories used across
the industry. Grouping this assessment's results against it lets the findings be reconciled with
whatever your security programme already reports on, and shows which categories came back clean.
<strong>{clean} of the 10 categories carry no actionable finding.</strong></p>
<table>
  <thead><tr>
    <th style="width:270px">Risk category</th>
    <th style="width:80px">Findings</th>
    <th style="width:110px">Worst severity</th>
    <th>What this category covers</th>
  </tr></thead>
  <tbody>{body}</tbody>
</table>
<p class="small muted">A category with no findings means the checks covering it were exercised and
came back clean — not that the risk is impossible. Categories that automated testing cannot fully
answer, such as Insecure Design, are marked <em>Manual review required</em> in the coverage matrix.</p>"##
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

/// Evidence handling, standards conformance and the honest limits of the work.
///
/// The section an auditor turns to first: it says what the assessment is
/// evidence *of*, how that evidence can be checked, and what it deliberately
/// does not cover.
fn assurance(
    ctx: &ReportContext,
    coverage: Option<&CoverageReport>,
    findings: &[Finding],
    split: &ReportFindings,
) -> String {
    let evidence_count: usize = findings.iter().map(|f| f.evidences.len()).sum();
    let engines = if ctx.engines_executed.is_empty() {
        "Sentinel Native (built in)".to_string()
    } else {
        html(&ctx.engines_executed.join(", "))
    };

    let unavailable = coverage
        .map(|c| c.engines_unavailable.clone())
        .unwrap_or_default();
    let unavailable_row = if unavailable.is_empty() {
        r##"<tr><th>Engines unavailable</th><td>None — every engine the catalogue references was present.</td></tr>"##.to_string()
    } else {
        format!(
            r##"<tr><th>Engines unavailable</th><td>{list}<div class="small muted">Test cases relying solely on these engines are reported as &ldquo;Not tested&rdquo;, never as passed.</div></td></tr>"##,
            list = html(&unavailable.join(", ")),
        )
    };

    let coverage_row = coverage
        .map(|c| {
            format!(
                r##"<tr><th>Automated coverage</th><td>{pct:.0}% of the {automatable} automatable test cases in the catalogue were exercised ({exercised} of them returning a definitive result).</td></tr>"##,
                pct = c.automated_coverage_pct,
                automatable = c.total_checks - c.manual_required,
                exercised = c.passed + c.issues_found,
            )
        })
        .unwrap_or_default();

    let dismissed = ctx.active_dismissals().len();
    let dismissed_row = if dismissed == 0 {
        String::new()
    } else {
        format!(
            r##"<tr><th>Dismissed as false positive</th><td>{dismissed} observation{p} {were} reviewed by the analyst, judged not to be a genuine weakness, and excluded from this report. The rationale for each is retained on the engagement record and is available on request.</td></tr>"##,
            p = if dismissed == 1 { "" } else { "s" },
            were = if dismissed == 1 { "was" } else { "were" },
        )
    };

    format!(
        r##"<h2 class="page-break">Assurance, Evidence &amp; Limitations</h2>
<p>This section records how the assessment was conducted to a standard that can be reviewed by a third party,
what evidence exists behind each statement in this report, and what the work does not cover.</p>

<h3>Standards this assessment was conducted against</h3>
<table>
  <thead><tr><th style="width:270px">Standard</th><th>How it was applied</th></tr></thead>
  <tbody>
    <tr><td><strong>OWASP WSTG v4.2</strong></td><td>Supplied the test-case inventory. Every case in the catalogue is reported with its actual state, including the cases that could not be exercised.</td></tr>
    <tr><td><strong>OWASP Top 10:2025</strong></td><td>Each finding carries the risk category it belongs to, so results can be rolled up against the framework your programme already tracks.</td></tr>
    <tr><td><strong>OWASP ASVS v4.0.3</strong></td><td>Used as the reference for the expected state of a control when judging whether an observation is a weakness.</td></tr>
    <tr><td><strong>NIST SP 800-115</strong></td><td>Planning, discovery, analysis and reporting phases follow the technical-assessment lifecycle it defines.</td></tr>
    <tr><td><strong>PTES</strong></td><td>Pre-engagement authorisation, scoping and rules of engagement follow the Penetration Testing Execution Standard.</td></tr>
    <tr><td><strong>CVSS v4.0 (FIRST)</strong></td><td>Severity is computed from a published vector for every finding, not asserted. The vector is printed in the technical report so any score can be recalculated independently.</td></tr>
    <tr><td><strong>CWE / MITRE</strong></td><td>Each finding is mapped to its weakness class, so remediation can be grouped by root cause rather than by symptom.</td></tr>
  </tbody>
</table>

{surface}
<h3>Evidence and reproducibility</h3>
<table>
  <tbody>
    <tr><th style="width:270px">Evidence artefacts captured</th><td>{evidence_count} — each stored with a SHA-256 content hash taken at the moment of capture, so any later alteration is detectable.</td></tr>
    <tr><th>Reproduction</th><td>Every finding in the technical report ships with the exact request or location needed to observe it again independently.</td></tr>
    <tr><th>Engines executed</th><td>{engines}</td></tr>
    {unavailable_row}
    {coverage_row}
    {dismissed_row}
    <tr><th>Redaction</th><td>Session cookies, authorisation headers and credentials are removed before any evidence reaches this document. No secret material is reproduced in the report.</td></tr>
    <tr><th>Data handling</th><td>The assessment ran entirely on locally controlled infrastructure. No finding, evidence artefact or credential was transmitted to a third-party service.</td></tr>
  </tbody>
</table>

<h3>Limitations of this assessment</h3>
<div class="warn">
<p style="margin-bottom:8px"><strong>Read this before treating the result as a clean bill of health.</strong></p>
<ul style="margin:0;padding-left:20px">
  <li>The result describes the application <strong>as it was during the testing window</strong>. Later changes to code, configuration, dependencies or infrastructure may introduce weaknesses this assessment could not have seen.</li>
  <li>Automated testing establishes the absence of <em>known patterns</em>, not the absence of weakness. Business-logic abuse, authorisation between two real user accounts and multi-step workflow manipulation need a human analyst; those cases are marked <em>Manual review required</em> rather than counted as passed.</li>
  <li>Testing was confined to the authorised scope. Systems, hosts and paths excluded by the Rules of Engagement were not examined and no assertion is made about them.</li>
  <li>Non-destructive technique was a condition of the engagement. Weaknesses that can only be proven by a destructive or availability-affecting action were not proven, and where such a weakness is suspected it is reported as requiring manual confirmation.</li>
  <li>This report is not a certification and does not, on its own, discharge a regulatory obligation.</li>
</ul>
</div>"##,
        surface = surface_block(split),
        evidence_count = evidence_count,
        engines = engines,
        unavailable_row = unavailable_row,
        coverage_row = coverage_row,
        dismissed_row = dismissed_row,
    )
}

/// How much of the application the assessment actually reached.
///
/// A clean result is only meaningful next to this. "No weaknesses found" across
/// eleven pages and the same words across four hundred are different claims,
/// and a report that presents them identically is asking for trust it has not
/// earned.
fn surface_block(split: &ReportFindings) -> String {
    let notes = split.surface_notes();
    if notes.is_empty() {
        return String::new();
    }

    let body: String = notes
        .iter()
        .map(|(description, evidences)| {
            let lists: String = evidences
                .iter()
                .map(|(title, content)| {
                    format!(
                        r##"<details style="margin-top:8px">
  <summary class="small" style="cursor:pointer;color:var(--brand)">{title}</summary>
  <pre class="small" style="margin-top:6px">{content}</pre>
</details>"##,
                        title = html(title),
                        content = html(content),
                    )
                })
                .collect();
            format!("<p>{}</p>{lists}", html_multiline(description))
        })
        .collect();

    format!(
        r##"<h3>How much of the application was reached</h3>
{body}
<p class="small muted">Pages behind a login are reachable only when scan credentials were supplied;
routes with no link pointing at them cannot be discovered by crawling at all, and would need to be
supplied explicitly or found by an analyst.</p>"##
    )
}

/// Issuer sign-off block, so the document has an accountable author.
fn signoff(ctx: &ReportContext) -> String {
    format!(
        r##"<h2>Sign-off</h2>
<p>The assessment described in this report was carried out under the authorisation referenced above, and the
findings recorded here reflect the evidence gathered during the testing window.</p>
<div class="grid grid-2">
  <div class="sign">
    <div class="small muted" style="letter-spacing:1px;text-transform:uppercase">Prepared by</div>
    <div class="line"></div>
    <div style="margin-top:6px"><strong>{analyst}</strong></div>
    <div class="small muted">Security analyst &middot; {issued}</div>
  </div>
  <div class="sign">
    <div class="small muted" style="letter-spacing:1px;text-transform:uppercase">Reviewed by</div>
    <div class="line"></div>
    <div style="margin-top:6px"><strong>{reviewer}</strong></div>
    <div class="small muted">Quality review &middot; revision {revision}</div>
  </div>
</div>
<p class="small muted" style="margin-top:12px">Questions about any finding, or a request for the underlying
evidence, should be directed to the preparer named above quoting report reference {reference}.</p>"##,
        analyst = html(&ctx.analyst),
        issued = ctx.assessment_end.format("%d %B %Y"),
        reviewer = html(ctx.reviewed_by.as_deref().unwrap_or("Pending independent review")),
        revision = html(&ctx.revision),
        reference = html(&ctx.report_reference),
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

    // ── Exceptions ──────────────────────────────────────────────────────────

    fn accepted(title: &str, sev: Severity, score: f64) -> (Finding, ExceptionRecord) {
        let mut f = finding(title, sev, score);
        f.status = crate::models::finding::FindingStatus::AcceptedRisk;
        let record = crate::exceptions::from_triage(
            &f,
            &crate::models::finding::FindingStatus::AcceptedRisk,
            "Mitigated by the WAF rule set; scheduled for the Q3 platform upgrade.",
            "R. Mehta, CISO",
            None,
            "EXC-1".into(),
        )
        .unwrap();
        (f, record)
    }

    /// The whole point of an exception: the client asked for a report that goes
    /// green once a risk is formally carried, without the risk disappearing.
    #[test]
    fn an_accepted_risk_leaves_the_counts_but_not_the_report() {
        let (f, record) = accepted("Directory listing enabled", Severity::High, 7.4);
        let mut c = ctx();
        c.exceptions = vec![record];

        let out = render(&c, &[f], None);

        assert!(out.contains("Accepted Risk Register"));
        assert!(out.contains("Directory listing enabled"), "the risk is disclosed, not deleted");
        assert!(out.contains("Mitigated by the WAF rule set"), "with its justification");
        assert!(out.contains("R. Mehta, CISO"), "and its owner");
        assert!(
            out.contains("No actionable weaknesses were identified"),
            "with the sole finding accepted, the live picture is clean"
        );
    }

    #[test]
    fn accepting_the_only_high_finding_lifts_the_posture_band() {
        let coverage = ChecklistEngine::assess(
            &["Sentinel Native".into(), "OWASP ZAP".into(), "Nuclei".into(),
              "Semgrep".into(), "Trivy".into(), "Gitleaks".into()],
            &[],
        );
        let open = finding("Directory listing enabled", Severity::High, 7.4);
        let (carried, record) = accepted("Directory listing enabled", Severity::High, 7.4);

        let before = render(&ctx(), &[open], Some(&coverage));
        let mut c = ctx();
        c.exceptions = vec![record];
        let after = render(&c, &[carried], Some(&coverage));

        assert!(before.contains("Needs Improvement") || before.contains("At Risk"));
        assert!(after.contains("Strong"), "an accepted risk must not hold the score down");
    }

    #[test]
    fn an_acceptance_nearing_expiry_is_called_out() {
        let (mut f, mut record) = accepted("TLS 1.0 accepted", Severity::Medium, 5.9);
        f.status = crate::models::finding::FindingStatus::AcceptedRisk;
        record.expires_at = Some(Utc::now() + chrono::Duration::days(14));
        let mut c = ctx();
        c.exceptions = vec![record];

        let out = render(&c, &[f], None);
        assert!(out.contains("due for review within 30 days"));
        assert!(out.contains("returns to the open findings list"));
    }

    #[test]
    fn an_open_ended_acceptance_says_so_rather_than_showing_a_blank() {
        let (f, record) = accepted("Server banner disclosed", Severity::Low, 2.1);
        let mut c = ctx();
        c.exceptions = vec![record];
        let out = render(&c, &[f], None);
        assert!(out.contains("Open-ended"));
        assert!(!out.contains("due for review within 30 days"));
    }

    #[test]
    fn no_acceptances_means_no_register_section() {
        let out = render(&ctx(), &[finding("XSS", Severity::High, 8.0)], None);
        assert!(!out.contains("Accepted Risk Register"));
    }

    #[test]
    fn dismissed_observations_are_accounted_for_in_the_assurance_section() {
        let f = finding("Phantom", Severity::Medium, 5.0);
        let record = crate::exceptions::from_triage(
            &f,
            &crate::models::finding::FindingStatus::FalsePositive,
            "Matched a fixture file, not shipped code.",
            "A. Analyst",
            None,
            "EXC-2".into(),
        )
        .unwrap();
        let mut c = ctx();
        c.exceptions = vec![record];

        // The dismissed finding itself never reaches the renderer.
        let out = render(&c, &[], None);
        assert!(out.contains("Dismissed as false positive"));
        assert!(out.contains("available on request"));
    }

    // ── Assurance, controls and document control ────────────────────────────

    #[test]
    fn passed_checks_are_presented_as_controls_that_were_verified() {
        let cov = ChecklistEngine::assess(&["Sentinel Native".into()], &[]);
        let out = render(&ctx(), &[], Some(&cov));
        assert!(out.contains("Controls Verified — What Is Protecting You"));
        assert!(out.contains("How we established this"));
        assert!(
            out.contains("checks passed"),
            "each category states how many of its checks came back clean"
        );
        // The plain-language assurance narrative, not just a tick.
        assert!(out.contains("Transport security, security response headers"));
    }

    /// A pass has to mean an engine actually answered the question.
    #[test]
    fn nothing_is_claimed_as_verified_when_no_engine_ran() {
        let cov = ChecklistEngine::assess(&[], &[]);
        let out = render(&ctx(), &[], Some(&cov));
        assert!(out.contains("No check completed cleanly in this assessment"));
        assert!(out.contains("statement about the\nassessment"));
    }

    #[test]
    fn the_assurance_section_names_the_standards_and_the_evidence() {
        let mut f = finding("XSS", Severity::High, 8.0);
        f.evidences = vec![crate::models::finding::Evidence {
            evidence_type: "http_response".into(),
            title: "Response".into(),
            content: "HTTP/1.1 200 OK".into(),
            hash: "abc".into(),
        }];
        let out = render(&ctx(), &[f], None);
        for standard in ["OWASP WSTG v4.2", "NIST SP 800-115", "PTES", "CVSS v4.0", "ASVS"] {
            assert!(out.contains(standard), "the assurance table must cite {standard}");
        }
        assert!(out.contains("SHA-256 content hash"));
        assert!(out.contains("Limitations of this assessment"));
        assert!(out.contains("not a certification"));
    }

    #[test]
    fn the_cover_carries_document_control_and_the_report_is_signed_off() {
        let mut c = ctx();
        c.reviewed_by = Some("D. Shah, Principal Consultant".into());
        c.revision = "2.1".into();
        let out = render(&c, &[], None);
        assert!(out.contains("Revision"));
        assert!(out.contains("2.1"));
        assert!(out.contains("D. Shah, Principal Consultant"));
        assert!(out.contains("Distribution"));
        assert!(out.contains("Sign-off"));
        assert!(out.contains("Prepared by"));
    }

    #[test]
    fn an_unreviewed_report_says_so_rather_than_leaving_it_blank() {
        let out = render(&ctx(), &[], None);
        assert!(out.contains("Pending independent review"));
    }

    #[test]
    fn the_contents_page_lists_only_the_sections_that_are_present() {
        let cov = ChecklistEngine::assess(&["Sentinel Native".into()], &[]);
        let with_coverage = render(&ctx(), &[finding("XSS", Severity::High, 8.0)], Some(&cov));
        assert!(with_coverage.contains("Contents"));
        assert!(with_coverage.contains("Controls Verified"));

        let without = render(&ctx(), &[], None);
        assert!(!without.contains(">Assessment Coverage"), "no coverage, no coverage entry");
    }

    /// The contents page is written by hand alongside the sections, so the two
    /// drift the moment a section is added and the list is not. This compares
    /// them rather than trusting that they match — which is how the
    /// Remediation Progress section shipped missing from the index.
    #[test]
    fn every_rendered_section_appears_in_the_contents() {
        let cov = ChecklistEngine::assess(&["Sentinel Native".into()], &[]);
        let (accepted_finding, record) = accepted("Directory listing", Severity::Low, 3.0);
        let mut c = comparison(
            vec![finding("Closed", Severity::Low, 2.0)],
            vec![finding("New", Severity::High, 7.5)],
            vec![finding("Open", Severity::Medium, 5.0)],
        );
        c.exceptions = vec![record];

        let out = render(
            &c,
            &[finding("Missing CSP", Severity::Medium, 5.3), accepted_finding],
            Some(&cov),
        );

        // Section titles as rendered, minus the contents heading itself.
        let headings: Vec<String> = out
            .split("<h2")
            .skip(1)
            .filter_map(|chunk| chunk.split_once('>').map(|(_, rest)| rest))
            .filter_map(|rest| rest.split_once("</h2>").map(|(title, _)| title.to_string()))
            .filter(|t| t != "Contents")
            .collect();

        // The contents entries themselves, not "everything after the contents
        // heading" — the first version of this test used the latter, so every
        // section matched itself further down the document and the assertion
        // could never fail.
        let listed: Vec<String> = out
            .split(r#"<div><span class="n">"#)
            .skip(1)
            .filter_map(|entry| entry.split_once("</span>"))
            .filter_map(|(_, rest)| rest.split_once("</div>"))
            .map(|(title, _)| title.to_string())
            .collect();

        assert!(!headings.is_empty(), "the report rendered no sections");
        assert!(!listed.is_empty(), "the contents page listed nothing");
        for heading in &headings {
            assert!(
                listed.contains(heading),
                "section '{heading}' is rendered but missing from the contents page.\n\
                 Contents lists: {listed:?}"
            );
        }
    }

    #[test]
    fn a_custom_classification_reaches_the_banner_and_the_cover() {
        let mut c = ctx();
        c.classification = "Restricted".into();
        let out = render(&c, &[], None);
        assert!(out.contains("Restricted — prepared for"));
        assert!(!out.contains("Confidential — prepared for"));
    }

    /// A scan-information record, as the native engine emits one.
    fn surface_record() -> Finding {
        let mut f = finding("Assessment Surface — What This Scan Reached", Severity::Info, 0.0);
        f.kind = crate::models::finding::FindingKind::ScanInformation;
        f.description = "87 page(s) were fetched and assessed; the page limit was reached, so \
some in-scope pages were not assessed. 12 in-scope URL(s) were queued but not reached."
            .into();
        f.evidences = vec![
            crate::models::finding::Evidence {
                evidence_type: "assessment_surface".into(),
                title: "Pages assessed (87)".into(),
                content: "https://dev.example.com/\nhttps://dev.example.com/account".into(),
                hash: String::new(),
            },
            crate::models::finding::Evidence {
                evidence_type: "assessment_surface".into(),
                title: "Third-party origins referenced (2)".into(),
                content: "cdn.example.net\nanalytics.example.net".into(),
                hash: String::new(),
            },
        ];
        f
    }

    /// A clean result is only meaningful next to how much was looked at, and
    /// this section is the only place the report says it.
    #[test]
    fn the_assurance_section_states_how_much_was_reached() {
        let out = render(&ctx(), &[surface_record()], None);

        assert!(out.contains("How much of the application was reached"));
        assert!(out.contains("87 page(s) were fetched"));
        assert!(out.contains("12 in-scope URL(s) were queued but not reached"));
        assert!(out.contains("Pages assessed (87)"));
        assert!(out.contains("cdn.example.net"), "third-party origins must be listed");
        assert!(out.contains("behind a login"), "the limits of crawling must be stated");
    }

    /// It is a statement about the scan, not a weakness. If it reached the
    /// counts, every report would carry an issue nobody can remediate.
    #[test]
    fn the_surface_record_is_not_reported_as_a_finding() {
        let out = render(&ctx(), &[surface_record()], None);
        assert!(out.contains("No security weaknesses were identified"));
        assert!(out.contains("No actionable weaknesses were identified"));
    }

    #[test]
    fn no_surface_record_means_no_such_section() {
        let out = render(&ctx(), &[finding("XSS", Severity::High, 8.0)], None);
        assert!(!out.contains("How much of the application was reached"));
    }

    fn comparison(resolved: Vec<Finding>, new: Vec<Finding>, open: Vec<Finding>) -> ReportContext {
        let mut c = ctx();
        c.comparison = Some(crate::reporting::delta::ScanDelta {
            previous_reference: "SV-20260801-0900".into(),
            previous_completed_at: Utc::now() - chrono::Duration::days(30),
            newly_found: new,
            resolved,
            still_open: open,
        });
        c
    }

    /// Without this the reader has to diff two PDFs by hand, which is how a
    /// regression survives a quarter.
    #[test]
    fn remediation_progress_states_what_closed_and_what_appeared() {
        let c = comparison(
            vec![finding("Directory listing enabled", Severity::Low, 3.0)],
            vec![finding("Leaked credential", Severity::Critical, 9.4)],
            vec![finding("Missing CSP", Severity::Medium, 5.3)],
        );
        let out = render(&c, &[finding("Missing CSP", Severity::Medium, 5.3)], None);

        assert!(out.contains("Remediation Progress"));
        assert!(out.contains("SV-20260801-0900"), "the baseline must be named");
        assert!(out.contains("Confirmed closed"));
        assert!(out.contains("Directory listing enabled"));
        assert!(out.contains("Appeared since the previous assessment"));
        assert!(out.contains("Leaked credential"));
    }

    /// Closing findings while introducing a critical is not progress, and the
    /// verdict must not read as though it were.
    #[test]
    fn the_verdict_does_not_congratulate_on_volume_alone() {
        let c = comparison(
            (0..5).map(|i| finding(&format!("Old {i}"), Severity::Low, 2.0)).collect(),
            vec![finding("RCE", Severity::Critical, 9.8)],
            vec![],
        );
        let out = render(&c, &[], None);
        assert!(out.contains("high-impact finding"), "the critical must lead the verdict");
        assert!(out.contains("that is the result that matters"));
    }

    /// A fix is confirmed by observation, which is why marking one Remediated
    /// by hand does not suppress the re-test.
    #[test]
    fn the_closed_list_explains_why_it_is_evidence() {
        let c = comparison(vec![finding("Fixed thing", Severity::High, 7.0)], vec![], vec![]);
        let out = render(&c, &[], None);
        assert!(out.contains("only place in the report that evidences remediation"));
        assert!(out.contains("re-tested rather than taken at its word"));
    }

    /// A first assessment is a different document and must not carry an empty
    /// comparison section.
    #[test]
    fn a_first_assessment_has_no_progress_section() {
        let out = render(&ctx(), &[finding("XSS", Severity::High, 8.0)], None);
        assert!(!out.contains("Remediation Progress"));
    }

    #[test]
    fn the_owasp_rollup_shows_every_category_including_the_clean_ones() {
        let mut f = finding("Missing CSP", Severity::Medium, 5.3);
        f.owasp_2025 = Some("A02:2025-Security Misconfiguration".into());
        let out = render(&ctx(), &[f], None);

        assert!(out.contains("OWASP Top 10:2025 — Where the Findings Sit"));
        for code in ["A01", "A02", "A05", "A10"] {
            assert!(out.contains(code), "category {code} must be listed even with no findings");
        }
        assert!(out.contains("9 of the 10 categories carry no actionable finding"));
        assert!(out.contains("not that the risk is impossible"), "a clean row must not overclaim");
    }

    #[test]
    fn an_accepted_risk_does_not_count_against_its_owasp_category() {
        let (mut f, record) = accepted("Directory listing enabled", Severity::High, 7.4);
        f.owasp_2025 = Some("A02:2025-Security Misconfiguration".into());
        let mut c = ctx();
        c.exceptions = vec![record];

        let out = render(&c, &[f], None);
        assert!(
            out.contains("10 of the 10 categories carry no actionable finding"),
            "an accepted risk is disclosed in its register, not counted as open exposure"
        );
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
