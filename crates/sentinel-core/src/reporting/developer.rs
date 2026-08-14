//! Developer / technical remediation report.
//!
//! Written for the engineer who has to fix the finding. Every section answers
//! the same four questions in order: where is it, how do I prove it, how do I
//! fix it, and how do I verify the fix worked.

use super::charts;
use super::escape::{href, html, html_multiline};
use super::{
    base_stylesheet, footer_html, remediation_window, sort_by_priority, ReportContext,
    SeverityCounts,
};
use crate::checklist::{CheckStatus, CoverageReport};
use crate::models::finding::{Finding, FindingStatus};
use crate::scoring::priority::PriorityScoringEngine;

/// Render the developer report as a self-contained HTML document.
pub fn render(
    ctx: &ReportContext,
    findings: &[Finding],
    coverage: Option<&CoverageReport>,
) -> String {
    let sorted = sort_by_priority(findings);
    let counts = SeverityCounts::of(&sorted);

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Technical Remediation Report — {target}</title>
<style>{css}{extra}</style>
</head>
<body>
<div class="page">
  <div class="banner">Confidential — technical distribution only</div>
  {header}
  {index}
  {untested}
  {details}
  {footer}
</div>
</body>
</html>"##,
        target = html(&ctx.target_name),
        css = base_stylesheet(),
        extra = extra_stylesheet(),
        header = header(ctx, &counts),
        index = index_table(&sorted),
        untested = untested_section(coverage),
        details = detail_sections(&sorted),
        footer = footer_html(ctx, "Technical Remediation Report"),
    )
}

fn extra_stylesheet() -> &'static str {
    r##"
.finding{background:#fff;border:1px solid var(--line);border-left-width:5px;border-radius:9px;
  padding:20px 22px;margin:0 0 22px}
.meta{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0 4px}
.tag{background:#f1f5f9;border:1px solid var(--line);border-radius:5px;padding:2px 8px;
  font-size:11px;font-family:'Cascadia Mono',Consolas,monospace;color:#475569;white-space:nowrap}
.section-label{font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;
  color:var(--muted);margin:16px 0 5px}
ol.steps{margin:4px 0;padding-left:20px}
ol.steps li{margin-bottom:5px}
ol.steps code{background:#f1f5f9;padding:1px 5px;border-radius:4px;word-break:break-all}
"##
}

fn header(ctx: &ReportContext, counts: &SeverityCounts) -> String {
    format!(
        r##"<header style="margin:24px 0 4px">
  <div class="small muted" style="letter-spacing:2px;text-transform:uppercase">Technical Remediation Report</div>
  <h1 style="font-size:29px;margin:8px 0 6px">{target}</h1>
  <div class="muted">{company} · {url}</div>
  <div class="grid grid-4" style="margin-top:20px">
    <div class="kpi"><div class="n" style="color:#b91c1c">{critical}</div><div class="l">Critical</div></div>
    <div class="kpi"><div class="n" style="color:#ea580c">{high}</div><div class="l">High</div></div>
    <div class="kpi"><div class="n" style="color:#ca8a04">{medium}</div><div class="l">Medium</div></div>
    <div class="kpi"><div class="n" style="color:#0284c7">{low}</div><div class="l">Low</div></div>
  </div>
  <p class="small muted" style="margin-top:14px">
    Assessment window {start} to {end} UTC · Engines: {engines} · Reference {reference}
  </p>
  <div class="callout small">
    Findings are ordered by integrated priority score:
    <code>CVSS 4.0 base × EPSS exploitation likelihood × CISA KEV × reachability × exposure</code>.
    Fix top-down — the ordering already accounts for how likely each weakness is to be attacked in practice,
    not just how severe it would be in theory.
  </div>
</header>"##,
        target = html(&ctx.target_name),
        company = html(&ctx.company_name),
        url = html(&ctx.target_url),
        critical = counts.critical,
        high = counts.high,
        medium = counts.medium,
        low = counts.low,
        start = ctx.assessment_start.format("%Y-%m-%d %H:%M"),
        end = ctx.assessment_end.format("%Y-%m-%d %H:%M"),
        engines = if ctx.engines_executed.is_empty() {
            "Sentinel Native".to_string()
        } else {
            html(&ctx.engines_executed.join(", "))
        },
        reference = html(&ctx.report_reference),
    )
}

fn index_table(sorted: &[Finding]) -> String {
    if sorted.is_empty() {
        return r##"<h2>Findings</h2>
<div class="fix"><strong>No findings to remediate.</strong> Every check that could be exercised
automatically returned clean. Review the coverage table in the client report for the test cases that
still require manual analysis.</div>"##
            .to_string();
    }

    let rows: String = sorted
        .iter()
        .enumerate()
        .map(|(i, f)| {
            format!(
                r##"<tr>
  <td style="text-align:center"><a href="#f{n}">{n}</a></td>
  <td><span class="pill" style="background:{color}">{severity}</span></td>
  <td style="text-align:center;font-weight:600">{score:.1}</td>
  <td>{title}</td>
  <td class="small"><code>{component}</code></td>
  <td class="small">{cwe}</td>
  <td class="small">{status}</td>
</tr>"##,
                n = i + 1,
                color = charts::severity_color(&f.severity),
                severity = charts::severity_name(&f.severity),
                score = f.priority_score,
                title = html(&f.title),
                component = html(&truncate(&f.affected_component, 70)),
                cwe = html(f.cwe_id.as_deref().unwrap_or("—")),
                status = html(status_label(&f.status)),
            )
        })
        .collect();

    format!(
        r##"<h2>Findings Index</h2>
<table>
  <thead><tr>
    <th style="width:40px">#</th><th style="width:90px">Severity</th><th style="width:66px">Priority</th>
    <th>Finding</th><th style="width:230px">Location</th><th style="width:90px">CWE</th><th style="width:96px">Status</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>"##
    )
}

fn untested_section(coverage: Option<&CoverageReport>) -> String {
    let Some(cov) = coverage else { return String::new() };

    let manual: Vec<_> = cov
        .results
        .iter()
        .filter(|r| r.status == CheckStatus::ManualRequired)
        .collect();
    let not_tested: Vec<_> = cov
        .results
        .iter()
        .filter(|r| r.status == CheckStatus::NotTested)
        .collect();

    if manual.is_empty() && not_tested.is_empty() {
        return String::new();
    }

    let manual_rows: String = manual
        .iter()
        .map(|r| {
            format!(
                r##"<tr><td class="small" style="white-space:nowrap"><code>{id}</code></td><td>{name}</td><td class="small muted">{cwe}</td></tr>"##,
                id = html(&r.id),
                name = html(&r.name),
                cwe = html(&r.cwe),
            )
        })
        .collect();

    let missing_rows: String = not_tested
        .iter()
        .map(|r| {
            let needs = if r.engines_missing.is_empty() {
                "Not exercised in this run".to_string()
            } else {
                format!("Install {}", html(&r.engines_missing.join(" or ")))
            };
            format!(
                r##"<tr><td class="small" style="white-space:nowrap"><code>{id}</code></td><td>{name}</td><td class="small">{needs}</td></tr>"##,
                id = html(&r.id),
                name = html(&r.name),
                needs = needs,
            )
        })
        .collect();

    let manual_block = if manual.is_empty() {
        String::new()
    } else {
        format!(
            r##"<h3>Requires manual analysis ({n})</h3>
<p class="small muted">No automated tool can answer these honestly. They need an analyst with knowledge of the
application's intended behaviour — most are authorisation and business-logic questions.</p>
<table><thead><tr><th style="width:130px">Reference</th><th>Test case</th><th style="width:110px">CWE</th></tr></thead><tbody>{rows}</tbody></table>"##,
            n = manual.len(),
            rows = manual_rows
        )
    };

    let missing_block = if not_tested.is_empty() {
        String::new()
    } else {
        format!(
            r##"<h3>Not exercised in this run ({n})</h3>
<p class="small muted">These checks were skipped because the engine that covers them was unavailable.
Installing the listed tool and re-running will close the gap.</p>
<table><thead><tr><th style="width:130px">Reference</th><th>Test case</th><th style="width:210px">To enable</th></tr></thead><tbody>{rows}</tbody></table>"##,
            n = not_tested.len(),
            rows = missing_rows
        )
    };

    format!(
        r##"<h2 class="page-break">Coverage Gaps</h2>
<p>A clean automated result only means the checks that ran found nothing. The test cases below were
<em>not</em> answered by this assessment and remain open questions.</p>
{manual_block}
{missing_block}"##
    )
}

fn detail_sections(sorted: &[Finding]) -> String {
    if sorted.is_empty() {
        return String::new();
    }

    let sections: String = sorted
        .iter()
        .enumerate()
        .map(|(i, f)| detail_section(i + 1, f))
        .collect();

    format!(r##"<h2 class="page-break">Finding Detail</h2>{sections}"##)
}

fn detail_section(n: usize, f: &Finding) -> String {
    let color = charts::severity_color(&f.severity);

    let tags: String = [
        f.cwe_id.as_deref(),
        f.owasp_2025.as_deref(),
        f.wstg_id.as_deref(),
        f.api_top10.as_deref(),
    ]
    .iter()
    .flatten()
    .filter(|v| !v.trim().is_empty())
    .map(|v| format!(r##"<span class="tag">{}</span>"##, html(v)))
    .collect();

    let vector = f
        .cvss4
        .as_ref()
        .map(|c| c.vector_string.clone())
        .filter(|v| !v.trim().is_empty());
    let vector_html = vector
        .map(|v| {
            format!(
                r##"<div class="section-label">CVSS 4.0 vector</div><pre>{}</pre>"##,
                html(&v)
            )
        })
        .unwrap_or_default();

    let rationale = if f.priority_rationale.trim().is_empty() {
        PriorityScoringEngine::explain(f)
    } else {
        f.priority_rationale.clone()
    };

    let steps = if f.repro_steps.is_empty() {
        r##"<p class="small muted">No automated reproduction steps were recorded for this finding. Reproduce by inspecting the affected component listed above.</p>"##.to_string()
    } else {
        let items: String = f
            .repro_steps
            .iter()
            .map(|s| format!("<li><code>{}</code></li>", html(s)))
            .collect();
        format!(r##"<ol class="steps">{items}</ol>"##)
    };

    let evidence = if f.evidences.is_empty() {
        String::new()
    } else {
        let blocks: String = f
            .evidences
            .iter()
            .map(|e| {
                format!(
                    r##"<div class="small muted" style="margin-top:8px">{title} <span class="tag">{etype}</span></div>
<pre>{content}</pre>
<div class="small muted">SHA-256 {hash}</div>"##,
                    title = html(&e.title),
                    etype = html(&e.evidence_type),
                    content = html(&e.content),
                    hash = html(&truncate(&e.hash, 24)),
                )
            })
            .collect();
        format!(r##"<div class="section-label">Evidence (sanitized)</div>{blocks}"##)
    };

    let references = if f.references.is_empty() {
        String::new()
    } else {
        let items: String = f
            .references
            .iter()
            .map(|r| {
                format!(
                    r##"<li><a href="{safe}" rel="noopener noreferrer">{shown}</a></li>"##,
                    safe = href(r),
                    shown = html(r)
                )
            })
            .collect();
        format!(r##"<div class="section-label">References</div><ul class="small">{items}</ul>"##)
    };

    let triage = f
        .ai_triage
        .as_ref()
        .filter(|t| t.is_false_positive_confidence >= 0.4)
        .map(|t| {
            format!(
                r##"<div class="warn small"><strong>Triage note.</strong> Automated analysis rates this
{pct:.0}% likely to be a false positive{notes}. Confirm before scheduling remediation work.</div>"##,
                pct = t.is_false_positive_confidence * 100.0,
                notes = t
                    .triage_notes
                    .as_deref()
                    .map(|n| format!(" — {}", html(n)))
                    .unwrap_or_default(),
            )
        })
        .unwrap_or_default();

    format!(
        r##"<div class="finding" id="f{n}" style="border-left-color:{color}">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px">
    <div>
      <div class="small muted">Finding {n}</div>
      <h3 style="margin:2px 0 0;font-size:18px">{title}</h3>
      <div class="meta">{tags}</div>
    </div>
    <div style="text-align:right;white-space:nowrap">
      <span class="pill" style="background:{color}">{severity}</span>
      <div style="font-size:26px;font-weight:700;margin-top:6px;color:{color}">{score:.1}</div>
      <div class="small muted">priority</div>
    </div>
  </div>

  {triage}

  <div class="section-label">Location</div>
  <pre>{component}</pre>

  <div class="section-label">Description</div>
  <p>{description}</p>

  <div class="section-label">Why it ranks here</div>
  <p class="small">{rationale}</p>

  {vector_html}

  <div class="section-label">Reproduction</div>
  {steps}

  {evidence}

  <div class="fix">
    <div class="section-label" style="margin-top:0;color:#166534">How to fix</div>
    <div>{remediation}</div>
  </div>

  <div class="section-label">Verification</div>
  <p class="small">After deploying the fix, repeat the reproduction steps above and confirm the observed
  behaviour has changed. Then re-run the assessment and confirm this finding no longer appears.</p>

  {references}

  <div class="small muted" style="margin-top:14px;padding-top:10px;border-top:1px solid var(--line)">
    Detected by {tools} · Target timeframe: {window} · Current status: {status}
  </div>
</div>"##,
        n = n,
        color = color,
        title = html(&f.title),
        tags = tags,
        severity = charts::severity_name(&f.severity),
        score = f.priority_score,
        triage = triage,
        component = html(&f.affected_component),
        description = html_multiline(&f.description),
        rationale = html(&rationale),
        vector_html = vector_html,
        steps = steps,
        evidence = evidence,
        remediation = html_multiline(&f.remediation),
        references = references,
        tools = html(&f.source_tools.join(", ")),
        window = html(remediation_window(&f.severity)),
        status = html(status_label(&f.status)),
    )
}

/// Ticket-ready Markdown export, one section per finding.
pub fn render_markdown(ctx: &ReportContext, findings: &[Finding]) -> String {
    let sorted = sort_by_priority(findings);
    let counts = SeverityCounts::of(&sorted);

    let mut out = String::new();
    out.push_str(&format!("## Technical Remediation Report — {}\n\n", ctx.target_name));
    out.push_str(&format!(
        "**Client:** {}  \n**Target:** {}  \n**Window:** {} to {} UTC  \n**Reference:** {}\n\n",
        ctx.company_name,
        ctx.target_url,
        ctx.assessment_start.format("%Y-%m-%d %H:%M"),
        ctx.assessment_end.format("%Y-%m-%d %H:%M"),
        ctx.report_reference,
    ));
    out.push_str(&format!(
        "**Summary:** {} critical · {} high · {} medium · {} low · {} informational\n\n---\n\n",
        counts.critical, counts.high, counts.medium, counts.low, counts.info
    ));

    if sorted.is_empty() {
        out.push_str("No findings to remediate.\n");
        return out;
    }

    for (i, f) in sorted.iter().enumerate() {
        out.push_str(&format!(
            "## {}. {} [{}]\n\n",
            i + 1,
            f.title,
            charts::severity_name(&f.severity)
        ));
        out.push_str(&format!("- **Priority score:** {:.1}/10\n", f.priority_score));
        out.push_str(&format!("- **Location:** `{}`\n", f.affected_component));
        if let Some(cwe) = &f.cwe_id {
            out.push_str(&format!("- **CWE:** {cwe}\n"));
        }
        if let Some(owasp) = &f.owasp_2025 {
            out.push_str(&format!("- **OWASP Top 10:2025:** {owasp}\n"));
        }
        if let Some(wstg) = &f.wstg_id {
            out.push_str(&format!("- **WSTG:** {wstg}\n"));
        }
        if let Some(cvss) = &f.cvss4 {
            if !cvss.vector_string.trim().is_empty() {
                out.push_str(&format!("- **CVSS 4.0:** `{}`\n", cvss.vector_string));
            }
        }
        out.push_str(&format!("- **Detected by:** {}\n", f.source_tools.join(", ")));
        out.push_str(&format!("- **Target timeframe:** {}\n\n", remediation_window(&f.severity)));

        out.push_str(&format!("### Description\n\n{}\n\n", f.description));

        if !f.repro_steps.is_empty() {
            out.push_str("### Reproduction\n\n");
            for (n, step) in f.repro_steps.iter().enumerate() {
                out.push_str(&format!("{}. `{}`\n", n + 1, step));
            }
            out.push('\n');
        }

        if !f.evidences.is_empty() {
            out.push_str("### Evidence\n\n");
            for e in &f.evidences {
                out.push_str(&format!("**{}**\n\n```\n{}\n```\n\n", e.title, e.content));
            }
        }

        out.push_str(&format!("### How to fix\n\n{}\n\n", f.remediation));

        if !f.references.is_empty() {
            out.push_str("### References\n\n");
            for r in &f.references {
                out.push_str(&format!("- {r}\n"));
            }
            out.push('\n');
        }
        out.push_str("---\n\n");
    }

    out
}

fn status_label(status: &FindingStatus) -> &'static str {
    match status {
        FindingStatus::Open => "Open",
        FindingStatus::InProgress => "In progress",
        FindingStatus::Remediated => "Remediated",
        FindingStatus::AcceptedRisk => "Accepted risk",
        FindingStatus::FalsePositive => "False positive",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    format!("{}…", s.chars().take(max).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checklist::ChecklistEngine;
    use crate::models::finding::{AITriage, Evidence, Severity};
    use crate::reporting::tests::finding;

    fn ctx() -> ReportContext {
        let mut c = ReportContext::new("Acme Corp", "Customer Portal", "https://portal.acme.test");
        c.engines_executed = vec!["Sentinel Native".into()];
        c
    }

    #[test]
    fn report_is_a_complete_html_document() {
        let out = render(&ctx(), &[finding("XSS", Severity::High, 8.0)], None);
        assert!(out.starts_with("<!DOCTYPE html>"));
        assert!(out.trim_end().ends_with("</html>"));
    }

    #[test]
    fn developer_report_includes_full_technical_taxonomy() {
        let out = render(&ctx(), &[finding("XSS", Severity::High, 8.0)], None);
        assert!(out.contains("CWE-79"));
        assert!(out.contains("A05:2025-Injection"));
        assert!(out.contains("WSTG-INPV-01"));
        assert!(out.contains("CVSS:4.0/"));
    }

    #[test]
    fn every_finding_has_fix_and_verification_guidance() {
        let out = render(&ctx(), &[finding("XSS", Severity::High, 8.0)], None);
        assert!(out.contains("How to fix"));
        assert!(out.contains("Verification"));
        assert!(out.contains("Reproduction"));
    }

    #[test]
    fn index_links_resolve_to_detail_anchors() {
        let out = render(&ctx(), &[finding("A", Severity::High, 8.0), finding("B", Severity::Low, 3.0)], None);
        assert!(out.contains(r##"href="#f1""##));
        assert!(out.contains(r##"id="f1""##));
        assert!(out.contains(r##"href="#f2""##));
        assert!(out.contains(r##"id="f2""##));
    }

    #[test]
    fn malicious_finding_content_cannot_inject_markup() {
        let mut evil = finding("</h3><script>alert(1)</script>", Severity::High, 8.0);
        evil.description = "<img src=x onerror=alert(1)>".into();
        evil.evidences = vec![Evidence {
            evidence_type: "http_response".into(),
            title: "</pre><script>x</script>".into(),
            content: "<script>evil()</script>".into(),
            hash: "abc".into(),
        }];
        let out = render(&ctx(), &[evil], None);
        assert!(!out.contains("<script>alert(1)</script>"));
        assert!(!out.contains("<script>evil()</script>"));
        // The payload survives as inert text; what matters is that no live tag
        // can form from it — the angle brackets are escaped.
        assert!(!out.contains("<img src=x"));
        assert!(out.contains("&lt;img src=x onerror=alert(1)&gt;"));
    }

    #[test]
    fn reference_links_reject_javascript_urls() {
        let mut evil = finding("X", Severity::High, 8.0);
        evil.references = vec!["javascript:alert(1)".into()];
        let out = render(&ctx(), &[evil], None);
        assert!(!out.contains(r##"href="javascript:"##));
        assert!(out.contains(r##"href="#""##));
    }

    #[test]
    fn report_contains_no_scripts() {
        let cov = ChecklistEngine::assess(&["Sentinel Native".into()], &[]);
        let out = render(&ctx(), &[finding("X", Severity::High, 8.0)], Some(&cov));
        assert!(!out.contains("<script"));
    }

    #[test]
    fn coverage_gaps_are_reported_to_developers() {
        let cov = ChecklistEngine::assess(&["Sentinel Native".into()], &[]);
        let out = render(&ctx(), &[], Some(&cov));
        assert!(out.contains("Coverage Gaps"));
        assert!(out.contains("Requires manual analysis"));
        assert!(out.contains("Not exercised in this run"));
        assert!(out.contains("Install"), "should say which tool closes the gap");
    }

    #[test]
    fn a_high_false_positive_score_surfaces_a_triage_warning() {
        let mut f = finding("Maybe", Severity::Medium, 5.0);
        f.ai_triage = Some(AITriage {
            is_false_positive_confidence: 0.75,
            cluster_id: None,
            triage_notes: Some("path looks like a test fixture".into()),
        });
        let out = render(&ctx(), &[f], None);
        assert!(out.contains("75% likely to be a false positive"));
    }

    #[test]
    fn a_low_false_positive_score_does_not_warn() {
        let mut f = finding("Confirmed", Severity::High, 8.0);
        f.ai_triage = Some(AITriage {
            is_false_positive_confidence: 0.02,
            cluster_id: None,
            triage_notes: None,
        });
        let out = render(&ctx(), &[f], None);
        assert!(!out.contains("likely to be a false positive"));
    }

    #[test]
    fn an_empty_assessment_says_so_rather_than_rendering_an_empty_table() {
        let out = render(&ctx(), &[], None);
        assert!(out.contains("No findings to remediate"));
    }

    #[test]
    fn markdown_export_is_ticket_ready() {
        let md = render_markdown(&ctx(), &[finding("SQL Injection", Severity::Critical, 9.5)]);
        assert!(md.starts_with("## Technical Remediation Report"));
        assert!(md.contains("## 1. SQL Injection [Critical]"));
        assert!(md.contains("**CWE:** CWE-79"));
        assert!(md.contains("### How to fix"));
        assert!(md.contains("### Reproduction"));
    }

    #[test]
    fn markdown_export_handles_an_empty_assessment() {
        let md = render_markdown(&ctx(), &[]);
        assert!(md.contains("No findings to remediate"));
    }

    #[test]
    fn findings_appear_in_priority_order() {
        let out = render(
            &ctx(),
            &[finding("Low one", Severity::Low, 2.0), finding("Critical one", Severity::Critical, 9.9)],
            None,
        );
        let crit = out.find("Critical one").unwrap();
        let low = out.find("Low one").unwrap();
        assert!(crit < low, "highest priority finding must be listed first");
    }

    #[test]
    fn long_locations_are_truncated_in_the_index_but_not_in_the_detail() {
        let mut f = finding("X", Severity::High, 8.0);
        f.affected_component = format!("https://app.test/{}", "a".repeat(200));
        let out = render(&ctx(), &[f.clone()], None);
        assert!(out.contains('…'), "index should truncate");
        assert!(out.contains(&html(&f.affected_component)), "detail should show the full location");
    }
}
