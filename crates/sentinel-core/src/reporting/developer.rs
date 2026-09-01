//! Developer / technical remediation report.
//!
//! Written for the engineer who has to fix the finding. Every section answers
//! the same four questions in order: where is it, how do I prove it, how do I
//! fix it, and how do I verify the fix worked.

use super::charts;
use super::escape::{href, html, html_multiline, image_data_uri};
use super::{
    base_stylesheet, footer_html, remediation_window, sort_by_priority, ReportContext,
    ReportFindings, SeverityCounts,
};
use crate::checklist::{CheckStatus, CoverageReport};
use crate::exceptions::{self, ExceptionRecord};
use crate::reporting::owasp;
use crate::scoring::Cvss4Vector;
use crate::models::finding::{Finding, FindingStatus};
use crate::scoring::priority::PriorityScoringEngine;
use chrono::Utc;

/// Render the developer report as a self-contained HTML document.
pub fn render(
    ctx: &ReportContext,
    findings: &[Finding],
    coverage: Option<&CoverageReport>,
) -> String {
    // Accepted risks are not remediation work. They are listed at the end so a
    // developer knows they exist, but they do not inflate the counts at the top
    // or the numbered work queue in between.
    let split = ReportFindings::partition(findings);
    let counts = split.counts();

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
  <div class="banner">{classification} — technical distribution only</div>
  {header}
  {triage_guide}
  {rollup}
  {index}
  {surface}
  {untested}
  {details}
  {accepted}
  {excluded}
  {footer}
</div>
</body>
</html>"##,
        target = html(&ctx.target_name),
        classification = html(&ctx.classification),
        css = base_stylesheet(),
        extra = extra_stylesheet(),
        header = header(ctx, &counts),
        triage_guide = triage_guide(&split),
        rollup = owasp_rollup(&split.active),
        index = index_table(&split.active),
        surface = surface_section(&split),
        untested = untested_section(coverage),
        details = detail_sections(&split.active),
        accepted = accepted_section(ctx, &split),
        excluded = excluded_section(ctx),
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

/* The findings index declares column widths, but without a fixed layout the
   browser widens the Location column to fit long URLs and crushes the Finding
   column to one word per line. Fixed layout honours the declared widths and
   wraps the URL instead. */
table.index{table-layout:fixed}
table.index td{vertical-align:top}
table.index td.loc{font-family:'Cascadia Mono',Consolas,monospace;font-size:10.5px;
  overflow-wrap:anywhere;word-break:break-word}
table.index td.title{overflow-wrap:break-word}
/* "Informational" is the longest severity label and overflowed its cell into
   the priority column. Let the pill shrink rather than spill. */
table.index .pill{font-size:10px;padding:2px 7px;max-width:100%}
/* Keep a row whole; a row split across the page boundary left an orphaned
   fragment ("in response headers") alone on an otherwise blank page. */
table.index tr{page-break-inside:avoid;break-inside:avoid}

/* Validation panel: the developer's first question about any scanner output is
   "is this actually real", so the answer gets its own fixed place on every
   finding rather than an occasional warning box. */
.validate{display:grid;grid-template-columns:150px 1fr;gap:0;border:1px solid var(--line);
  border-radius:8px;overflow:hidden;margin:12px 0}
.validate .score{padding:12px;text-align:center;color:#fff;display:flex;flex-direction:column;
  justify-content:center}
.validate .score b{font-size:22px;line-height:1.1}
.validate .score span{font-size:10px;letter-spacing:.7px;text-transform:uppercase;opacity:.9}
.validate .body{padding:11px 14px;font-size:12.5px;background:var(--soft)}
.validate .body p{margin:0 0 6px}
.validate .body p:last-child{margin-bottom:0}
.dismiss{border-left:4px solid #64748b;background:#f8fafc;padding:11px 14px;
  border-radius:0 7px 7px 0;margin:10px 0;font-size:12.5px}

/* CVSS metric breakdown: the vector spelled out, so a reader can challenge the
   score instead of taking it on faith. */
table.cvss{font-size:11.5px;margin:6px 0 2px}
table.cvss td,table.cvss th{padding:5px 9px}
table.cvss .m{font-family:'Cascadia Mono',Consolas,monospace;font-weight:700;
  white-space:nowrap;width:52px}
table.cvss .v{font-weight:600;white-space:nowrap;width:120px}
/* Evidence transcripts read as a terminal session, not as prose. */
pre.transcript{background:#0b1220;border-left:3px solid #38bdf8}
pre.fix-code{background:#052e1a;border-left:3px solid #16a34a;color:#d1fae5}
.owasp-row td{vertical-align:middle}
@media print{.validate,.dismiss{page-break-inside:avoid}}
"##
}

/// How confident the engine is that a finding is genuine, and on what basis.
///
/// Scanner output is not evidence on its own, and a developer whose first three
/// tickets were noise stops reading the fourth. Every finding therefore states
/// what it was determined from and how much of that is direct observation
/// versus inference, so a real weakness is not lost among things that merely
/// look like one.
struct Validation {
    /// 0–100 confidence that the finding is genuine.
    confidence: u8,
    label: &'static str,
    colour: &'static str,
    /// How the finding was established.
    basis: String,
    /// What would make this a false positive, in this specific case.
    caveat: &'static str,
}

fn validation_of(f: &Finding) -> Validation {
    let fp_confidence = f
        .ai_triage
        .as_ref()
        .map(|t| t.is_false_positive_confidence)
        .unwrap_or(0.25)
        .clamp(0.0, 1.0);
    let confidence = ((1.0 - fp_confidence) * 100.0).round() as u8;

    let tools_lower: Vec<String> = f.source_tools.iter().map(|t| t.to_lowercase()).collect();
    let is_runtime = tools_lower.iter().any(|t| {
        t.contains("native") || t.contains("zap") || t.contains("nuclei") || t.contains("dast")
    });
    let is_static = tools_lower
        .iter()
        .any(|t| t.contains("semgrep") || t.contains("sast") || t.contains("gitleaks"));
    let is_dependency = tools_lower.iter().any(|t| t.contains("trivy"));
    let has_evidence = !f.evidences.is_empty();
    let multi_tool = f.source_tools.len() >= 2;

    let mut basis = if multi_tool && is_runtime && is_static {
        format!(
            "Confirmed independently by {} engines, including one that observed it on the running \
             application and one that located it in the source.",
            f.source_tools.len()
        )
    } else if is_runtime {
        "Observed directly in a live HTTP or TLS response from the target — the state described below \
         is what the server actually returned, not an inference about what it might return."
            .to_string()
    } else if is_dependency {
        "Derived from a declared dependency version matched against a public vulnerability database. \
         The version is a fact; whether the vulnerable code path is reachable from your application \
         is not established by this check."
            .to_string()
    } else if is_static {
        "Matched by static analysis against the source. The pattern is present in the code; whether \
         it is reachable with attacker-controlled input at runtime has not been confirmed."
            .to_string()
    } else {
        "Reported by the engine named below.".to_string()
    };

    if has_evidence {
        basis.push_str(&format!(
            " {} evidence artefact{} captured at the time of testing {} attached below, each with a \
             SHA-256 hash so it can be checked against the engagement record.",
            f.evidences.len(),
            if f.evidences.len() == 1 { "" } else { "s" },
            if f.evidences.len() == 1 { "is" } else { "are" },
        ));
    } else {
        basis.push_str(
            " No evidence artefact was captured for this finding, so verify it by hand before \
             scheduling work.",
        );
    }

    let caveat = if is_dependency {
        "the vulnerable function is never called on any reachable path, or the component is already \
         patched by a distribution backport that leaves the version string unchanged"
    } else if is_static && !is_runtime {
        "the matched code is unreachable in production, the input is already validated upstream, or \
         the pattern is inside test or fixture code"
    } else if is_runtime {
        "the behaviour differs on the production edge — a CDN, WAF or reverse proxy that adds the \
         missing control after this response left the origin"
    } else {
        "the engine matched a pattern that does not hold in your deployment"
    };

    let (label, colour) = match confidence {
        90..=100 => ("Confirmed", "#166534"),
        70..=89 => ("High confidence", "#15803d"),
        45..=69 => ("Needs verification", "#ca8a04"),
        _ => ("Likely false positive", "#b91c1c"),
    };

    Validation { confidence, label, colour, basis, caveat }
}

/// The block that turns "this might be noise" into an action a developer can take.
fn validation_panel(f: &Finding) -> String {
    let v = validation_of(f);
    format!(
        r##"<div class="validate">
  <div class="score" style="background:{colour}">
    <b>{confidence}%</b>
    <span>{label}</span>
  </div>
  <div class="body">
    <p><strong>How this was determined.</strong> {basis}</p>
    <p><strong>This is a false positive if</strong> {caveat}. If that is the case, dismiss it in
    SentinelVAPT with the reason — the dismissal is recorded against the target and is applied
    automatically to every later scan, so this finding will not come back in the next report.</p>
  </div>
</div>"##,
        colour = v.colour,
        confidence = v.confidence,
        label = v.label,
        basis = html(&v.basis),
        caveat = v.caveat,
    )
}

/// Up-front explanation of how to deal with output that is not a real weakness.
///
/// Placed before the findings index because it changes how the list is read: a
/// developer who knows a dismissal is permanent triages the queue instead of
/// arguing with it.
fn triage_guide(split: &ReportFindings) -> String {
    let unverified = split
        .active
        .iter()
        .filter(|f| validation_of(f).confidence < 70)
        .count();

    let counts_line = if unverified == 0 {
        "Every finding in this report was either observed directly on the running application or \
         confirmed by more than one engine."
            .to_string()
    } else {
        format!(
            "{unverified} of the {total} findings below are flagged <em>Needs verification</em> or \
             lower. Start with those: confirming or dismissing them is faster than fixing them, and \
             it shortens the queue for everyone else.",
            total = split.active.len(),
        )
    };

    format!(
        r##"<h2>Before You Start — Handling False Positives</h2>
<p>{counts_line}</p>
<p>Every finding carries a confidence panel stating what it was determined from and the specific
condition that would make it wrong. Three outcomes, and only three:</p>
<table>
  <thead><tr><th style="width:170px">If it is…</th><th style="width:190px">Mark it</th><th>What happens next</th></tr></thead>
  <tbody>
    <tr><td><strong>Real, and you will fix it</strong></td><td><code>In Progress</code> &rarr; <code>Remediated</code></td>
        <td>Nothing is suppressed. The next scan re-tests it, which is how the fix gets proven rather than assumed.</td></tr>
    <tr><td><strong>Real, but you are choosing to carry it</strong></td><td><code>Accepted Risk</code></td>
        <td>It leaves the open counts and the roadmap, and appears in the client report&#39;s accepted-risk register with your justification and a review date. Disclosed, not deleted.</td></tr>
    <tr><td><strong>Not real</strong></td><td><code>False Positive</code></td>
        <td>It is removed from every deliverable, and the dismissal is recorded against the target so the next scan applies it automatically. You triage it once.</td></tr>
  </tbody>
</table>
<div class="callout small"><strong>A dismissal needs a reason and a name.</strong> Both are required by the
tool and both are retained: the point of the register is that a later reader can challenge the judgement,
which is not possible if the record only says the finding was dismissed.</div>"##
    )
}

/// Findings the business has formally accepted — context, not work.
fn accepted_section(ctx: &ReportContext, split: &ReportFindings) -> String {
    if split.accepted.is_empty() {
        return String::new();
    }

    let now = Utc::now();
    let register = exceptions::ExceptionRegister::from_records(ctx.exceptions.iter());

    let rows: String = split
        .accepted
        .iter()
        .map(|f| {
            let record: Option<&ExceptionRecord> = register.covering(f, now);
            let reason = record
                .map(|r| html(&r.justification))
                .unwrap_or_else(|| "See the engagement record.".to_string());
            let review = record
                .and_then(|r| r.expires_at)
                .map(|w| w.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "open-ended".to_string());
            format!(
                r##"<tr>
  <td><span class="pill" style="background:{colour}">{severity}</span></td>
  <td>{title}<div class="small muted">{cwe}</div></td>
  <td class="loc small">{component}</td>
  <td class="small">{reason}</td>
  <td class="small" style="white-space:nowrap">{owner}<div class="muted">review {review}</div></td>
</tr>"##,
                colour = charts::severity_color(&f.severity),
                severity = charts::severity_name(&f.severity),
                title = html(&f.title),
                cwe = html(f.cwe_id.as_deref().unwrap_or("—")),
                component = html(&truncate(&f.affected_component, 70)),
                reason = reason,
                owner = html(&record.map(|r| r.raised_by.clone()).unwrap_or_else(|| "—".into())),
                review = review,
            )
        })
        .collect();

    format!(
        r##"<h2 class="page-break">Accepted Risks — No Action Required</h2>
<p>These weaknesses are real and were confirmed, but the business has formally accepted them. They are here
so you are not surprised by them in the code or by a scanner run of your own — they are not on the
remediation queue above.</p>
<table class="index">
  <thead><tr>
    <th style="width:12%">Severity</th><th style="width:28%">Finding</th><th style="width:24%">Location</th>
    <th style="width:24%">Why it was accepted</th><th style="width:12%">Owner</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>
<div class="callout small">An acceptance with a review date lapses on that date. When it does, the finding
returns to the open queue on the next scan rather than staying suppressed indefinitely.</div>"##
    )
}

/// What was dismissed as noise, so the report's silence is accounted for.
fn excluded_section(ctx: &ReportContext) -> String {
    let dismissals = ctx.active_dismissals();
    if dismissals.is_empty() {
        return String::new();
    }

    let rows: String = dismissals
        .iter()
        .map(|r| {
            format!(
                r##"<tr>
  <td>{title}</td>
  <td class="loc small">{component}</td>
  <td class="small">{reason}</td>
  <td class="small" style="white-space:nowrap">{who}<div class="muted">{when}</div></td>
</tr>"##,
                title = html(&r.title),
                component = html(&truncate(&r.affected_component, 70)),
                reason = html(&r.justification),
                who = html(&r.raised_by),
                when = r.created_at.format("%Y-%m-%d"),
            )
        })
        .collect();

    format!(
        r##"<h2>Dismissed as False Positives</h2>
<p>The observations below were raised by an engine, reviewed, and judged not to be genuine weaknesses. They
are excluded from the findings above and from the client report. They are listed here so the exclusion is
visible and reviewable rather than silent — if one of these is wrong, reopen it in SentinelVAPT and it
returns to the queue on the next scan.</p>
<table class="index">
  <thead><tr>
    <th style="width:30%">Observation</th><th style="width:26%">Location</th>
    <th style="width:30%">Why it was dismissed</th><th style="width:14%">Dismissed by</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>"##
    )
}

/// The CVSS vector, spelled out metric by metric.
///
/// A vector string is a checksum, not an argument. `PR:N/UI:N` is the
/// difference between "anyone on the internet" and "an authenticated user who
/// also has to be tricked into clicking", and a reader who cannot see that has
/// no basis on which to disagree with the score — which means the score is
/// being taken on faith rather than reviewed.
fn cvss_breakdown(f: &Finding) -> String {
    let Some(cvss) = f.cvss4.as_ref() else { return String::new() };
    if cvss.vector_string.trim().is_empty() {
        return String::new();
    }

    // A vector this engine cannot parse still has to reach the reader. It may
    // have come from another tool, or use a metric added after this build; in
    // either case printing it raw loses nothing, whereas returning early would
    // silently drop the one piece of evidence behind the score.
    let Ok(vector) = Cvss4Vector::parse(&cvss.vector_string) else {
        return format!(
            r##"<div class="section-label">CVSS 4.0 vector</div><pre>{vector}</pre>
<p class="small muted">Base score <strong>{score:.1}</strong> ({label}), as reported by the engine
that raised this finding. The vector could not be broken down here — recompute it with any CVSS 4.0
calculator to check the score.</p>"##,
            vector = html(&cvss.vector_string),
            score = cvss.base_score,
            label = html(&cvss.severity_label),
        );
    };

    let rows: String = vector
        .present()
        .into_iter()
        .filter_map(|(metric, value)| {
            let (name, meaning) = metric_meaning(metric, value)?;
            Some(format!(
                r##"<tr><td class="m">{metric}:{value}</td><td class="v">{name}</td><td>{meaning}</td></tr>"##,
                metric = html(metric),
                value = html(value),
                name = html(name),
                meaning = html(meaning),
            ))
        })
        .collect();

    if rows.is_empty() {
        return String::new();
    }

    format!(
        r##"<div class="section-label">CVSS 4.0 — how this score is reached</div>
<pre>{vector}</pre>
<table class="cvss">
  <thead><tr><th>Metric</th><th>Value</th><th>What it means here</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<p class="small muted">Base score <strong>{score:.1}</strong> ({label}). Recompute it from the
vector above with any CVSS 4.0 calculator — this figure is derived from the vector, never
declared alongside it.</p>"##,
        vector = html(&cvss.vector_string),
        rows = rows,
        score = cvss.base_score,
        label = html(&cvss.severity_label),
    )
}

/// Plain-language meaning of one CVSS 4.0 metric value.
///
/// Only the base and threat metrics are described. An environmental metric is
/// the client's own judgement about their deployment, and this engine has no
/// basis on which to narrate it.
fn metric_meaning(metric: &str, value: &str) -> Option<(&'static str, &'static str)> {
    Some(match (metric, value) {
        ("AV", "N") => ("Attack vector", "Reachable across the network — no local access needed."),
        ("AV", "A") => ("Attack vector", "Requires access to the adjacent network."),
        ("AV", "L") => ("Attack vector", "Requires local access to the host."),
        ("AV", "P") => ("Attack vector", "Requires physical access to the device."),

        ("AC", "L") => ("Attack complexity", "No special conditions — it works reliably."),
        ("AC", "H") => ("Attack complexity", "The attacker must defeat a mitigation first."),

        ("AT", "N") => ("Attack requirements", "No preconditions on the target's state."),
        ("AT", "P") => ("Attack requirements", "Depends on a condition the attacker does not control."),

        ("PR", "N") => ("Privileges required", "None — an anonymous visitor can do this."),
        ("PR", "L") => ("Privileges required", "An ordinary authenticated account is enough."),
        ("PR", "H") => ("Privileges required", "Administrative privileges are needed."),

        ("UI", "N") => ("User interaction", "None — no victim has to do anything."),
        ("UI", "P") => ("User interaction", "A user must perform an ordinary action, such as following a link."),
        ("UI", "A") => ("User interaction", "A user must be induced into a deliberate, unusual action."),

        ("VC", "H") => ("Confidentiality impact", "Total loss of confidentiality for the affected component."),
        ("VC", "L") => ("Confidentiality impact", "Some information is disclosed, but not everything."),
        ("VC", "N") => ("Confidentiality impact", "No information is disclosed."),

        ("VI", "H") => ("Integrity impact", "The attacker can modify any data the component holds."),
        ("VI", "L") => ("Integrity impact", "Limited modification, with the attacker unable to choose the outcome."),
        ("VI", "N") => ("Integrity impact", "No data can be modified."),

        ("VA", "H") => ("Availability impact", "The component can be made fully unavailable."),
        ("VA", "L") => ("Availability impact", "Performance is degraded but the service continues."),
        ("VA", "N") => ("Availability impact", "Availability is unaffected."),

        ("SC", "H") => ("Subsequent confidentiality", "Total disclosure in a system beyond the vulnerable one."),
        ("SC", "L") => ("Subsequent confidentiality", "Partial disclosure beyond the vulnerable component."),
        ("SC", "N") => ("Subsequent confidentiality", "No impact beyond the vulnerable component."),

        ("SI", "H") => ("Subsequent integrity", "Data in another system can be modified at will."),
        ("SI", "L") => ("Subsequent integrity", "Limited modification beyond the vulnerable component."),
        ("SI", "N") => ("Subsequent integrity", "No integrity impact beyond the vulnerable component."),

        ("SA", "H") => ("Subsequent availability", "Another system can be made fully unavailable."),
        ("SA", "L") => ("Subsequent availability", "Another system is degraded."),
        ("SA", "N") => ("Subsequent availability", "No availability impact beyond the vulnerable component."),

        ("E", "A") => ("Exploit maturity", "Attacked in the wild, or automated exploitation exists."),
        ("E", "P") => ("Exploit maturity", "A proof-of-concept exploit is public."),
        ("E", "U") => ("Exploit maturity", "No public exploit is known."),

        _ => return None,
    })
}

/// Where the Top 10 rollup sits in the technical document.
///
/// The point here is different from the client report's version. Twenty tickets
/// that turn out to be one missing header block is one piece of work, not
/// twenty, and nothing else in the document makes that visible.
fn owasp_rollup(sorted: &[Finding]) -> String {
    let rows = owasp::rollup(sorted);
    if rows.iter().all(|r| r.total == 0) {
        return String::new();
    }

    let body: String = rows
        .iter()
        .map(|r| {
            let examples = if r.examples.is_empty() {
                r##"<span class="muted">—</span>"##.to_string()
            } else {
                html(&r.examples.join("; "))
            };
            let focus = owasp::category(&r.code)
                .map(|c| html(c.developer_focus))
                .unwrap_or_default();
            format!(
                r##"<tr class="owasp-row">
  <td style="white-space:nowrap"><strong>{code}</strong><div class="small muted">{name}</div></td>
  <td style="text-align:center;font-weight:700;color:{colour}">{total}</td>
  <td class="small">{examples}<div class="muted" style="margin-top:4px">{focus}</div></td>
</tr>"##,
                code = html(&r.code),
                name = html(&r.name),
                colour = r.status_color(),
                total = r.total,
                examples = examples,
                focus = focus,
            )
        })
        .collect();

    format!(
        r##"<h2>Findings by OWASP Top 10:2025</h2>
<p>The same findings grouped by root cause. Several tickets landing in one row usually means
one fix, applied once, closes all of them — a missing header block or an unparameterised query
pattern rather than a list of unrelated defects.</p>
<table>
  <thead><tr><th style="width:210px">Category</th><th style="width:70px">Findings</th><th>What landed here, and where to look</th></tr></thead>
  <tbody>{body}</tbody>
</table>"##
    )
}

fn header(ctx: &ReportContext, counts: &SeverityCounts) -> String {
    let logo = ctx
        .logo_data_uri
        .as_deref()
        .and_then(image_data_uri)
        // max-width matters as much as max-height: a wide banner logo bounded
        // only by height renders wider than the page and breaks the layout.
        .map(|uri| {
            format!(
                r##"<img src="{uri}" alt="" style="max-height:44px;max-width:240px;object-fit:contain;margin-bottom:16px">"##
            )
        })
        .unwrap_or_default();

    format!(
        r##"<header style="margin:24px 0 4px">
  {logo}
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
        logo = logo,
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
            let v = validation_of(f);
                format!(
                r##"<tr>
  <td style="text-align:center"><a href="#f{n}">{n}</a></td>
  <td><span class="pill" style="background:{color}">{severity}</span></td>
  <td style="text-align:center;font-weight:600">{score:.1}</td>
  <td style="text-align:center;font-weight:600;color:{vcolour}">{confidence}%<div class="small muted" style="font-weight:400">{vlabel}</div></td>
  <td class="title">{title}</td>
  <td class="loc">{component}</td>
  <td class="small">{cwe}</td>
  <td class="small">{status}</td>
</tr>"##,
                n = i + 1,
                color = charts::severity_color(&f.severity),
                severity = charts::severity_name(&f.severity),
                score = f.priority_score,
                vcolour = v.colour,
                confidence = v.confidence,
                vlabel = v.label,
                title = html(&f.title),
                component = html(&truncate(&f.affected_component, 70)),
                cwe = html(f.cwe_id.as_deref().unwrap_or("—")),
                status = html(status_label(&f.status)),
            )
        })
        .collect();

    format!(
        // Widths total 100%: the finding title gets the most room, because a
        // squeezed title column wraps to one word per line and makes the index
        // unreadable.
        r##"<h2>Findings Index</h2>
<table class="index">
  <thead><tr>
    <th style="width:4%">#</th><th style="width:12%">Severity</th><th style="width:7%">Priority</th>
    <th style="width:11%">Confidence</th>
    <th style="width:24%">Finding</th><th style="width:22%">Location</th>
    <th style="width:10%">CWE</th><th style="width:10%">Status</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>"##
    )
}

/// What the scan reached, before the reader draws conclusions from what it did
/// not find.
fn surface_section(split: &ReportFindings) -> String {
    let notes = split.surface_notes();
    if notes.is_empty() {
        return String::new();
    }

    let body: String = notes
        .iter()
        .map(|(description, evidences)| {
            let blocks: String = evidences
                .iter()
                .map(|(title, content)| {
                    format!(
                        r##"<div class="section-label">{title}</div><pre>{content}</pre>"##,
                        title = html(title),
                        content = html(content),
                    )
                })
                .collect();
            format!("<p>{}</p>{blocks}", html_multiline(description))
        })
        .collect();

    format!(
        r##"<h2 class="page-break">Assessment Surface</h2>
<p>What this scan reached. Read it before drawing a conclusion from what is <em>not</em> in the
findings above — an unvisited route was not assessed, and absence of a finding there is absence of
evidence rather than evidence of absence.</p>
{body}"##
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

    // The vector spelled out rather than printed as an opaque string: a score
    // nobody can check is a number, not an argument.
    let vector_html = cvss_breakdown(f);

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
                // An HTTP exchange reads as a transcript, not as prose, and the
                // styling should say which one the reader is looking at.
                let is_transcript = matches!(
                    e.evidence_type.as_str(),
                    "http_request" | "http_response" | "http_exchange" | "tls_handshake"
                );
                let class = if is_transcript { " class=\"transcript\"" } else { "" };
                let integrity = if e.hash.trim().is_empty() {
                    r##"<span class="muted">derived from the findings above; no separate artefact</span>"##.to_string()
                } else {
                    format!("SHA-256 {}", html(&truncate(&e.hash, 32)))
                };
                format!(
                    r##"<div class="small muted" style="margin-top:8px">{title} <span class="tag">{etype}</span></div>
<pre{class}>{content}</pre>
<div class="small muted">{integrity}</div>"##,
                    title = html(&e.title),
                    etype = html(&e.evidence_type),
                    class = class,
                    content = html(&e.content),
                    integrity = integrity,
                )
            })
            .collect();
        format!(
            r##"<div class="section-label">Evidence (sanitized)</div>
<p class="small muted">Captured at the time of testing and hashed on capture, so any later
alteration is detectable. Credentials, session cookies and authorization headers are removed
before an artefact is stored — a report is a document that gets emailed around.</p>
{blocks}"##
        )
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

    // Every finding gets the validation panel, not only the doubtful ones: a
    // developer needs to know a finding is solid just as much as they need to
    // know it is shaky, and a box that appears only on bad news teaches the
    // reader to skim past the good news too.
    let triage = validation_panel(f);

    // The engine's own triage note, when it recorded one, sits under the panel.
    let triage_note = f
        .ai_triage
        .as_ref()
        .and_then(|t| t.triage_notes.as_deref())
        .filter(|n| !n.trim().is_empty())
        .map(|n| format!(r##"<div class="small muted">Engine note: {}</div>"##, html(n)))
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
  {triage_note}

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
  behaviour has changed. Then re-run the assessment: the finding disappearing from the next report is the
  proof the fix landed. Marking it <code>Remediated</code> by hand does <em>not</em> suppress the re-test —
  that is deliberate, so a fix is confirmed rather than asserted.</p>

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
        triage_note = triage_note,
        component = html(&f.affected_component),
        description = html_multiline(&f.description),
        rationale = html(&rationale),
        vector_html = vector_html,
        steps = steps,
        evidence = evidence,
        remediation = remediation_html(&f.remediation),
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

/// Render remediation prose, turning fenced blocks into real code blocks.
///
/// Checks that can offer an exact configuration line do so as a ```-fenced
/// block. Escaping it as prose would leave the developer retyping a directive
/// from a wrapped paragraph, which is how a `Content-Security-Policy` ends up
/// deployed with a typo in it.
fn remediation_html(remediation: &str) -> String {
    if !remediation.contains("```") {
        return html_multiline(remediation);
    }

    let mut out = String::new();
    let mut in_code = false;
    let mut buffer: Vec<&str> = Vec::new();

    let flush = |out: &mut String, buffer: &mut Vec<&str>, in_code: bool| {
        if buffer.is_empty() {
            return;
        }
        let text = buffer.join("\n");
        if in_code {
            out.push_str(&format!(
                r##"<pre class="fix-code">{}</pre>"##,
                html(text.trim_matches('\n'))
            ));
        } else if !text.trim().is_empty() {
            out.push_str(&format!("<div>{}</div>", html_multiline(text.trim())));
        }
        buffer.clear();
    };

    for line in remediation.lines() {
        if line.trim_start().starts_with("```") {
            flush(&mut out, &mut buffer, in_code);
            in_code = !in_code;
            continue;
        }
        buffer.push(line);
    }
    // An unterminated fence is a content bug, not a reason to lose the text.
    flush(&mut out, &mut buffer, in_code);
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

    /// A 1x1 PNG — the smallest valid logo payload.
    const PNG: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==";

    #[test]
    fn the_company_logo_is_embedded_in_the_header() {
        let mut c = ctx();
        c.logo_data_uri = Some(PNG.into());
        let out = render(&c, &[finding("XSS", Severity::High, 8.0)], None);
        assert!(out.contains(PNG), "developer report must carry the client's logo");
    }

    #[test]
    fn a_scriptable_logo_is_refused_rather_than_embedded() {
        let mut c = ctx();
        // SVG can carry script, so it must never reach the document.
        c.logo_data_uri = Some("data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=".into());
        let out = render(&c, &[finding("XSS", Severity::High, 8.0)], None);
        assert!(!out.contains("svg+xml"));
        assert!(!out.contains("<img"), "report should render unbranded instead");
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
    fn a_doubtful_finding_is_labelled_and_the_engine_note_carried_through() {
        let mut f = finding("Maybe", Severity::Medium, 5.0);
        f.ai_triage = Some(AITriage {
            is_false_positive_confidence: 0.75,
            cluster_id: None,
            triage_notes: Some("path looks like a test fixture".into()),
        });
        let out = render(&ctx(), &[f], None);
        assert!(out.contains("25%"), "confidence is the complement of the false-positive score");
        assert!(out.contains("Likely false positive"));
        assert!(out.contains("path looks like a test fixture"), "the engine's reasoning must reach the reader");
    }

    #[test]
    fn a_directly_observed_finding_is_reported_as_confirmed() {
        let mut f = finding("Confirmed", Severity::High, 8.0);
        f.ai_triage = Some(AITriage {
            is_false_positive_confidence: 0.02,
            cluster_id: None,
            triage_notes: None,
        });
        let out = render(&ctx(), &[f], None);
        assert!(out.contains("98%"));
        assert!(out.contains("Confirmed"));
        assert!(!out.contains("Likely false positive"));
    }

    /// The panel is the point: a developer must always be told the basis, not
    /// only when the engine happens to doubt itself.
    #[test]
    fn every_finding_carries_a_validation_panel_and_a_way_out() {
        let out = render(&ctx(), &[finding("XSS", Severity::High, 8.0)], None);
        assert!(out.contains("How this was determined"));
        assert!(out.contains("This is a false positive if"));
        assert!(out.contains("will not come back in the next report"));
    }

    #[test]
    fn the_report_explains_the_three_triage_outcomes_before_the_queue() {
        let out = render(&ctx(), &[finding("XSS", Severity::High, 8.0)], None);
        assert!(out.contains("Handling False Positives"));
        for status in ["In Progress", "Accepted Risk", "False Positive"] {
            assert!(out.contains(status), "the guide must name the {status} outcome");
        }
        assert!(
            out.find("Handling False Positives") < out.find("Findings Index"),
            "the guide has to come before the queue it changes how you read"
        );
    }

    /// Static analysis and a live observation are not the same kind of claim,
    /// and a developer deciding what to trust needs the difference stated.
    #[test]
    fn the_basis_distinguishes_a_live_observation_from_a_code_match() {
        let mut runtime = finding("Missing HSTS", Severity::Medium, 5.0);
        runtime.source_tools = vec!["Sentinel Native".into()];
        assert!(validation_of(&runtime).basis.contains("Observed directly"));

        let mut static_only = finding("Tainted sink", Severity::High, 7.0);
        static_only.source_tools = vec!["Semgrep SAST".into()];
        let v = validation_of(&static_only);
        assert!(v.basis.contains("static analysis"));
        assert!(v.caveat.contains("unreachable"), "a SAST match needs its own caveat");

        let mut dependency = finding("CVE in lodash", Severity::High, 7.5);
        dependency.source_tools = vec!["Trivy".into()];
        assert!(validation_of(&dependency).basis.contains("dependency version"));
    }

    #[test]
    fn two_engines_agreeing_raises_the_stated_basis() {
        let mut f = finding("SQL injection", Severity::Critical, 9.4);
        f.source_tools = vec!["Semgrep SAST".into(), "OWASP ZAP".into()];
        assert!(validation_of(&f).basis.contains("Confirmed independently"));
    }

    #[test]
    fn a_finding_with_no_evidence_says_so_rather_than_implying_proof() {
        let mut f = finding("Unproven", Severity::Medium, 5.0);
        f.evidences.clear();
        assert!(validation_of(&f).basis.contains("No evidence artefact"));
    }

    // ── Technical depth ─────────────────────────────────────────────────────

    /// A vector string is a checksum, not an argument. A reader who cannot see
    /// that PR:N means "anyone on the internet" has no basis on which to
    /// disagree with the score.
    #[test]
    fn the_cvss_vector_is_spelled_out_metric_by_metric() {
        let mut f = finding("SQL injection", Severity::Critical, 9.4);
        f.cvss4 = Some(crate::models::finding::CVSS4Data {
            vector_string: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N".into(),
            base_score: 9.3,
            severity_label: "Critical".into(),
        });
        let out = render(&ctx(), &[f], None);

        assert!(out.contains("how this score is reached"));
        assert!(out.contains("Privileges required"));
        assert!(out.contains("None — an anonymous visitor can do this."));
        assert!(out.contains("Total loss of confidentiality"));
        assert!(out.contains("Recompute it from the"), "the reader must be told they can check it");
    }

    /// A vector from another tool, or using a metric added after this build,
    /// must still reach the reader rather than being silently dropped.
    #[test]
    fn an_unparseable_vector_is_still_printed_rather_than_discarded() {
        let mut f = finding("From another engine", Severity::High, 7.0);
        f.cvss4 = Some(crate::models::finding::CVSS4Data {
            vector_string: "CVSS:4.0/AV:N/AC:L/ZZ:Q".into(),
            base_score: 7.0,
            severity_label: "High".into(),
        });
        let out = render(&ctx(), &[f], None);
        assert!(out.contains("CVSS:4.0/AV:N/AC:L/ZZ:Q"));
        assert!(out.contains("could not be broken down here"));
    }

    #[test]
    fn findings_are_rolled_up_by_owasp_category() {
        let mut a = finding("Missing CSP", Severity::Medium, 5.3);
        a.owasp_2025 = Some("A02:2025-Security Misconfiguration".into());
        let mut b = finding("Missing HSTS", Severity::Medium, 5.0);
        b.owasp_2025 = Some("A02:2025-Security Misconfiguration".into());

        let out = render(&ctx(), &[a, b], None);
        assert!(out.contains("Findings by OWASP Top 10:2025"));
        assert!(out.contains("Security Misconfiguration"));
        // The point of the section: several tickets, one root cause.
        assert!(out.contains("usually means"));
        assert!(out.contains("Response headers, cookie attributes"), "developer focus must be shown");
    }

    #[test]
    fn the_rollup_is_omitted_when_there_is_nothing_to_roll_up() {
        let out = render(&ctx(), &[], None);
        assert!(!out.contains("Findings by OWASP Top 10"));
    }

    /// A directive retyped out of a wrapped paragraph is how a CSP ends up
    /// deployed with a typo in it.
    #[test]
    fn fenced_remediation_renders_as_a_code_block() {
        let mut f = finding("Missing header", Severity::Medium, 5.0);
        f.remediation = "Set the header at the edge:\n\n```\nadd_header X-Frame-Options DENY;\n```\n\nThen redeploy.".into();
        let out = render(&ctx(), &[f], None);

        assert!(out.contains(r#"<pre class="fix-code">"#), "the snippet must be a code block");
        assert!(out.contains("add_header X-Frame-Options DENY;"));
        assert!(out.contains("Then redeploy."), "prose either side of the fence must survive");
    }

    /// An unterminated fence is a content bug; losing the text would turn it
    /// into a missing remediation.
    #[test]
    fn an_unterminated_fence_does_not_swallow_the_remediation() {
        let mut f = finding("Odd", Severity::Low, 2.0);
        f.remediation = "Do this:\n```\nsome config".into();
        let out = render(&ctx(), &[f], None);
        assert!(out.contains("some config"));
        assert!(out.contains("Do this:"));
    }

    #[test]
    fn remediation_without_a_fence_is_unchanged() {
        let out = render(&ctx(), &[finding("Plain", Severity::Low, 2.0)], None);
        assert!(out.contains("Fix it properly."));
        // The class name is always in the stylesheet; what must not appear is
        // an element using it.
        assert!(!out.contains(r#"<pre class="fix-code">"#));
    }

    #[test]
    fn http_evidence_is_presented_as_a_transcript_with_its_integrity_note() {
        let mut f = finding("Missing header", Severity::Medium, 5.0);
        f.evidences = vec![crate::models::finding::Evidence {
            evidence_type: "http_response".into(),
            title: "Response headers".into(),
            content: "HTTP/1.1 200 OK\nServer: nginx".into(),
            hash: "abc123def456".into(),
        }];
        let out = render(&ctx(), &[f], None);

        assert!(out.contains(r#"<pre class="transcript">"#));
        assert!(out.contains("SHA-256 abc123def456"));
        assert!(out.contains("hashed on capture"));
    }

    /// An aggregated finding's instance list has no artefact hash of its own,
    /// and claiming one would be a lie about the evidence chain.
    #[test]
    fn evidence_with_no_hash_says_so_rather_than_printing_an_empty_one() {
        let mut f = finding("Missing header", Severity::Medium, 5.0);
        f.evidences = vec![crate::models::finding::Evidence {
            evidence_type: "affected_locations".into(),
            title: "Affected pages (3)".into(),
            content: "/a\n/b\n/c".into(),
            hash: String::new(),
        }];
        let out = render(&ctx(), &[f], None);
        assert!(out.contains("no separate artefact"));
        assert!(!out.contains("SHA-256 </div>"));
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
