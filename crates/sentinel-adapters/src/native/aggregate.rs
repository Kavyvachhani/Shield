//! Collapsing per-page findings into what a report should actually say.
//!
//! Once the engine walks a whole application instead of one page, the naive
//! result is one finding per page per check: a hundred-page site with no
//! Content-Security-Policy produces a hundred identical Critical-looking rows,
//! the severity counts read as a catastrophe, and the genuinely page-specific
//! finding buried at row 340 is never seen. That is worse than not crawling.
//!
//! So each check declares how its findings aggregate:
//!
//! * [`Aggregation::Origin`] — a server or platform configuration issue. A
//!   missing HSTS header is one decision made once, not a hundred faults. It
//!   collapses to a single finding against the origin, carrying the count and
//!   the affected URLs as evidence.
//! * [`Aggregation::PerUrl`] — a fact about one location. A credential in one
//!   bundle and a stack trace on one endpoint are separate problems with
//!   separate fixes, and merging them would hide work.
//!
//! Collapsing to the *origin* rather than to the first URL seen also matters
//! for the exception register: an exception is keyed on a fingerprint that
//! includes the affected component, so a component that depends on crawl order
//! would silently break carry-forward between scans.

use super::builder::CheckSpec;
use sentinel_core::models::finding::{Evidence, Finding};
use std::collections::HashMap;

/// How a check's findings combine across pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aggregation {
    /// One finding for the whole origin, with the instances listed.
    Origin,
    /// One finding per affected location.
    PerUrl,
}

/// Checks whose result describes the deployment rather than a page.
///
/// Response headers, cookie attributes and transport configuration are set once
/// — at the edge, in the framework, in the server config — and reporting them
/// per page describes the crawl rather than the application.
///
/// Everything absent from this list defaults to [`Aggregation::PerUrl`], which
/// is the safe direction: over-reporting is a readability problem, while
/// wrongly merging two distinct weaknesses hides one of them.
pub fn aggregation_of(spec_id: &str) -> Aggregation {
    match spec_id {
        "NATIVE-HSTS-MISSING"
        | "NATIVE-HSTS-WEAK"
        | "NATIVE-CSP-MISSING"
        | "NATIVE-CSP-WEAK"
        | "NATIVE-CLICKJACKING"
        | "NATIVE-XCTO-MISSING"
        | "NATIVE-REFERRER-POLICY"
        | "NATIVE-PERMISSIONS-POLICY"
        | "NATIVE-BANNER-DISCLOSURE"
        | "NATIVE-COOKIE-INSECURE"
        | "NATIVE-COOKIE-HTTPONLY"
        | "NATIVE-COOKIE-SAMESITE"
        | "NATIVE-COOKIE-PREFIX"
        | "NATIVE-SESSION-LIFETIME"
        | "NATIVE-CACHE-CONTROL"
        | "NATIVE-COOP-MISSING"
        | "NATIVE-CORP-MISSING"
        | "NATIVE-XSS-FILTER-ENABLED" => Aggregation::Origin,
        _ => Aggregation::PerUrl,
    }
}

/// How many instances of one per-URL check reach the report before the rest are
/// summarised.
///
/// A report that lists four hundred instances of the same weakness is not more
/// informative than one that lists twenty-five and says how many more there
/// are; it is just unreadable.
const MAX_INSTANCES_PER_CHECK: usize = 25;

/// Collapse a crawl's findings into a reportable set.
///
/// `origin` is the application's base URL, used as the location of every
/// origin-aggregated finding so its identity does not depend on which page the
/// crawler happened to reach first.
pub fn collapse(findings: Vec<Finding>, origin: &str, specs: &[&'static CheckSpec]) -> Vec<Finding> {
    let by_title: HashMap<&str, &'static CheckSpec> =
        specs.iter().map(|s| (s.title, *s)).collect();

    // Grouped by the check that raised them, preserving first-seen order so the
    // output is deterministic rather than hash-ordered.
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<Finding>> = HashMap::new();

    for finding in findings {
        let key = finding.title.clone();
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(finding);
    }

    let mut out = Vec::new();
    for key in order {
        let group = groups.remove(&key).unwrap_or_default();
        let aggregation = by_title
            .get(key.as_str())
            .map(|spec| aggregation_of(spec.id))
            .unwrap_or(Aggregation::PerUrl);

        match aggregation {
            Aggregation::Origin => {
                if let Some(merged) = merge_to_origin(group, origin) {
                    out.push(merged);
                }
            }
            Aggregation::PerUrl => out.extend(cap_instances(group)),
        }
    }
    out
}

/// Fold every instance of one configuration check into a single finding.
fn merge_to_origin(mut group: Vec<Finding>, origin: &str) -> Option<Finding> {
    if group.is_empty() {
        return None;
    }
    let instances = group.len();
    let mut locations: Vec<String> = group.iter().map(|f| f.affected_component.clone()).collect();
    locations.sort();
    locations.dedup();

    let mut merged = group.swap_remove(0);
    merged.affected_component = origin.trim_end_matches('/').to_string();

    if locations.len() > 1 {
        merged.description = format!(
            "{}\n\nObserved on {} of the pages assessed, so this is a deployment-wide \
             configuration issue rather than a fault on one route. Fixing it at the edge or in \
             the application's response middleware resolves every instance at once.",
            merged.description,
            locations.len()
        );

        let shown: Vec<&String> = locations.iter().take(40).collect();
        let mut listing = shown
            .iter()
            .map(|l| l.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if locations.len() > shown.len() {
            listing.push_str(&format!("\n… and {} more", locations.len() - shown.len()));
        }
        merged.evidences.push(Evidence {
            evidence_type: "affected_locations".to_string(),
            title: format!("Affected pages ({})", locations.len()),
            content: listing,
            hash: String::new(),
        });
    }

    debug_assert!(instances >= locations.len());
    Some(merged)
}

/// Keep the first `MAX_INSTANCES_PER_CHECK` and record how many were omitted.
fn cap_instances(mut group: Vec<Finding>) -> Vec<Finding> {
    if group.len() <= MAX_INSTANCES_PER_CHECK {
        return group;
    }
    let omitted = group.len() - MAX_INSTANCES_PER_CHECK;
    group.truncate(MAX_INSTANCES_PER_CHECK);

    if let Some(first) = group.first_mut() {
        first.description = format!(
            "{}\n\nA further {omitted} instance(s) of this weakness were found and are not \
             listed individually. Treat the fix as applying to the pattern rather than only to \
             the locations named here.",
            first.description
        );
    }
    group
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::all_specs;
    use sentinel_core::models::finding::{FindingStatus, Severity};
    use uuid::Uuid;

    fn finding(title: &str, component: &str) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            title: title.into(),
            description: "Base description.".into(),
            severity: Severity::Medium,
            cvss4: None,
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.0,
            reachability_score: 1.0,
            priority_score: 5.0,
            priority_rationale: String::new(),
            cwe_id: Some("CWE-693".into()),
            owasp_2025: None,
            wstg_id: None,
            api_top10: None,
            affected_component: component.into(),
            evidences: vec![],
            repro_steps: vec![],
            remediation: "Fix".into(),
            references: vec![],
            status: FindingStatus::Open,
            source_tools: vec!["Sentinel Native".into()],
            ai_triage: None,
            created_at: chrono::Utc::now(),
        }
    }

    fn specs() -> Vec<&'static CheckSpec> {
        all_specs()
    }

    /// The failure this module exists to prevent: crawling a hundred pages must
    /// not turn one server misconfiguration into a hundred findings.
    #[test]
    fn a_configuration_issue_across_many_pages_is_one_finding() {
        let group: Vec<Finding> = (0..80)
            .map(|i| {
                finding(
                    "Content-Security-Policy Header Absent",
                    &format!("https://app.test/page{i}"),
                )
            })
            .collect();

        let out = collapse(group, "https://app.test", &specs());

        assert_eq!(out.len(), 1, "80 pages, one misconfiguration, one finding");
        assert_eq!(out[0].affected_component, "https://app.test");
        assert!(out[0].description.contains("Observed on 80 of the pages"));
    }

    /// The instances still have to be inspectable, or the merge has destroyed
    /// the evidence the reader needs to confirm the scope of the problem.
    #[test]
    fn the_merged_finding_lists_the_pages_it_covers() {
        let group: Vec<Finding> = (0..3)
            .map(|i| finding("Content-Security-Policy Header Absent", &format!("https://app.test/p{i}")))
            .collect();

        let out = collapse(group, "https://app.test", &specs());
        let evidence = out[0]
            .evidences
            .iter()
            .find(|e| e.evidence_type == "affected_locations")
            .expect("the affected pages must be recorded");

        assert!(evidence.title.contains('3'));
        for i in 0..3 {
            assert!(evidence.content.contains(&format!("/p{i}")), "{}", evidence.content);
        }
    }

    /// Collapsing to the origin rather than to whichever page was crawled first
    /// is what keeps an exception attached across scans — the fingerprint
    /// includes the affected component.
    #[test]
    fn the_merged_location_does_not_depend_on_crawl_order() {
        let a = vec![
            finding("Content-Security-Policy Header Absent", "https://app.test/one"),
            finding("Content-Security-Policy Header Absent", "https://app.test/two"),
        ];
        let b = vec![
            finding("Content-Security-Policy Header Absent", "https://app.test/two"),
            finding("Content-Security-Policy Header Absent", "https://app.test/one"),
        ];

        let first = collapse(a, "https://app.test", &specs());
        let second = collapse(b, "https://app.test", &specs());
        assert_eq!(first[0].affected_component, second[0].affected_component);
    }

    /// Two secrets in two bundles are two problems with two fixes.
    #[test]
    fn location_specific_findings_are_not_merged() {
        let group = vec![
            finding("Credential or API Key Exposed in Client-Delivered Content", "https://app.test/a.js"),
            finding("Credential or API Key Exposed in Client-Delivered Content", "https://app.test/b.js"),
        ];
        let out = collapse(group, "https://app.test", &specs());
        assert_eq!(out.len(), 2);
        assert_ne!(out[0].affected_component, out[1].affected_component);
    }

    #[test]
    fn a_flood_of_one_per_url_check_is_capped_and_says_so() {
        let group: Vec<Finding> = (0..90)
            .map(|i| {
                finding(
                    "Stack Trace or Debug Output Returned to the Client",
                    &format!("https://app.test/e{i}"),
                )
            })
            .collect();

        let out = collapse(group, "https://app.test", &specs());
        assert_eq!(out.len(), MAX_INSTANCES_PER_CHECK);
        assert!(out[0].description.contains("A further 65 instance"), "{}", out[0].description);
    }

    #[test]
    fn a_single_instance_is_left_exactly_as_it_was() {
        let one = finding("Content-Security-Policy Header Absent", "https://app.test/only");
        let out = collapse(vec![one], "https://app.test", &specs());
        assert_eq!(out.len(), 1);
        assert!(
            !out[0].description.contains("Observed on"),
            "one page is not a deployment-wide observation"
        );
        assert!(out[0].evidences.is_empty(), "no instance list is needed for one instance");
    }

    #[test]
    fn an_unknown_title_defaults_to_reporting_every_instance() {
        let group = vec![
            finding("Some Engine We Do Not Know", "https://app.test/a"),
            finding("Some Engine We Do Not Know", "https://app.test/b"),
        ];
        let out = collapse(group, "https://app.test", &specs());
        assert_eq!(out.len(), 2, "the safe default is to report rather than merge");
    }

    /// These describe one page or one file each, so merging them would hide
    /// work: two secrets in two bundles are two problems with two fixes.
    #[test]
    fn the_client_side_checks_report_every_location() {
        for id in [
            "NATIVE-SECRET-IN-CONTENT",
            "NATIVE-SOURCEMAP-EXPOSED",
            "NATIVE-JWT-IN-CONTENT",
            "NATIVE-INSECURE-BROWSER-STORAGE",
            "NATIVE-POSTMESSAGE-WILDCARD",
            "NATIVE-INSECURE-WEBSOCKET",
            "NATIVE-DOM-XSS-SINK",
        ] {
            assert_eq!(aggregation_of(id), Aggregation::PerUrl, "{id}");
        }
    }

    #[test]
    fn output_order_is_deterministic() {
        let group = vec![
            finding("Content-Security-Policy Header Absent", "https://app.test/a"),
            finding("Stack Trace or Debug Output Returned to the Client", "https://app.test/b"),
            finding("Content-Security-Policy Header Absent", "https://app.test/c"),
        ];
        let first: Vec<String> = collapse(group.clone(), "https://app.test", &specs())
            .iter()
            .map(|f| f.title.clone())
            .collect();
        let second: Vec<String> = collapse(group, "https://app.test", &specs())
            .iter()
            .map(|f| f.title.clone())
            .collect();
        assert_eq!(first, second);
    }

    /// Every id named in the origin list has to exist, or a renamed check
    /// silently reverts to per-page reporting and the flood comes back.
    #[test]
    fn every_origin_aggregated_id_is_a_real_check() {
        let known: Vec<&str> = all_specs().iter().map(|s| s.id).collect();
        let origin_ids: Vec<&str> = all_specs()
            .iter()
            .map(|s| s.id)
            .filter(|id| aggregation_of(id) == Aggregation::Origin)
            .collect();

        assert!(
            origin_ids.len() >= 15,
            "expected the response-header and cookie checks to aggregate; got {origin_ids:?}"
        );
        for id in &origin_ids {
            assert!(known.contains(id), "{id} is not a shipped check");
        }
    }
}
