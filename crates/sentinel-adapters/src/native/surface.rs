//! What the assessment actually reached.
//!
//! A clean report is only meaningful next to a statement of how much was
//! looked at. "No weaknesses found" after eleven pages and "no weaknesses
//! found" after four hundred are different claims, and until this existed the
//! report made them identically.
//!
//! This is emitted as a [`FindingKind::ScanInformation`] record rather than as
//! a weakness. It travels with the findings because that is the channel an
//! adapter has, but it is not something anyone can remediate: the reports lift
//! it out of the findings list and render it in their coverage narrative, so it
//! never reaches a severity count, the posture score or the remediation queue.

use super::builder::{CheckSpec, NativeFinding};
use super::crawl::Crawl;
use sentinel_core::models::finding::{Finding, FindingKind, Severity};
use uuid::Uuid;

/// The record's shape. Severity is informational and the vector scores 0.0, so
/// even if something downstream treated this as a weakness it could not move a
/// posture score.
const ASSESSMENT_SURFACE: CheckSpec = CheckSpec {
    id: "NATIVE-ASSESSMENT-SURFACE",
    title: "Assessment Surface — What This Scan Reached",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1059",
    wstg: "WSTG-INFO-01",
    owasp_2025: "A02:2025-Security Misconfiguration",
    api_top10: None,
    description: "A record of how much of the application this assessment covered. It is not a \
weakness and requires no remediation — it exists so that a clean result can be read correctly. \
\"No weaknesses found\" across eleven pages and the same words across four hundred are different \
claims, and a report that does not say which one it is asking the reader to trust is asking for \
trust it has not earned.",
    remediation: "No action required. If the pages reached are fewer than expected, raise the \
crawl limits in the scan's engine configuration — `crawl.maxPages`, `crawl.maxDepth` and \
`crawl.budgetSeconds` — or check whether the unvisited routes sit behind authentication that the \
scan was not given credentials for.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
    ],
};

/// Build the coverage record for a completed crawl.
pub fn record(target_id: Uuid, scan_id: Uuid, base_url: &str, crawl: &Crawl) -> Finding {
    let assessed = crawl.pages.len();
    let skipped = crawl.not_visited.len();

    let declared_note = if crawl.declared.is_empty() {
        String::new()
    } else {
        format!(
            " {} endpoint(s) were found from the application's own published descriptions — its \
             API specification, robots.txt, sitemap and client-side scripts — rather than by \
             following links, which is the only way an application whose routes live in a \
             JavaScript bundle can be reached at all.",
            crawl.declared.len()
        )
    };

    let detail = format!(
        "{assessed} page(s) were fetched and assessed; {}. {}{declared_note}",
        crawl.stopped_because.describe(),
        if skipped == 0 {
            "No in-scope page was left unvisited.".to_string()
        } else {
            format!("{skipped} in-scope URL(s) were queued but not reached.")
        }
    );

    let mut evidences = vec![NativeFinding::evidence(
        "assessment_surface",
        &format!("Pages assessed ({assessed})"),
        &page_listing(crawl),
    )];

    // How the surface was established, not just how large it was. A reader
    // judging whether the assessment reached the application needs to know
    // whether routes came from following links — which finds nothing in a
    // single-page application — or from the application's own published
    // description of itself.
    if !crawl.declared.is_empty() {
        evidences.push(NativeFinding::evidence(
            "assessment_surface",
            &format!("Endpoints found by declaration ({})", crawl.declared.len()),
            &declared_listing(crawl),
        ));
    }

    if !crawl.not_visited.is_empty() {
        evidences.push(NativeFinding::evidence(
            "assessment_surface",
            &format!("In-scope URLs not reached ({})", crawl.not_visited.len()),
            &listing(&crawl.not_visited, 40),
        ));
    }

    if !crawl.external_hosts.is_empty() {
        evidences.push(NativeFinding::evidence(
            "assessment_surface",
            &format!("Third-party origins referenced ({})", crawl.external_hosts.len()),
            &format!(
                "{}\n\nThese are outside the authorised scope and were not tested. Each one is \
                 code or content the application trusts at run time, so each is a supply-chain \
                 dependency worth reviewing.",
                listing(&crawl.external_hosts, 40)
            ),
        ));
    }

    let mut finding = NativeFinding::build(
        &ASSESSMENT_SURFACE,
        target_id,
        scan_id,
        base_url.trim_end_matches('/'),
        &detail,
        vec![],
        evidences,
    );
    finding.kind = FindingKind::ScanInformation;
    finding.severity = Severity::Info;
    finding
}

/// Discovered endpoints grouped by where they were declared, so the reader can
/// see which of the application's own descriptions were actually available.
fn declared_listing(crawl: &Crawl) -> String {
    use std::collections::BTreeMap;

    let mut by_origin: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for endpoint in &crawl.declared {
        by_origin
            .entry(endpoint.origin.describe())
            .or_default()
            .push(endpoint.url.clone());
    }

    by_origin
        .into_iter()
        .map(|(origin, urls)| {
            format!("{} ({}):\n{}", capitalise(origin), urls.len(), listing(&urls, 25))
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn page_listing(crawl: &Crawl) -> String {
    let urls: Vec<String> = crawl.pages.iter().map(|p| p.final_url.clone()).collect();
    listing(&urls, 60)
}

/// Render a bounded list, saying how much was elided rather than truncating
/// silently.
fn listing(items: &[String], cap: usize) -> String {
    let mut sorted: Vec<&String> = items.iter().collect();
    sorted.sort();
    sorted.dedup();

    let shown: Vec<&&String> = sorted.iter().take(cap).collect();
    let mut out = shown
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if sorted.len() > shown.len() {
        out.push_str(&format!("\n… and {} more", sorted.len() - shown.len()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::crawl::{Crawl, StopReason};
    use reqwest::header::HeaderMap;
    use sentinel_adapters_probe_stub::*;

    // A minimal stand-in so this module's tests do not need a live server.
    mod sentinel_adapters_probe_stub {
        use super::*;
        use crate::native::probe::ProbeResponse;

        pub fn page(url: &str) -> ProbeResponse {
            ProbeResponse {
                url: url.into(),
                final_url: url.into(),
                status: 200,
                headers: HeaderMap::new(),
                body: String::new(),
                body_truncated: false,
                elapsed_ms: 1,
            }
        }
    }

    fn crawl_with_declared(
        pages: &[&str],
        declared: Vec<crate::native::endpoints::Endpoint>,
    ) -> Crawl {
        Crawl {
            pages: pages.iter().map(|u| page(u)).collect(),
            not_visited: Vec::new(),
            declared,
            external_hosts: Vec::new(),
            stopped_because: StopReason::Exhausted,
        }
    }

    fn crawl(pages: &[&str], not_visited: &[&str], external: &[&str], reason: StopReason) -> Crawl {
        Crawl {
            pages: pages.iter().map(|u| page(u)).collect(),
            not_visited: not_visited.iter().map(|s| s.to_string()).collect(),
            declared: Vec::new(),
            external_hosts: external.iter().map(|s| s.to_string()).collect(),
            stopped_because: reason,
        }
    }

    /// The whole point: this must never be counted as a weakness, or every
    /// report gains a finding nobody can fix.
    #[test]
    fn the_record_is_scan_information_and_scores_nothing() {
        let c = crawl(&["https://app.test/"], &[], &[], StopReason::Exhausted);
        let f = record(Uuid::new_v4(), Uuid::new_v4(), "https://app.test", &c);

        assert_eq!(f.kind, FindingKind::ScanInformation);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.cvss4.as_ref().unwrap().base_score, 0.0);
    }

    #[test]
    fn a_complete_crawl_says_nothing_was_left_out() {
        let c = crawl(&["https://app.test/", "https://app.test/a"], &[], &[], StopReason::Exhausted);
        let f = record(Uuid::new_v4(), Uuid::new_v4(), "https://app.test", &c);

        assert!(f.description.contains("2 page(s) were fetched"));
        assert!(f.description.contains("every in-scope page reachable by link was assessed"));
        assert!(f.description.contains("No in-scope page was left unvisited"));
    }

    /// A truncated crawl must say so. This is the difference between "we found
    /// nothing" and "we found nothing in the part we looked at".
    #[test]
    fn a_truncated_crawl_reports_what_it_did_not_reach() {
        let c = crawl(
            &["https://app.test/"],
            &["https://app.test/deep/one", "https://app.test/deep/two"],
            &[],
            StopReason::PageLimit,
        );
        let f = record(Uuid::new_v4(), Uuid::new_v4(), "https://app.test", &c);

        assert!(f.description.contains("the page limit was reached"));
        assert!(f.description.contains("2 in-scope URL(s) were queued but not reached"));

        let unreached = f
            .evidences
            .iter()
            .find(|e| e.title.contains("not reached"))
            .expect("the unreached URLs must be listed");
        assert!(unreached.content.contains("/deep/one"));
    }

    #[test]
    fn third_party_origins_are_listed_as_supply_chain_surface() {
        let c = crawl(&["https://app.test/"], &[], &["cdn.test", "analytics.test"], StopReason::Exhausted);
        let f = record(Uuid::new_v4(), Uuid::new_v4(), "https://app.test", &c);

        let third_party = f
            .evidences
            .iter()
            .find(|e| e.title.contains("Third-party"))
            .expect("third-party origins must be recorded");
        assert!(third_party.content.contains("cdn.test"));
        assert!(third_party.content.contains("supply-chain dependency"));
    }

    /// Whether routes came from following links or from the application's own
    /// description of itself changes what a clean result means — following
    /// links finds nothing in a single-page application.
    #[test]
    fn how_the_surface_was_established_is_recorded_not_just_how_large_it_was() {
        use crate::native::endpoints::{Endpoint, Origin};

        let c = crawl_with_declared(
            &["https://app.test/"],
            vec![
                Endpoint { url: "https://app.test/api/v2/orders".into(), origin: Origin::ApiSpecification },
                Endpoint { url: "https://app.test/internal-admin/".into(), origin: Origin::RobotsDirective },
            ],
        );
        let f = record(Uuid::new_v4(), Uuid::new_v4(), "https://app.test", &c);

        assert!(f.description.contains("2 endpoint(s) were found from the application's own"));
        assert!(f.description.contains("JavaScript bundle"), "the reason it matters must be stated");

        let declared = f
            .evidences
            .iter()
            .find(|e| e.title.contains("by declaration"))
            .expect("the declared endpoints must be listed");
        assert!(declared.content.contains("API specification"), "{}", declared.content);
        assert!(declared.content.contains("robots.txt"), "{}", declared.content);
        assert!(declared.content.contains("/api/v2/orders"));
    }

    #[test]
    fn nothing_declared_means_no_such_block() {
        let c = crawl(&["https://app.test/"], &[], &[], StopReason::Exhausted);
        let f = record(Uuid::new_v4(), Uuid::new_v4(), "https://app.test", &c);
        assert!(!f.evidences.iter().any(|e| e.title.contains("by declaration")));
    }

    #[test]
    fn no_third_party_origins_means_no_such_block() {
        let c = crawl(&["https://app.test/"], &[], &[], StopReason::Exhausted);
        let f = record(Uuid::new_v4(), Uuid::new_v4(), "https://app.test", &c);
        assert!(!f.evidences.iter().any(|e| e.title.contains("Third-party")));
    }

    /// Silently truncating a list would misrepresent the surface as smaller
    /// than it is.
    #[test]
    fn a_long_listing_says_how_much_it_elided() {
        let urls: Vec<String> = (0..120).map(|i| format!("https://app.test/p{i:03}")).collect();
        let rendered = listing(&urls, 40);
        assert!(rendered.contains("… and 80 more"), "{rendered}");
    }
}
