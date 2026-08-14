//! Audits every check the native engine ships.
//!
//! Findings from these specs are printed in client and developer reports with a
//! severity, a CVSS 4.0 vector and a CWE/OWASP/WSTG mapping. If any of those
//! disagree with each other, the report misinforms the reader — a "Medium"
//! labelled finding carrying a 9.1 score, or a vector that is not valid CVSS
//! 4.0, undermines every number in the document.
//!
//! These tests are about internal coherence, which is what a report can promise.
//! They cannot establish that a given severity is the *right* judgement call.

use sentinel_adapters::native::all_specs;
use sentinel_core::models::finding::Severity;

/// The CVSS 4.0 severity bands, per the FIRST specification.
fn band_for(score: f64) -> &'static str {
    match score {
        s if s == 0.0 => "None",
        s if s < 4.0 => "Low",
        s if s < 7.0 => "Medium",
        s if s < 9.0 => "High",
        _ => "Critical",
    }
}

fn severity_name(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "None",
    }
}

#[test]
fn every_check_ships_with_a_complete_taxonomy() {
    for spec in all_specs() {
        assert!(!spec.id.is_empty(), "a check has no id");
        assert!(!spec.title.is_empty(), "{} has no title", spec.id);
        assert!(
            spec.cwe.starts_with("CWE-"),
            "{} has a malformed CWE: {:?}",
            spec.id,
            spec.cwe
        );
        assert!(
            spec.wstg.starts_with("WSTG-"),
            "{} has a malformed WSTG id: {:?}",
            spec.id,
            spec.wstg
        );
        assert!(
            spec.owasp_2025.contains(":2025-"),
            "{} has a malformed OWASP category: {:?}",
            spec.id,
            spec.owasp_2025
        );
        assert!(
            !spec.remediation.trim().is_empty(),
            "{} has no remediation guidance; the developer report would render an empty fix",
            spec.id
        );
        assert!(
            !spec.description.trim().is_empty(),
            "{} has no description",
            spec.id
        );
        assert!(
            !spec.references.is_empty(),
            "{} cites no references",
            spec.id
        );
    }
}

#[test]
fn stated_severity_agrees_with_the_cvss_score() {
    // Collected rather than asserted one at a time: fixing these is a single
    // editorial pass over the catalogue, so the whole list is more useful than
    // the first offender.
    let mismatches: Vec<String> = all_specs()
        .iter()
        .filter_map(|spec| {
            let expected = band_for(spec.cvss_score);
            let stated = severity_name(&spec.severity);
            (stated != expected).then(|| {
                format!(
                    "  {:<34} labelled {:<8} but scores {:.1} ({})",
                    spec.id, stated, spec.cvss_score, expected
                )
            })
        })
        .collect();

    assert!(
        mismatches.is_empty(),
        "{} check(s) state a severity their own CVSS score contradicts:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn every_cvss_vector_is_well_formed_v4() {
    // The four base metrics that CVSS 4.0 requires on every vector.
    const REQUIRED: &[&str] = &["AV:", "AC:", "PR:", "UI:", "VC:", "VI:", "VA:"];

    for spec in all_specs() {
        assert!(
            spec.cvss_vector.starts_with("CVSS:4.0/"),
            "{} is not a CVSS 4.0 vector: {:?}",
            spec.id,
            spec.cvss_vector
        );
        for metric in REQUIRED {
            assert!(
                spec.cvss_vector.contains(metric),
                "{} is missing the {} metric: {:?}",
                spec.id,
                metric.trim_end_matches(':'),
                spec.cvss_vector
            );
        }
        assert!(
            (0.0..=10.0).contains(&spec.cvss_score),
            "{} scores {:.1}, outside the 0.0-10.0 range",
            spec.id,
            spec.cvss_score
        );
    }
}

#[test]
fn check_ids_are_unique() {
    let specs = all_specs();
    let mut ids: Vec<&str> = specs.iter().map(|s| s.id).collect();
    ids.sort_unstable();
    let before = ids.len();
    ids.dedup();
    assert_eq!(
        before,
        ids.len(),
        "duplicate check ids would merge distinct findings during deduplication"
    );
}

#[test]
fn the_engine_ships_the_checks_it_claims() {
    // Guards against a module being added but never wired into `all_specs`,
    // which would silently drop its checks from every scan.
    assert_eq!(
        all_specs().len(),
        45,
        "native check count changed — update this figure and the README/INSTALL \
         coverage claims together, so the documentation cannot drift from the engine"
    );
}
