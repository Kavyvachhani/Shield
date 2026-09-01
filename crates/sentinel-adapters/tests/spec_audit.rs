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
use sentinel_core::scoring::{Cvss4Severity, Cvss4Vector};

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
        // The vector must actually parse, since the score and the severity the
        // report prints are both derived from it.
        let parsed = Cvss4Vector::parse(spec.cvss_vector)
            .unwrap_or_else(|e| panic!("{} has an unparseable vector: {e}", spec.id));
        let score = parsed.score();
        assert!(
            (0.0..=10.0).contains(&score),
            "{} scores {score:.1}, outside the 0.0-10.0 range",
            spec.id
        );
        assert!(
            (score - spec.score()).abs() < f64::EPSILON,
            "{} disagrees with its own vector",
            spec.id
        );
    }
}

#[test]
fn severity_is_the_band_of_the_computed_score() {
    // Severity is derived, so this can no longer drift — the test documents the
    // guarantee and would catch a regression in the mapping.
    for spec in all_specs() {
        let expected = match Cvss4Severity::of(spec.score()) {
            Cvss4Severity::Critical => "Critical",
            Cvss4Severity::High => "High",
            Cvss4Severity::Medium => "Medium",
            Cvss4Severity::Low => "Low",
            Cvss4Severity::None => "Info",
        };
        let actual = format!("{:?}", spec.severity());
        assert_eq!(
            actual, expected,
            "{} scores {:.1} but reports severity {actual}",
            spec.id,
            spec.score()
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
        61,
        "native check count changed — update this figure and the README/INSTALL \
         coverage claims together, so the documentation cannot drift from the engine"
    );
}
