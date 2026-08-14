//! Conformance tests for the CVSS 4.0 calculator.
//!
//! The scores in `fixtures/cvss4_golden.tsv` come from the reference
//! implementation published by FIRST.ORG and Red Hat, not from this code. They
//! are the standard this calculator is held to: a client reads a CVSS score as
//! an industry-standard number, so "our arithmetic" is not good enough — it has
//! to be *the* arithmetic.
//!
//! The fixture was sampled from a full differential run over the complete
//! base-metric space (104,976 vectors) plus 60,000 randomised vectors carrying
//! threat and environmental metrics, all of which matched exactly.

use sentinel_core::scoring::{Cvss4Severity, Cvss4Vector};

const GOLDEN: &str = include_str!("fixtures/cvss4_golden.tsv");

#[test]
fn every_golden_vector_scores_exactly_as_the_reference_implementation() {
    let mut checked = 0usize;
    let mut failures = Vec::new();

    for line in GOLDEN.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let (vector, expected) = line.split_once('\t').expect("fixture is vector<TAB>score");
        let expected: f64 = expected.parse().expect("fixture score is numeric");

        let parsed = Cvss4Vector::parse(vector)
            .unwrap_or_else(|e| panic!("golden vector rejected by the parser: {vector} — {e}"));
        let actual = parsed.score();

        checked += 1;
        if (actual - expected).abs() > f64::EPSILON {
            failures.push(format!("  {vector}\n    expected {expected:.1}, got {actual:.1}"));
        }
    }

    assert!(checked > 1_500, "fixture looks truncated: only {checked} vectors");
    assert!(
        failures.is_empty(),
        "{} of {checked} vectors disagree with the reference implementation:\n{}",
        failures.len(),
        failures.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn the_specification_examples_score_correctly() {
    // Worked examples from the CVSS v4.0 specification and the public calculator.
    let cases = [
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
        ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 1.0),
    ];
    for (vector, expected) in cases {
        let score = Cvss4Vector::parse(vector).unwrap().score();
        assert!(
            (score - expected).abs() < f64::EPSILON,
            "{vector}\n  expected {expected:.1}, got {score:.1}"
        );
    }
}

#[test]
fn a_score_always_agrees_with_its_own_severity_band() {
    for line in GOLDEN.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let (vector, _) = line.split_once('\t').unwrap();
        let parsed = Cvss4Vector::parse(vector).unwrap();
        let score = parsed.score();
        let expected = Cvss4Severity::of(score);
        assert_eq!(
            parsed.severity(),
            expected,
            "{vector} scores {score:.1} but reports a different band"
        );
    }
}

#[test]
fn scores_stay_within_the_defined_range() {
    for line in GOLDEN.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let (vector, _) = line.split_once('\t').unwrap();
        let score = Cvss4Vector::parse(vector).unwrap().score();
        assert!(
            (0.0..=10.0).contains(&score),
            "{vector} scored {score}, outside 0.0-10.0"
        );
    }
}
