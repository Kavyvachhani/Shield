//! CVSS 4.0 base score calculation.
//!
//! Every finding this tool reports carries a CVSS 4.0 vector and a numeric
//! score, and a client reads that number as authoritative. Deriving it by hand,
//! or carrying a CVSS 3.1 score across onto a 4.0 vector, produces a document
//! that looks precise and is not. This computes the score from the vector using
//! the published algorithm, so the two can never disagree.
//!
//! The method follows the CVSS v4.0 specification (§8.2, "Scoring"): reduce the
//! vector's metrics to a six-digit MacroVector, look up that MacroVector's
//! score, then subtract a mean severity distance interpolated against the
//! next-lower MacroVector in each equivalence class. Tables in
//! [`super::cvss4_tables`] are the official ones.
//!
//! Only Base metrics plus the Threat (`E`) and Environmental metrics that the
//! algorithm consumes are modelled; unspecified optional metrics take their
//! specified defaults, exactly as the reference implementation does.

use super::cvss4_tables::*;
use std::collections::BTreeMap;

/// A parsed CVSS 4.0 vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cvss4Vector {
    metrics: BTreeMap<String, String>,
}

/// Why a vector string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cvss4Error {
    /// The string did not begin with `CVSS:4.0/`.
    NotVersion4,
    /// A `Metric:Value` pair was malformed.
    MalformedComponent(String),
    /// A metric was named that is not part of CVSS 4.0.
    UnknownMetric(String),
    /// A metric carried a value it does not define.
    InvalidValue { metric: String, value: String },
    /// One of AV, AC, AT, PR, UI, VC, VI, VA, SC, SI or SA was absent.
    MissingMandatory(&'static str),
    /// The same metric appeared twice.
    Duplicate(String),
}

impl std::fmt::Display for Cvss4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotVersion4 => write!(f, "vector must start with 'CVSS:4.0/'"),
            Self::MalformedComponent(c) => write!(f, "malformed component '{c}', expected 'Metric:Value'"),
            Self::UnknownMetric(m) => write!(f, "'{m}' is not a CVSS 4.0 metric"),
            Self::InvalidValue { metric, value } => write!(f, "'{value}' is not a valid value for {metric}"),
            Self::MissingMandatory(m) => write!(f, "mandatory metric {m} is missing"),
            Self::Duplicate(m) => write!(f, "metric {m} appears more than once"),
        }
    }
}

impl std::error::Error for Cvss4Error {}

/// Metrics that must be present on every vector.
const MANDATORY: &[&str] = &[
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
];

/// Every metric and its permitted values.
const DEFINITIONS: &[(&str, &[&str])] = &[
    // Base — Exploitability
    ("AV", &["N", "A", "L", "P"]),
    ("AC", &["L", "H"]),
    ("AT", &["N", "P"]),
    ("PR", &["N", "L", "H"]),
    ("UI", &["N", "P", "A"]),
    // Base — Vulnerable system impact
    ("VC", &["H", "L", "N"]),
    ("VI", &["H", "L", "N"]),
    ("VA", &["H", "L", "N"]),
    // Base — Subsequent system impact
    ("SC", &["H", "L", "N"]),
    ("SI", &["H", "L", "N"]),
    ("SA", &["H", "L", "N"]),
    // Threat
    ("E", &["X", "A", "P", "U"]),
    // Environmental — requirements
    ("CR", &["X", "H", "M", "L"]),
    ("IR", &["X", "H", "M", "L"]),
    ("AR", &["X", "H", "M", "L"]),
    // Environmental — modified base
    ("MAV", &["X", "N", "A", "L", "P"]),
    ("MAC", &["X", "L", "H"]),
    ("MAT", &["X", "N", "P"]),
    ("MPR", &["X", "N", "L", "H"]),
    ("MUI", &["X", "N", "P", "A"]),
    ("MVC", &["X", "H", "L", "N"]),
    ("MVI", &["X", "H", "L", "N"]),
    ("MVA", &["X", "H", "L", "N"]),
    ("MSC", &["X", "H", "L", "N"]),
    // Modified subsequent integrity/availability add "Safety".
    ("MSI", &["X", "S", "H", "L", "N"]),
    ("MSA", &["X", "S", "H", "L", "N"]),
    // Supplemental — parsed and ignored; they do not affect the score.
    ("S", &["X", "N", "P"]),
    ("AU", &["X", "N", "Y"]),
    ("R", &["X", "A", "U", "I"]),
    ("V", &["X", "D", "C"]),
    ("RE", &["X", "L", "M", "H"]),
    ("U", &["X", "Clear", "Green", "Amber", "Red"]),
];

fn allowed_values(metric: &str) -> Option<&'static [&'static str]> {
    DEFINITIONS.iter().find(|(m, _)| *m == metric).map(|(_, v)| *v)
}

impl Cvss4Vector {
    /// Parse a `CVSS:4.0/...` vector string.
    pub fn parse(vector: &str) -> Result<Self, Cvss4Error> {
        let trimmed = vector.trim();
        let rest = trimmed
            .strip_prefix("CVSS:4.0/")
            .ok_or(Cvss4Error::NotVersion4)?;

        let mut metrics = BTreeMap::new();
        for component in rest.split('/').filter(|c| !c.is_empty()) {
            let (name, value) = component
                .split_once(':')
                .ok_or_else(|| Cvss4Error::MalformedComponent(component.to_string()))?;
            let allowed =
                allowed_values(name).ok_or_else(|| Cvss4Error::UnknownMetric(name.to_string()))?;
            if !allowed.contains(&value) {
                return Err(Cvss4Error::InvalidValue {
                    metric: name.to_string(),
                    value: value.to_string(),
                });
            }
            if metrics.insert(name.to_string(), value.to_string()).is_some() {
                return Err(Cvss4Error::Duplicate(name.to_string()));
            }
        }

        for required in MANDATORY {
            if !metrics.contains_key(*required) {
                return Err(Cvss4Error::MissingMandatory(required));
            }
        }

        Ok(Self { metrics })
    }

    /// The effective value of a metric.
    ///
    /// Applies the specification's defaults for unspecified Threat and
    /// Environmental metrics, and lets a Modified metric override its base.
    fn m(&self, metric: &str) -> &str {
        let selected = self.metrics.get(metric).map(String::as_str);

        // Unspecified Threat/Environmental metrics take their worst-case default.
        match (metric, selected) {
            ("E", None | Some("X")) => return "A",
            ("CR" | "IR" | "AR", None | Some("X")) => return "H",
            _ => {}
        }

        if let Some(modified) = self.metrics.get(&format!("M{metric}")) {
            if modified != "X" {
                return modified;
            }
        }

        // MSI/MSA may be "S" (Safety), a value the base metric cannot take;
        // when unset they fall back to the base metric below.
        selected.unwrap_or("X")
    }

    /// The six-digit MacroVector: one digit per equivalence class.
    fn macro_vector(&self) -> String {
        let (av, pr, ui) = (self.m("AV"), self.m("PR"), self.m("UI"));
        let eq1 = if av == "N" && pr == "N" && ui == "N" {
            '0'
        } else if (av == "N" || pr == "N" || ui == "N") && av != "P" {
            '1'
        } else {
            '2'
        };

        let eq2 = if self.m("AC") == "L" && self.m("AT") == "N" { '0' } else { '1' };

        let (vc, vi, va) = (self.m("VC"), self.m("VI"), self.m("VA"));
        let eq3 = if vc == "H" && vi == "H" {
            '0'
        } else if vc == "H" || vi == "H" || va == "H" {
            '1'
        } else {
            '2'
        };

        let safety = self.m("MSI") == "S" || self.m("MSA") == "S";
        let subsequent_high = self.m("SC") == "H" || self.m("SI") == "H" || self.m("SA") == "H";
        let eq4 = if safety {
            '0'
        } else if subsequent_high {
            '1'
        } else {
            '2'
        };

        let eq5 = match self.m("E") {
            "A" => '0',
            "P" => '1',
            _ => '2',
        };

        let eq6 = if (self.m("CR") == "H" && vc == "H")
            || (self.m("IR") == "H" && vi == "H")
            || (self.m("AR") == "H" && va == "H")
        {
            '0'
        } else {
            '1'
        };

        [eq1, eq2, eq3, eq4, eq5, eq6].iter().collect()
    }

    /// The CVSS 4.0 base score, 0.0–10.0, rounded to one decimal place.
    /// The value of one metric, if the vector declares it.
    ///
    /// Exposed so the developer report can print the vector metric by metric
    /// rather than as an opaque string. A reader who cannot see that `PR:N`
    /// means "no privileges required" has no way to challenge the score, and a
    /// score nobody can challenge is a number rather than an argument.
    pub fn get(&self, metric: &str) -> Option<&str> {
        self.metrics.get(metric).map(String::as_str)
    }

    /// Every metric present in the vector, in canonical CVSS order.
    pub fn present(&self) -> Vec<(&str, &str)> {
        const ORDER: &[&str] = &[
            "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
            "E", "CR", "IR", "AR", "S", "AU", "R", "V", "RE", "U",
        ];
        ORDER
            .iter()
            .filter_map(|m| self.metrics.get(*m).map(|v| (*m, v.as_str())))
            .collect()
    }

    pub fn score(&self) -> f64 {
        // No impact anywhere scores zero, short-circuiting the interpolation.
        if ["VC", "VI", "VA", "SC", "SI", "SA"].iter().all(|m| self.m(m) == "N") {
            return 0.0;
        }

        let macro_vector = self.macro_vector();
        let Some(mut value) = lookup(&macro_vector) else {
            return 0.0;
        };

        let eq: Vec<u32> = macro_vector.chars().map(|c| c.to_digit(10).unwrap()).collect();
        let (eq1, eq2, eq3, eq4, eq5, eq6) = (eq[0], eq[1], eq[2], eq[3], eq[4], eq[5]);

        let with = |a: u32, b: u32, c: u32, d: u32, e: u32, f: u32| format!("{a}{b}{c}{d}{e}{f}");

        let score_eq1_lower = lookup(&with(eq1 + 1, eq2, eq3, eq4, eq5, eq6));
        let score_eq2_lower = lookup(&with(eq1, eq2 + 1, eq3, eq4, eq5, eq6));

        // EQ3 and EQ6 are interpolated jointly; when both are 0 there are two
        // candidate lower MacroVectors and the higher score wins.
        let score_eq3eq6_lower = match (eq3, eq6) {
            (0, 0) => {
                let left = lookup(&with(eq1, eq2, eq3, eq4, eq5, eq6 + 1));
                let right = lookup(&with(eq1, eq2, eq3 + 1, eq4, eq5, eq6));
                match (left, right) {
                    (Some(l), Some(r)) => Some(l.max(r)),
                    (Some(l), None) => Some(l),
                    (None, Some(r)) => Some(r),
                    (None, None) => None,
                }
            }
            (1, 0) => lookup(&with(eq1, eq2, eq3, eq4, eq5, eq6 + 1)),
            (0, 1) | (1, 1) => lookup(&with(eq1, eq2, eq3 + 1, eq4, eq5, eq6)),
            _ => lookup(&with(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)),
        };

        let score_eq4_lower = lookup(&with(eq1, eq2, eq3, eq4 + 1, eq5, eq6));
        let score_eq5_lower = lookup(&with(eq1, eq2, eq3, eq4, eq5 + 1, eq6));

        // Find the first max-vector this vector does not exceed on any metric.
        let Some(distances) = self.severity_distances(&macro_vector) else {
            return round_half_up(value);
        };

        let d_eq1 = distances.av + distances.pr + distances.ui;
        let d_eq2 = distances.ac + distances.at;
        let d_eq3eq6 = distances.vc + distances.vi + distances.va + distances.cr + distances.ir + distances.ar;
        let d_eq4 = distances.sc + distances.si + distances.sa;

        const STEP: f64 = 0.1;
        let max_eq1 = max_severity(MAX_SEVERITY_EQ1, eq1) * STEP;
        let max_eq2 = max_severity(MAX_SEVERITY_EQ2, eq2) * STEP;
        let max_eq3eq6 = max_severity_eq3eq6(eq3, eq6) * STEP;
        let max_eq4 = max_severity(MAX_SEVERITY_EQ4, eq4) * STEP;

        let mut n_lower = 0u32;
        let mut normalized = 0.0f64;

        for (available, current, max) in [
            (score_eq1_lower, d_eq1, max_eq1),
            (score_eq2_lower, d_eq2, max_eq2),
            (score_eq3eq6_lower, d_eq3eq6, max_eq3eq6),
            (score_eq4_lower, d_eq4, max_eq4),
        ] {
            if let Some(lower) = available {
                let distance = value - lower;
                if distance >= 0.0 && max > 0.0 {
                    n_lower += 1;
                    normalized += distance * (current / max);
                }
            }
        }

        // EQ5 contributes to the count but never to the sum: its percentage to
        // the next severity is defined as zero.
        if let Some(lower) = score_eq5_lower {
            if value - lower >= 0.0 {
                n_lower += 1;
            }
        }

        if n_lower > 0 {
            value -= normalized / f64::from(n_lower);
        }

        round_half_up(value.clamp(0.0, 10.0))
    }

    /// Distance from this vector to the first admissible max-vector, per metric.
    fn severity_distances(&self, macro_vector: &str) -> Option<Distances> {
        let digits: Vec<char> = macro_vector.chars().collect();
        let eq1 = composed(MAX_COMPOSED_EQ1, digits[0])?;
        let eq2 = composed(MAX_COMPOSED_EQ2, digits[1])?;
        let eq3eq6 = composed_eq3(digits[2], digits[5])?;
        let eq4 = composed(MAX_COMPOSED_EQ4, digits[3])?;
        let eq5 = composed(MAX_COMPOSED_EQ5, digits[4])?;

        for a in eq1 {
            for b in eq2 {
                for c in eq3eq6 {
                    for d in eq4 {
                        for e in eq5 {
                            let candidate = format!("{a}{b}{c}{d}{e}");
                            if let Some(dist) = self.distances_to(&candidate) {
                                return Some(dist);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Per-metric distances to `max_vector`, or `None` if this vector exceeds it
    /// on any metric (which disqualifies that max-vector).
    fn distances_to(&self, max_vector: &str) -> Option<Distances> {
        let level = |metric: &str, table: &[(&str, f64)]| -> Option<f64> {
            let mine = lookup_level(table, self.m(metric))?;
            let theirs = lookup_level(table, &extract_metric(max_vector, metric)?)?;
            let d = mine - theirs;
            (d >= -f64::EPSILON).then_some(d)
        };

        const AV: &[(&str, f64)] = &[("N", 0.0), ("A", 0.1), ("L", 0.2), ("P", 0.3)];
        const PR: &[(&str, f64)] = &[("N", 0.0), ("L", 0.1), ("H", 0.2)];
        const UI: &[(&str, f64)] = &[("N", 0.0), ("P", 0.1), ("A", 0.2)];
        const AC: &[(&str, f64)] = &[("L", 0.0), ("H", 0.1)];
        const AT: &[(&str, f64)] = &[("N", 0.0), ("P", 0.1)];
        const IMPACT: &[(&str, f64)] = &[("H", 0.0), ("L", 0.1), ("N", 0.2)];
        const SC_T: &[(&str, f64)] = &[("H", 0.1), ("L", 0.2), ("N", 0.3)];
        const SI_T: &[(&str, f64)] = &[("S", 0.0), ("H", 0.1), ("L", 0.2), ("N", 0.3)];
        const REQ: &[(&str, f64)] = &[("H", 0.0), ("M", 0.1), ("L", 0.2)];

        Some(Distances {
            av: level("AV", AV)?,
            pr: level("PR", PR)?,
            ui: level("UI", UI)?,
            ac: level("AC", AC)?,
            at: level("AT", AT)?,
            vc: level("VC", IMPACT)?,
            vi: level("VI", IMPACT)?,
            va: level("VA", IMPACT)?,
            sc: level("SC", SC_T)?,
            si: level("SI", SI_T)?,
            sa: level("SA", SI_T)?,
            cr: level("CR", REQ)?,
            ir: level("IR", REQ)?,
            ar: level("AR", REQ)?,
        })
    }

    /// The qualitative rating for this vector's score.
    pub fn severity(&self) -> Cvss4Severity {
        Cvss4Severity::of(self.score())
    }
}

#[derive(Debug, Clone, Copy)]
struct Distances {
    av: f64, pr: f64, ui: f64, ac: f64, at: f64,
    vc: f64, vi: f64, va: f64,
    sc: f64, si: f64, sa: f64,
    cr: f64, ir: f64, ar: f64,
}

/// The CVSS 4.0 qualitative severity bands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cvss4Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Cvss4Severity {
    /// The band a score falls into, per the specification's rating scale.
    pub fn of(score: f64) -> Self {
        if score <= 0.0 {
            Self::None
        } else if score < 4.0 {
            Self::Low
        } else if score < 7.0 {
            Self::Medium
        } else if score < 9.0 {
            Self::High
        } else {
            Self::Critical
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

// ── Table access ─────────────────────────────────────────────────────────────

fn lookup(macro_vector: &str) -> Option<f64> {
    CVSS_LOOKUP_GLOBAL
        .iter()
        .find(|(k, _)| *k == macro_vector)
        .map(|(_, v)| *v)
}

fn lookup_level(table: &[(&str, f64)], value: &str) -> Option<f64> {
    table.iter().find(|(k, _)| *k == value).map(|(_, v)| *v)
}

fn composed(table: &'static [(&'static str, &'static [&'static str])], digit: char) -> Option<&'static [&'static str]> {
    let key = digit.to_string();
    table.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

fn composed_eq3(eq3: char, eq6: char) -> Option<&'static [&'static str]> {
    let (k3, k6) = (eq3.to_string(), eq6.to_string());
    MAX_COMPOSED_EQ3
        .iter()
        .find(|(a, b, _)| *a == k3 && *b == k6)
        .map(|(_, _, v)| *v)
}

fn max_severity(table: &[(u8, f64)], eq: u32) -> f64 {
    table
        .iter()
        .find(|(k, _)| u32::from(*k) == eq)
        .map(|(_, v)| *v)
        .unwrap_or(0.0)
}

fn max_severity_eq3eq6(eq3: u32, eq6: u32) -> f64 {
    MAX_SEVERITY_EQ3EQ6
        .iter()
        .find(|(a, b, _)| u32::from(*a) == eq3 && u32::from(*b) == eq6)
        .map(|(_, _, v)| *v)
        .unwrap_or(0.0)
}

/// Pull `metric`'s value out of a max-vector string like `AV:N/PR:N/UI:N/`.
fn extract_metric(vector: &str, metric: &str) -> Option<String> {
    for component in vector.split('/').filter(|c| !c.is_empty()) {
        if let Some((name, value)) = component.split_once(':') {
            if name == metric {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Round half away from zero to one decimal place.
///
/// Plain `f64::round` after scaling is not enough: values such as
/// `8.6 - 7.15 = 1.4499999999999993` must still reach 1.5, which the reference
/// implementation achieves with a small epsilon before rounding.
fn round_half_up(value: f64) -> f64 {
    const EPSILON: f64 = 1e-6;
    // `f64::round` rounds half away from zero, which is round-half-up for the
    // non-negative scores this produces. Truncating with `floor` instead makes
    // every interpolated score 0.1 too low.
    ((value + EPSILON) * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_official_lookup_table_is_complete() {
        assert_eq!(
            CVSS_LOOKUP_GLOBAL.len(),
            270,
            "CVSS 4.0 defines exactly 270 MacroVectors"
        );
    }

    #[test]
    fn a_vector_with_no_impact_scores_zero() {
        let v = Cvss4Vector::parse(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
        )
        .unwrap();
        assert_eq!(v.score(), 0.0);
        assert_eq!(v.severity(), Cvss4Severity::None);
    }

    #[test]
    fn the_worst_possible_vector_scores_ten() {
        let v = Cvss4Vector::parse(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        )
        .unwrap();
        assert_eq!(v.score(), 10.0);
        assert_eq!(v.severity(), Cvss4Severity::Critical);
    }

    #[test]
    fn malformed_vectors_are_rejected_with_a_reason() {
        assert_eq!(
            Cvss4Vector::parse("CVSS:3.1/AV:N/AC:L").unwrap_err(),
            Cvss4Error::NotVersion4
        );
        // Missing SA.
        assert!(matches!(
            Cvss4Vector::parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N")
                .unwrap_err(),
            Cvss4Error::MissingMandatory("SA")
        ));
        assert!(matches!(
            Cvss4Vector::parse(
                "CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            )
            .unwrap_err(),
            Cvss4Error::InvalidValue { .. }
        ));
        assert!(matches!(
            Cvss4Vector::parse(
                "CVSS:4.0/XX:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            )
            .unwrap_err(),
            Cvss4Error::UnknownMetric(_)
        ));
    }

    #[test]
    fn severity_bands_follow_the_specification() {
        assert_eq!(Cvss4Severity::of(0.0), Cvss4Severity::None);
        assert_eq!(Cvss4Severity::of(0.1), Cvss4Severity::Low);
        assert_eq!(Cvss4Severity::of(3.9), Cvss4Severity::Low);
        assert_eq!(Cvss4Severity::of(4.0), Cvss4Severity::Medium);
        assert_eq!(Cvss4Severity::of(6.9), Cvss4Severity::Medium);
        assert_eq!(Cvss4Severity::of(7.0), Cvss4Severity::High);
        assert_eq!(Cvss4Severity::of(8.9), Cvss4Severity::High);
        assert_eq!(Cvss4Severity::of(9.0), Cvss4Severity::Critical);
        assert_eq!(Cvss4Severity::of(10.0), Cvss4Severity::Critical);
    }
}
