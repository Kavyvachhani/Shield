//! Shared construction for findings that come from an external scanner.
//!
//! Each tool speaks its own dialect, so the *parsing* has to be per-tool. What
//! follows parsing is identical every time: normalise a severity, attach a
//! taxonomy, hash the evidence, and produce a `Finding` the rest of the
//! pipeline can score, deduplicate and report. Doing that by hand in each
//! parser is how six copies drift apart — and how one of them quietly forgets
//! to set `owasp_2025`, leaving its findings out of the Top 10 rollup with
//! nothing to indicate they are missing.
//!
//! ## On severity that did not come from a CVSS 4.0 vector
//!
//! Most tools report a severity band, and some report a CVSS 3.1 vector. This
//! engine scores on CVSS 4.0, and the two are not interchangeable: 3.1 has no
//! Attack Requirements metric and models scope differently, so translating a
//! vector between them invents precision that was never measured.
//!
//! So nothing is translated. A tool's band is mapped to a representative base
//! score for ranking, `cvss4` is left `None`, and the rationale says the score
//! came from the tool's own rating rather than from a vector. A reader can then
//! tell which numbers in the report were computed and which were reported.

use crate::models::finding::{
    AITriage, Evidence, Finding, FindingKind, FindingStatus, Severity,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// A finding as an external tool describes it, before it becomes a `Finding`.
#[derive(Debug, Clone)]
pub struct ExternalFinding {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    /// Where it is: a file path, a URL, or a package coordinate.
    pub affected_component: String,
    pub remediation: String,
    pub cwe_id: Option<String>,
    pub owasp_2025: Option<String>,
    pub wstg_id: Option<String>,
    pub api_top10: Option<String>,
    pub references: Vec<String>,
    pub repro_steps: Vec<String>,
    pub evidences: Vec<Evidence>,
    /// The engine's display name, e.g. "OSV-Scanner".
    pub source_tool: String,
    /// How likely the tool is to be wrong, 0.0–1.0. Per-tool rather than
    /// per-finding where the tool gives no confidence of its own.
    pub false_positive_confidence: f64,
    /// What the tool's claim actually rests on, shown in the developer report.
    pub triage_note: Option<String>,
    /// EPSS probability, when the tool supplies one.
    pub epss: Option<f64>,
    /// Whether the underlying CVE is in the CISA Known Exploited catalogue.
    pub kev_listed: bool,
    /// 0.7 (pattern match in source) to 1.2 (observed on the running target).
    pub reachability_score: f64,
}

impl ExternalFinding {
    /// A finding with the fields every tool supplies, and defaults for the rest.
    pub fn new(
        title: impl Into<String>,
        severity: Severity,
        affected_component: impl Into<String>,
        source_tool: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            description: String::new(),
            severity,
            affected_component: affected_component.into(),
            remediation: String::new(),
            cwe_id: None,
            owasp_2025: None,
            wstg_id: None,
            api_top10: None,
            references: Vec::new(),
            repro_steps: Vec::new(),
            evidences: Vec::new(),
            source_tool: source_tool.into(),
            false_positive_confidence: 0.15,
            triage_note: None,
            epss: None,
            kev_listed: false,
            // Most external tools match a pattern rather than observe a live
            // exploit, so the default is deliberately below 1.0.
            reachability_score: 0.9,
        }
    }

    pub fn description(mut self, v: impl Into<String>) -> Self {
        self.description = v.into();
        self
    }
    pub fn remediation(mut self, v: impl Into<String>) -> Self {
        self.remediation = v.into();
        self
    }
    pub fn taxonomy(
        mut self,
        cwe: impl Into<String>,
        owasp: impl Into<String>,
        wstg: Option<&str>,
    ) -> Self {
        self.cwe_id = Some(cwe.into());
        self.owasp_2025 = Some(owasp.into());
        self.wstg_id = wstg.map(str::to_string);
        self
    }
    pub fn references(mut self, v: Vec<String>) -> Self {
        self.references = v;
        self
    }
    pub fn repro(mut self, v: Vec<String>) -> Self {
        self.repro_steps = v;
        self
    }
    pub fn evidence(mut self, evidence_type: &str, title: &str, content: &str) -> Self {
        self.evidences.push(hashed_evidence(evidence_type, title, content));
        self
    }
    pub fn confidence(mut self, false_positive_confidence: f64, note: impl Into<String>) -> Self {
        self.false_positive_confidence = false_positive_confidence.clamp(0.0, 1.0);
        self.triage_note = Some(note.into());
        self
    }
    pub fn reachability(mut self, v: f64) -> Self {
        self.reachability_score = v;
        self
    }
    pub fn exploit_intelligence(mut self, epss: Option<f64>, kev_listed: bool) -> Self {
        self.epss = epss;
        self.kev_listed = kev_listed;
        self
    }

    /// Turn this into a scoreable `Finding`.
    pub fn into_finding(self, target_id: Uuid, scan_id: Uuid) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            scan_id,
            target_id,
            title: self.title,
            description: self.description,
            severity: self.severity,
            kind: FindingKind::Weakness,
            // Deliberately absent. This tool did not produce a CVSS 4.0 vector,
            // and inventing one would put a number in the report that nobody
            // measured. The severity band still drives the ranking.
            cvss4: None,
            epss: self.epss.map(|score| crate::models::finding::EPSSData {
                score,
                percentile: score,
            }),
            kev_listed: self.kev_listed,
            asset_exposure_factor: 1.0,
            reachability_score: self.reachability_score,
            priority_score: 0.0,
            priority_rationale: String::new(),
            cwe_id: self.cwe_id,
            owasp_2025: self.owasp_2025,
            wstg_id: self.wstg_id,
            api_top10: self.api_top10,
            affected_component: self.affected_component,
            evidences: self.evidences,
            repro_steps: self.repro_steps,
            remediation: self.remediation,
            references: self.references,
            status: FindingStatus::Open,
            source_tools: vec![self.source_tool],
            ai_triage: Some(AITriage {
                is_false_positive_confidence: self.false_positive_confidence,
                cluster_id: None,
                triage_notes: self.triage_note,
            }),
            created_at: Utc::now(),
        }
    }
}

/// An evidence block with its content hash, so a later alteration is detectable.
pub fn hashed_evidence(evidence_type: &str, title: &str, content: &str) -> Evidence {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    Evidence {
        evidence_type: evidence_type.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        hash: format!("{:x}", hasher.finalize()),
    }
}

/// Map a tool's severity word to this engine's band.
///
/// Deliberately permissive about spelling — tools disagree on case, on
/// `INFORMATIONAL` versus `INFO` versus `NONE`, and on whether `WARNING` is a
/// severity at all. An unrecognised word becomes `Medium` rather than being
/// dropped: a finding nobody can classify is still a finding, and silently
/// discarding it would be the worst outcome.
pub fn severity_from_label(raw: &str) -> Severity {
    match raw.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" | "CRIT" | "BLOCKER" | "SEV0" => Severity::Critical,
        "HIGH" | "ERROR" | "SEV1" | "IMPORTANT" => Severity::High,
        "MEDIUM" | "MODERATE" | "WARNING" | "WARN" | "SEV2" => Severity::Medium,
        "LOW" | "MINOR" | "SEV3" => Severity::Low,
        "INFO" | "INFORMATIONAL" | "INFORMATION" | "NONE" | "NEGLIGIBLE" | "UNKNOWN" => {
            Severity::Info
        }
        _ => Severity::Medium,
    }
}

/// A representative base score for a severity band.
///
/// Used only for ranking findings that carry no vector. The midpoint of each
/// CVSS band rather than its ceiling, so a band-derived score never outranks a
/// measured vector that genuinely scored higher in the same band.
pub fn base_score_for(severity: &Severity) -> f64 {
    match severity {
        Severity::Critical => 9.3,
        Severity::High => 7.9,
        Severity::Medium => 5.4,
        Severity::Low => 2.9,
        Severity::Info => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_words_map_across_tool_dialects() {
        assert_eq!(severity_from_label("CRITICAL"), Severity::Critical);
        assert_eq!(severity_from_label("critical"), Severity::Critical);
        assert_eq!(severity_from_label(" High "), Severity::High);
        assert_eq!(severity_from_label("ERROR"), Severity::High);
        assert_eq!(severity_from_label("MODERATE"), Severity::Medium);
        assert_eq!(severity_from_label("WARNING"), Severity::Medium);
        assert_eq!(severity_from_label("minor"), Severity::Low);
        assert_eq!(severity_from_label("INFORMATIONAL"), Severity::Info);
    }

    /// Dropping a finding because its severity word is unfamiliar is the worst
    /// available outcome — the weakness is still there.
    #[test]
    fn an_unfamiliar_severity_is_kept_rather_than_discarded() {
        assert_eq!(severity_from_label("banana"), Severity::Medium);
        assert_eq!(severity_from_label(""), Severity::Medium);
    }

    /// CVSS 3.1 and 4.0 are not interchangeable — 3.1 has no Attack
    /// Requirements metric and models scope differently — so a tool's band must
    /// never be dressed up as a measured 4.0 vector.
    #[test]
    fn a_tool_supplied_severity_never_becomes_a_fabricated_cvss_vector() {
        let f = ExternalFinding::new("CVE-2024-1", Severity::High, "pkg@1.0", "OSV-Scanner")
            .into_finding(Uuid::new_v4(), Uuid::new_v4());
        assert!(
            f.cvss4.is_none(),
            "no vector was measured, so none may be reported"
        );
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn band_scores_sit_inside_their_cvss_range() {
        assert!((9.0..10.0).contains(&base_score_for(&Severity::Critical)));
        assert!((7.0..9.0).contains(&base_score_for(&Severity::High)));
        assert!((4.0..7.0).contains(&base_score_for(&Severity::Medium)));
        assert!((0.1..4.0).contains(&base_score_for(&Severity::Low)));
        assert_eq!(base_score_for(&Severity::Info), 0.0);
    }

    #[test]
    fn the_builder_carries_taxonomy_evidence_and_confidence_through() {
        let f = ExternalFinding::new("Leaked key", Severity::Critical, "src/a.ts:4", "TruffleHog")
            .description("A verified credential.")
            .remediation("Revoke it.")
            .taxonomy("CWE-798", "A04:2025-Cryptographic Failures", Some("WSTG-INFO-05"))
            .references(vec!["https://example.test".into()])
            .repro(vec!["grep -n key src/a.ts".into()])
            .evidence("code_snippet", "Match", "const k = ...")
            .confidence(0.02, "Verified live against the provider.")
            .reachability(1.1)
            .exploit_intelligence(Some(0.42), true)
            .into_finding(Uuid::new_v4(), Uuid::new_v4());

        assert_eq!(f.cwe_id.as_deref(), Some("CWE-798"));
        assert_eq!(f.owasp_2025.as_deref(), Some("A04:2025-Cryptographic Failures"));
        assert_eq!(f.source_tools, vec!["TruffleHog".to_string()]);
        assert_eq!(f.evidences.len(), 1);
        assert!(!f.evidences[0].hash.is_empty(), "evidence must be hashed on capture");
        assert_eq!(f.ai_triage.as_ref().unwrap().is_false_positive_confidence, 0.02);
        assert!(f.kev_listed);
        assert_eq!(f.reachability_score, 1.1);
    }

    #[test]
    fn confidence_stays_a_probability_however_it_is_supplied() {
        let f = ExternalFinding::new("x", Severity::Low, "y", "T")
            .confidence(4.2, "nonsense")
            .into_finding(Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(f.ai_triage.unwrap().is_false_positive_confidence, 1.0);
    }

    #[test]
    fn identical_evidence_hashes_identically() {
        let a = hashed_evidence("code", "t", "same");
        let b = hashed_evidence("code", "t", "same");
        let c = hashed_evidence("code", "t", "different");
        assert_eq!(a.hash, b.hash);
        assert_ne!(a.hash, c.hash);
    }
}
