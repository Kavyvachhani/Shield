//! Finding construction for the native check engine.
//!
//! Each native check declares a `CheckSpec` — a compile-time description of the
//! weakness including its CVSS 4.0 vector, CWE, WSTG identifier and remediation
//! guidance for both audiences. `NativeFinding` turns a spec plus per-instance
//! evidence into a fully-populated `Finding`, so scoring, deduplication and the
//! report engine all receive consistent, taxonomy-complete data.

use sentinel_core::models::finding::{
    AITriage, CVSS4Data, Evidence, Finding, FindingStatus, Severity,
};
use sentinel_core::scoring::{Cvss4Severity, Cvss4Vector};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Compile-time description of one native check.
#[derive(Debug, Clone)]
pub struct CheckSpec {
    /// Stable internal identifier, e.g. "NATIVE-HSTS-MISSING".
    pub id: &'static str,
    pub title: &'static str,
    /// The CVSS 4.0 vector, and the single source of truth for how serious this
    /// check is.
    ///
    /// Neither a numeric score nor a severity label is stored alongside it.
    /// Both are computed from this string by [`CheckSpec::score`] and
    /// [`CheckSpec::severity`]. When they were declared by hand, 37 of the 45
    /// checks drifted away from the vector printed next to them in the report —
    /// deriving them makes that class of error unrepresentable.
    pub cvss_vector: &'static str,
    pub cwe: &'static str,
    pub wstg: &'static str,
    pub owasp_2025: &'static str,
    pub api_top10: Option<&'static str>,
    /// Technical explanation for the developer report.
    pub description: &'static str,
    /// Concrete fix instructions for the developer report.
    pub remediation: &'static str,
    /// Reference URLs.
    pub references: &'static [&'static str],
}

impl CheckSpec {
    /// The CVSS 4.0 base score, computed from [`Self::cvss_vector`].
    ///
    /// A malformed vector scores 0.0 rather than panicking; the spec audit
    /// fails the build long before a scan could reach that state.
    pub fn score(&self) -> f64 {
        Cvss4Vector::parse(self.cvss_vector)
            .map(|v| v.score())
            .unwrap_or(0.0)
    }

    /// The severity band this check's score falls into.
    pub fn severity(&self) -> Severity {
        match Cvss4Severity::of(self.score()) {
            Cvss4Severity::Critical => Severity::Critical,
            Cvss4Severity::High => Severity::High,
            Cvss4Severity::Medium => Severity::Medium,
            Cvss4Severity::Low => Severity::Low,
            Cvss4Severity::None => Severity::Info,
        }
    }
}

/// Builder that attaches per-instance detail to a `CheckSpec`.
pub struct NativeFinding;

impl NativeFinding {
    /// Construct a `Finding` from a spec.
    ///
    /// * `component` — the affected URL or endpoint.
    /// * `detail` — instance-specific sentence appended to the spec description.
    /// * `repro_steps` — copy-pasteable verification steps.
    /// * `evidences` — sanitized proof captured during the probe.
    pub fn build(
        spec: &CheckSpec,
        target_id: Uuid,
        scan_id: Uuid,
        component: &str,
        detail: &str,
        repro_steps: Vec<String>,
        evidences: Vec<Evidence>,
    ) -> Finding {
        let description = if detail.trim().is_empty() {
            spec.description.to_string()
        } else {
            format!("{}\n\nObserved: {}", spec.description, detail)
        };

        Finding {
            id: Uuid::new_v4(),
            scan_id,
            target_id,
            title: spec.title.to_string(),
            description,
            severity: spec.severity(),
            cvss4: Some(CVSS4Data {
                vector_string: spec.cvss_vector.to_string(),
                base_score: spec.score(),
                severity_label: severity_label(&spec.severity()).to_string(),
            }),
            // Native checks observe live configuration; they are not CVE-backed,
            // so EPSS/KEV do not apply and must stay absent rather than be faked.
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.0,
            // Directly observed on the running target: confirmed reachable.
            reachability_score: 1.1,
            priority_score: 0.0,
            priority_rationale: String::new(),
            cwe_id: Some(spec.cwe.to_string()),
            owasp_2025: Some(spec.owasp_2025.to_string()),
            wstg_id: Some(spec.wstg.to_string()),
            api_top10: spec.api_top10.map(str::to_string),
            affected_component: component.to_string(),
            evidences,
            repro_steps,
            remediation: spec.remediation.to_string(),
            references: spec.references.iter().map(|r| r.to_string()).collect(),
            status: FindingStatus::Open,
            source_tools: vec!["Sentinel Native".to_string()],
            ai_triage: Some(AITriage {
                // Directly observed configuration state, not inference.
                is_false_positive_confidence: 0.02,
                cluster_id: Some(format!("CLUSTER_{}", spec.cwe)),
                triage_notes: Some(
                    "Observed directly from the live HTTP/TLS response; not inferred.".to_string(),
                ),
            }),
            created_at: chrono::Utc::now(),
        }
    }

    /// Convenience constructor for evidence blocks with a content hash.
    pub fn evidence(evidence_type: &str, title: &str, content: &str) -> Evidence {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        Evidence {
            evidence_type: evidence_type.to_string(),
            title: title.to_string(),
            content: content.to_string(),
            hash: format!("{:x}", hasher.finalize()),
        }
    }
}

pub fn severity_label(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "None",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: CheckSpec = CheckSpec {
        id: "NATIVE-TEST",
        title: "Test Check",
        cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
        cwe: "CWE-16",
        wstg: "WSTG-CONF-02",
        owasp_2025: "A02:2025-Security Misconfiguration",
        api_top10: None,
        description: "Base description.",
        remediation: "Do the fix.",
        references: &["https://example.test/ref"],
    };

    #[test]
    fn build_populates_full_taxonomy() {
        let f = NativeFinding::build(
            &SPEC,
            Uuid::new_v4(),
            Uuid::new_v4(),
            "https://app.test/",
            "header was absent",
            vec!["curl -I https://app.test/".into()],
            vec![NativeFinding::evidence("http_response", "Response", "HTTP/1.1 200 OK")],
        );

        assert_eq!(f.cwe_id.as_deref(), Some("CWE-16"));
        assert_eq!(f.wstg_id.as_deref(), Some("WSTG-CONF-02"));
        assert_eq!(f.owasp_2025.as_deref(), Some("A02:2025-Security Misconfiguration"));
        assert_eq!(f.source_tools, vec!["Sentinel Native".to_string()]);
        assert!(f.description.contains("Observed: header was absent"));
        // Computed from the vector above, not declared beside it.
        assert_eq!(f.cvss4.unwrap().base_score, 6.9);
        assert_eq!(f.references.len(), 1);
    }

    #[test]
    fn native_findings_do_not_fabricate_epss_or_kev() {
        let f = NativeFinding::build(
            &SPEC, Uuid::new_v4(), Uuid::new_v4(), "https://app.test/", "", vec![], vec![],
        );
        assert!(f.epss.is_none(), "configuration findings have no EPSS score");
        assert!(!f.kev_listed, "configuration findings are not CVEs");
    }

    #[test]
    fn empty_detail_leaves_description_unchanged() {
        let f = NativeFinding::build(
            &SPEC, Uuid::new_v4(), Uuid::new_v4(), "https://app.test/", "   ", vec![], vec![],
        );
        assert_eq!(f.description, "Base description.");
    }

    #[test]
    fn evidence_hash_is_stable_and_content_addressed() {
        let a = NativeFinding::evidence("http_response", "R", "same");
        let b = NativeFinding::evidence("http_response", "R", "same");
        let c = NativeFinding::evidence("http_response", "R", "different");
        assert_eq!(a.hash, b.hash);
        assert_ne!(a.hash, c.hash);
    }
}
