use crate::models::finding::Finding;

pub struct PriorityScoringEngine;

impl PriorityScoringEngine {
    /// Calculates the SentinelVAPT integrated Priority Score [0.0 - 10.0].
    ///
    /// Formula:
    ///   Priority = min(10.0, CVSS4_Base × (1 + 0.3 × EPSS) × KEV_Multiplier × Reachability × Asset_Exposure)
    ///
    /// Components:
    ///   • CVSS4_Base: 0.0–10.0 (default 5.0 if not scored)
    ///   • EPSS factor: 1.0–1.3 (exploitation probability)
    ///   • KEV multiplier: 1.35 if in CISA KEV, 1.0 otherwise
    ///   • Reachability: 0.7 (SAST unconfirmed) to 1.2 (SAST+DAST verified)
    ///   • Asset exposure: 0.8 (internal) to 1.2 (internet-facing)
    pub fn calculate_priority_score(finding: &Finding) -> f64 {
        let cvss_base  = finding.cvss4.as_ref().map(|c| c.base_score).unwrap_or(5.0);
        let epss_score = finding.epss.as_ref().map(|e| e.score).unwrap_or(0.0);
        let epss_factor     = 1.0 + (0.3 * epss_score);
        let kev_multiplier  = if finding.kev_listed { 1.35 } else { 1.0 };
        let reachability    = finding.reachability_score;
        let asset_exposure  = finding.asset_exposure_factor;

        let raw = cvss_base * epss_factor * kev_multiplier * reachability * asset_exposure;
        let clamped = raw.min(10.0);
        (clamped * 10.0).round() / 10.0
    }

    /// Generate a human-readable rationale string explaining WHY a finding
    /// has its priority score.  This is attached as `finding.priority_rationale`.
    ///
    /// Developer report:  full detail with numeric breakdown
    /// Executive report:  this string is translated to plain business language
    ///   by the report engine (see `explain_executive`).
    pub fn explain(finding: &Finding) -> String {
        let cvss_base  = finding.cvss4.as_ref().map(|c| c.base_score).unwrap_or(5.0);
        let cvss_vec   = finding.cvss4.as_ref().map(|c| c.vector_string.as_str()).unwrap_or("—");
        let epss       = finding.epss.as_ref().map(|e| e.score).unwrap_or(0.0);
        let epss_pct   = (epss * 100.0).round() as u32;
        let epss_percentile = finding.epss.as_ref().map(|e| e.percentile * 100.0).unwrap_or(0.0);

        let score = finding.priority_score;

        let kev_part = if finding.kev_listed {
            "CISA KEV listed (×1.35 exploit-confirmed boost)"
        } else {
            "Not in CISA KEV"
        };

        let reach_part = match (finding.reachability_score * 10.0).round() as i32 {
            i32::MIN..=7  => "Unconfirmed reachability (SAST only, 0.7×)",
            8             => "Likely reachable (0.8×)",
            9             => "Reachable (0.9×)",
            10            => "Reachable (1.0×)",
            11            => "High reachability (1.1×)",
            _             => "SAST+DAST confirmed reachable (1.2× boost)",
        };

        let exposure_part = match (finding.asset_exposure_factor * 10.0).round() as i32 {
            i32::MIN..=8 => "Internal asset (0.8× exposure)",
            9            => "Partially exposed (0.9×)",
            10           => "Mixed exposure (1.0×)",
            11           => "Partially public (1.1×)",
            _            => "Internet-facing (1.2× exposure boost)",
        };

        let source_list = finding.source_tools.join(" + ");

        format!(
            "Priority {score:.1}/10 — CVSS4 {cvss_base:.1} ({cvss_vec}) × \
             EPSS {epss_pct}% (top {epss_percentile:.0}th percentile) × \
             {kev_part} × {reach_part} × {exposure_part}. \
             Confirmed by: {source_list}."
        )
    }

    /// Plain-language executive rationale (no vectors, no percentiles).
    /// Used in the executive summary report.
    pub fn explain_executive(finding: &Finding) -> String {
        let score = finding.priority_score;
        let sev = format!("{:?}", finding.severity);

        let urgency = if score >= 9.0 {
            "requires immediate attention"
        } else if score >= 7.0 {
            "should be addressed within days"
        } else if score >= 5.0 {
            "should be planned for next sprint"
        } else {
            "can be addressed in a future release"
        };

        let kev_note = if finding.kev_listed {
            " This vulnerability is actively exploited in the wild (CISA KEV)."
        } else {
            ""
        };

        let confirmed_note = if finding.source_tools.len() > 1 {
            format!(" Independently confirmed by {} security tools.", finding.source_tools.len())
        } else {
            String::new()
        };

        format!(
            "{sev}-severity finding that {urgency} (risk score {score:.1}/10).{kev_note}{confirmed_note}"
        )
    }

    /// Compute and attach `priority_score` and `priority_rationale` to a Finding.
    pub fn score_and_explain(finding: &mut Finding) {
        finding.priority_score = Self::calculate_priority_score(finding);
        finding.priority_rationale = Self::explain(finding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{
        Finding, Severity, CVSS4Data, EPSSData, FindingStatus,
    };
    use uuid::Uuid;
    use chrono::Utc;

    fn make_finding(cvss: f64, epss: f64, kev: bool, reachability: f64, exposure: f64) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            title: "Test Finding".into(),
            description: "Test".into(),
            severity: Severity::High,
            cvss4: Some(CVSS4Data {
                vector_string: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".into(),
                base_score: cvss,
                severity_label: "High".into(),
            }),
            epss: Some(EPSSData { score: epss, percentile: epss }),
            kev_listed: kev,
            asset_exposure_factor: exposure,
            reachability_score: reachability,
            priority_score: 0.0,
            priority_rationale: String::new(),
            cwe_id: Some("CWE-89".into()),
            owasp_2025: None, wstg_id: None, api_top10: None,
            affected_component: "http://target.local/api".into(),
            evidences: vec![], repro_steps: vec![],
            remediation: "Fix it".into(), references: vec![],
            status: FindingStatus::Open,
            source_tools: vec!["OWASP ZAP".into(), "Semgrep".into()],
            ai_triage: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_priority_score_clamped_to_10() {
        let f = make_finding(9.3, 0.95, true, 1.2, 1.2);
        let score = PriorityScoringEngine::calculate_priority_score(&f);
        assert_eq!(score, 10.0);
    }

    #[test]
    fn test_priority_score_formula() {
        // CVSS 7.0, EPSS 0%, no KEV, 1.0 reachability, 1.0 exposure → 7.0
        let f = make_finding(7.0, 0.0, false, 1.0, 1.0);
        let score = PriorityScoringEngine::calculate_priority_score(&f);
        assert_eq!(score, 7.0);
    }

    #[test]
    fn test_explain_contains_score_components() {
        let mut f = make_finding(8.5, 0.72, true, 1.2, 1.1);
        PriorityScoringEngine::score_and_explain(&mut f);
        assert!(f.priority_rationale.contains("CVSS4"));
        assert!(f.priority_rationale.contains("EPSS"));
        assert!(f.priority_rationale.contains("CISA KEV"));
        assert!(f.priority_rationale.contains("SAST+DAST confirmed"));
    }

    #[test]
    fn test_explain_executive_immediate() {
        let mut f = make_finding(9.0, 0.9, true, 1.2, 1.2);
        f.priority_score = 10.0;
        let text = PriorityScoringEngine::explain_executive(&f);
        assert!(text.contains("immediate attention"));
        assert!(text.contains("actively exploited"));
        assert!(text.contains("2 security tools"));
    }
}
