use crate::models::finding::Finding;
use crate::scoring::priority::PriorityScoringEngine;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

pub struct DeduplicationEngine;

impl DeduplicationEngine {
    /// Compute exact SHA-256 fingerprint: target + CWE + component + title.
    pub fn compute_exact_fingerprint(finding: &Finding) -> String {
        let mut hasher = Sha256::new();
        let cwe = finding.cwe_id.as_deref().unwrap_or("UNKNOWN_CWE");
        hasher.update(format!(
            "{}:{}:{}:{}",
            finding.target_id,
            cwe,
            finding.affected_component.to_lowercase(),
            finding.title.to_lowercase()
        ));
        format!("{:x}", hasher.finalize())
    }

    /// Fuzzy fingerprint: matches the same vulnerability class in the same component
    /// even when titles differ slightly between tools (e.g. "SQL Injection" vs "SQLi").
    /// Uses target + CWE + component path prefix (up to first query string `?`).
    pub fn compute_fuzzy_fingerprint(finding: &Finding) -> String {
        let mut hasher = Sha256::new();
        let cwe = finding.cwe_id.as_deref().unwrap_or("UNKNOWN_CWE");
        let component = finding.affected_component
            .split('?').next().unwrap_or(&finding.affected_component)
            .to_lowercase();
        hasher.update(format!(
            "FUZZY:{}:{}:{}",
            finding.target_id, cwe, component
        ));
        format!("{:x}", hasher.finalize())
    }

    /// Deduplicate and merge a list of findings from multiple scanner tools.
    ///
    /// Merge strategy:
    ///   1. Exact fingerprint match → merge evidences + source tools.
    ///   2. Fuzzy fingerprint match (same CWE + component prefix) → merge with note.
    ///   3. After merge, re-score priority and regenerate rationale (reachability boosted
    ///      when multiple tools confirm the same finding).
    ///   4. Sort by `priority_score` descending — highest risk first.
    pub fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
        // ── Pass 1: Exact dedup ──────────────────────────────────────────────
        let mut exact_map: HashMap<String, Finding> = HashMap::new();

        for mut finding in findings {
            let fp = Self::compute_exact_fingerprint(&finding);

            if let Some(existing) = exact_map.get_mut(&fp) {
                // Merge source tools (deduplicated)
                for tool in &finding.source_tools {
                    if !existing.source_tools.contains(tool) {
                        existing.source_tools.push(tool.clone());
                    }
                }
                // Merge evidence items
                existing.evidences.append(&mut finding.evidences);
                // Merge repro steps if not already present
                for step in finding.repro_steps {
                    if !existing.repro_steps.contains(&step) {
                        existing.repro_steps.push(step);
                    }
                }
            } else {
                exact_map.insert(fp, finding);
            }
        }

        // ── Pass 2: Fuzzy dedup (same CWE + component, different tool phrasing) ──
        let exact_findings: Vec<Finding> = exact_map.into_values().collect();
        let mut fuzzy_map: HashMap<String, Finding> = HashMap::new();

        for mut finding in exact_findings {
            let fp = Self::compute_fuzzy_fingerprint(&finding);

            if let Some(existing) = fuzzy_map.get_mut(&fp) {
                // Fuzzy merge: carry over source tools and note the merge
                for tool in &finding.source_tools {
                    if !existing.source_tools.contains(tool) {
                        existing.source_tools.push(tool.clone());
                    }
                }
                existing.evidences.append(&mut finding.evidences);
                // Keep higher severity between the two
                if finding.severity < existing.severity {
                    existing.severity = finding.severity;
                }
            } else {
                fuzzy_map.insert(fp, finding);
            }
        }

        // ── Pass 3: Re-score with cross-tool reachability boost ──────────────
        let mut merged: Vec<Finding> = fuzzy_map.into_values()
            .map(|mut f| {
                // Multi-tool confirmation → higher reachability confidence
                if f.source_tools.len() >= 2 {
                    // SAST + DAST confirmation = maximum reachability
                    let has_dast = f.source_tools.iter().any(|t| {
                        let tl = t.to_lowercase();
                        tl.contains("zap") || tl.contains("nuclei") || tl.contains("dast")
                    });
                    let has_sast = f.source_tools.iter().any(|t| {
                        let tl = t.to_lowercase();
                        tl.contains("semgrep") || tl.contains("sast") || tl.contains("trivy")
                    });
                    if has_dast && has_sast {
                        f.reachability_score = 1.2; // Full SAST+DAST verification boost
                    } else {
                        f.reachability_score = f.reachability_score.max(1.0); // At minimum confirmed
                    }
                }
                // Re-compute score and regenerate rationale with updated inputs
                PriorityScoringEngine::score_and_explain(&mut f);
                f
            })
            .collect();

        // ── Pass 4: Sort by priority descending (highest risk first) ─────────
        merged.sort_by(|a, b| {
            b.priority_score.partial_cmp(&a.priority_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                // Tie-break: severity, then created_at descending
                .then(a.severity.cmp(&b.severity))
                .then(b.created_at.cmp(&a.created_at))
        });

        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{Finding, Severity, FindingStatus, CVSS4Data};
    use uuid::Uuid;
    use chrono::Utc;

    fn make(title: &str, cwe: &str, component: &str, tool: &str, cvss: f64) -> Finding {
        let target_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let scan_id = Uuid::new_v4();
        Finding {
            id: Uuid::new_v4(),
            scan_id,
            target_id,
            title: title.into(),
            description: "Test".into(),
            severity: Severity::High,
            cvss4: Some(CVSS4Data {
                vector_string: String::new(),
                base_score: cvss,
                severity_label: "High".into(),
            }),
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.0,
            reachability_score: 1.0,
            priority_score: cvss,
            priority_rationale: String::new(),
            cwe_id: Some(cwe.into()),
            owasp_2025: None, wstg_id: None, api_top10: None,
            affected_component: component.into(),
            evidences: vec![], repro_steps: vec![],
            remediation: "Fix".into(), references: vec![],
            status: FindingStatus::Open,
            source_tools: vec![tool.into()],
            ai_triage: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn exact_dedup_merges_same_finding_from_two_tools() {
        let f1 = make("SQL Injection", "CWE-89", "/api/users", "Semgrep SAST", 8.0);
        let f2 = make("SQL Injection", "CWE-89", "/api/users", "OWASP ZAP", 8.0);
        let result = DeduplicationEngine::deduplicate_findings(vec![f1, f2]);
        assert_eq!(result.len(), 1, "Exact duplicates must be merged to 1");
        assert_eq!(result[0].source_tools.len(), 2, "Both tool names must be in merged finding");
    }

    #[test]
    fn fuzzy_dedup_merges_same_cwe_same_component() {
        let f1 = make("SQL Injection in User Search", "CWE-89", "/api/search?q=test", "Semgrep", 7.5);
        let f2 = make("SQLi detected at /api/search", "CWE-89", "/api/search", "Nuclei", 7.0);
        let result = DeduplicationEngine::deduplicate_findings(vec![f1, f2]);
        assert_eq!(result.len(), 1, "Fuzzy duplicates (same CWE + component prefix) must be merged");
    }

    #[test]
    fn different_cwes_not_merged() {
        let f1 = make("XSS", "CWE-79", "/api/users", "ZAP", 6.0);
        let f2 = make("SQLi", "CWE-89", "/api/users", "ZAP", 7.0);
        let result = DeduplicationEngine::deduplicate_findings(vec![f1, f2]);
        assert_eq!(result.len(), 2, "Different CWEs should not be merged");
    }

    #[test]
    fn sast_plus_dast_boosts_reachability_to_1_2() {
        let f1 = make("SQL Injection", "CWE-89", "/api/data", "Semgrep SAST", 8.0);
        let mut f2 = make("SQL Injection", "CWE-89", "/api/data", "OWASP ZAP", 8.0);
        f2.reachability_score = 1.0;
        let result = DeduplicationEngine::deduplicate_findings(vec![f1, f2]);
        assert_eq!(result[0].reachability_score, 1.2,
            "SAST+DAST confirmed finding must get 1.2 reachability boost");
    }

    #[test]
    fn output_sorted_by_priority_descending() {
        let low  = make("XSS", "CWE-79", "/api/a", "ZAP", 4.0);
        let high = make("RCE", "CWE-78", "/api/b", "ZAP", 9.5);
        let med  = make("SSRF", "CWE-918", "/api/c", "ZAP", 6.5);
        let result = DeduplicationEngine::deduplicate_findings(vec![low, high, med]);
        assert!(result[0].priority_score >= result[1].priority_score);
        assert!(result[1].priority_score >= result[2].priority_score);
    }

    #[test]
    fn priority_rationale_is_set_after_dedup() {
        let f = make("XSS", "CWE-79", "/api/x", "ZAP", 7.0);
        let result = DeduplicationEngine::deduplicate_findings(vec![f]);
        assert!(!result[0].priority_rationale.is_empty(),
            "priority_rationale must be populated after dedup");
        assert!(result[0].priority_rationale.contains("Priority"));
    }
}
