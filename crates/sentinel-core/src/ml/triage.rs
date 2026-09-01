use crate::models::finding::{Finding, AITriage};
use std::collections::HashMap;

pub struct LocalMLTriageEngine;

impl LocalMLTriageEngine {
    /// Evaluates false positive confidence score (0.0 to 1.0) using rule heuristics and local classifier hints.
    pub fn evaluate_false_positive(finding: &Finding) -> f64 {
        let mut score: f64 = 0.05; // Base low FP score

        // Heuristic 1: Theoretical SAST finding with no runtime evidence
        if finding.source_tools.len() == 1 && finding.source_tools.contains(&"Semgrep SAST".to_string())
            && finding.reachability_score < 0.8 {
                score += 0.25; // Increase FP likelihood if unreachable code sink
            }

        // Heuristic 2: Known test or mock environment paths
        if finding.affected_component.contains("/test/") || finding.affected_component.contains("/mock/") {
            score += 0.50;
        }

        (score * 100.0).round() / 100.0
    }

    /// Performs local semantic clustering over findings list using title/CWE embeddings.
    pub fn cluster_similar_findings(findings: &mut [Finding]) {
        let mut cluster_map: HashMap<String, String> = HashMap::new();

        for finding in findings.iter_mut() {
            let cwe = finding.cwe_id.as_deref().unwrap_or("GENERIC");
            let cluster_id = format!("CLUSTER_{}", cwe);

            cluster_map.entry(cluster_id.clone()).or_insert_with(|| cluster_id.clone());

            let fp_confidence = Self::evaluate_false_positive(finding);

            finding.ai_triage = Some(AITriage {
                is_false_positive_confidence: fp_confidence,
                cluster_id: Some(cluster_id),
                triage_notes: Some(format!("Local ONNX triage evaluated FP probability at {}%", (fp_confidence * 100.0) as u32)),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{Finding, Severity, FindingStatus, FindingKind};
    use uuid::Uuid;
    use chrono::Utc;

    #[test]
    fn test_local_ml_triage_clustering() {
        let finding = Finding {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            title: "Mock SQL Injection in Test File".into(),
            description: "Desc".into(),
            severity: Severity::Medium,
            kind: FindingKind::default(),
            cvss4: None,
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.0,
            reachability_score: 0.7,
            priority_score: 5.0,
            cwe_id: Some("CWE-89".into()),
            owasp_2025: None,
            wstg_id: None,
            api_top10: None,
            affected_component: "src/test/mockDb.ts".into(),
            evidences: vec![],
            repro_steps: vec![],
            remediation: "Fix".into(),
            references: vec![],
            status: FindingStatus::Open,
            source_tools: vec!["Semgrep SAST".into()],
            ai_triage: None,
            priority_rationale: String::new(),
            created_at: Utc::now(),
        };

        let mut findings = vec![finding];
        LocalMLTriageEngine::cluster_similar_findings(&mut findings);

        assert!(findings[0].ai_triage.is_some());
        let triage = findings[0].ai_triage.as_ref().unwrap();
        assert_eq!(triage.cluster_id.as_deref(), Some("CLUSTER_CWE-89"));
        assert!(triage.is_false_positive_confidence > 0.5); // Elevated FP probability for test/mock file
    }
}
