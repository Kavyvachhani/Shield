use crate::models::finding::{Finding, Severity, FindingStatus, Evidence, FindingKind};
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;
use chrono::Utc;
use sha2::{Sha256, Digest};

pub struct GitleaksJsonParser;

impl GitleaksJsonParser {
    pub fn parse(raw_json: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let items: Vec<Value> = serde_json::from_str(raw_json)?;
        let mut findings = Vec::new();

        for item in items {
            let description = item.get("Description").and_then(|d| d.as_str()).unwrap_or("Hardcoded Secret");
            let file_path = item.get("File").and_then(|f| f.as_str()).unwrap_or("unknown_file");
            let line = item.get("StartLine").and_then(|l| l.as_u64()).unwrap_or(1);
            let secret = item.get("Secret").and_then(|s| s.as_str()).unwrap_or("*****");
            let rule_id = item.get("RuleID").and_then(|r| r.as_str()).unwrap_or("secret-leak");

            let component = format!("{}:L{}", file_path, line);
            let mut hasher = Sha256::new();
            hasher.update(secret);
            let hash_str = format!("{:x}", hasher.finalize());

            let finding = Finding {
                id: Uuid::new_v4(),
                scan_id,
                target_id,
                title: format!("Secret Leak: {} ({})", description, rule_id),
                description: format!("Gitleaks identified hardcoded secret pattern '{}' in repository code.", rule_id),
                severity: Severity::Critical,
                kind: FindingKind::default(),
                cvss4: Some(crate::models::finding::CVSS4Data {
                    vector_string: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H".into(),
                    base_score: 9.5,
                    severity_label: "Critical".into(),
                }),
                epss: None,
                kev_listed: false,
                asset_exposure_factor: 1.2,
                reachability_score: 1.0,
                priority_score: 9.5,
                cwe_id: Some("CWE-798".into()),
                owasp_2025: Some("A03:2025-Software Supply Chain Failures".into()),
                wstg_id: None,
                api_top10: None,
                affected_component: component,
                evidences: vec![Evidence {
                    evidence_type: "secret_leak".into(),
                    title: "Pattern Match Evidence".into(),
                    content: format!("Pattern Rule: {}\nLine: {}\nRedacted Hash: {}", rule_id, line, hash_str),
                    hash: hash_str,
                }],
                repro_steps: vec![format!("Inspect file {} at line {}", file_path, line)],
                remediation: "Revoke key immediately in dashboard, rotate credential, and migrate to OS keyring.".into(),
                references: vec!["https://github.com/gitleaks/gitleaks".into()],
                status: FindingStatus::Open,
                source_tools: vec!["Gitleaks".into()],
                ai_triage: None,
                priority_rationale: String::new(),
                created_at: Utc::now(),
            };

            findings.push(finding);
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_gitleaks_json() {
        let raw_json = r#"[
            {
                "Description": "AWS Access Key",
                "File": "src/config/aws.ts",
                "StartLine": 14,
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "RuleID": "aws-access-token"
            }
        ]"#;

        let target_id = Uuid::new_v4();
        let scan_id = Uuid::new_v4();
        let findings = GitleaksJsonParser::parse(raw_json, target_id, scan_id).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].affected_component, "src/config/aws.ts:L14");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].cwe_id, Some("CWE-798".to_string()));
    }
}
