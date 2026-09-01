use crate::models::finding::{Finding, Severity, FindingStatus, Evidence, FindingKind};
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;
use chrono::Utc;
use sha2::{Sha256, Digest};

pub struct NucleiJsonlParser;

impl NucleiJsonlParser {
    pub fn parse(raw_jsonl: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for line in raw_jsonl.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Ok(item) = serde_json::from_str::<Value>(line) {
                let template_id = item.get("template-id").and_then(|id| id.as_str()).unwrap_or("nuclei-template");
                let name = item.pointer("/info/name").and_then(|n| n.as_str()).unwrap_or(template_id);
                let description = item.pointer("/info/description").and_then(|d| d.as_str()).unwrap_or("Nuclei template match");
                let severity_str = item.pointer("/info/severity").and_then(|s| s.as_str()).unwrap_or("medium");
                let matched_at = item.get("matched-at").and_then(|m| m.as_str()).unwrap_or("http://target.local");

                let severity = match severity_str.to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Medium,
                };

                let mut hasher = Sha256::new();
                hasher.update(format!("{}:{}", template_id, matched_at));
                let hash_str = format!("{:x}", hasher.finalize());

                let finding = Finding {
                    id: Uuid::new_v4(),
                    scan_id,
                    target_id,
                    title: format!("Nuclei: {}", name),
                    description: description.to_string(),
                    severity,
                    kind: FindingKind::default(),
                    cvss4: None,
                    epss: None,
                    kev_listed: false,
                    asset_exposure_factor: 1.0,
                    reachability_score: 1.0,
                    priority_score: 8.0,
                    cwe_id: Some("CWE-552".into()),
                    owasp_2025: Some("A02:2025-Security Misconfiguration".into()),
                    wstg_id: Some("WSTG-CONFIG-04".into()),
                    api_top10: None,
                    affected_component: matched_at.to_string(),
                    evidences: vec![Evidence {
                        evidence_type: "template_match".into(),
                        title: format!("Template Match: {}", template_id),
                        content: format!("Matched Endpoint: {}\nTemplate ID: {}", matched_at, template_id),
                        hash: hash_str,
                    }],
                    repro_steps: vec![format!("curl -i {}", matched_at)],
                    remediation: "Remediate configuration or exposure according to Nuclei template details.".into(),
                    references: vec!["https://nuclei.projectdiscovery.io/".into()],
                    status: FindingStatus::Open,
                    source_tools: vec!["Nuclei".into()],
                    ai_triage: None,
                    priority_rationale: String::new(),
                    created_at: Utc::now(),
                };

                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_nuclei_jsonl() {
        let raw_jsonl = r#"{"template-id":"env-file-exposure","info":{"name":"Exposed Environment Configuration File","description":".env file exposed","severity":"critical"},"matched-at":"http://example.com/.env"}"#;

        let target_id = Uuid::new_v4();
        let scan_id = Uuid::new_v4();
        let findings = NucleiJsonlParser::parse(raw_jsonl, target_id, scan_id).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].affected_component, "http://example.com/.env");
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
