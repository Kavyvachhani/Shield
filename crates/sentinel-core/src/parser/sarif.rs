use crate::models::finding::{Finding, Severity, FindingStatus, Evidence, FindingKind};
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;
use chrono::Utc;
use sha2::{Sha256, Digest};

pub struct SarifParser;

impl SarifParser {
    pub fn parse(raw_json: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let v: Value = serde_json::from_str(raw_json)?;
        let mut findings = Vec::new();

        if let Some(runs) = v.get("runs").and_then(|r| r.as_array()) {
            for run in runs {
                let tool_name = run.pointer("/tool/driver/name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("SARIF Tool");

                if let Some(results) = run.get("results").and_then(|r| r.as_array()) {
                    for res in results {
                        let rule_id = res.get("ruleId").and_then(|r| r.as_str()).unwrap_or("VAPT-GENERIC");
                        let message = res.pointer("/message/text").and_then(|m| m.as_str()).unwrap_or("Security Finding");
                        
                        let location = res.pointer("/locations/0/physicalLocation/artifactLocation/uri")
                            .and_then(|u| u.as_str())
                            .unwrap_or("unknown_location");
                        
                        let line = res.pointer("/locations/0/physicalLocation/region/startLine")
                            .and_then(|l| l.as_u64())
                            .unwrap_or(1);

                        let level = res.get("level").and_then(|l| l.as_str()).unwrap_or("warning");
                        let severity = match level {
                            "error" => Severity::High,
                            "warning" => Severity::Medium,
                            "note" => Severity::Low,
                            _ => Severity::Medium,
                        };

                        let component = format!("{}:L{}", location, line);
                        let mut hasher = Sha256::new();
                        hasher.update(format!("{}:{}", rule_id, message));
                        let hash_str = format!("{:x}", hasher.finalize());

                        let finding = Finding {
                            id: Uuid::new_v4(),
                            scan_id,
                            target_id,
                            title: message.to_string(),
                            description: format!("SARIF rule {} reported violation.", rule_id),
                            severity,
                            kind: FindingKind::default(),
                            cvss4: None,
                            epss: None,
                            kev_listed: false,
                            asset_exposure_factor: 1.0,
                            reachability_score: 0.7,
                            priority_score: 6.0,
                            cwe_id: if rule_id.starts_with("CWE") { Some(rule_id.to_string()) } else { None },
                            owasp_2025: None,
                            wstg_id: None,
                            api_top10: None,
                            affected_component: component,
                            evidences: vec![Evidence {
                                evidence_type: "sarif_result".into(),
                                title: format!("Rule {} match", rule_id),
                                content: serde_json::to_string_pretty(res).unwrap_or_default(),
                                hash: hash_str,
                            }],
                            repro_steps: vec![format!("Review static code at {}", location)],
                            remediation: "Remediate static code flaw per SARIF rule guidance.".into(),
                            references: vec![],
                            status: FindingStatus::Open,
                            source_tools: vec![tool_name.to_string()],
                            ai_triage: None,
                            priority_rationale: String::new(),
                            created_at: Utc::now(),
                        };

                        findings.push(finding);
                    }
                }
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_sarif_json() {
        let raw_sarif = r#"{
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "Semgrep" } },
                "results": [{
                    "ruleId": "CWE-89",
                    "level": "error",
                    "message": { "text": "SQL Injection vulnerability" },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": "src/db.ts" },
                            "region": { "startLine": 25 }
                        }
                    }]
                }]
            }]
        }"#;

        let target_id = Uuid::new_v4();
        let scan_id = Uuid::new_v4();
        let findings = SarifParser::parse(raw_sarif, target_id, scan_id).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "SQL Injection vulnerability");
        assert_eq!(findings[0].affected_component, "src/db.ts:L25");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].source_tools, vec!["Semgrep"]);
    }
}
