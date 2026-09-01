use crate::models::finding::{Finding, Severity, FindingStatus, Evidence, FindingKind};
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;
use chrono::Utc;
use sha2::{Sha256, Digest};

pub struct SemgrepJsonParser;

impl SemgrepJsonParser {
    pub fn parse(raw_json: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let v: Value = serde_json::from_str(raw_json)?;
        let mut findings = Vec::new();

        if let Some(results) = v.get("results").and_then(|r| r.as_array()) {
            for res in results {
                let check_id = res.get("check_id").and_then(|c| c.as_str()).unwrap_or("semgrep-rule");
                let path = res.get("path").and_then(|p| p.as_str()).unwrap_or("unknown_file");
                let line = res.pointer("/start/line").and_then(|l| l.as_u64()).unwrap_or(1);
                let message = res.pointer("/extra/message").and_then(|m| m.as_str()).unwrap_or("Semgrep rule match");
                let severity_str = res.pointer("/extra/severity").and_then(|s| s.as_str()).unwrap_or("WARNING");

                let severity = match severity_str {
                    "ERROR" => Severity::High,
                    "WARNING" => Severity::Medium,
                    "INFO" => Severity::Low,
                    _ => Severity::Medium,
                };

                let lines_code = res.pointer("/extra/lines").and_then(|l| l.as_str()).unwrap_or("");

                let mut hasher = Sha256::new();
                hasher.update(lines_code);
                let hash_str = format!("{:x}", hasher.finalize());

                let finding = Finding {
                    id: Uuid::new_v4(),
                    scan_id,
                    target_id,
                    title: format!("SAST: {}", check_id),
                    description: message.to_string(),
                    severity,
                    kind: FindingKind::default(),
                    cvss4: None,
                    epss: None,
                    kev_listed: false,
                    asset_exposure_factor: 1.0,
                    reachability_score: 0.7,
                    priority_score: 5.5,
                    cwe_id: extract_cwe_from_rule(check_id),
                    owasp_2025: Some("A01:2025-Broken Access Control".into()),
                    wstg_id: None,
                    api_top10: None,
                    affected_component: format!("{}:L{}", path, line),
                    evidences: vec![Evidence {
                        evidence_type: "code_snippet".into(),
                        title: "Source to Sink Dataflow".into(),
                        content: lines_code.to_string(),
                        hash: hash_str,
                    }],
                    repro_steps: vec![format!("Inspect {} at line {}", path, line)],
                    remediation: "Remediate source code flaw following Semgrep pattern guidance.".into(),
                    references: vec!["https://semgrep.dev/docs/".into()],
                    status: FindingStatus::Open,
                    source_tools: vec!["Semgrep SAST".into()],
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

fn extract_cwe_from_rule(check_id: &str) -> Option<String> {
    if check_id.to_lowercase().contains("sqli") || check_id.to_lowercase().contains("sql-injection") {
        Some("CWE-89".to_string())
    } else if check_id.to_lowercase().contains("xss") {
        Some("CWE-79".to_string())
    } else if check_id.to_lowercase().contains("command-injection") {
        Some("CWE-78".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_semgrep_json() {
        let raw_json = r#"{
            "results": [{
                "check_id": "javascript.express.security.sqli.express-sqli",
                "path": "src/controllers/user.ts",
                "start": { "line": 42 },
                "extra": {
                    "message": "Detected user input flowing into database query.",
                    "severity": "ERROR",
                    "lines": "const res = await db.query('SELECT * FROM users WHERE id = ' + req.query.id);"
                }
            }]
        }"#;

        let target_id = Uuid::new_v4();
        let scan_id = Uuid::new_v4();
        let findings = SemgrepJsonParser::parse(raw_json, target_id, scan_id).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].affected_component, "src/controllers/user.ts:L42");
        assert_eq!(findings[0].cwe_id, Some("CWE-89".to_string()));
        assert_eq!(findings[0].severity, Severity::High);
    }
}
