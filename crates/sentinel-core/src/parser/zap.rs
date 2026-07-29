use crate::models::finding::{Finding, Severity, FindingStatus, Evidence};
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;
use chrono::Utc;
use sha2::{Sha256, Digest};

pub struct ZapJsonParser;

impl ZapJsonParser {
    pub fn parse(raw_json: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let v: Value = serde_json::from_str(raw_json)?;
        let mut findings = Vec::new();

        if let Some(sites) = v.get("site").and_then(|s| s.as_array()) {
            for site in sites {
                if let Some(alerts) = site.get("alerts").and_then(|a| a.as_array()) {
                    for alert in alerts {
                        let name = alert.get("name").and_then(|n| n.as_str()).unwrap_or("ZAP DAST Alert");
                        let desc = alert.get("desc").and_then(|d| d.as_str()).unwrap_or("");
                        let risk = alert.get("riskdesc").and_then(|r| r.as_str()).unwrap_or("Medium");
                        let cwe = alert.get("cweid").and_then(|c| c.as_str()).unwrap_or("89");
                        let solution = alert.get("solution").and_then(|s| s.as_str()).unwrap_or("Remediate flaw.");

                        let severity = if risk.contains("High") || risk.contains("Critical") {
                            Severity::High
                        } else if risk.contains("Medium") {
                            Severity::Medium
                        } else {
                            Severity::Low
                        };

                        let url = alert.get("url").and_then(|u| u.as_str()).unwrap_or("http://target.local");
                        let param = alert.get("param").and_then(|p| p.as_str()).unwrap_or("");

                        let component = if !param.is_empty() {
                            format!("{}?{}", url, param)
                        } else {
                            url.to_string()
                        };

                        let mut hasher = Sha256::new();
                        hasher.update(format!("{}:{}", name, component));
                        let hash_str = format!("{:x}", hasher.finalize());

                        let finding = Finding {
                            id: Uuid::new_v4(),
                            scan_id,
                            target_id,
                            title: format!("DAST: {}", name),
                            description: desc.to_string(),
                            severity,
                            cvss4: None,
                            epss: None,
                            kev_listed: false,
                            asset_exposure_factor: 1.0,
                            reachability_score: 1.0, // DAST runtime finding
                            priority_score: 7.5,
                            cwe_id: Some(format!("CWE-{}", cwe)),
                            owasp_2025: Some("A01:2025-Broken Access Control".into()),
                            wstg_id: Some("WSTG-INPV-05".into()),
                            api_top10: None,
                            affected_component: component,
                            evidences: vec![Evidence {
                                evidence_type: "http_response".into(),
                                title: "DAST Vector Alert".into(),
                                content: format!("Target URL: {}\nParam: {}", url, param),
                                hash: hash_str,
                            }],
                            repro_steps: vec![format!("Send HTTP Request to {}", url)],
                            remediation: solution.to_string(),
                            references: vec!["https://www.zaproxy.org/".into()],
                            status: FindingStatus::Open,
                            source_tools: vec!["OWASP ZAP".into()],
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
    fn test_parse_valid_zap_json() {
        let raw_json = r#"{
            "site": [{
                "alerts": [{
                    "name": "Cross-Site Scripting (Reflected)",
                    "desc": "Reflected XSS parameter vulnerability",
                    "riskdesc": "High (High)",
                    "cweid": "79",
                    "solution": "Sanitize user input",
                    "url": "http://example.com/search",
                    "param": "q"
                }]
            }]
        }"#;

        let target_id = Uuid::new_v4();
        let scan_id = Uuid::new_v4();
        let findings = ZapJsonParser::parse(raw_json, target_id, scan_id).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].affected_component, "http://example.com/search?q");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cwe_id, Some("CWE-79".to_string()));
    }
}
