use crate::models::finding::{Finding, Severity, FindingStatus, Evidence};
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;
use chrono::Utc;
use sha2::{Sha256, Digest};

pub struct TrivyJsonParser;

impl TrivyJsonParser {
    pub fn parse(raw_json: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let v: Value = serde_json::from_str(raw_json)?;
        let mut findings = Vec::new();

        if let Some(results) = v.get("Results").and_then(|r| r.as_array()) {
            for res in results {
                let target = res.get("Target").and_then(|t| t.as_str()).unwrap_or("package.json");

                if let Some(vulns) = res.get("Vulnerabilities").and_then(|v| v.as_array()) {
                    for vuln in vulns {
                        let cve_id = vuln.get("VulnerabilityID").and_then(|id| id.as_str()).unwrap_or("CVE-UNKNOWN");
                        let pkg_name = vuln.get("PkgName").and_then(|p| p.as_str()).unwrap_or("package");
                        let installed_version = vuln.get("InstalledVersion").and_then(|v| v.as_str()).unwrap_or("0.0.0");
                        let fixed_version = vuln.get("FixedVersion").and_then(|f| f.as_str()).unwrap_or("N/A");
                        let title = vuln.get("Title").and_then(|t| t.as_str()).unwrap_or(cve_id);
                        let description = vuln.get("Description").and_then(|d| d.as_str()).unwrap_or("SCA vulnerability");
                        let severity_str = vuln.get("Severity").and_then(|s| s.as_str()).unwrap_or("MEDIUM");

                        let severity = match severity_str {
                            "CRITICAL" => Severity::Critical,
                            "HIGH" => Severity::High,
                            "MEDIUM" => Severity::Medium,
                            "LOW" => Severity::Low,
                            _ => Severity::Medium,
                        };

                        let component = format!("{} ({}@{})", target, pkg_name, installed_version);
                        let mut hasher = Sha256::new();
                        hasher.update(format!("{}:{}", cve_id, pkg_name));
                        let hash_str = format!("{:x}", hasher.finalize());

                        let finding = Finding {
                            id: Uuid::new_v4(),
                            scan_id,
                            target_id,
                            title: format!("{}: {} in {}", cve_id, title, pkg_name),
                            description: description.to_string(),
                            severity,
                            cvss4: None,
                            epss: None,
                            kev_listed: false,
                            asset_exposure_factor: 1.0,
                            reachability_score: 1.0,
                            priority_score: 7.0,
                            cwe_id: Some("CWE-1395".into()),
                            owasp_2025: Some("A03:2025-Software Supply Chain Failures".into()),
                            wstg_id: None,
                            api_top10: None,
                            affected_component: component,
                            evidences: vec![Evidence {
                                evidence_type: "dependency_lock".into(),
                                title: format!("Package Lock Exception: {}", pkg_name),
                                content: format!("Installed: {}\nFixed Version: {}", installed_version, fixed_version),
                                hash: hash_str,
                            }],
                            repro_steps: vec![format!("Check dependency {} version in {}", pkg_name, target)],
                            remediation: format!("Upgrade dependency package {} to version >= {}", pkg_name, fixed_version),
                            references: vec![format!("https://nvd.nist.gov/vuln/detail/{}", cve_id)],
                            status: FindingStatus::Open,
                            source_tools: vec!["Trivy SCA".into()],
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
    fn test_parse_valid_trivy_json() {
        let raw_json = r#"{
            "Results": [{
                "Target": "package-lock.json",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-29041",
                    "PkgName": "express",
                    "InstalledVersion": "4.18.1",
                    "FixedVersion": "4.19.2",
                    "Title": "Open Redirect via malformed URLs",
                    "Description": "Express open redirect vulnerability",
                    "Severity": "HIGH"
                }]
            }]
        }"#;

        let target_id = Uuid::new_v4();
        let scan_id = Uuid::new_v4();
        let findings = TrivyJsonParser::parse(raw_json, target_id, scan_id).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].affected_component, "package-lock.json (express@4.18.1)");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].remediation, "Upgrade dependency package express to version >= 4.19.2");
    }
}
