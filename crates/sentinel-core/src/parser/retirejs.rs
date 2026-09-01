//! retire.js output.
//!
//! Trivy and OSV read lockfiles, which describe what the *build* declares.
//! retire.js reads the JavaScript the browser actually receives, which is not
//! the same thing: a vendored copy of jQuery committed years ago, a library
//! pulled from a CDN, or a bundle built from a lockfile nobody has updated
//! appear here and nowhere else.
//!
//! It pairs directly with this engine's crawler. The crawl already fetches
//! every same-origin script it finds — that is where a leaked credential is
//! caught — and those same files are what retire.js needs.

use super::external::ExternalFinding;
use crate::models::finding::Finding;
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

pub struct RetireJsParser;

impl RetireJsParser {
    /// Parse `retire --outputformat json` output.
    pub fn parse(raw_json: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let root: Value = serde_json::from_str(raw_json)?;
        let mut findings = Vec::new();

        // retire.js has emitted both a bare array and a `{"data": [...]}`
        // wrapper across versions; accept either rather than depending on which
        // one the user happens to have installed.
        let entries = root
            .get("data")
            .and_then(Value::as_array)
            .or_else(|| root.as_array())
            .cloned()
            .unwrap_or_default();

        for entry in &entries {
            let file = entry
                .get("file")
                .and_then(Value::as_str)
                .unwrap_or("client-side script");

            let Some(results) = entry.get("results").and_then(Value::as_array) else {
                continue;
            };

            for result in results {
                let component = result
                    .get("component")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown library");
                let version = result
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");

                let Some(vulnerabilities) = result.get("vulnerabilities").and_then(Value::as_array)
                else {
                    continue;
                };

                for vuln in vulnerabilities {
                    findings.push(
                        Self::finding(vuln, file, component, version)
                            .into_finding(target_id, scan_id),
                    );
                }
            }
        }

        Ok(findings)
    }

    fn finding(vuln: &Value, file: &str, component: &str, version: &str) -> ExternalFinding {
        let severity = super::external::severity_from_label(
            vuln.get("severity").and_then(Value::as_str).unwrap_or("medium"),
        );

        let identifiers = vuln.get("identifiers");
        let summary = identifiers
            .and_then(|i| i.get("summary"))
            .and_then(Value::as_str)
            .unwrap_or("Known vulnerability in a client-side library");

        let cves: Vec<String> = identifiers
            .and_then(|i| i.get("CVE"))
            .and_then(Value::as_array)
            .map(|c| c.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();

        let below = vuln.get("below").and_then(Value::as_str);
        let at_or_above = vuln.get("atOrAbove").and_then(Value::as_str);

        let mut references: Vec<String> = vuln
            .get("info")
            .and_then(Value::as_array)
            .map(|i| i.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        for cve in &cves {
            references.push(format!("https://nvd.nist.gov/vuln/detail/{cve}"));
        }
        references.truncate(8);

        let title = if cves.is_empty() {
            format!("{component} {version} is vulnerable: {summary}")
        } else {
            format!("{} in {component} {version}", cves.join(", "))
        };

        let affected_range = match (at_or_above, below) {
            (Some(from), Some(to)) => format!("versions >= {from} and < {to}"),
            (None, Some(to)) => format!("versions before {to}"),
            _ => "the version in use".to_string(),
        };

        let remediation = match below {
            Some(fixed) => format!(
                "Upgrade {component} to {fixed} or later. If this file is vendored into the \
                 repository rather than installed by a package manager, replacing the file is the \
                 fix — a lockfile bump will not touch it, which is the usual reason a library stays \
                 vulnerable long after the dependency was updated.\n\n\
                 Serve client-side libraries from your own origin with Subresource Integrity rather \
                 than from a third-party CDN, so the version you audited is the version that runs."
            ),
            None => format!(
                "No fixed release of {component} is identified for this issue. Check whether the \
                 vulnerable functionality is actually used by your code; if it is, replacing the \
                 library is the only reliable fix."
            ),
        };

        ExternalFinding::new(title, severity, format!("{file} ({component}@{version})"), "retire.js")
            .description(format!(
                "{summary}\n\nThe browser loads {component} {version} from {file}. This advisory \
                 affects {affected_range}.\n\nThis is the library the browser actually receives, \
                 which is not necessarily what the lockfile declares: a vendored copy, a CDN \
                 reference or a stale build can all leave a vulnerable version running long after \
                 the dependency was updated."
            ))
            .remediation(remediation)
            .taxonomy(
                "CWE-1395",
                "A03:2025-Software Supply Chain Failures",
                Some("WSTG-CLNT-13"),
            )
            .references(references)
            .repro(vec![format!("retire --js --path {file} --outputformat json")])
            .evidence(
                "dependency_lock",
                &format!("{component} {version}"),
                &format!(
                    "File:     {file}\nLibrary:  {component}\nVersion:  {version}\nAffected: {affected_range}\nCVEs:     {}",
                    if cves.is_empty() { "none listed".to_string() } else { cves.join(", ") }
                ),
            )
            .confidence(
                0.15,
                "The library version was read from the file the browser receives, so the version is \
                 a fact. Whether your code calls the vulnerable function is not established here.",
            )
            // Client-side and served to every visitor: more reachable than a
            // server-side dependency, less than a proven exploit.
            .reachability(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::Severity;

    const SAMPLE: &str = r#"{"data":[{
      "file": "https://app.test/static/vendor/jquery-1.7.2.min.js",
      "results": [{
        "component": "jquery",
        "version": "1.7.2",
        "vulnerabilities": [{
          "atOrAbove": "1.4.0",
          "below": "1.9.0",
          "severity": "medium",
          "identifiers": { "summary": "Selector interpreted as HTML", "CVE": ["CVE-2012-6708"] },
          "info": ["https://bugs.jquery.com/ticket/11290"]
        }]
      }]
    }]}"#;

    #[test]
    fn a_vulnerable_client_library_is_parsed_with_its_cve() {
        let out = RetireJsParser::parse(SAMPLE, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].title.contains("CVE-2012-6708"));
        assert!(out[0].title.contains("jquery 1.7.2"));
        assert_eq!(out[0].severity, Severity::Medium);
        assert_eq!(out[0].owasp_2025.as_deref(), Some("A03:2025-Software Supply Chain Failures"));
        assert!(out[0].affected_component.contains("jquery-1.7.2.min.js"));
    }

    /// The distinction that makes this tool worth running next to Trivy.
    #[test]
    fn the_finding_explains_why_a_lockfile_scan_would_miss_it() {
        let out = RetireJsParser::parse(SAMPLE, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].description.contains("not necessarily what the lockfile declares"));
        assert!(out[0].remediation.contains("vendored"), "{}", out[0].remediation);
        assert!(out[0].remediation.contains("Subresource Integrity"));
    }

    #[test]
    fn the_affected_range_is_stated_rather_than_just_the_fixed_version() {
        let out = RetireJsParser::parse(SAMPLE, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].description.contains("versions >= 1.4.0 and < 1.9.0"), "{}", out[0].description);
    }

    /// The tool has emitted both shapes across versions; depending on one would
    /// break for whichever the user has installed.
    #[test]
    fn both_the_wrapped_and_bare_array_shapes_parse() {
        let bare = SAMPLE.trim_start_matches(r#"{"data":"#).trim_end_matches('}');
        let out = RetireJsParser::parse(bare, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn an_advisory_with_no_fixed_release_says_so() {
        let json = SAMPLE.replace(r#""below": "1.9.0","#, "");
        let out = RetireJsParser::parse(&json, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].remediation.contains("No fixed release"), "{}", out[0].remediation);
    }

    #[test]
    fn a_clean_scan_produces_nothing() {
        for json in [r#"{"data":[]}"#, "[]", r#"{"data":[{"file":"a.js","results":[]}]}"#] {
            assert!(RetireJsParser::parse(json, Uuid::new_v4(), Uuid::new_v4()).unwrap().is_empty());
        }
    }

    #[test]
    fn malformed_json_is_an_error_not_a_silent_pass() {
        assert!(RetireJsParser::parse("<html>", Uuid::new_v4(), Uuid::new_v4()).is_err());
    }
}
