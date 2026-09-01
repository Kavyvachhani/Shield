//! OSV-Scanner output.
//!
//! OSV is the vulnerability database Google maintains for open source, and its
//! scanner resolves a repository's lockfiles against it. It overlaps Trivy but
//! is not redundant: OSV covers ecosystems Trivy handles thinly (Go modules,
//! crates, Hex, Pub, Maven ranges), and it reports *affected version ranges*
//! rather than a single fixed version, so it catches a dependency sitting
//! between two patched releases.
//!
//! Running both and letting deduplication merge them is the point. A CVE
//! reported by two independent databases is a stronger claim than one reported
//! by either alone, and the dedup engine raises reachability when it sees that.

use super::external::{severity_from_label, ExternalFinding};
use crate::models::finding::{Finding, Severity};
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

pub struct OsvScannerParser;

impl OsvScannerParser {
    /// Parse `osv-scanner --format json` output.
    pub fn parse(raw_json: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let root: Value = serde_json::from_str(raw_json)?;
        let mut findings = Vec::new();

        let Some(results) = root.get("results").and_then(Value::as_array) else {
            return Ok(findings);
        };

        for result in results {
            let source = result
                .pointer("/source/path")
                .and_then(Value::as_str)
                .unwrap_or("dependency manifest");

            let Some(packages) = result.get("packages").and_then(Value::as_array) else {
                continue;
            };

            for entry in packages {
                let name = entry
                    .pointer("/package/name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown package");
                let version = entry
                    .pointer("/package/version")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let ecosystem = entry
                    .pointer("/package/ecosystem")
                    .and_then(Value::as_str)
                    .unwrap_or("");

                let Some(vulns) = entry.get("vulnerabilities").and_then(Value::as_array) else {
                    continue;
                };

                for vuln in vulns {
                    findings.push(
                        Self::finding(vuln, entry, source, name, version, ecosystem)
                            .into_finding(target_id, scan_id),
                    );
                }
            }
        }

        Ok(findings)
    }

    fn finding(
        vuln: &Value,
        entry: &Value,
        source: &str,
        name: &str,
        version: &str,
        ecosystem: &str,
    ) -> ExternalFinding {
        let id = vuln.get("id").and_then(Value::as_str).unwrap_or("OSV-UNKNOWN");
        let summary = vuln
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or("Known vulnerability in a declared dependency");
        let details = vuln
            .get("details")
            .and_then(Value::as_str)
            .unwrap_or(summary);

        let severity = Self::severity(vuln, entry, id);
        let aliases = Self::aliases(vuln);
        let fixed = Self::first_fixed_version(vuln);

        let component = if ecosystem.is_empty() {
            format!("{source} ({name}@{version})")
        } else {
            format!("{source} ({ecosystem}: {name}@{version})")
        };

        let remediation = match &fixed {
            Some(v) => format!(
                "Upgrade `{name}` to {v} or later. Check the advisory first — a fixed version \
                 solves this CVE but may itself be affected by a later one, and a range-based \
                 advisory can list several fixed versions across different release lines.\n\n\
                 ```\n{}\n```",
                Self::upgrade_command(ecosystem, name, v)
            ),
            None => format!(
                "No fixed version is published for `{name}` yet. Until one exists, the options are \
                 to pin to an unaffected earlier release, apply the advisory's stated workaround, \
                 or replace the dependency. Confirm whether the vulnerable code path is reachable \
                 from your application before treating this as urgent — a vulnerability in an \
                 unused function of a dependency is still worth fixing, but it is not an incident."
            ),
        };

        let mut references: Vec<String> = vuln
            .get("references")
            .and_then(Value::as_array)
            .map(|refs| {
                refs.iter()
                    .filter_map(|r| r.get("url").and_then(Value::as_str).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        references.push(format!("https://osv.dev/vulnerability/{id}"));
        references.truncate(8);

        let title = if aliases.is_empty() {
            format!("{id}: {summary}")
        } else {
            format!("{id} ({}): {summary}", aliases.join(", "))
        };

        ExternalFinding::new(title, severity, component, "OSV-Scanner")
            .description(format!(
                "{details}\n\nDeclared in {source} as {name}@{version}."
            ))
            .remediation(remediation)
            .taxonomy(
                "CWE-1395",
                "A03:2025-Software Supply Chain Failures",
                Some("WSTG-CONF-01"),
            )
            .references(references)
            .repro(vec![format!("osv-scanner --lockfile {source}")])
            .evidence(
                "dependency_lock",
                &format!("Advisory {id}"),
                &format!(
                    "Package:   {name}\nVersion:   {version}\nEcosystem: {}\nSource:    {source}\nFixed in:  {}",
                    if ecosystem.is_empty() { "unknown" } else { ecosystem },
                    fixed.as_deref().unwrap_or("no fix published"),
                ),
            )
            // A declared version matched against a database is a fact. What it
            // does not establish is whether the vulnerable path is reachable,
            // which is the usual reason an SCA finding turns out not to matter.
            .confidence(
                0.10,
                "The dependency version is a fact from the lockfile. Whether the vulnerable code \
                 path is reachable from your application is not established by this check.",
            )
            .reachability(0.8)
    }

    /// OSV reports severity in several places depending on the advisory source.
    fn severity(vuln: &Value, entry: &Value, id: &str) -> Severity {
        // 1. A database-specific severity string.
        if let Some(label) = vuln
            .pointer("/database_specific/severity")
            .and_then(Value::as_str)
        {
            return severity_from_label(label);
        }
        // 2. The grouped severity the scanner computes per package.
        if let Some(label) = entry
            .pointer("/groups/0/max_severity")
            .and_then(Value::as_str)
        {
            if let Ok(score) = label.parse::<f64>() {
                return Self::severity_from_score(score);
            }
            return severity_from_label(label);
        }
        // 3. A CVSS vector's own band, when one is attached.
        if let Some(score) = vuln
            .get("severity")
            .and_then(Value::as_array)
            .and_then(|s| s.first())
            .and_then(|s| s.get("score"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<f64>().ok())
        {
            return Self::severity_from_score(score);
        }
        // A withdrawn or unscored advisory still describes a real dependency
        // problem; Medium keeps it visible without overstating it.
        let _ = id;
        Severity::Medium
    }

    fn severity_from_score(score: f64) -> Severity {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s > 0.0 => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// CVE and GHSA identifiers the advisory is also known by.
    fn aliases(vuln: &Value) -> Vec<String> {
        vuln.get("aliases")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .filter(|s| s.starts_with("CVE-"))
                    .take(3)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The first version an advisory says the problem is fixed in.
    fn first_fixed_version(vuln: &Value) -> Option<String> {
        vuln.get("affected")
            .and_then(Value::as_array)?
            .iter()
            .filter_map(|affected| affected.get("ranges").and_then(Value::as_array))
            .flatten()
            .filter_map(|range| range.get("events").and_then(Value::as_array))
            .flatten()
            .find_map(|event| event.get("fixed").and_then(Value::as_str))
            .map(str::to_string)
    }

    /// The command that actually performs the upgrade, per ecosystem.
    fn upgrade_command(ecosystem: &str, name: &str, version: &str) -> String {
        match ecosystem.to_ascii_lowercase().as_str() {
            "npm" => format!("npm install {name}@{version}"),
            "pypi" => format!("pip install --upgrade '{name}=={version}'"),
            "go" => format!("go get {name}@v{}", version.trim_start_matches('v')),
            "crates.io" => format!("cargo update -p {name} --precise {version}"),
            "rubygems" => format!("bundle update {name}"),
            "packagist" => format!("composer require {name}:^{version}"),
            "maven" => format!("<!-- set the {name} dependency version to {version} -->"),
            "nuget" => format!("dotnet add package {name} --version {version}"),
            _ => format!("Upgrade {name} to {version} using this ecosystem's package manager"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "results": [{
        "source": { "path": "/repo/package-lock.json", "type": "lockfile" },
        "packages": [{
          "package": { "name": "lodash", "version": "4.17.15", "ecosystem": "npm" },
          "vulnerabilities": [{
            "id": "GHSA-p6mc-m468-83gg",
            "aliases": ["CVE-2020-8203"],
            "summary": "Prototype pollution in lodash",
            "details": "Versions before 4.17.19 are vulnerable to prototype pollution.",
            "affected": [{
              "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "0" }, { "fixed": "4.17.19" }] }]
            }],
            "references": [{ "type": "ADVISORY", "url": "https://github.com/advisories/GHSA-p6mc-m468-83gg" }],
            "database_specific": { "severity": "HIGH" }
          }]
        }],
        "groups": [{ "max_severity": "7.4" }]
      }]
    }"#;

    #[test]
    fn a_vulnerable_dependency_is_parsed_with_its_taxonomy() {
        let out = OsvScannerParser::parse(SAMPLE, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out.len(), 1);

        let f = &out[0];
        assert!(f.title.contains("GHSA-p6mc-m468-83gg"));
        assert!(f.title.contains("CVE-2020-8203"), "the CVE alias belongs in the title: {}", f.title);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-1395"));
        assert_eq!(f.owasp_2025.as_deref(), Some("A03:2025-Software Supply Chain Failures"));
        assert!(f.affected_component.contains("lodash@4.17.15"));
        assert!(f.affected_component.contains("npm"));
    }

    #[test]
    fn the_fix_is_an_actual_command_for_the_right_ecosystem() {
        let out = OsvScannerParser::parse(SAMPLE, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].remediation.contains("npm install lodash@4.17.19"), "{}", out[0].remediation);
        assert!(out[0].remediation.contains("```"), "the command must be fenced for the report");
    }

    #[test]
    fn upgrade_commands_are_written_per_ecosystem() {
        assert!(OsvScannerParser::upgrade_command("PyPI", "requests", "2.32.0").starts_with("pip install"));
        assert!(OsvScannerParser::upgrade_command("Go", "golang.org/x/net", "0.23.0").starts_with("go get"));
        assert!(OsvScannerParser::upgrade_command("crates.io", "time", "0.3.36").starts_with("cargo update"));
        assert!(OsvScannerParser::upgrade_command("weird", "x", "1").contains("package manager"));
    }

    /// An SCA finding is a fact about a lockfile, not proof the vulnerable path
    /// runs. The report has to say which of those it is claiming.
    #[test]
    fn the_finding_declares_what_it_does_and_does_not_establish() {
        let out = OsvScannerParser::parse(SAMPLE, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        let note = out[0].ai_triage.as_ref().unwrap().triage_notes.as_deref().unwrap();
        assert!(note.contains("reachable"), "{note}");
        assert!(out[0].cvss4.is_none(), "OSV supplied no CVSS 4.0 vector, so none may be claimed");
    }

    #[test]
    fn an_advisory_with_no_fix_says_so_rather_than_inventing_a_version() {
        let json = SAMPLE.replace(r#", { "fixed": "4.17.19" }"#, "");
        let out = OsvScannerParser::parse(&json, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].remediation.contains("No fixed version is published"), "{}", out[0].remediation);
        assert!(!out[0].remediation.contains("npm install"));
    }

    #[test]
    fn severity_falls_back_through_the_places_osv_reports_it() {
        let no_db_specific = SAMPLE.replace(r#", "database_specific": { "severity": "HIGH" }"#, "");
        let out = OsvScannerParser::parse(&no_db_specific, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out[0].severity, Severity::High, "7.4 from the group's max_severity is High");
    }

    #[test]
    fn an_unscored_advisory_stays_visible_rather_than_vanishing() {
        let json = r#"{"results":[{"source":{"path":"go.mod"},"packages":[{
            "package":{"name":"x","version":"1.0.0","ecosystem":"Go"},
            "vulnerabilities":[{"id":"OSV-1","summary":"s"}]}]}]}"#;
        let out = OsvScannerParser::parse(json, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Medium);
    }

    #[test]
    fn a_clean_scan_produces_nothing() {
        for json in [r#"{"results":[]}"#, "{}", r#"{"results":[{"source":{"path":"x"},"packages":[]}]}"#] {
            assert!(OsvScannerParser::parse(json, Uuid::new_v4(), Uuid::new_v4()).unwrap().is_empty());
        }
    }

    #[test]
    fn malformed_json_is_an_error_not_a_silent_empty_result() {
        assert!(OsvScannerParser::parse("not json", Uuid::new_v4(), Uuid::new_v4()).is_err());
    }
}
