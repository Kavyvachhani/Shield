//! Nikto output.
//!
//! Nikto is the oldest tool in this pipeline and still finds things the others
//! do not: forgotten CGI scripts, sample and default files shipped by a server
//! package, admin panels on non-obvious paths, and server software with known
//! problems. It carries several thousand path and banner checks accumulated
//! over two decades, which is coverage nobody is going to reproduce.
//!
//! It is also the noisiest tool here, and this parser is written around that.
//! Nikto reports observations at a single flat severity with no notion of
//! confidence, so severity is derived from what the observation actually is,
//! and everything is marked as needing confirmation. A Nikto run pasted
//! verbatim into a client report is how a VAPT deliverable loses its
//! credibility; the value is in the leads, not in the raw list.

use super::external::ExternalFinding;
use crate::models::finding::{Finding, Severity};
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

pub struct NiktoParser;

impl NiktoParser {
    /// Parse `nikto -Format json` output.
    pub fn parse(raw_json: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let root: Value = serde_json::from_str(raw_json)?;
        let mut findings = Vec::new();

        // Nikto wraps results in a host object, or emits an array of them when
        // several hosts were scanned.
        let hosts: Vec<&Value> = match root.as_array() {
            Some(list) => list.iter().collect(),
            None => vec![&root],
        };

        for host in hosts {
            let target_host = host
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("the assessed host");

            let Some(items) = host.get("vulnerabilities").and_then(Value::as_array) else {
                continue;
            };

            for item in items {
                findings.push(Self::finding(item, target_host).into_finding(target_id, scan_id));
            }
        }

        Ok(findings)
    }

    fn finding(item: &Value, host: &str) -> ExternalFinding {
        let message = item
            .get("msg")
            .and_then(Value::as_str)
            .unwrap_or("Observation reported by Nikto");
        let uri = item.get("url").and_then(Value::as_str).unwrap_or("/");
        let method = item.get("method").and_then(Value::as_str).unwrap_or("GET");
        let test_id = item.get("id").and_then(Value::as_str).unwrap_or("");

        let (severity, cwe, owasp, wstg) = Self::classify(message);
        let component = if uri.starts_with("http") {
            uri.to_string()
        } else {
            format!("{}{uri}", host.trim_end_matches('/'))
        };

        let references = item
            .get("references")
            .and_then(Value::as_str)
            .filter(|r| !r.trim().is_empty())
            .map(|r| vec![r.to_string()])
            .unwrap_or_else(|| vec!["https://github.com/sullo/nikto/wiki".to_string()]);

        ExternalFinding::new(
            format!("{}: {}", Self::headline(&severity), Self::truncate(message, 120)),
            severity,
            component.clone(),
            "Nikto",
        )
        .description(format!(
            "{message}\n\nNikto reached this over {method} {uri}. Nikto matches paths and banners \
             against a large historical signature set, so a result is a lead rather than a \
             confirmed weakness: a catch-all route that answers 200 to everything, a reverse proxy \
             that rewrites paths, or a deliberately published file will all produce one. Confirm by \
             requesting the URL yourself and reading what comes back before scheduling work."
        ))
        .remediation(
            "Request the URL and decide what it actually is. If it is a leftover sample file, an \
             unused CGI script or a default page from the server package, delete it — those exist \
             only because a package installed them and nobody removed them. If it is a real \
             administrative surface, put it behind authentication and restrict it by network. If \
             it is expected and intentionally public, dismiss it as a false positive so it does \
             not return in the next report.",
        )
        .taxonomy(cwe, owasp, Some(wstg))
        .references(references)
        .repro(vec![format!("curl -sSI '{component}'")])
        .evidence(
            "http_response",
            "Nikto observation",
            &format!(
                "Test ID:  {}\nRequest:  {method} {uri}\nHost:     {host}\nMessage:  {message}",
                if test_id.is_empty() { "not reported" } else { test_id }
            ),
        )
        // The highest false-positive rate of any engine in the pipeline, and
        // the developer report's confidence panel should say so plainly.
        .confidence(
            0.45,
            "Nikto matches paths and banners against a historical signature set and does not \
             confirm what it finds. Verify the URL by hand before acting on it.",
        )
        .reachability(0.9)
    }

    /// Derive a severity and taxonomy from what the observation describes.
    ///
    /// Nikto reports everything at one flat level, so passing its output
    /// through unchanged would rank a missing header identically to an exposed
    /// administrative interface.
    fn classify(message: &str) -> (Severity, &'static str, &'static str, &'static str) {
        const MISCONFIG: &str = "A02:2025-Security Misconfiguration";
        const ACCESS: &str = "A01:2025-Broken Access Control";
        let lower = message.to_ascii_lowercase();

        if lower.contains("remote code") || lower.contains("shell") || lower.contains("rce") {
            (Severity::Critical, "CWE-94", "A05:2025-Injection", "WSTG-INPV-12")
        } else if lower.contains("sql injection") {
            (Severity::Critical, "CWE-89", "A05:2025-Injection", "WSTG-INPV-05")
        } else if lower.contains("traversal") || lower.contains("../") {
            (Severity::High, "CWE-22", ACCESS, "WSTG-ATHZ-01")
        } else if lower.contains("admin") || lower.contains("phpmyadmin") || lower.contains("manager") {
            (Severity::High, "CWE-284", ACCESS, "WSTG-CONF-05")
        } else if lower.contains("password") || lower.contains("credential") || lower.contains("backup") {
            (Severity::High, "CWE-530", MISCONFIG, "WSTG-CONF-04")
        } else if lower.contains("default") || lower.contains("sample") || lower.contains("test file") {
            (Severity::Medium, "CWE-1188", MISCONFIG, "WSTG-CONF-02")
        } else if lower.contains("directory indexing") || lower.contains("directory listing") {
            (Severity::Medium, "CWE-548", MISCONFIG, "WSTG-CONF-04")
        } else if lower.contains("outdated") || lower.contains("appears to be") && lower.contains("version") {
            (Severity::Medium, "CWE-1395", "A03:2025-Software Supply Chain Failures", "WSTG-CONF-01")
        } else if lower.contains("header") || lower.contains("x-frame") || lower.contains("cookie") {
            (Severity::Low, "CWE-693", MISCONFIG, "WSTG-CONF-12")
        } else {
            (Severity::Info, "CWE-200", MISCONFIG, "WSTG-INFO-02")
        }
    }

    fn headline(severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical | Severity::High => "Exposed surface",
            Severity::Medium => "Server misconfiguration",
            Severity::Low => "Hardening gap",
            Severity::Info => "Server observation",
        }
    }

    fn truncate(s: &str, max: usize) -> String {
        if s.chars().count() <= max {
            return s.to_string();
        }
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_json(msg: &str) -> String {
        format!(
            r#"{{"host":"https://app.test","vulnerabilities":[
                {{"id":"999990","method":"GET","url":"/admin/","msg":"{msg}"}}]}}"#
        )
    }

    /// Nikto reports everything at one flat level. Passing that through would
    /// rank a missing header identically to an exposed admin console.
    #[test]
    fn severity_is_derived_from_what_the_observation_describes() {
        let cases = [
            ("Remote code execution possible in cgi-bin", Severity::Critical),
            ("Directory traversal found via ../", Severity::High),
            ("/phpmyadmin/: phpMyAdmin directory found", Severity::High),
            ("backup.sql: Database backup found", Severity::High),
            ("Default Apache sample file present", Severity::Medium),
            ("Directory indexing found", Severity::Medium),
            ("The X-Frame-Options header is not present", Severity::Low),
            ("Server leaks inodes via ETags", Severity::Info),
        ];
        for (msg, expected) in cases {
            let out = NiktoParser::parse(&host_json(msg), Uuid::new_v4(), Uuid::new_v4()).unwrap();
            assert_eq!(out[0].severity, expected, "misclassified: {msg}");
        }
    }

    /// A Nikto run pasted verbatim into a client report is how a deliverable
    /// loses credibility. Every finding has to carry that caveat.
    #[test]
    fn every_observation_is_marked_as_needing_confirmation() {
        let out = NiktoParser::parse(&host_json("Directory indexing found"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        let triage = out[0].ai_triage.as_ref().unwrap();
        assert!(triage.is_false_positive_confidence >= 0.4, "Nikto is the noisiest engine here");
        assert!(triage.triage_notes.as_deref().unwrap().contains("Verify the URL by hand"));
        assert!(out[0].description.contains("a lead rather than a"));
    }

    #[test]
    fn the_taxonomy_follows_the_classification() {
        let out = NiktoParser::parse(&host_json("SQL injection in /search"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out[0].cwe_id.as_deref(), Some("CWE-89"));
        assert_eq!(out[0].owasp_2025.as_deref(), Some("A05:2025-Injection"));
        assert_eq!(out[0].wstg_id.as_deref(), Some("WSTG-INPV-05"));
    }

    #[test]
    fn a_relative_url_is_resolved_against_the_host() {
        let out = NiktoParser::parse(&host_json("Directory indexing found"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out[0].affected_component, "https://app.test/admin/");
    }

    #[test]
    fn the_fix_includes_dismissing_it_when_the_finding_is_expected() {
        let out = NiktoParser::parse(&host_json("Directory indexing found"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].remediation.contains("dismiss it as a false positive"));
    }

    #[test]
    fn several_scanned_hosts_all_parse() {
        let json = format!("[{},{}]", host_json("A"), host_json("B"));
        assert_eq!(NiktoParser::parse(&json, Uuid::new_v4(), Uuid::new_v4()).unwrap().len(), 2);
    }

    #[test]
    fn a_clean_scan_produces_nothing() {
        assert!(NiktoParser::parse(r#"{"host":"x","vulnerabilities":[]}"#, Uuid::new_v4(), Uuid::new_v4())
            .unwrap()
            .is_empty());
    }
}
