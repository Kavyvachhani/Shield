//! SARIF 2.1.0 import.
//!
//! SARIF is the interchange format the industry actually settled on: CodeQL,
//! Snyk, Checkmarx, Grype, ESLint, .NET analysers and GitHub code scanning all
//! emit it. Reading it means this tool is not limited to the engines it happens
//! to ship adapters for — anything that produces a SARIF file can be brought
//! into the same deduplicated, ranked, exception-aware report.
//!
//! That matters more than another built-in check. A client already running
//! CodeQL in CI does not want a second report; they want their existing results
//! ranked alongside everything else, with the same exceptions applied.
//!
//! ## Reading what SARIF actually carries
//!
//! A result is deliberately thin — it points at a rule. The description, the
//! remediation guidance, the help URI and the taxonomy live in
//! `tool.driver.rules[]`, and a parser that reads only the result throws all of
//! that away and produces a finding saying "rule X was violated", which is
//! useless to whoever has to fix it. The rules table is resolved here, by
//! `ruleId` and by `ruleIndex`, because producers use both.

use super::external::ExternalFinding;
use crate::models::finding::{Finding, Severity};
use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

pub struct SarifParser;

impl SarifParser {
    /// Parse a SARIF 2.1.0 log.
    pub fn parse(raw_json: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let log: Value = serde_json::from_str(raw_json)?;
        let mut findings = Vec::new();

        let Some(runs) = log.get("runs").and_then(Value::as_array) else {
            return Ok(findings);
        };

        for run in runs {
            let tool = run
                .pointer("/tool/driver/name")
                .and_then(Value::as_str)
                .unwrap_or("SARIF import");

            // Resolve the rules table once per run, keyed both ways: producers
            // reference rules by id and by index, and some emit both.
            let rules_array = run
                .pointer("/tool/driver/rules")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let by_id: HashMap<&str, &Value> = rules_array
                .iter()
                .filter_map(|r| r.get("id").and_then(Value::as_str).map(|id| (id, r)))
                .collect();

            let Some(results) = run.get("results").and_then(Value::as_array) else {
                continue;
            };

            for result in results {
                let rule = Self::resolve_rule(result, &by_id, &rules_array);
                findings.push(
                    Self::finding(result, rule, tool).into_finding(target_id, scan_id),
                );
            }
        }

        Ok(findings)
    }

    /// The rule a result refers to, by id or by index.
    fn resolve_rule<'a>(
        result: &Value,
        by_id: &HashMap<&str, &'a Value>,
        rules: &'a [Value],
    ) -> Option<&'a Value> {
        if let Some(id) = result.get("ruleId").and_then(Value::as_str) {
            if let Some(rule) = by_id.get(id) {
                return Some(rule);
            }
        }
        result
            .get("ruleIndex")
            .and_then(Value::as_u64)
            .and_then(|i| rules.get(i as usize))
    }

    fn finding(result: &Value, rule: Option<&Value>, tool: &str) -> ExternalFinding {
        let rule_id = result
            .get("ruleId")
            .and_then(Value::as_str)
            .or_else(|| rule.and_then(|r| r.get("id")).and_then(Value::as_str))
            .unwrap_or("unnamed rule");

        let message = result
            .pointer("/message/text")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                rule.and_then(|r| r.pointer("/shortDescription/text"))
                    .and_then(Value::as_str)
                    .unwrap_or("Finding reported without a message")
            });

        let severity = Self::severity(result, rule);
        let component = Self::location(result);
        let (cwe, owasp) = Self::taxonomy(rule, rule_id);

        // The rule's own long description, which is where a producer puts the
        // explanation worth reading.
        let detail = rule
            .and_then(|r| r.pointer("/fullDescription/text"))
            .and_then(Value::as_str)
            .filter(|d| d.trim() != message)
            .map(|d| format!("\n\n{d}"))
            .unwrap_or_default();

        // And its help text, which is where the remediation guidance lives.
        let help = rule
            .and_then(|r| {
                r.pointer("/help/markdown")
                    .or_else(|| r.pointer("/help/text"))
            })
            .and_then(Value::as_str)
            .map(str::to_string);

        let help_uri = rule
            .and_then(|r| r.get("helpUri"))
            .and_then(Value::as_str)
            .map(str::to_string);

        let remediation = match help {
            Some(text) => text,
            None => format!(
                "No remediation guidance was included for `{rule_id}` in the imported file. \
                 Consult {}'s documentation for this rule — SARIF carries guidance in the rule's \
                 `help` field, and a producer that omits it leaves the reader to look it up.",
                tool
            ),
        };

        let mut references: Vec<String> = Vec::new();
        if let Some(uri) = help_uri {
            references.push(uri);
        }
        if let Some(cwe) = cwe.as_deref() {
            if let Some(number) = cwe.strip_prefix("CWE-") {
                references.push(format!("https://cwe.mitre.org/data/definitions/{number}.html"));
            }
        }

        let mut finding = ExternalFinding::new(
            format!("{rule_id}: {}", Self::truncate(message, 140)),
            severity,
            component.clone(),
            tool.to_string(),
        )
        .description(format!("{message}{detail}"))
        .remediation(remediation)
        .references(references)
        .repro(vec![format!("Review {component}")])
        .evidence(
            "sarif_result",
            &format!("SARIF result for {rule_id}"),
            &serde_json::to_string_pretty(result).unwrap_or_default(),
        )
        // Imported from another tool's own output: this engine cannot judge how
        // reliable that producer is, and pretending otherwise would attach a
        // confidence figure to a claim it did not make.
        .confidence(
            0.20,
            format!(
                "Imported from {tool}'s own SARIF output. The severity and rule are as that tool \
                 reported them — this engine did not verify the finding independently."
            ),
        )
        // Almost every SARIF producer is a static analyser, so the vulnerable
        // path is matched rather than observed running.
        .reachability(0.8);

        if let Some(cwe) = cwe {
            finding = finding.taxonomy(cwe, owasp, None);
        } else {
            finding.owasp_2025 = Some(owasp.to_string());
        }
        finding
    }

    /// Severity, preferring the numeric score producers attach over the coarse
    /// SARIF level.
    ///
    /// `security-severity` is the convention GitHub code scanning established
    /// and most security producers now emit; it carries a CVSS-style number,
    /// where `level` only distinguishes error from warning from note.
    fn severity(result: &Value, rule: Option<&Value>) -> Severity {
        let score = result
            .pointer("/properties/security-severity")
            .or_else(|| rule.and_then(|r| r.pointer("/properties/security-severity")))
            .and_then(|v| {
                v.as_f64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
            });

        if let Some(score) = score {
            return match score {
                s if s >= 9.0 => Severity::Critical,
                s if s >= 7.0 => Severity::High,
                s if s >= 4.0 => Severity::Medium,
                s if s > 0.0 => Severity::Low,
                _ => Severity::Info,
            };
        }

        let level = result
            .get("level")
            .and_then(Value::as_str)
            .or_else(|| {
                rule.and_then(|r| r.pointer("/defaultConfiguration/level"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("warning");

        match level {
            "error" => Severity::High,
            "warning" => Severity::Medium,
            "note" => Severity::Low,
            "none" => Severity::Info,
            _ => Severity::Medium,
        }
    }

    /// CWE and OWASP category, from the rule's tags where the producer set them.
    ///
    /// The `tags` array is where SARIF producers put taxonomy, conventionally as
    /// `external/cwe/cwe-89` or plain `CWE-89`.
    fn taxonomy(rule: Option<&Value>, rule_id: &str) -> (Option<String>, &'static str) {
        const SUPPLY_CHAIN: &str = "A03:2025-Software Supply Chain Failures";
        const MISCONFIG: &str = "A02:2025-Security Misconfiguration";

        let tags: Vec<String> = rule
            .and_then(|r| r.pointer("/properties/tags"))
            .and_then(Value::as_array)
            .map(|t| {
                t.iter()
                    .filter_map(Value::as_str)
                    .map(|s| s.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();

        // The rule id itself is sometimes the CWE.
        let mut cwe = if rule_id.to_ascii_uppercase().starts_with("CWE-") {
            Some(rule_id.to_ascii_uppercase())
        } else {
            None
        };

        if cwe.is_none() {
            cwe = tags.iter().find_map(|tag| {
                let at = tag.find("cwe-")?;
                let digits: String = tag[at + 4..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                (!digits.is_empty()).then(|| format!("CWE-{digits}"))
            });
        }

        // Map the CWE to a Top 10 category where the mapping is unambiguous, so
        // imported findings are not invisible in the rollup.
        let owasp = match cwe.as_deref() {
            Some("CWE-89") | Some("CWE-79") | Some("CWE-78") | Some("CWE-94")
            | Some("CWE-77") | Some("CWE-917") => "A05:2025-Injection",
            Some("CWE-22") | Some("CWE-284") | Some("CWE-285") | Some("CWE-639")
            | Some("CWE-918") => "A01:2025-Broken Access Control",
            Some("CWE-798") | Some("CWE-259") | Some("CWE-327") | Some("CWE-311")
            | Some("CWE-319") | Some("CWE-326") => "A04:2025-Cryptographic Failures",
            Some("CWE-1395") | Some("CWE-1104") => SUPPLY_CHAIN,
            Some("CWE-502") | Some("CWE-353") | Some("CWE-345") => {
                "A08:2025-Software or Data Integrity Failures"
            }
            Some("CWE-287") | Some("CWE-306") | Some("CWE-384") => "A07:2025-Authentication Failures",
            Some("CWE-209") | Some("CWE-248") => "A10:2025-Mishandling of Exceptional Conditions",
            Some("CWE-778") | Some("CWE-532") => "A09:2025-Security Logging and Alerting Failures",
            // Unmapped CWEs and untagged rules land in misconfiguration rather
            // than nowhere: a finding missing from the rollup entirely is worse
            // than one in a broad category.
            _ => MISCONFIG,
        };

        (cwe, owasp)
    }

    /// Where the finding is, as precisely as the result records.
    fn location(result: &Value) -> String {
        let uri = result
            .pointer("/locations/0/physicalLocation/artifactLocation/uri")
            .and_then(Value::as_str)
            .unwrap_or("location not recorded");

        match result
            .pointer("/locations/0/physicalLocation/region/startLine")
            .and_then(Value::as_u64)
        {
            Some(line) => format!("{uri}:{line}"),
            None => uri.to_string(),
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

    const CODEQL: &str = r#"{
      "version": "2.1.0",
      "runs": [{
        "tool": { "driver": {
          "name": "CodeQL",
          "rules": [{
            "id": "js/sql-injection",
            "shortDescription": { "text": "Database query built from user-controlled sources" },
            "fullDescription": { "text": "Building a database query from user-controlled data allows an attacker to change the query's meaning." },
            "help": { "markdown": "Use a parameterised query. Never concatenate user input into SQL." },
            "helpUri": "https://codeql.github.com/codeql-query-help/javascript/js-sql-injection/",
            "properties": { "tags": ["security", "external/cwe/cwe-089"], "security-severity": "8.8" }
          }]
        }},
        "results": [{
          "ruleId": "js/sql-injection",
          "ruleIndex": 0,
          "level": "error",
          "message": { "text": "This query depends on a user-provided value." },
          "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": "src/db/orders.js" },
            "region": { "startLine": 42 }
          }}]
        }]
      }]
    }"#;

    /// A parser that reads only the result produces "rule X was violated",
    /// which is useless to whoever has to fix it. Everything worth reading is
    /// in the rules table.
    #[test]
    fn the_rule_definition_is_resolved_and_its_guidance_carried_through() {
        let out = SarifParser::parse(CODEQL, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];

        assert!(f.title.contains("js/sql-injection"));
        assert!(f.description.contains("change the query's meaning"), "the full description must survive");
        assert!(f.remediation.contains("parameterised query"), "the rule's own guidance is the remediation");
        assert!(
            f.references.iter().any(|r| r.contains("codeql.github.com")),
            "the helpUri belongs in references: {:?}",
            f.references
        );
    }

    /// `level` only says error/warning/note. `security-severity` carries the
    /// number, and it is what security producers actually emit.
    #[test]
    fn a_numeric_security_severity_outranks_the_coarse_level() {
        let out = SarifParser::parse(CODEQL, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(
            out[0].severity,
            Severity::High,
            "8.8 is High; the level 'error' would also be High but for the wrong reason"
        );

        let critical = CODEQL.replace(r#""security-severity": "8.8""#, r#""security-severity": "9.4""#);
        let out = SarifParser::parse(&critical, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out[0].severity, Severity::Critical, "the level alone could never reach Critical");
    }

    #[test]
    fn the_level_is_used_when_no_score_is_supplied() {
        let no_score = CODEQL.replace(r#", "security-severity": "8.8""#, "");
        let out = SarifParser::parse(&no_score, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out[0].severity, Severity::High, "level 'error' maps to High");
    }

    /// An imported finding with no OWASP category is invisible in the rollup,
    /// which is where a client reconciles the report against their programme.
    #[test]
    fn cwe_tags_become_a_cwe_and_an_owasp_category() {
        let out = SarifParser::parse(CODEQL, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out[0].cwe_id.as_deref(), Some("CWE-089"));
        assert_eq!(out[0].owasp_2025.as_deref(), Some("A02:2025-Security Misconfiguration"));
    }

    #[test]
    fn a_recognised_cwe_maps_to_its_top_ten_category() {
        let (cwe, owasp) = SarifParser::taxonomy(None, "CWE-89");
        assert_eq!(cwe.as_deref(), Some("CWE-89"));
        assert_eq!(owasp, "A05:2025-Injection");

        assert_eq!(SarifParser::taxonomy(None, "CWE-798").1, "A04:2025-Cryptographic Failures");
        assert_eq!(SarifParser::taxonomy(None, "CWE-22").1, "A01:2025-Broken Access Control");
    }

    /// A finding missing from the rollup entirely is worse than one in a broad
    /// category.
    #[test]
    fn an_untagged_rule_still_lands_somewhere_in_the_rollup() {
        let json = r#"{"runs":[{"tool":{"driver":{"name":"Some Linter"}},
            "results":[{"ruleId":"x/y","message":{"text":"m"}}]}]}"#;
        let out = SarifParser::parse(json, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].owasp_2025.is_some(), "every imported finding needs a category");
        assert!(out[0].cwe_id.is_none(), "but a CWE must not be invented");
    }

    /// Producers reference rules by id and by index; some emit only one.
    #[test]
    fn a_rule_is_resolvable_by_index_when_the_id_does_not_match() {
        let json = r#"{"runs":[{"tool":{"driver":{"name":"T","rules":[
            {"id":"actual-id","help":{"text":"Fix it this way."}}]}},
            "results":[{"ruleIndex":0,"message":{"text":"m"}}]}]}"#;
        let out = SarifParser::parse(json, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].remediation.contains("Fix it this way."), "{}", out[0].remediation);
    }

    #[test]
    fn the_location_carries_the_file_and_line() {
        let out = SarifParser::parse(CODEQL, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out[0].affected_component, "src/db/orders.js:42");
    }

    /// This engine cannot judge how reliable another producer is, and attaching
    /// a confidence it did not earn would be inventing one.
    #[test]
    fn an_imported_finding_says_it_was_not_independently_verified() {
        let out = SarifParser::parse(CODEQL, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        let note = out[0].ai_triage.as_ref().unwrap().triage_notes.as_deref().unwrap();
        assert!(note.contains("did not verify the finding independently"), "{note}");
        assert_eq!(out[0].source_tools, vec!["CodeQL".to_string()], "the producer is credited");
    }

    #[test]
    fn a_producer_that_omits_guidance_says_so_rather_than_inventing_advice() {
        let json = r#"{"runs":[{"tool":{"driver":{"name":"Terse Tool"}},
            "results":[{"ruleId":"r1","message":{"text":"m"}}]}]}"#;
        let out = SarifParser::parse(json, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].remediation.contains("No remediation guidance was included"));
        assert!(out[0].remediation.contains("Terse Tool"));
    }

    #[test]
    fn several_runs_in_one_log_all_parse() {
        let json = format!(
            r#"{{"runs":[{},{}]}}"#,
            r#"{"tool":{"driver":{"name":"A"}},"results":[{"ruleId":"a","message":{"text":"m"}}]}"#,
            r#"{"tool":{"driver":{"name":"B"}},"results":[{"ruleId":"b","message":{"text":"m"}}]}"#,
        );
        let out = SarifParser::parse(&json, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out.len(), 2);
        assert_ne!(out[0].source_tools, out[1].source_tools);
    }

    #[test]
    fn a_clean_log_produces_nothing() {
        for json in [r#"{"runs":[]}"#, r#"{"version":"2.1.0"}"#,
                     r#"{"runs":[{"tool":{"driver":{"name":"T"}},"results":[]}]}"#] {
            assert!(SarifParser::parse(json, Uuid::new_v4(), Uuid::new_v4()).unwrap().is_empty());
        }
    }

    #[test]
    fn a_file_that_is_not_sarif_is_an_error_rather_than_a_silent_pass() {
        assert!(SarifParser::parse("<html>", Uuid::new_v4(), Uuid::new_v4()).is_err());
    }
}
