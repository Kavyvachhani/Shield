//! Checkov output.
//!
//! Every other engine in this pipeline looks at the application. Checkov looks
//! at what the application is deployed *onto*: the Terraform, CloudFormation,
//! Kubernetes manifests, Helm charts and Dockerfiles that decide whether the
//! storage bucket is public, whether the database is reachable from the
//! internet, whether the container runs as root, and whether anything is
//! encrypted at rest.
//!
//! That gap matters because the findings on either side of it have completely
//! different blast radii. A cross-site scripting flaw affects the users who
//! click the link; a security group open to `0.0.0.0/0` on port 5432 affects
//! the whole database, and no amount of application hardening compensates for
//! it. An assessment that reads the code but not the infrastructure is
//! answering half the question.
//!
//! Checkov only runs when the repository actually contains IaC. On a target
//! with none it exits cleanly having found nothing, which is a correct result
//! rather than a failure.

use super::external::ExternalFinding;
use crate::models::finding::{Finding, Severity};
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

pub struct CheckovParser;

impl CheckovParser {
    /// Parse `checkov --output json` output.
    pub fn parse(raw_json: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let root: Value = serde_json::from_str(raw_json)?;
        let mut findings = Vec::new();

        // Checkov emits one object per framework it detected, or a single
        // object when only one applies. Both shapes are normal output.
        let runs: Vec<&Value> = match root.as_array() {
            Some(list) => list.iter().collect(),
            None => vec![&root],
        };

        for run in runs {
            let check_type = run
                .get("check_type")
                .and_then(Value::as_str)
                .unwrap_or("infrastructure");

            let Some(failed) = run
                .pointer("/results/failed_checks")
                .and_then(Value::as_array)
            else {
                continue;
            };

            for check in failed {
                findings.push(Self::finding(check, check_type).into_finding(target_id, scan_id));
            }
        }

        Ok(findings)
    }

    fn finding(check: &Value, framework: &str) -> ExternalFinding {
        let check_id = check.get("check_id").and_then(Value::as_str).unwrap_or("CKV-UNKNOWN");
        let name = check
            .get("check_name")
            .and_then(Value::as_str)
            .unwrap_or("Infrastructure misconfiguration");
        let file = check
            .get("file_path")
            .and_then(Value::as_str)
            .unwrap_or("infrastructure definition");
        let resource = check
            .get("resource")
            .and_then(Value::as_str)
            .unwrap_or("unknown resource");
        let guideline = check.get("guideline").and_then(Value::as_str);

        let line = check
            .pointer("/file_line_range/0")
            .and_then(Value::as_i64);
        let component = match line {
            Some(l) => format!("{file}:{l} ({resource})"),
            None => format!("{file} ({resource})"),
        };

        let severity = Self::severity(check, name);
        let (cwe, owasp) = Self::taxonomy(name);

        let mut references = vec![
            "https://www.checkov.io/5.Policy%20Index/all.html".to_string(),
        ];
        if let Some(g) = guideline {
            references.insert(0, g.to_string());
        }

        let code_block = check
            .get("code_block")
            .and_then(Value::as_array)
            .map(|lines| {
                lines
                    .iter()
                    .filter_map(|entry| {
                        let arr = entry.as_array()?;
                        let number = arr.first()?.as_i64()?;
                        let text = arr.get(1)?.as_str()?;
                        Some(format!("{number:>5} | {}", text.trim_end()))
                    })
                    .take(30)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .filter(|s| !s.is_empty());

        let mut finding = ExternalFinding::new(
            format!("{name} ({check_id})"),
            severity,
            component,
            "Checkov",
        )
        .description(format!(
            "The {framework} definition for `{resource}` fails this check.\n\n\
             Infrastructure misconfiguration sits underneath the application rather than inside \
             it, which is why it is worth separating from the rest of this report: hardening the \
             application does not compensate for a resource that is reachable, unencrypted or \
             over-privileged by declaration. The fix is a change to the definition and a redeploy, \
             not a code change."
        ))
        .remediation(format!(
            "Correct the `{resource}` definition in {file} so it satisfies {check_id}, then \
             re-plan and apply. {}\n\nRun Checkov in CI against the same definitions so the change \
             cannot be reverted silently by a later edit — infrastructure drifts back far more \
             easily than application code, because a misconfiguration usually still works.",
            match guideline {
                Some(g) => format!("The policy's own guidance explains the required state: {g}"),
                None => "The Checkov policy index documents the required state for this check."
                    .to_string(),
            }
        ))
        .taxonomy(cwe, owasp, Some("WSTG-CONF-01"))
        .references(references)
        .repro(vec![format!("checkov --file {file} --check {check_id}")])
        .confidence(
            0.08,
            "Checkov evaluates the declaration itself, so the finding is a fact about what would \
             be deployed. Whether that resource is actually deployed from this definition, and \
             whether a compensating control exists elsewhere, is not established here.",
        )
        // Read from a file rather than observed running: real, but not proven
        // live on the assessed environment.
        .reachability(0.8);

        if let Some(block) = code_block {
            finding = finding.evidence(
                "code_snippet",
                &format!("{file} — {resource}"),
                &block,
            );
        }
        finding
    }

    /// Checkov supplies a severity only with a paid policy feed, so for the
    /// open-source policy set it is derived from what the check is about.
    ///
    /// The alternative — one flat severity for everything — would rank a
    /// missing resource tag identically to a database open to the internet.
    fn severity(check: &Value, name: &str) -> Severity {
        // A paid policy feed supplies one; the open-source set does not.
        if let Some(label) = check.get("severity").and_then(Value::as_str) {
            return super::external::severity_from_label(label);
        }

        let lower = name.to_ascii_lowercase();
        let reachable_from_the_internet = lower.contains("public")
            || lower.contains("0.0.0.0")
            || lower.contains("internet")
            || lower.contains("anonymous");
        let holds_data = lower.contains("bucket")
            || lower.contains("database")
            || lower.contains("rds")
            || lower.contains("storage");

        // Public *and* holding data is the combination that turns a
        // misconfiguration into a breach without anyone attacking anything.
        if reachable_from_the_internet && holds_data {
            return Severity::Critical;
        }

        let over_privileged = lower.contains("wildcard")
            || lower.contains("admin")
            || lower.contains("privileged")
            || lower.contains("root");
        let protects_data = lower.contains("encrypt")
            || lower.contains("tls")
            || lower.contains("ssl")
            || lower.contains("secret")
            || lower.contains("iam")
            || lower.contains("mfa");

        if reachable_from_the_internet || over_privileged || protects_data {
            return Severity::High;
        }

        // Everything else — logging, backups, versioning, tagging. Real, but
        // it is the difference between detecting an incident and preventing
        // one, so it does not belong in the same band as an open database.
        Severity::Medium
    }

    fn taxonomy(name: &str) -> (&'static str, &'static str) {
        const MISCONFIG: &str = "A02:2025-Security Misconfiguration";
        let lower = name.to_ascii_lowercase();

        if lower.contains("encrypt") || lower.contains("tls") || lower.contains("ssl") {
            ("CWE-311", "A04:2025-Cryptographic Failures")
        } else if lower.contains("public") || lower.contains("0.0.0.0") || lower.contains("internet") {
            ("CWE-284", "A01:2025-Broken Access Control")
        } else if lower.contains("iam") || lower.contains("policy") || lower.contains("privileg")
            || lower.contains("role") || lower.contains("wildcard")
        {
            ("CWE-732", "A01:2025-Broken Access Control")
        } else if lower.contains("log") || lower.contains("audit") || lower.contains("monitor") {
            ("CWE-778", "A09:2025-Security Logging and Alerting Failures")
        } else if lower.contains("secret") || lower.contains("password") || lower.contains("key") {
            ("CWE-798", "A04:2025-Cryptographic Failures")
        } else {
            ("CWE-16", MISCONFIG)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(check_id: &str, name: &str, resource: &str) -> String {
        format!(
            r#"{{"check_type":"terraform","results":{{"failed_checks":[{{
                "check_id":"{check_id}","check_name":"{name}","resource":"{resource}",
                "file_path":"/infra/main.tf","file_line_range":[12,20],
                "guideline":"https://docs.example/{check_id}",
                "code_block":[[12,"resource \"aws_s3_bucket\" \"data\" {{"],[13,"  acl = \"public-read\""]]
            }}]}}}}"#
        )
    }

    #[test]
    fn a_failed_check_becomes_a_finding_with_its_location() {
        let json = run("CKV_AWS_20", "S3 Bucket has an ACL defined which allows public access", "aws_s3_bucket.data");
        let out = CheckovParser::parse(&json, Uuid::new_v4(), Uuid::new_v4()).unwrap();

        assert_eq!(out.len(), 1);
        assert!(out[0].title.contains("CKV_AWS_20"));
        assert_eq!(out[0].affected_component, "/infra/main.tf:12 (aws_s3_bucket.data)");
        assert!(out[0].references[0].contains("docs.example"), "the policy guideline comes first");
    }

    /// One flat severity would rank a missing tag identically to a database
    /// open to the internet.
    #[test]
    fn severity_is_derived_from_what_the_check_is_about() {
        let cases = [
            ("S3 Bucket has an ACL which allows public access", Severity::Critical),
            ("Ensure no security group allows ingress from 0.0.0.0/0", Severity::High),
            ("Ensure IAM policies do not allow wildcard admin privileges", Severity::High),
            ("Ensure RDS instances have encryption at rest enabled", Severity::High),
            ("Ensure CloudTrail log file validation is enabled", Severity::Medium),
        ];
        for (name, expected) in cases {
            let out = CheckovParser::parse(&run("CKV_X", name, "r"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
            assert_eq!(out[0].severity, expected, "misclassified: {name}");
        }
    }

    #[test]
    fn taxonomy_follows_the_check_subject() {
        let encryption = CheckovParser::parse(
            &run("CKV_1", "Ensure RDS encryption at rest is enabled", "r"),
            Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(encryption[0].cwe_id.as_deref(), Some("CWE-311"));
        assert_eq!(encryption[0].owasp_2025.as_deref(), Some("A04:2025-Cryptographic Failures"));

        let logging = CheckovParser::parse(
            &run("CKV_2", "Ensure CloudTrail audit logging is enabled", "r"),
            Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(logging[0].owasp_2025.as_deref(), Some("A09:2025-Security Logging and Alerting Failures"));
    }

    #[test]
    fn the_offending_definition_is_attached_as_evidence() {
        let out = CheckovParser::parse(&run("CKV_AWS_20", "public access", "aws_s3_bucket.data"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        let evidence = &out[0].evidences[0];
        assert!(evidence.content.contains("aws_s3_bucket"));
        assert!(evidence.content.contains("public-read"));
        assert!(evidence.content.contains("   12 |"), "line numbers make it locatable: {}", evidence.content);
    }

    /// The fix is a redeploy, not a code change, and the report should say so.
    #[test]
    fn the_finding_explains_why_application_hardening_does_not_cover_it() {
        let out = CheckovParser::parse(&run("CKV_1", "public bucket", "r"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].description.contains("does not compensate"));
        assert!(out[0].remediation.contains("re-plan and apply"));
        assert!(out[0].remediation.contains("in CI"), "drift is the real risk here");
    }

    #[test]
    fn several_frameworks_in_one_run_all_parse() {
        let json = format!("[{},{}]", run("CKV_1", "a", "r1"), run("CKV_2", "b", "r2"));
        assert_eq!(CheckovParser::parse(&json, Uuid::new_v4(), Uuid::new_v4()).unwrap().len(), 2);
    }

    /// A repository with no infrastructure-as-code is a correct result, not a
    /// failure.
    #[test]
    fn a_repository_with_no_iac_produces_nothing() {
        for json in [
            r#"{"check_type":"terraform","results":{"failed_checks":[]}}"#,
            r#"{"check_type":"terraform","results":{}}"#,
            "[]",
        ] {
            assert!(CheckovParser::parse(json, Uuid::new_v4(), Uuid::new_v4()).unwrap().is_empty());
        }
    }
}
