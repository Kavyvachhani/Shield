//! TruffleHog output.
//!
//! Gitleaks is already in the pipeline and finds secrets by pattern. TruffleHog
//! is here for the thing patterns cannot do: it takes a candidate credential
//! and *asks the provider whether it works*. A verified result is not "this
//! looks like an AWS key" but "this AWS key authenticated forty seconds ago".
//!
//! That distinction is the whole reason to run both. Pattern matching on
//! secrets produces the noisiest findings in application security — example
//! keys in documentation, rotated credentials in old commits, test fixtures —
//! and a triage queue full of them is how a real leaked key gets missed. A
//! verified finding cannot be any of those things.
//!
//! So verification drives severity, not just confidence: an unverified match is
//! reported at the pattern's own worth and says openly that it was not
//! confirmed, while a verified one is Critical and says why.
//!
//! ## What is never reproduced
//!
//! The raw secret. TruffleHog returns it, and a report that printed it would
//! disclose the credential a second time in a document that gets emailed and
//! archived. Only a fingerprint — provider, location, and the first characters
//! — reaches the finding.

use super::external::ExternalFinding;
use crate::models::finding::{Finding, Severity};
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

pub struct TruffleHogParser;

impl TruffleHogParser {
    /// Parse TruffleHog's JSON-lines output.
    ///
    /// The tool emits one JSON object per line rather than a document, and a
    /// malformed line is skipped rather than failing the run: losing one result
    /// is better than discarding a scan that found a live credential.
    pub fn parse(raw: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || !line.starts_with('{') {
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            // Progress and status objects share the stream with results.
            if value.get("DetectorName").is_none() {
                continue;
            }
            findings.push(Self::finding(&value).into_finding(target_id, scan_id));
        }

        Ok(findings)
    }

    fn finding(value: &Value) -> ExternalFinding {
        let detector = value
            .get("DetectorName")
            .and_then(Value::as_str)
            .unwrap_or("Unknown provider");
        let verified = value
            .get("Verified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let location = Self::location(value);
        let redacted = Self::redacted(value);

        let (severity, confidence, note) = if verified {
            (
                Severity::Critical,
                0.01,
                format!(
                    "TruffleHog authenticated this credential against {detector} during the scan. \
                     It is live, not a pattern match."
                ),
            )
        } else {
            (
                Severity::High,
                0.35,
                format!(
                    "This matched the {detector} credential format but could not be verified — \
                     the provider was unreachable, the detector has no verifier, or the credential \
                     has already been revoked. Treat it as unconfirmed until checked by hand."
                ),
            )
        };

        let title = if verified {
            format!("Verified live {detector} credential in source")
        } else {
            format!("Unverified {detector} credential pattern in source")
        };

        let description = if verified {
            format!(
                "A credential for {detector} was found in the repository and **successfully \
                 authenticated** against the provider during this scan. It is not an example, a \
                 fixture or a rotated key: it works right now.\n\nAnything in version control is \
                 disclosed to everyone who can clone the repository, and it remains in the history \
                 after the working tree is cleaned. Treat it as compromised from the moment it was \
                 first committed."
            )
        } else {
            format!(
                "A string matching the {detector} credential format was found in the repository. \
                 Verification did not succeed, which means one of: the credential is already \
                 revoked, the provider could not be reached, or this detector has no verifier. \
                 None of those is the same as it being harmless — an unverifiable match still needs \
                 a human to confirm what it is."
            )
        };

        let remediation = format!(
            "Revoke and reissue the credential at {detector} first. Removing it from the file \
             does not un-disclose it: the value stays in every clone, fork and CI cache that has \
             ever held the history.\n\nThen purge it from history and move the secret to a \
             manager the application reads at run time.\n\n```\n\
             # Rewrite history (coordinate with everyone who has a clone first)\n\
             git filter-repo --invert-paths --path {path}\n\n\
             # Then force-push, and have every collaborator re-clone rather than pull\n\
             git push --force --all\n```\n\n\
             Add a pre-commit secret scanner so the next one is stopped before it is committed.",
            path = Self::file_path(value).unwrap_or_else(|| "<file>".into()),
        );

        ExternalFinding::new(title, severity, location, "TruffleHog")
            .description(description)
            .remediation(remediation)
            .taxonomy(
                "CWE-798",
                "A04:2025-Cryptographic Failures",
                Some("WSTG-INFO-05"),
            )
            .references(vec![
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html".into(),
                "https://cwe.mitre.org/data/definitions/798.html".into(),
            ])
            .repro(vec![
                "trufflehog filesystem <repo> --results=verified,unknown --json".into(),
            ])
            .evidence(
                "code_snippet",
                &format!("{detector} credential (redacted)"),
                &format!(
                    "Provider:  {detector}\nVerified:  {}\nLocation:  {}\nValue:     {redacted}",
                    if verified { "yes — authenticated during this scan" } else { "no" },
                    Self::location(value),
                ),
            )
            .confidence(confidence, note)
            // A verified credential is as reachable as it is possible to be:
            // the scanner used it.
            .reachability(if verified { 1.2 } else { 0.9 })
    }

    /// Where the secret is, as precisely as the source metadata allows.
    fn location(value: &Value) -> String {
        let file = Self::file_path(value);
        let line = value
            .pointer("/SourceMetadata/Data/Filesystem/line")
            .or_else(|| value.pointer("/SourceMetadata/Data/Git/line"))
            .and_then(Value::as_i64);

        match (file, line) {
            (Some(f), Some(l)) => format!("{f}:{l}"),
            (Some(f), None) => f,
            (None, _) => "unknown location".to_string(),
        }
    }

    fn file_path(value: &Value) -> Option<String> {
        value
            .pointer("/SourceMetadata/Data/Filesystem/file")
            .or_else(|| value.pointer("/SourceMetadata/Data/Git/file"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    /// A fingerprint of the secret, never the secret.
    ///
    /// TruffleHog returns the raw value; reprinting it in a report would
    /// disclose the credential a second time, in a document that gets emailed
    /// around and archived.
    fn redacted(value: &Value) -> String {
        let raw = value
            .get("Raw")
            .and_then(Value::as_str)
            .or_else(|| value.get("Redacted").and_then(Value::as_str))
            .unwrap_or("");

        let chars: Vec<char> = raw.chars().collect();
        if chars.is_empty() {
            return "<not returned by the scanner>".to_string();
        }
        if chars.len() <= 8 {
            return format!("{} ({} characters)", "*".repeat(chars.len()), chars.len());
        }
        let head: String = chars.iter().take(4).collect();
        format!("{head}… ({} characters)", chars.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(detector: &str, verified: bool, raw: &str) -> String {
        format!(
            r#"{{"DetectorName":"{detector}","Verified":{verified},"Raw":"{raw}",
                "SourceMetadata":{{"Data":{{"Filesystem":{{"file":"src/config.ts","line":42}}}}}}}}"#
        )
        .replace('\n', "")
    }

    /// The reason for running TruffleHog alongside Gitleaks: a verified
    /// credential is a different claim from a pattern match, and the report has
    /// to rank it differently.
    #[test]
    fn a_verified_credential_outranks_an_unverified_pattern() {
        let verified = TruffleHogParser::parse(
            &line("AWS", true, "AKIAEXAMPLEEXAMPLE12"),
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .unwrap();
        let unverified = TruffleHogParser::parse(
            &line("AWS", false, "AKIAEXAMPLEEXAMPLE12"),
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .unwrap();

        assert_eq!(verified[0].severity, Severity::Critical);
        assert_eq!(unverified[0].severity, Severity::High);

        let v_conf = verified[0].ai_triage.as_ref().unwrap().is_false_positive_confidence;
        let u_conf = unverified[0].ai_triage.as_ref().unwrap().is_false_positive_confidence;
        assert!(v_conf < u_conf, "a verified credential cannot be the more doubtful of the two");
        assert_eq!(verified[0].reachability_score, 1.2, "the scanner used it; it is reachable");
    }

    #[test]
    fn the_verified_finding_says_it_authenticated_rather_than_matched() {
        let out = TruffleHogParser::parse(&line("Stripe", true, "sk_x"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].title.contains("Verified live"));
        assert!(out[0].description.contains("successfully \\\n                 authenticated")
             || out[0].description.contains("authenticated"));
        let note = out[0].ai_triage.as_ref().unwrap().triage_notes.as_deref().unwrap();
        assert!(note.contains("live, not a pattern match"), "{note}");
    }

    /// An unverifiable match is not the same as a harmless one, and the report
    /// must not imply that it is.
    #[test]
    fn an_unverified_match_lists_the_reasons_it_could_not_be_confirmed() {
        let out = TruffleHogParser::parse(&line("GitHub", false, "ghp_x"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        let note = out[0].ai_triage.as_ref().unwrap().triage_notes.as_deref().unwrap();
        assert!(note.contains("revoked"));
        assert!(note.contains("unreachable"));
        assert!(out[0].description.contains("None of those is the same as it being harmless"));
    }

    /// A report is emailed and archived. Printing the secret would disclose it
    /// a second time.
    #[test]
    fn the_secret_itself_never_reaches_the_finding() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let out = TruffleHogParser::parse(&line("AWS", true, secret), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        let rendered = format!(
            "{} {} {} {:?}",
            out[0].title, out[0].description, out[0].remediation,
            out[0].evidences.iter().map(|e| &e.content).collect::<Vec<_>>()
        );
        assert!(!rendered.contains(secret), "the credential was reprinted");
        assert!(rendered.contains("AKIA…"), "but it must stay identifiable");
    }

    #[test]
    fn the_location_carries_the_file_and_line() {
        let out = TruffleHogParser::parse(&line("AWS", true, "x"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out[0].affected_component, "src/config.ts:42");
        assert!(out[0].remediation.contains("src/config.ts"), "the fix names the file");
    }

    #[test]
    fn the_fix_says_revoke_before_it_says_delete() {
        let out = TruffleHogParser::parse(&line("AWS", true, "x"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        let fix = &out[0].remediation;
        assert!(fix.find("Revoke").unwrap() < fix.find("filter-repo").unwrap());
        assert!(fix.contains("does not un-disclose it"));
    }

    /// The stream carries progress objects alongside results, and a truncated
    /// line must not discard a scan that found a live credential.
    #[test]
    fn non_result_and_malformed_lines_are_skipped() {
        let stream = format!(
            "{}\n{{\"level\":\"info\",\"msg\":\"scanning\"}}\n{{ truncated\n\n{}",
            line("AWS", true, "a"),
            line("GitHub", false, "b"),
        );
        let out = TruffleHogParser::parse(&stream, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out.len(), 2, "both results survive the noise");
    }

    #[test]
    fn a_clean_scan_produces_nothing() {
        assert!(TruffleHogParser::parse("", Uuid::new_v4(), Uuid::new_v4()).unwrap().is_empty());
        assert!(TruffleHogParser::parse("\n\n", Uuid::new_v4(), Uuid::new_v4()).unwrap().is_empty());
    }
}
