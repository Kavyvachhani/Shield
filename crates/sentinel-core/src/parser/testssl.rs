//! testssl.sh output.
//!
//! The native engine reads a certificate: is it valid, does it match the host,
//! has it expired, is the signature weak. That is the shallow half of TLS. The
//! deep half is what the server will *negotiate* — which protocol versions it
//! still accepts, which cipher suites, whether it offers forward secrecy,
//! whether it is vulnerable to the named attacks that come up in every
//! assessment — and answering that means actually handshaking with the server
//! dozens of times.
//!
//! testssl.sh is the tool that does it, and it is the reference for TLS
//! sections in penetration test reports.
//!
//! ## Filtering
//!
//! testssl.sh emits several hundred records per host and most are `OK` or
//! `INFO`: the protocols it *doesn't* accept, the ciphers it *doesn't* offer,
//! header observations already covered by the native engine. Passing all of
//! that through would bury the report. Only records the tool rates as a
//! problem become findings, and the informational ones are dropped — the
//! coverage matrix already records that TLS was assessed.

use super::external::ExternalFinding;
use crate::models::finding::{Finding, Severity};
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

pub struct TestSslParser;

impl TestSslParser {
    /// Parse `testssl.sh --jsonfile-pretty` output.
    pub fn parse(raw_json: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let root: Value = serde_json::from_str(raw_json)?;
        let mut findings = Vec::new();

        // The pretty format wraps records in `scanResult[].{section}[]`; the
        // flat format is a bare array. Accept both — which one you get depends
        // on the flag the user's wrapper script happens to pass.
        let records: Vec<&Value> = if let Some(array) = root.as_array() {
            array.iter().collect()
        } else if let Some(results) = root.get("scanResult").and_then(Value::as_array) {
            results
                .iter()
                .flat_map(|host| {
                    host.as_object()
                        .map(|o| o.values().collect::<Vec<_>>())
                        .unwrap_or_default()
                })
                .filter_map(Value::as_array)
                .flatten()
                .collect()
        } else {
            Vec::new()
        };

        for record in records {
            let Some(finding) = Self::finding(record) else { continue };
            findings.push(finding.into_finding(target_id, scan_id));
        }

        Ok(findings)
    }

    /// Turn one record into a finding, or `None` when it is not a problem.
    fn finding(record: &Value) -> Option<ExternalFinding> {
        let id = record.get("id").and_then(Value::as_str)?;
        let severity_label = record.get("severity").and_then(Value::as_str)?;
        let output = record.get("finding").and_then(Value::as_str).unwrap_or("");
        let target = record
            .get("ip")
            .and_then(Value::as_str)
            .or_else(|| record.get("host").and_then(Value::as_str))
            .unwrap_or("the assessed host");

        let severity = Self::severity(severity_label)?;
        let (cwe, owasp, wstg) = Self::taxonomy(id);
        let (title, explanation, fix) = Self::describe(id, output);

        let cve = record
            .get("cve")
            .and_then(Value::as_str)
            .filter(|c| !c.trim().is_empty());

        let mut references = vec![
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html".to_string(),
            "https://ssl-config.mozilla.org/".to_string(),
        ];
        if let Some(cve) = cve {
            for id in cve.split_whitespace().take(3) {
                references.insert(0, format!("https://nvd.nist.gov/vuln/detail/{id}"));
            }
        }

        Some(
            ExternalFinding::new(title, severity, target, "testssl.sh")
                .description(format!("{explanation}\n\ntestssl.sh reported: {output}"))
                .remediation(fix)
                .taxonomy(cwe, owasp, Some(wstg))
                .references(references)
                .repro(vec![format!("testssl.sh --jsonfile-pretty - {target}")])
                .evidence(
                    "tls_handshake",
                    &format!("testssl.sh check: {id}"),
                    &format!(
                        "Check:    {id}\nSeverity: {severity_label}\nResult:   {output}\nCVE:      {}",
                        cve.unwrap_or("none referenced")
                    ),
                )
                // The tool negotiates with the server rather than inferring from
                // a banner, so what it reports is what the server actually does.
                .confidence(
                    0.03,
                    "testssl.sh established this by completing handshakes with the server, so it \
                     describes what the server actually negotiates rather than what it advertises.",
                )
                .reachability(1.1),
        )
    }

    /// testssl.sh's own severity words, or `None` for records that are not
    /// problems.
    ///
    /// `OK`, `INFO` and `DEBUG` describe what the server got *right* or what it
    /// simply is. Several hundred of those per host would bury the findings
    /// that matter, and the coverage matrix already records that TLS was
    /// assessed.
    fn severity(label: &str) -> Option<Severity> {
        match label.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Some(Severity::Critical),
            "HIGH" => Some(Severity::High),
            "MEDIUM" => Some(Severity::Medium),
            "LOW" => Some(Severity::Low),
            "WARN" => Some(Severity::Low),
            _ => None,
        }
    }

    /// Taxonomy from the check id, since testssl.sh supplies none.
    fn taxonomy(id: &str) -> (&'static str, &'static str, &'static str) {
        const CRYPTO: &str = "A04:2025-Cryptographic Failures";
        const MISCONFIG: &str = "A02:2025-Security Misconfiguration";
        let lower = id.to_ascii_lowercase();

        if lower.starts_with("cert") || lower.contains("chain") || lower.contains("ocsp") {
            ("CWE-295", CRYPTO, "WSTG-CRYP-01")
        } else if lower.starts_with("sslv") || lower.starts_with("tls1")
            || lower.contains("protocol") || lower.contains("drown") || lower.contains("poodle")
        {
            ("CWE-327", CRYPTO, "WSTG-CRYP-01")
        } else if lower.contains("cipher") || lower.contains("rc4") || lower.contains("3des")
            || lower.contains("export") || lower.contains("null") || lower.contains("anon")
        {
            ("CWE-327", CRYPTO, "WSTG-CRYP-04")
        } else if lower.contains("fs") || lower.contains("pfs") {
            ("CWE-326", CRYPTO, "WSTG-CRYP-01")
        } else if lower.contains("heartbleed") || lower.contains("ticketbleed")
            || lower.contains("robot") || lower.contains("ccs")
        {
            ("CWE-200", CRYPTO, "WSTG-CRYP-01")
        } else if lower.contains("hsts") || lower.contains("header") {
            ("CWE-319", MISCONFIG, "WSTG-CONF-07")
        } else if lower.contains("renego") || lower.contains("crime") || lower.contains("breach") {
            ("CWE-310", CRYPTO, "WSTG-CRYP-03")
        } else {
            ("CWE-326", CRYPTO, "WSTG-CRYP-01")
        }
    }

    /// A title, an explanation of why it matters, and the fix.
    ///
    /// testssl.sh's own output is terse and written for someone who already
    /// knows TLS — `"TLS1: offered"` is accurate and means nothing to the
    /// person who has to authorise the remediation.
    fn describe(id: &str, output: &str) -> (String, String, String) {
        let lower = id.to_ascii_lowercase();

        if lower == "tls1" || lower == "tls1_1" || lower.starts_with("sslv") {
            return (
                format!("Obsolete TLS protocol version still accepted ({id})"),
                "The server still negotiates a protocol version that has been formally deprecated. \
                 TLS 1.0 and 1.1 were deprecated by RFC 8996 and every major browser removed them \
                 in 2020; SSLv2 and SSLv3 are broken outright. A client that can be induced to \
                 downgrade — or an old client that never had a choice — gets a connection whose \
                 encryption cannot be relied on.\n\nIt is also a direct PCI DSS finding: TLS 1.0 has \
                 not been acceptable for cardholder data since June 2018."
                    .to_string(),
                "Disable everything below TLS 1.2 and prefer TLS 1.3. Mozilla's SSL Configuration \
                 Generator produces the exact directives for your server and a stated compatibility \
                 target:\n\n```\n# nginx — 'intermediate' profile\nssl_protocols TLSv1.2 TLSv1.3;\n\
                 ssl_prefer_server_ciphers off;\n\n# Apache\nSSLProtocol -all +TLSv1.2 +TLSv1.3\n```\n\n\
                 Check your access logs for clients still negotiating the old version before \
                 removing it, so the change is a decision rather than a surprise."
                    .to_string(),
            );
        }

        if lower.contains("rc4") || lower.contains("3des") || lower.contains("export")
            || lower.contains("null") || lower.contains("anon") || lower.contains("cipher")
        {
            return (
                format!("Weak cipher suite offered ({id})"),
                "The server offers a cipher suite that is no longer considered sound. Depending on \
                 the suite this means a broken keystream (RC4), a 64-bit block size vulnerable to \
                 birthday attacks over long-lived connections (3DES/Sweet32), deliberately \
                 weakened export-grade key sizes, or — for NULL and anonymous suites — no \
                 encryption or no authentication at all.\n\nA suite being *offered* matters even if \
                 nothing normally selects it, because it is available to whatever the client \
                 proposes."
                    .to_string(),
                "Restrict the server to AEAD suites with forward secrecy. Take the cipher string \
                 from Mozilla's generator for your compatibility target rather than assembling one \
                 by hand — an ordering mistake in a hand-written string is how a weak suite ends up \
                 preferred:\n\n```\n# nginx — 'intermediate'\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:\
                 ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                 ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\n```"
                    .to_string(),
            );
        }

        if lower.contains("heartbleed") || lower.contains("robot") || lower.contains("ticketbleed")
            || lower.contains("ccs") || lower.contains("poodle") || lower.contains("drown")
            || lower.contains("crime") || lower.contains("logjam") || lower.contains("freak")
            || lower.contains("beast") || lower.contains("sweet32")
        {
            return (
                format!("Server vulnerable to a known TLS attack ({id})"),
                format!(
                    "The server is vulnerable to {id}, a named and published attack against TLS. \
                     These are not theoretical: each has working public tooling, and several — \
                     Heartbleed and ROBOT in particular — allow an attacker to recover memory \
                     contents or decrypt captured traffic without any credential.\n\nTreat traffic \
                     captured while this was exploitable as potentially compromised, not merely at \
                     risk."
                ),
                "Patch the TLS library to a version where this is fixed; for most of these the fix \
                 is a library update rather than a configuration change. Where the attack depends \
                 on a specific feature — session tickets, renegotiation, compression — disable that \
                 feature as well, since a patched library with the feature enabled can regress on a \
                 later upgrade. Re-run testssl.sh afterwards to confirm the server no longer \
                 answers, rather than assuming the patch applied."
                    .to_string(),
            );
        }

        if lower.contains("fs") || lower.contains("pfs") {
            return (
                "Forward secrecy not offered".to_string(),
                "The server negotiates key exchange without forward secrecy. Without it, every \
                 session is encrypted in a way that the server's private key can later decrypt — so \
                 an attacker who records traffic today and obtains the key at any point in the \
                 future, by compromise, subpoena or a Heartbleed-class bug, can read all of it \
                 retrospectively."
                    .to_string(),
                "Enable ECDHE key exchange and prefer it. TLS 1.3 requires forward secrecy, so \
                 supporting 1.3 solves this for clients that speak it:\n\n```\nssl_protocols TLSv1.2 TLSv1.3;\n\
                 ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...;\n```"
                    .to_string(),
            );
        }

        if lower.contains("cert") {
            return (
                format!("Certificate problem reported ({id})"),
                format!(
                    "testssl.sh reported a problem with the certificate or its chain. A chain that \
                     validates in your browser can still fail elsewhere: browsers carry cached \
                     intermediates that a freshly installed client, a mobile app or a server-side \
                     HTTP client will not have, so an incomplete chain frequently breaks \
                     machine-to-machine traffic while looking fine to a human.\n\nReported as: {output}"
                ),
                "Serve the full chain — leaf plus every intermediate, in order, excluding the root. \
                 Confirm with `openssl s_client -connect host:443 -showcerts` from a machine that \
                 has never visited the site, and check the expiry and hostname coverage while you \
                 are there. Automate renewal if it is not already."
                    .to_string(),
            );
        }

        (
            format!("TLS configuration issue ({id})"),
            format!(
                "testssl.sh flagged this as a weakness in the server's TLS configuration. \
                 Reported as: {output}"
            ),
            "Compare the server's configuration against Mozilla's SSL Configuration Generator for \
             your compatibility target, and re-run testssl.sh afterwards to confirm the change took \
             effect on the live endpoint rather than only in the config file."
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, severity: &str, finding: &str) -> String {
        format!(
            r#"[{{"id":"{id}","severity":"{severity}","finding":"{finding}","ip":"app.test/93.184.216.34"}}]"#
        )
    }

    /// Several hundred `OK` and `INFO` records per host would bury the findings
    /// that matter, and the coverage matrix already records that TLS was tested.
    #[test]
    fn only_records_the_tool_rates_as_a_problem_become_findings() {
        for label in ["OK", "INFO", "DEBUG"] {
            let out = TestSslParser::parse(&record("TLS1_3", label, "offered"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
            assert!(out.is_empty(), "{label} records are not findings");
        }
        for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN"] {
            let out = TestSslParser::parse(&record("TLS1", label, "offered"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
            assert_eq!(out.len(), 1, "{label} records are findings");
        }
    }

    /// "TLS1: offered" is accurate and means nothing to the person who has to
    /// authorise the fix.
    #[test]
    fn a_terse_tool_output_becomes_an_explanation_someone_can_act_on() {
        let out = TestSslParser::parse(&record("TLS1", "MEDIUM", "offered"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].title.contains("Obsolete TLS protocol version"));
        assert!(out[0].description.contains("RFC 8996"));
        assert!(out[0].description.contains("PCI DSS"), "the compliance consequence is the reason it gets funded");
        assert!(out[0].remediation.contains("ssl_protocols TLSv1.2 TLSv1.3"));
        assert!(out[0].remediation.contains("```"), "the directive must be fenced for the report");
    }

    #[test]
    fn a_named_attack_says_what_was_already_exposed_rather_than_only_what_to_patch() {
        let out = TestSslParser::parse(&record("heartbleed", "CRITICAL", "VULNERABLE"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out[0].severity, Severity::Critical);
        assert!(out[0].description.contains("potentially compromised"));
        assert!(out[0].remediation.contains("Re-run testssl.sh"));
    }

    #[test]
    fn taxonomy_follows_the_check_id() {
        let cases = [
            ("TLS1", "CWE-327", "WSTG-CRYP-01"),
            ("RC4", "CWE-327", "WSTG-CRYP-04"),
            ("cert_chain_of_trust", "CWE-295", "WSTG-CRYP-01"),
            ("heartbleed", "CWE-200", "WSTG-CRYP-01"),
        ];
        for (id, cwe, wstg) in cases {
            let out = TestSslParser::parse(&record(id, "HIGH", "x"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
            assert_eq!(out[0].cwe_id.as_deref(), Some(cwe), "for {id}");
            assert_eq!(out[0].wstg_id.as_deref(), Some(wstg), "for {id}");
        }
    }

    /// The tool completes real handshakes rather than reading a banner, so its
    /// findings are among the most reliable in the pipeline.
    #[test]
    fn the_confidence_reflects_that_the_server_was_actually_negotiated_with() {
        let out = TestSslParser::parse(&record("TLS1", "MEDIUM", "offered"), Uuid::new_v4(), Uuid::new_v4()).unwrap();
        let triage = out[0].ai_triage.as_ref().unwrap();
        assert!(triage.is_false_positive_confidence <= 0.05);
        assert!(triage.triage_notes.as_deref().unwrap().contains("completing handshakes"));
    }

    #[test]
    fn a_cve_reference_is_promoted_above_the_generic_guidance() {
        let json = r#"[{"id":"ROBOT","severity":"HIGH","finding":"VULNERABLE","cve":"CVE-2017-13099","ip":"app.test"}]"#;
        let out = TestSslParser::parse(json, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(out[0].references[0].contains("CVE-2017-13099"), "{:?}", out[0].references);
    }

    /// Which shape you get depends on the flag the user's wrapper passes, so
    /// depending on one would break for half of them.
    #[test]
    fn both_the_flat_array_and_the_pretty_wrapper_parse() {
        let pretty = r#"{"scanResult":[{"protocols":[{"id":"TLS1","severity":"MEDIUM","finding":"offered","ip":"app.test"}]}]}"#;
        let out = TestSslParser::parse(pretty, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn a_clean_server_produces_nothing() {
        assert!(TestSslParser::parse("[]", Uuid::new_v4(), Uuid::new_v4()).unwrap().is_empty());
        assert!(TestSslParser::parse("{}", Uuid::new_v4(), Uuid::new_v4()).unwrap().is_empty());
    }

    #[test]
    fn a_record_missing_its_severity_is_skipped_rather_than_guessed_at() {
        let json = r#"[{"id":"TLS1","finding":"offered"}]"#;
        assert!(TestSslParser::parse(json, Uuid::new_v4(), Uuid::new_v4()).unwrap().is_empty());
    }
}
