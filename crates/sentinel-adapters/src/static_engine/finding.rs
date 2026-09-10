//! Turning a static match into a `Finding` the rest of the pipeline can use.
//!
//! The native DAST engine has an equivalent in `native::builder`, and the two
//! share a principle worth restating: severity is never declared next to a
//! vector, it is *computed from* the vector. When the two were written by hand
//! side by side they drifted apart on most of the checks, and a report that
//! prints `CVSS:4.0/…/VC:H` beside the word "Low" has stopped being evidence.
//!
//! What is different here is confidence. A DAST check reads a header off the
//! wire: it was there or it was not. A static rule matches a *shape* in source
//! code, and the distance between "this line calls `exec` with a variable in
//! it" and "this is a command injection" is exactly the judgement the analyst
//! is being paid for. Every rule therefore carries its own honest false-positive
//! estimate and a sentence saying what its match does and does not establish,
//! and the developer report sorts by it so a reviewer starts where their time
//! is worth most.

use sentinel_core::models::finding::{
    AITriage, CVSS4Data, Evidence, Finding, FindingKind, FindingStatus, Severity,
};
use sentinel_core::scoring::{Cvss4Severity, Cvss4Vector};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// How much of a claim a rule's match actually is.
///
/// This is the single most important field on a static rule. A tool that
/// reports a hardcoded AWS key and a suspicious-looking string concatenation
/// at the same confidence trains its reader to believe neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// The match is the weakness. A private key block in a tracked file is a
    /// leaked private key; there is no second reading.
    Certain,
    /// The construct is dangerous by nature and the match shows it being used
    /// with data the rule could not prove was constant.
    Firm,
    /// The shape is right but a safe explanation is common — a sanitiser in
    /// between, a constant that merely looks dynamic, a framework that escapes
    /// by default.
    Tentative,
}

impl Confidence {
    /// The probability that a finding from this rule is not a real weakness.
    ///
    /// Feeds `AITriage::is_false_positive_confidence`, which drives the
    /// developer report's review-order panel.
    pub fn false_positive_rate(self) -> f64 {
        match self {
            Confidence::Certain => 0.03,
            Confidence::Firm => 0.20,
            Confidence::Tentative => 0.45,
        }
    }

    /// How far a match moves the priority score.
    ///
    /// `reachability_score` multiplies priority, and the honest position for
    /// static analysis is below a live observation: the code exists, but
    /// nothing here proved an attacker can reach it. 1.0 is the neutral point
    /// the DAST engine exceeds at 1.1 for something it watched happen.
    pub fn reachability(self) -> f64 {
        match self {
            Confidence::Certain => 1.0,
            Confidence::Firm => 0.9,
            Confidence::Tentative => 0.7,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Confidence::Certain => "Certain",
            Confidence::Firm => "Firm",
            Confidence::Tentative => "Tentative",
        }
    }
}

/// Compile-time description of one static check, shared by all four static
/// engines so a code finding and a dependency finding carry identical metadata.
#[derive(Debug, Clone)]
pub struct CodeSpec {
    /// Stable identifier, e.g. "SENTINEL-JS-SQLI".
    pub id: &'static str,
    pub title: &'static str,
    /// The CVSS 4.0 vector, and the only place severity comes from.
    pub cvss_vector: &'static str,
    pub cwe: &'static str,
    pub wstg: &'static str,
    pub owasp_2025: &'static str,
    pub api_top10: Option<&'static str>,
    pub description: &'static str,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
    pub confidence: Confidence,
    /// What the match proves, and what it does not. Never a restatement of the
    /// title: this is the sentence a reviewer reads before deciding whether to
    /// open the file.
    pub triage_note: &'static str,
}

impl CodeSpec {
    pub fn score(&self) -> f64 {
        Cvss4Vector::parse(self.cvss_vector).map(|v| v.score()).unwrap_or(0.0)
    }

    pub fn severity(&self) -> Severity {
        match Cvss4Severity::of(self.score()) {
            Cvss4Severity::Critical => Severity::Critical,
            Cvss4Severity::High => Severity::High,
            Cvss4Severity::Medium => Severity::Medium,
            Cvss4Severity::Low => Severity::Low,
            Cvss4Severity::None => Severity::Info,
        }
    }

    pub fn severity_label(&self) -> &'static str {
        match self.severity() {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "None",
        }
    }
}

/// Everything about one occurrence, as opposed to the rule that found it.
pub struct CodeMatch<'a> {
    /// Repository-relative path.
    pub file: &'a str,
    /// 1-indexed line, or 0 for a whole-file finding.
    pub line: usize,
    /// The matched source line, already truncated and redacted for a report.
    pub snippet: String,
    /// Sentence appended to the spec's description, naming what was seen here.
    pub detail: String,
    /// Lines either side of the match, for context in the evidence block.
    pub context: Vec<(usize, String)>,
}

/// Build a `Finding` from a spec plus one occurrence.
pub fn build(
    spec: &CodeSpec,
    engine: &str,
    target_id: Uuid,
    scan_id: Uuid,
    m: &CodeMatch<'_>,
) -> Finding {
    let component = if m.line > 0 {
        format!("{}:{}", m.file, m.line)
    } else {
        m.file.to_string()
    };

    let description = if m.detail.trim().is_empty() {
        spec.description.to_string()
    } else {
        format!("{}\n\nObserved: {}", spec.description, m.detail)
    };

    let mut evidences = vec![evidence(
        "code_snippet",
        &format!("{component} — matched source"),
        &m.snippet,
    )];
    if !m.context.is_empty() {
        let block = m
            .context
            .iter()
            .map(|(n, text)| {
                let marker = if *n == m.line { ">" } else { " " };
                format!("{marker} {n:>5} | {text}")
            })
            .collect::<Vec<_>>()
            .join("\n");
        evidences.push(evidence("code_context", &format!("{} — surrounding lines", m.file), &block));
    }

    Finding {
        id: Uuid::new_v4(),
        scan_id,
        target_id,
        title: spec.title.to_string(),
        description,
        severity: spec.severity(),
        kind: FindingKind::Weakness,
        cvss4: Some(CVSS4Data {
            vector_string: spec.cvss_vector.to_string(),
            base_score: spec.score(),
            severity_label: spec.severity_label().to_string(),
        }),
        // A code pattern is not a CVE. EPSS and KEV describe the exploitation
        // of a published vulnerability with an identifier, and attaching either
        // to a rule match would invent evidence. The dependency engine sets
        // both, because there the finding genuinely is a CVE.
        epss: None,
        kev_listed: false,
        asset_exposure_factor: 1.0,
        reachability_score: spec.confidence.reachability(),
        priority_score: 0.0,
        priority_rationale: String::new(),
        cwe_id: Some(spec.cwe.to_string()),
        owasp_2025: Some(spec.owasp_2025.to_string()),
        wstg_id: Some(spec.wstg.to_string()),
        api_top10: spec.api_top10.map(str::to_string),
        affected_component: component,
        evidences,
        repro_steps: vec![
            format!("Open {} at line {} in the source checkout.", m.file, m.line.max(1)),
            "Read the surrounding function to establish whether the value reaching this \
             call can be influenced by a request, a file or another user."
                .to_string(),
            "If it can, follow it back to its entry point and confirm what validation, \
             encoding or parameterisation is applied on the way."
                .to_string(),
        ],
        remediation: spec.remediation.to_string(),
        references: spec.references.iter().map(|r| r.to_string()).collect(),
        status: FindingStatus::Open,
        source_tools: vec![engine.to_string()],
        ai_triage: Some(AITriage {
            is_false_positive_confidence: spec.confidence.false_positive_rate(),
            cluster_id: Some(format!("CLUSTER_{}", spec.cwe)),
            triage_notes: Some(format!(
                "[{} confidence] {}",
                spec.confidence.label(),
                spec.triage_note
            )),
        }),
        created_at: chrono::Utc::now(),
    }
}

/// An evidence block with a content hash, so a report can prove it was not
/// edited between the scan and the deliverable.
pub fn evidence(evidence_type: &str, title: &str, content: &str) -> Evidence {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    Evidence {
        evidence_type: evidence_type.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        hash: format!("{:x}", hasher.finalize()),
    }
}

/// The longest source line that goes into a report verbatim.
const MAX_SNIPPET: usize = 240;

/// Prepare a source line for publication.
///
/// Two jobs, both mandatory. Long lines are truncated, because a bundler emits
/// single lines of 200 000 characters and one of them in an evidence block
/// makes the whole document unreadable. And anything that looks like a live
/// credential is masked: this engine reads secrets for a living, and a report
/// that quotes the key it found has leaked it a second time, into a document
/// that gets emailed.
pub fn redact_snippet(line: &str) -> String {
    let trimmed = line.trim();
    let masked = mask_secrets(trimmed);
    if masked.chars().count() > MAX_SNIPPET {
        let head: String = masked.chars().take(MAX_SNIPPET).collect();
        format!("{head}… [line truncated at {MAX_SNIPPET} characters]")
    } else {
        masked
    }
}

/// Replace the value side of an assignment that names a credential.
///
/// Deliberately blunt. Failing to mask a real key is unrecoverable; masking a
/// variable that merely had "token" in its name costs the reader one trip to
/// the file, and the file path and line number are right there in the finding.
fn mask_secrets(line: &str) -> String {
    const SENSITIVE: &[&str] = &[
        "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
        "access_key", "secret_key", "private_key", "client_secret", "auth",
        "credential", "bearer", "session", "signature", "passphrase",
    ];
    let lower = line.to_ascii_lowercase();
    if !SENSITIVE.iter().any(|s| lower.contains(s)) {
        return line.to_string();
    }

    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        out.push(c);
        // A quote following an assignment-ish character starts a value.
        if c == '"' || c == '\'' || c == '`' {
            let quote = c;
            let mut value = String::new();
            let mut closed = false;
            for v in chars.by_ref() {
                if v == quote {
                    closed = true;
                    break;
                }
                value.push(v);
            }
            // Short values are field names and format strings, not secrets.
            if value.chars().count() >= 8 {
                out.push_str(&format!("[{} characters redacted]", value.chars().count()));
            } else {
                out.push_str(&value);
            }
            if closed {
                out.push(quote);
            }
        }
    }
    out
}

/// The lines around `line`, for the context evidence block.
pub fn context_lines(content: &str, line: usize, radius: usize) -> Vec<(usize, String)> {
    if line == 0 {
        return Vec::new();
    }
    let start = line.saturating_sub(radius).max(1);
    content
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l))
        .filter(|(n, _)| *n >= start && *n <= line + radius)
        .map(|(n, l)| (n, redact_snippet(l)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: CodeSpec = CodeSpec {
        id: "SENTINEL-TEST",
        title: "Test rule",
        cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        cwe: "CWE-89",
        wstg: "WSTG-INPV-05",
        owasp_2025: "A03:2025-Injection",
        api_top10: None,
        description: "Base description.",
        remediation: "Parameterise the query.",
        references: &["https://example.test/ref"],
        confidence: Confidence::Firm,
        triage_note: "A concatenation reached a query call.",
    };

    fn a_match<'a>() -> CodeMatch<'a> {
        CodeMatch {
            file: "src/db.js",
            line: 42,
            snippet: "db.query('SELECT * FROM u WHERE id=' + req.params.id)".into(),
            detail: "request data concatenated into SQL".into(),
            context: vec![(41, "function get(req) {".into()), (42, "  db.query(...)".into())],
        }
    }

    #[test]
    fn severity_is_computed_from_the_vector_not_declared_beside_it() {
        assert_eq!(SPEC.score(), 9.3);
        assert_eq!(SPEC.severity(), Severity::Critical);
        assert_eq!(SPEC.severity_label(), "Critical");
    }

    #[test]
    fn a_finding_carries_file_and_line_as_its_component() {
        let f = build(&SPEC, "Sentinel Code", Uuid::new_v4(), Uuid::new_v4(), &a_match());
        assert_eq!(f.affected_component, "src/db.js:42");
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-89"));
        assert_eq!(f.source_tools, vec!["Sentinel Code".to_string()]);
        assert!(f.description.contains("Observed: request data concatenated into SQL"));
        assert_eq!(f.evidences.len(), 2, "matched line plus surrounding context");
    }

    /// Static analysis proves the code exists, not that anyone can reach it.
    /// Claiming otherwise would put a rule match above a live observation in
    /// the ranking.
    #[test]
    fn static_findings_rank_below_a_live_observation() {
        const NATIVE_OBSERVED: f64 = 1.1;
        assert!(Confidence::Certain.reachability() < NATIVE_OBSERVED);
        assert!(Confidence::Tentative.reachability() < Confidence::Firm.reachability());
        assert!(Confidence::Firm.reachability() < Confidence::Certain.reachability());
    }

    #[test]
    fn confidence_is_reported_per_rule_rather_than_as_one_number_for_all() {
        assert!(Confidence::Certain.false_positive_rate() < 0.05);
        assert!(Confidence::Tentative.false_positive_rate() > 0.4);
        let f = build(&SPEC, "Sentinel Code", Uuid::new_v4(), Uuid::new_v4(), &a_match());
        let triage = f.ai_triage.unwrap();
        assert_eq!(triage.is_false_positive_confidence, 0.20);
        assert!(triage.triage_notes.unwrap().starts_with("[Firm confidence]"));
    }

    #[test]
    fn code_rules_never_fabricate_epss_or_kev() {
        let f = build(&SPEC, "Sentinel Code", Uuid::new_v4(), Uuid::new_v4(), &a_match());
        assert!(f.epss.is_none(), "a rule match has no exploit-prediction score");
        assert!(!f.kev_listed);
    }

    /// The engine that finds credentials must not republish them.
    #[test]
    fn a_credential_in_a_matched_line_is_masked_before_it_reaches_a_report() {
        let key = format!("sk_{}_51H8xQ2eZvKYlo2C0abcdef", "live");
        let snippet = format!(r#"const apiKey = "{key}";"#);
        let masked = redact_snippet(&snippet);
        assert!(!masked.contains(&key), "got {masked}");
        assert!(masked.contains("redacted"));
        assert!(masked.contains("apiKey"), "the variable name is what makes it reviewable");
    }

    #[test]
    fn an_ordinary_line_is_quoted_unchanged() {
        let line = "const total = price * quantity;";
        assert_eq!(redact_snippet(line), line);
    }

    #[test]
    fn a_bundler_line_is_truncated_rather_than_pasted_into_the_report() {
        let long = format!("var x = {};", "a".repeat(50_000));
        let out = redact_snippet(&long);
        assert!(out.chars().count() < 400, "got {} chars", out.chars().count());
        assert!(out.contains("truncated"));
    }

    #[test]
    fn context_lines_are_bounded_and_numbered() {
        let content = (1..=20).map(|i| format!("line {i}")).collect::<Vec<_>>().join("\n");
        let ctx = context_lines(&content, 10, 2);
        assert_eq!(ctx.first().unwrap().0, 8);
        assert_eq!(ctx.last().unwrap().0, 12);
    }

    #[test]
    fn context_near_the_top_of_a_file_does_not_underflow() {
        let ctx = context_lines("a\nb\nc", 1, 3);
        assert_eq!(ctx.first().unwrap().0, 1);
    }

    #[test]
    fn evidence_hashes_are_content_addressed() {
        assert_eq!(evidence("t", "x", "same").hash, evidence("t", "y", "same").hash);
        assert_ne!(evidence("t", "x", "a").hash, evidence("t", "x", "b").hash);
    }
}
