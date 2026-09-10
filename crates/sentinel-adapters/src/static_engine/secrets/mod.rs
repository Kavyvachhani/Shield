//! Sentinel Secrets — the built-in credential scanner.
//!
//! Reads every text file in the checkout, including the ones the code engine
//! deliberately skips. A key compiled into a bundle, sitting in a `.env` that
//! was committed by accident, or pasted into a test fixture is still a live key,
//! and the deployment does not care which file it came from.
//!
//! Two things this engine will not do.
//!
//! It will not print what it found. Every value is masked before it reaches a
//! finding, because a report naming the credential it discovered has published
//! it a second time — into a document that gets emailed, archived and forwarded.
//! Enough of the value survives that its owner can tell which of their nine keys
//! it is; not enough that anyone can use it.
//!
//! And it will not tell you the credential is still valid, because it does not
//! ask. Verifying a secret means authenticating to somebody else's service with
//! it, which is a live authentication attempt against a third party from an
//! assessment that was not authorised to make one. TruffleHog does this
//! deliberately and well, and where the analyst has installed it the pipeline
//! runs it; this engine reports what it found and says plainly that validity is
//! unknown.

pub mod patterns;

use crate::adapter_trait::ScannerAdapter;
use crate::static_engine::codebase::{self, Codebase, SourceFile, WalkLimits};
use crate::static_engine::engine::SECRETS;
use crate::static_engine::finding as fb;
use anyhow::Result;
use async_trait::async_trait;
use patterns::{Impact, SecretKind, SecretPattern};
use regex::Regex;
use sentinel_core::checklist::catalog::owasp;
use sentinel_core::models::finding::{
    AITriage, CVSS4Data, Evidence, Finding, FindingKind, FindingStatus, Severity,
};
use sentinel_core::models::target::Target;
use sentinel_core::scoring::{Cvss4Severity, Cvss4Vector};
use std::collections::HashSet;
use std::sync::OnceLock;
use uuid::Uuid;

/// Findings per pattern before the rest are summarised.
const MAX_PER_PATTERN: usize = 25;

/// Files whose whole purpose is to hold example configuration.
///
/// A secret in one of these is usually a placeholder, and the engine still
/// reports it — at reduced confidence, saying why — rather than staying silent,
/// because `.env.example` is also where a real key ends up when someone copies
/// the wrong file.
const EXAMPLE_FILES: &[&str] = &[
    ".env.example", ".env.sample", ".env.template", ".env.dist",
    "example.env", "sample.env", "config.example.json", "config.sample.yml",
];

/// Files where a long random string is expected and is not a credential.
///
/// Integrity hashes, resolved digests and content addresses all pass an entropy
/// test comfortably. Provider patterns still run over these — an AWS key in a
/// lockfile is an AWS key — but the entropy heuristic does not.
const HASH_HEAVY_FILES: &[&str] = &[
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock",
    "Gemfile.lock", "Cargo.lock", "poetry.lock", "Pipfile.lock", "go.sum",
    "npm-shrinkwrap.json", "bun.lockb", "flake.lock",
];

pub struct NativeSecretsAdapter;

#[async_trait]
impl ScannerAdapter for NativeSecretsAdapter {
    fn name(&self) -> &'static str {
        SECRETS
    }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(true)
    }

    async fn run(&self, target: &Target, _config_json: &str) -> Result<Vec<Finding>> {
        let Some(repo) = target.repo_ref.as_deref().filter(|r| !r.trim().is_empty()) else {
            tracing::info!("Sentinel Secrets: no source repository to read");
            return Ok(Vec::new());
        };

        let root = std::path::PathBuf::from(repo);
        let codebase = tokio::task::spawn_blocking(move || {
            codebase::walk(&root, &WalkLimits::default())
        })
        .await??;

        let mut findings = scan(&codebase, target.id, Uuid::new_v4());
        for f in &mut findings {
            sentinel_core::scoring::priority::PriorityScoringEngine::score_and_explain(f);
        }
        tracing::info!(finding_count = findings.len(), "Sentinel Secrets: complete");
        Ok(findings)
    }
}

/// One credential the engine found.
struct Hit {
    pattern_id: &'static str,
    /// The provider pattern, or `None` for a heuristic match.
    spec: Option<&'static SecretPattern>,
    /// For a heuristic match, which kind it was judged to be.
    kind: Option<SecretKind>,
    /// Variable name for an entropy match, so the finding can say what to look for.
    field: String,
    file: String,
    line: usize,
    masked: String,
    /// A committed example file is a weaker claim than a committed source file.
    example_file: bool,
}

/// Scan a whole codebase.
pub fn scan(codebase: &Codebase, target_id: Uuid, scan_id: Uuid) -> Vec<Finding> {
    let mut hits: Vec<Hit> = Vec::new();
    // The same key committed to four files is one leaked key with four
    // locations, not four findings, and the report groups it that way.
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for file in &codebase.files {
        scan_file(file, &mut hits, &mut seen);
    }

    group_into_findings(hits, target_id, scan_id)
}

fn scan_file(file: &SourceFile, hits: &mut Vec<Hit>, seen: &mut HashSet<(String, String)>) {
    let name = file.file_name();
    let example_file = EXAMPLE_FILES.iter().any(|e| name.eq_ignore_ascii_case(e))
        || name.ends_with(".example")
        || name.ends_with(".sample");
    let hash_heavy = HASH_HEAVY_FILES.iter().any(|h| name.eq_ignore_ascii_case(h));

    for (number, line) in file.content.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        // A single line of a minified bundle can be a megabyte; entropy over it
        // is meaningless and a provider pattern would match the whole line as
        // context. Provider patterns still get a bounded prefix.
        let line = if line.len() > 4_000 { &line[..4_000] } else { line };

        // ── Provider patterns ────────────────────────────────────────────────
        for compiled in patterns::compiled() {
            let Some(caps) = compiled.regex.captures(line) else {
                continue;
            };
            if compiled.spec.not_if.iter().any(|marker| line.contains(marker)) {
                continue;
            }
            // Group 1 is the credential itself where the pattern isolates it;
            // otherwise the whole match, which is already the credential.
            let value = caps
                .get(1)
                .or_else(|| caps.get(0))
                .map(|m| m.as_str())
                .unwrap_or_default();
            if value.is_empty() {
                continue;
            }
            if !seen.insert((compiled.spec.id.to_string(), value.to_string())) {
                continue;
            }
            hits.push(Hit {
                pattern_id: compiled.spec.id,
                spec: Some(compiled.spec),
                kind: None,
                field: String::new(),
                file: file.relative.clone(),
                line: number,
                masked: patterns::mask(value),
                example_file,
            });
        }

        // ── Entropy detection ────────────────────────────────────────────────
        if hash_heavy {
            continue;
        }
        for (field, value) in assignments(line) {
            let Some(kind) = patterns::classify_secret(&field, &value) else {
                continue;
            };
            // Grouped by kind, so a generated key and a chosen password become
            // two findings that read differently rather than one that describes
            // both wrongly.
            let pattern_id = match kind {
                SecretKind::GeneratedCredential => "SECRET-HIGH-ENTROPY",
                SecretKind::HardcodedPassword => "SECRET-HARDCODED-PASSWORD",
            };
            if !seen.insert((pattern_id.to_string(), value.clone())) {
                continue;
            }
            hits.push(Hit {
                pattern_id,
                spec: None,
                kind: Some(kind),
                field,
                file: file.relative.clone(),
                line: number,
                masked: patterns::mask(&value),
                example_file,
            });
        }
    }
}

/// Extract `name = "value"` pairs from a line, across the assignment syntaxes
/// every configuration and source format in the tree uses.
fn assignments(line: &str) -> Vec<(String, String)> {
    static RE: OnceLock<Vec<Regex>> = OnceLock::new();
    let regexes = RE.get_or_init(|| {
        [
            // key = "value" / key: "value" / "key": "value"
            r#"["']?([A-Za-z_][A-Za-z0-9_\-\.]{2,40})["']?\s*[:=]\s*["']([^"'\n]{8,200})["']"#,
            // KEY=value  (dotenv, shell, Dockerfile ENV)
            r#"^\s*(?:export\s+|ENV\s+)?([A-Z][A-Z0-9_]{2,40})=([^\s"'#]{8,200})\s*$"#,
        ]
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
    });

    let mut out = Vec::new();
    for re in regexes {
        for caps in re.captures_iter(line) {
            if let (Some(k), Some(v)) = (caps.get(1), caps.get(2)) {
                out.push((k.as_str().to_string(), v.as_str().to_string()));
            }
        }
    }
    out
}

/// Group hits by credential kind and build one finding per kind.
fn group_into_findings(hits: Vec<Hit>, target_id: Uuid, scan_id: Uuid) -> Vec<Finding> {
    use std::collections::BTreeMap;
    let mut grouped: BTreeMap<&'static str, Vec<Hit>> = BTreeMap::new();
    for hit in hits {
        grouped.entry(hit.pattern_id).or_default().push(hit);
    }

    grouped
        .into_values()
        .map(|group| build_finding(group, target_id, scan_id))
        .collect()
}

/// CVSS vectors by impact. A leaked credential's severity is a property of what
/// it opens, not of how it was found.
const V_CRITICAL: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
const V_HIGH: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N";
const V_MODERATE: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N";

fn build_finding(group: Vec<Hit>, target_id: Uuid, scan_id: Uuid) -> Finding {
    let first = &group[0];
    let spec = first.spec;
    let all_examples = group.iter().all(|h| h.example_file);

    let (name, vector, revocation) = match (spec, first.kind) {
        (Some(s), _) => (
            s.name.to_string(),
            match s.impact {
                Impact::Critical => V_CRITICAL,
                Impact::High => V_HIGH,
                Impact::Moderate => V_MODERATE,
            },
            s.revocation.to_string(),
        ),
        (None, Some(SecretKind::HardcodedPassword)) => (
            "Hardcoded password".to_string(),
            V_HIGH,
            "Change the password on the system it authenticates to — a password committed to a \
             repository is disclosed to everyone who has ever cloned it, and changing the \
             source without changing the password leaves the account open. Then read the value \
             from the environment or a secret manager.\n\n\
             If this is a local development default rather than a real credential, it is still \
             worth removing: a development password that also works in staging is the most \
             common way one of these turns out to matter."
                .to_string(),
        ),
        (None, _) => (
            "High-entropy value in a credential field".to_string(),
            V_HIGH,
            "Identify what the value authenticates to, rotate it there, and move it into the \
             environment or a secret manager. Where it turns out to be a placeholder, replace \
             it with an obvious one — an empty string or `CHANGE_ME` — so the next scan, and \
             the next reader, does not have to work it out again."
                .to_string(),
        ),
    };

    let score = Cvss4Vector::parse(vector).map(|v| v.score()).unwrap_or(0.0);
    let mut severity = band(score);
    // A value in a file whose entire purpose is to be an example is usually a
    // placeholder. Still reported — that is where a real key lands when
    // somebody copies the wrong file — but not at the top of the queue.
    if all_examples && severity != Severity::Info {
        severity = Severity::Medium;
    }

    let locations: Vec<String> = group
        .iter()
        .take(MAX_PER_PATTERN)
        .map(|h| format!("  • {}:{}  →  {}", h.file, h.line, h.masked))
        .collect();
    let overflow = group.len().saturating_sub(MAX_PER_PATTERN);

    // Lower-cased for the sentence: the names read as titles ("Hardcoded
    // password", "AWS access key identifier") and "A Hardcoded password" is a
    // capital in the middle of a sentence.
    let subject = {
        let mut c = name.chars();
        match c.next() {
            Some(first) => format!("{}{}", first.to_lowercase(), c.as_str()),
            None => name.clone(),
        }
    };
    let article = if subject.starts_with(['a', 'e', 'i', 'o', 'u']) { "An" } else { "A" };

    let mut description = format!(
        "{article} {subject} was found committed to the source tree.\n\n\
         Occurrence{} ({} total, value masked):\n{}{}",
        if group.len() == 1 { "" } else { "s" },
        group.len(),
        locations.join("\n"),
        if overflow > 0 {
            format!("\n  • … and {overflow} more")
        } else {
            String::new()
        },
    );

    if spec.is_none() {
        let fields: Vec<&str> = group.iter().map(|h| h.field.as_str()).take(6).collect();
        description.push_str(&match first.kind {
            Some(SecretKind::HardcodedPassword) => format!(
                "\n\nThis is a password literal rather than a generated key: it is not random \
                 enough to have been issued by a system, which is exactly what a password \
                 somebody chose looks like. The field it is assigned to ({}) names it as a \
                 credential. Entropy-based scanners miss this class entirely, and it is the \
                 more common one in application code.",
                fields.join(", ")
            ),
            _ => format!(
                "\n\nMatched by entropy rather than by a known provider format: the value is \
                 long and random enough to be a generated credential, and the field it is \
                 assigned to ({}) is named like one. That is a strong hint, not a certainty — \
                 read the value in place before acting.",
                fields.join(", ")
            ),
        });
    }

    description.push_str(
        "\n\nWhat this finding does and does not establish. The value is present in the \
         checked-out tree, which means it is present in the repository's history as well: \
         deleting the line does not remove it, and anyone who has ever cloned the repository \
         still has it. Whether the credential is *still valid* was not tested — doing so would \
         mean authenticating to a third-party service, which is outside what this assessment \
         is authorised to do. Treat it as live until the issuing system says otherwise.",
    );

    if all_examples {
        description.push_str(
            "\n\nEvery occurrence is in a file whose name marks it as an example or template, \
             so this is most likely a placeholder. It is reported rather than suppressed \
             because an example file is exactly where a real credential ends up when somebody \
             copies the wrong one — confirm the value, then either rotate it or replace it with \
             an obviously fake placeholder.",
        );
    }

    let remediation = format!(
        "1. Rotate the credential first, before anything else. {revocation}\n\n\
         2. Remove it from the working tree and read it from the environment or a secret \
            manager instead.\n\n\
         3. Purge it from the history — `git filter-repo --invert-paths --path <file>`, or \
            BFG — and force-push. Every clone and fork keeps its own copy, so tell whoever \
            holds one. Rotation in step 1 is what actually closes the exposure; this step \
            stops it being rediscovered.\n\n\
         4. Add a pre-commit secret scan so the next one is caught before it is pushed, and \
            check whether the provider offers push protection (GitHub, GitLab and several \
            others do)."
    );

    let evidences: Vec<Evidence> = vec![fb::evidence(
        "secret_location",
        &format!("{name} — locations (masked)"),
        &locations.join("\n"),
    )];

    Finding {
        id: Uuid::new_v4(),
        scan_id,
        target_id,
        title: format!("{name} committed to source control"),
        description,
        severity: severity.clone(),
        kind: FindingKind::Weakness,
        cvss4: Some(CVSS4Data {
            vector_string: vector.to_string(),
            base_score: score,
            severity_label: label(severity.clone()).to_string(),
        }),
        epss: None,
        kev_listed: false,
        asset_exposure_factor: 1.0,
        // Present in the tree is directly observed. Whether it authenticates is
        // not, which is what the triage note is for.
        reachability_score: if spec.is_some() { 1.0 } else { 0.8 },
        priority_score: 0.0,
        priority_rationale: String::new(),
        cwe_id: Some("CWE-798".to_string()),
        owasp_2025: Some(owasp::A07.to_string()),
        wstg_id: Some("WSTG-ATHN-07".to_string()),
        api_top10: None,
        affected_component: format!("{}:{}", first.file, first.line),
        evidences,
        repro_steps: vec![
            format!("Open {} at line {}.", first.file, first.line),
            "Read the value in place; the report holds only a masked form of it.".to_string(),
            "Run `git log -S '<value>' --all` to find when it entered the history and which \
             branches carry it."
                .to_string(),
        ],
        remediation,
        references: vec![
            "https://cwe.mitre.org/data/definitions/798.html".to_string(),
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html".to_string(),
            "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning".to_string(),
        ],
        status: FindingStatus::Open,
        source_tools: vec![SECRETS.to_string()],
        ai_triage: Some(AITriage {
            is_false_positive_confidence: match (spec, first.kind, all_examples) {
                // A provider format is close to unambiguous.
                (Some(_), _, false) => 0.04,
                (Some(_), _, true) => 0.35,
                // A password-named field with a literal in it is a firmer claim
                // than an entropy match, because the field name is doing more
                // of the work and there are fewer innocent explanations.
                (None, Some(SecretKind::HardcodedPassword), false) => 0.20,
                (None, Some(SecretKind::HardcodedPassword), true) => 0.55,
                (None, _, false) => 0.30,
                (None, _, true) => 0.60,
            },
            cluster_id: Some("CLUSTER_CWE-798".to_string()),
            triage_notes: Some(match (spec, first.kind) {
                (None, Some(SecretKind::HardcodedPassword)) =>
                    "[Firm confidence] A literal value in a field named as a password. What is \
                     not established is whether the account it belongs to still exists or \
                     whether the value was ever live — but a password in source is worth \
                     changing regardless of which, because you cannot tell from here."
                        .to_string(),
                (Some(s), _) => format!(
                    "[Certain confidence] The value matches {}'s published credential format, \
                     so what it is is not in doubt. What is not established is whether it still \
                     authenticates — that was deliberately not tested. Rotate first and \
                     investigate afterwards.",
                    s.name
                ),
                (None, _) => "[Tentative confidence] Matched on entropy and field name rather \
                         than a known provider format. Read the value before acting: a \
                         generated identifier or a test fixture can pass the same test."
                    .to_string(),
            }),
        }),
        created_at: chrono::Utc::now(),
    }
}

fn band(score: f64) -> Severity {
    match Cvss4Severity::of(score) {
        Cvss4Severity::Critical => Severity::Critical,
        Cvss4Severity::High => Severity::High,
        Cvss4Severity::Medium => Severity::Medium,
        Cvss4Severity::Low => Severity::Low,
        Cvss4Severity::None => Severity::Info,
    }
}

fn label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "None",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_engine::codebase::{Provenance, WalkStop};
    use std::path::PathBuf;

    fn file(relative: &str, content: &str) -> SourceFile {
        SourceFile {
            path: PathBuf::from(format!("/repo/{relative}")),
            relative: relative.to_string(),
            extension: relative.rsplit('.').next().unwrap_or("").to_string(),
            provenance: Provenance::Authored,
            size_bytes: content.len() as u64,
            content: content.to_string(),
        }
    }

    fn run(files: Vec<SourceFile>) -> Vec<Finding> {
        let cb = Codebase {
            root: PathBuf::from("/repo"),
            files,
            skipped: vec![],
            stopped_because: WalkStop::Exhausted,
        };
        scan(&cb, Uuid::new_v4(), Uuid::new_v4())
    }

    #[test]
    fn an_aws_key_is_found_and_named() {
        let f = run(vec![file("src/config.js", "const k = 'AKIAIOSFODNN7REALKEY';")]);
        assert_eq!(f.len(), 1);
        assert!(f[0].title.contains("AWS access key identifier"));
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].cwe_id.as_deref(), Some("CWE-798"));
    }

    /// The single most important property of this engine.
    #[test]
    fn the_credential_never_appears_in_the_finding() {
        let secret = "AKIAIOSFODNN7REALKEY";
        let f = run(vec![file("src/config.js", &format!("const k = '{secret}';"))]);
        let whole = format!(
            "{}{}{}{}",
            f[0].title,
            f[0].description,
            f[0].remediation,
            f[0].evidences.iter().map(|e| e.content.clone()).collect::<String>()
        );
        assert!(!whole.contains(secret), "the report republished the credential");
        assert!(whole.contains("AKIA"), "enough survives to identify which key");
        assert!(whole.contains('•'), "the body is masked");
    }

    #[test]
    fn every_finding_leads_with_rotation_rather_than_deletion() {
        let f = run(vec![file("src/a.js", "const k = 'AKIAIOSFODNN7REALKEY';")]);
        assert!(
            f[0].remediation.starts_with("1. Rotate the credential first"),
            "deleting the line does not close the exposure"
        );
        assert!(f[0].remediation.contains("filter-repo"), "and history must be addressed too");
    }

    #[test]
    fn the_same_credential_in_several_files_is_one_finding_with_several_locations() {
        let f = run(vec![
            file("src/a.js", "const k = 'AKIAIOSFODNN7REALKEY';"),
            file("src/b.js", "const k = 'AKIAIOSFODNN7REALKEY';"),
        ]);
        assert_eq!(f.len(), 1, "one leaked key, not two");
    }

    #[test]
    fn different_credentials_of_the_same_kind_are_listed_together() {
        let f = run(vec![file(
            "src/a.js",
            "const a = 'AKIAIOSFODNN7REALKEY';\nconst b = 'AKIA234567890ABCDEF1';",
        )]);
        assert_eq!(f.len(), 1);
        assert!(f[0].description.contains("2 total"));
    }

    #[test]
    fn a_private_key_block_is_reported_as_critical() {
        let f = run(vec![file("deploy/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n")]);
        assert!(f[0].title.contains("Private key"));
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].remediation.contains("passphrase"), "a passphrase is not a fix");
    }

    /// Integrity hashes are why a naive entropy scanner is unusable.
    #[test]
    fn hashes_in_a_lockfile_do_not_trigger_the_entropy_heuristic() {
        let lock = r#"{ "integrity": "sha512-Xq9rT2vLp0zWmK4dN7bH3sG6aB2cD4eF5gH6iJ7kL8m" }"#;
        assert!(run(vec![file("package-lock.json", lock)]).is_empty());
    }

    #[test]
    fn a_provider_key_in_a_lockfile_is_still_reported() {
        let lock = r#"{ "resolved": "https://x/AKIAIOSFODNN7REALKEY" }"#;
        let f = run(vec![file("package-lock.json", lock)]);
        assert_eq!(f.len(), 1, "a real key does not become safe by its filename");
    }

    #[test]
    fn a_dotenv_assignment_is_read() {
        let f = run(vec![file(".env", "DATABASE_PASSWORD=9fK2mQ7xR4tZ8vB1nL6y\n")]);
        assert_eq!(f.len(), 1);
        assert!(f[0].title.contains("High-entropy"));
    }

    /// Reading from the environment is the fix, so flagging it would penalise
    /// doing the right thing.
    #[test]
    fn reading_a_credential_from_configuration_is_not_a_finding() {
        let f = run(vec![file(
            "src/db.js",
            "const password = process.env.DB_PASSWORD;\nconst token = `${VAULT_TOKEN}`;",
        )]);
        assert!(f.is_empty(), "got {:?}", f.iter().map(|x| &x.title).collect::<Vec<_>>());
    }

    #[test]
    fn an_example_file_is_reported_but_ranked_below_a_real_source_file() {
        let example = run(vec![file(".env.example", "API_SECRET=9fK2mQ7xR4tZ8vB1nL6y\n")]);
        assert_eq!(example.len(), 1, "an example file is still reported");
        assert_eq!(example[0].severity, Severity::Medium);
        assert!(example[0].description.contains("placeholder"));
        assert!(example[0].ai_triage.as_ref().unwrap().is_false_positive_confidence > 0.4);

        let real = run(vec![file("src/config.js", "const API_SECRET = '9fK2mQ7xR4tZ8vB1nL6y';")]);
        assert!(real[0].ai_triage.as_ref().unwrap().is_false_positive_confidence < 0.4);
    }

    #[test]
    fn a_documented_example_key_is_not_reported() {
        let f = run(vec![file("README.md", "Use AKIAIOSFODNN7EXAMPLE as your key id.")]);
        assert!(f.is_empty(), "the AWS documentation key is not a leak");
    }

    /// The engine must not imply it tested the credential.
    #[test]
    fn the_finding_states_that_validity_was_not_tested() {
        let f = run(vec![file("src/a.js", "const k = 'AKIAIOSFODNN7REALKEY';")]);
        assert!(f[0].description.contains("still valid"));
        assert!(f[0].description.contains("not tested") || f[0].description.contains("was not tested"));
        assert!(
            f[0].description.contains("history"),
            "a committed secret is in the history, and the reader has to know that"
        );
    }

    /// The class an entropy-only scanner misses, and the more common one in
    /// application code.
    #[test]
    fn a_chosen_password_is_reported_and_reads_differently_from_a_generated_key() {
        let f = run(vec![file(
            "config.js",
            "module.exports = { dbPassword: \"super_secret_password_123!\" };",
        )]);
        assert_eq!(f.len(), 1, "got {:?}", f.iter().map(|x| &x.title).collect::<Vec<_>>());
        assert!(f[0].title.contains("Hardcoded password"), "{}", f[0].title);
        assert!(f[0].description.contains("password literal rather than a generated key"));
        assert!(
            f[0].remediation.contains("Change the password on the system"),
            "rotation, not deletion"
        );
        assert!(!f[0].description.contains("super_secret_password_123"), "still masked");
    }

    #[test]
    fn a_provider_match_is_more_confident_than_an_entropy_match() {
        let provider = run(vec![file("a.js", "const k = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';")]);
        let entropy = run(vec![file("b.js", "const apiSecret = '9fK2mQ7xR4tZ8vB1nL6y';")]);
        let conf = |f: &Finding| f.ai_triage.as_ref().unwrap().is_false_positive_confidence;
        assert!(conf(&provider[0]) < conf(&entropy[0]));
    }

    #[test]
    fn assignment_extraction_handles_the_common_syntaxes() {
        let quoted = assignments(r#"const apiKey = "Xq9rT2vLp0zWmK4d";"#);
        assert_eq!(quoted[0].0, "apiKey");
        assert_eq!(quoted[0].1, "Xq9rT2vLp0zWmK4d");

        let json = assignments(r#""client_secret": "Xq9rT2vLp0zWmK4d""#);
        assert_eq!(json[0].0, "client_secret");

        let env = assignments("export API_TOKEN=Xq9rT2vLp0zWmK4d");
        assert_eq!(env[0].0, "API_TOKEN");
    }

    #[tokio::test]
    async fn the_engine_is_always_available_and_needs_no_repository_to_succeed() {
        use chrono::Utc;
        assert!(NativeSecretsAdapter.healthcheck().await.unwrap());
        let target = Target {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            name: "t".into(),
            target_type: "Web App".into(),
            base_url: "https://x.test".into(),
            repo_ref: None,
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: None,
            created_at: Utc::now(),
        };
        assert!(NativeSecretsAdapter.run(&target, "{}").await.unwrap().is_empty());
    }
}
