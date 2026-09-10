//! Sentinel Code — the built-in static analysis engine.
//!
//! Reads a source checkout and reports the weaknesses a compiler would not.
//! Twelve languages, one rule catalog, and an intra-file dataflow pass that
//! decides whether each dangerous call is actually reachable with data somebody
//! else controls.
//!
//! What it will not do is as important as what it will. It does not resolve
//! imports, follow calls between files, or model a framework's routing. Those
//! are the things a whole-program analyser does, and one that does them badly
//! produces confident findings that are wrong — which costs a reviewer more
//! time than reporting nothing would have. Everything here is scoped to what a
//! single file can establish, and every finding says so.
//!
//! SAFETY: reads files. Executes nothing, resolves no dependency, runs no
//! build, opens no socket.

pub mod lang;
pub mod rules;
pub mod taint;

use crate::adapter_trait::ScannerAdapter;
use crate::static_engine::codebase::{self, Codebase, SourceFile, WalkLimits};
use crate::static_engine::engine::CODE;
use crate::static_engine::finding::{self, CodeMatch, Confidence};
use anyhow::Result;
use async_trait::async_trait;
use lang::Language;
use regex::Regex;
use rules::{Mode, SastRule};
use sentinel_core::models::finding::{Finding, FindingKind, Severity};
use sentinel_core::models::target::Target;
use std::collections::HashMap;
use std::sync::OnceLock;
use taint::{Taint, TaintTable};

/// The most occurrences of one rule that go into a report as separate findings.
///
/// A rule that matches in three hundred places is telling the reader one thing —
/// "this pattern is used everywhere" — and three hundred rows say it three
/// hundred times while burying every other finding. Past this the engine keeps
/// counting and says so in the finding it did raise.
const MAX_PER_RULE: usize = 20;

/// A hard ceiling across all rules, so a pathological repository cannot produce
/// a report nobody can open.
const MAX_TOTAL: usize = 600;

pub struct NativeSastAdapter;

#[async_trait]
impl ScannerAdapter for NativeSastAdapter {
    fn name(&self) -> &'static str {
        CODE
    }

    /// Compiled in, so always available.
    async fn healthcheck(&self) -> Result<bool> {
        Ok(true)
    }

    async fn run(&self, target: &Target, _config_json: &str) -> Result<Vec<Finding>> {
        let Some(repo) = target.repo_ref.as_deref().filter(|r| !r.trim().is_empty()) else {
            // Not an error: a URL-only engagement has no source to read, and
            // failing the stage would put a red card on the console for a
            // situation that is entirely normal.
            tracing::info!("Sentinel Code: target has no source repository; nothing to analyse");
            return Ok(Vec::new());
        };

        let target_id = target.id;
        let scan_id = uuid::Uuid::new_v4();
        let root = std::path::PathBuf::from(repo);

        // The walk is synchronous filesystem work; keeping it off the async
        // runtime's worker threads means a large monorepo cannot starve the
        // DAST stages running alongside it.
        let codebase = tokio::task::spawn_blocking(move || {
            codebase::walk(&root, &WalkLimits::default())
        })
        .await??;

        tracing::info!(
            files = codebase.files.len(),
            skipped = codebase.skipped.len(),
            "Sentinel Code: source tree read"
        );

        let mut findings = analyze(&codebase, target_id, scan_id);
        for f in &mut findings {
            sentinel_core::scoring::priority::PriorityScoringEngine::score_and_explain(f);
        }

        tracing::info!(
            finding_count = findings.len(),
            "Sentinel Code: analysis complete"
        );
        Ok(findings)
    }
}

/// Run every applicable rule over every file, and assemble the findings.
pub fn analyze(codebase: &Codebase, target_id: uuid::Uuid, scan_id: uuid::Uuid) -> Vec<Finding> {
    let compiled = compiled_rules();
    let mut per_rule: HashMap<&'static str, Vec<CodeMatch<'_>>> = HashMap::new();
    let mut suppressed: HashMap<&'static str, usize> = HashMap::new();

    for file in &codebase.files {
        let Some(language) = Language::from_extension(&file.extension) else {
            continue;
        };
        // Generated code is somebody else's output and its weaknesses belong to
        // whatever produced it. The secret scanner still reads these files.
        if file.provenance == codebase::Provenance::Generated {
            continue;
        }

        let applicable: Vec<&CompiledRule> = compiled
            .iter()
            .filter(|c| c.rule.languages.contains(&language))
            .filter(|c| c.rule.scan_tests || file.is_authored())
            .collect();
        if applicable.is_empty() {
            continue;
        }

        scan_file(file, language, &applicable, &mut per_rule, &mut suppressed);
    }

    let mut findings = assemble(per_rule, suppressed, target_id, scan_id);
    // Emitted here rather than by the adapter, so that every path which
    // analyses a tree also states what it read. A caller that gets findings
    // without the record could report "nothing found" over a tree the walker
    // barely entered.
    findings.push(coverage_record(codebase, target_id, scan_id));
    findings
}

/// Apply one file's applicable rules, updating the per-rule match lists.
fn scan_file<'a>(
    file: &'a SourceFile,
    language: Language,
    applicable: &[&'static CompiledRule],
    per_rule: &mut HashMap<&'static str, Vec<CodeMatch<'a>>>,
    suppressed: &mut HashMap<&'static str, usize>,
) {
    let mut table = TaintTable::new(language);
    let mut state = lang::CommentState::new(language);

    for (number, line) in file.content.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        // The taint table must see every line, including ones it will not
        // report on — an assignment inside a commented block is not code, but a
        // long line the comment state machine got wrong should still not lose
        // the file's dataflow.
        let is_code = state.is_code(line);
        table.observe(number, line);
        if !is_code {
            continue;
        }
        // A bundler line that slipped past the provenance check would otherwise
        // become an unreadable evidence block.
        if line.len() > 2_000 {
            continue;
        }

        for compiled in applicable {
            let rule = compiled.rule;
            if compiled.suppressors.iter().any(|s| line.contains(s)) {
                continue;
            }
            // An explicit annotation is the analyst's decision, and honouring it
            // is what keeps them from disabling the whole engine instead.
            if is_suppression_annotated(file, number, rule.spec.id) {
                *suppressed.entry(rule.spec.id).or_default() += 1;
                continue;
            }
            let Some(caps) = compiled.pattern.captures(line) else {
                continue;
            };

            let argument = caps
                .name("arg")
                .map(|m| m.as_str())
                .unwrap_or(line);

            let taint = match rule.mode {
                Mode::Always => Taint::Unknown,
                Mode::Tainted => table.classify(number, argument),
            };
            if rule.mode == Mode::Tainted && !taint.is_reportable() {
                continue;
            }

            let entry = per_rule.entry(rule.spec.id).or_default();
            if entry.len() >= MAX_PER_RULE {
                *suppressed.entry(rule.spec.id).or_default() += 1;
                continue;
            }
            entry.push(CodeMatch {
                file: &file.relative,
                line: number,
                snippet: finding::redact_snippet(line),
                detail: describe(rule, &taint, language),
                context: finding::context_lines(&file.content, number, 3),
            });
        }
    }
}

/// Turn the collected matches into findings, applying the global cap.
fn assemble(
    per_rule: HashMap<&'static str, Vec<CodeMatch<'_>>>,
    suppressed: HashMap<&'static str, usize>,
    target_id: uuid::Uuid,
    scan_id: uuid::Uuid,
) -> Vec<Finding> {
    let by_id: HashMap<&str, &SastRule> =
        rules::all().iter().map(|r| (r.spec.id, r)).collect();

    // Severest first, so the global cap drops the least important rather than
    // whatever happened to be last in the map.
    let mut ordered: Vec<(&'static str, Vec<CodeMatch<'_>>)> = per_rule.into_iter().collect();
    ordered.sort_by(|a, b| {
        let sev = |id: &str| by_id.get(id).map(|r| r.spec.score()).unwrap_or(0.0);
        sev(b.0)
            .partial_cmp(&sev(a.0))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(b.0))
    });

    let mut findings = Vec::new();
    for (rule_id, matches) in ordered {
        let Some(rule) = by_id.get(rule_id) else { continue };
        for m in matches {
            if findings.len() >= MAX_TOTAL {
                return findings;
            }
            let mut f = finding::build(&rule.spec, CODE, target_id, scan_id, &m);
            // The engine downgrades its own confidence when the dataflow did
            // not support the rule's claim. A rule does not get to assert more
            // than the analysis established — and the printed label has to move
            // with the number, or the finding says "Firm confidence" beside a
            // sentence admitting the source was never traced.
            if m.detail.contains("could not establish") {
                f.reachability_score = Confidence::Tentative.reachability();
                if let Some(t) = f.ai_triage.as_mut() {
                    t.is_false_positive_confidence = Confidence::Tentative.false_positive_rate();
                    t.triage_notes = Some(format!(
                        "[{} confidence] {} The engine could not trace this argument back to a \
                         request, so it is reported as a construct worth reading rather than as \
                         a demonstrated flow.",
                        Confidence::Tentative.label(),
                        rule.spec.triage_note,
                    ));
                }
            }
            findings.push(f);
        }
        if let Some(extra) = suppressed.get(rule_id).filter(|n| **n > 0) {
            if let Some(last) = findings.last_mut() {
                last.description.push_str(&format!(
                    "\n\nThis pattern matches in {extra} further place(s) not listed \
                     individually. A weakness that appears this many times is usually one \
                     habit rather than {extra} separate decisions, and is best fixed by \
                     changing the shared helper or the lint configuration rather than \
                     line by line."
                ));
            }
        }
    }
    findings
}

/// The sentence that goes in the finding's "Observed:" line.
fn describe(rule: &SastRule, taint: &Taint, language: Language) -> String {
    match rule.mode {
        Mode::Always => format!(
            "{} source; the construct itself is what this rule reports, independently of \
             what is passed to it",
            language.label()
        ),
        Mode::Tainted => format!("{} source — {}", language.label(), taint.describe()),
    }
}

/// Whether the analyst has annotated this line to be ignored.
///
/// Two forms, both on the line itself or the line above:
/// `sentinel:ignore` for everything, `sentinel:ignore SENTINEL-SQLI` for one
/// rule. An engine with no way to say "I looked at this and it is fine" gets
/// turned off wholesale, which is a worse outcome than honouring an annotation.
fn is_suppression_annotated(file: &SourceFile, line_no: usize, rule_id: &str) -> bool {
    let mut lines = file.content.lines();
    let this = lines.clone().nth(line_no.saturating_sub(1)).unwrap_or("");
    let previous = if line_no >= 2 {
        lines.nth(line_no - 2).unwrap_or("")
    } else {
        ""
    };

    [this, previous].iter().any(|text| {
        let Some(idx) = text.to_ascii_lowercase().find("sentinel:ignore") else {
            return false;
        };
        let rest = text[idx + "sentinel:ignore".len()..].trim();
        // A bare annotation covers every rule; a qualified one covers only the
        // rules it names, so a blanket suppression has to be written as one.
        rest.is_empty()
            || rest.starts_with("//")
            || rest.starts_with("#")
            || rest.starts_with("*/")
            || rest.to_ascii_uppercase().contains(rule_id)
    })
}

/// What the engine read, as a scan-information record rather than a weakness.
///
/// "Nothing found" across nine files and across nine thousand are different
/// claims. The DAST engine already reports its reach; a static engine that does
/// not is asking for the same trust without offering the same evidence.
fn coverage_record(codebase: &Codebase, target_id: uuid::Uuid, scan_id: uuid::Uuid) -> Finding {
    let mut by_language: HashMap<&'static str, usize> = HashMap::new();
    let mut authored = 0usize;
    for file in &codebase.files {
        if let Some(l) = Language::from_extension(&file.extension) {
            *by_language.entry(l.label()).or_default() += 1;
            if file.is_authored() {
                authored += 1;
            }
        }
    }
    let mut languages: Vec<(&str, usize)> = by_language.into_iter().collect();
    languages.sort_by_key(|(_, n)| std::cmp::Reverse(*n));

    let breakdown = if languages.is_empty() {
        "no files in a language this engine has rules for".to_string()
    } else {
        languages
            .iter()
            .map(|(l, n)| format!("{l}: {n}"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let unread = if codebase.skipped.is_empty() {
        String::new()
    } else {
        let sample: Vec<String> = codebase
            .skipped
            .iter()
            .take(10)
            .map(|(path, why)| format!("  • {path} — {}", why.describe()))
            .collect();
        format!(
            "\n\n{} file(s) were not read:\n{}{}",
            codebase.skipped.len(),
            sample.join("\n"),
            if codebase.skipped.len() > 10 { "\n  • …" } else { "" }
        )
    };

    let completeness = if codebase.is_complete() {
        "The whole tree was walked.".to_string()
    } else {
        format!(
            "The walk stopped early ({:?}), so part of the tree was not analysed. \
             A clean result here is a statement about what was read, not about the \
             repository.",
            codebase.stopped_because
        )
    };

    let description = format!(
        "Sentinel Code read {} file(s) under {}, of which {authored} are hand-written \
         application source in a language the engine has rules for.\n\n\
         By language — {breakdown}.\n\n\
         {completeness}{unread}\n\n\
         Scope of the analysis: each file is examined on its own. Data is followed from a \
         source to a sink within a single file and within roughly one function body; calls \
         between files, framework routing and dependency-injected behaviour are not \
         modelled. Weaknesses that only exist across a module boundary — an unvalidated \
         value passed through three layers before reaching a query — will not appear here, \
         and are the reason the coverage matrix still marks several test cases as needing \
         manual analysis.",
        codebase.files.len(),
        codebase.root.display(),
    );

    Finding {
        id: uuid::Uuid::new_v4(),
        scan_id,
        target_id,
        title: "Static analysis coverage".to_string(),
        description,
        severity: Severity::Info,
        kind: FindingKind::ScanInformation,
        cvss4: None,
        epss: None,
        kev_listed: false,
        asset_exposure_factor: 1.0,
        reachability_score: 1.0,
        priority_score: 0.0,
        priority_rationale: String::new(),
        cwe_id: None,
        owasp_2025: None,
        wstg_id: None,
        api_top10: None,
        affected_component: codebase.root.display().to_string(),
        evidences: vec![finding::evidence(
            "scan_coverage",
            "Files read",
            &codebase
                .files
                .iter()
                .take(200)
                .map(|f| f.relative.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        )],
        repro_steps: Vec::new(),
        remediation: String::new(),
        references: Vec::new(),
        status: sentinel_core::models::finding::FindingStatus::Open,
        source_tools: vec![CODE.to_string()],
        ai_triage: None,
        created_at: chrono::Utc::now(),
    }
}

// ── Compiled rule cache ──────────────────────────────────────────────────────

pub struct CompiledRule {
    pub rule: &'static SastRule,
    pub pattern: Regex,
    pub suppressors: &'static [&'static str],
}

/// Compile every rule once for the process.
///
/// A rule whose pattern does not compile is dropped rather than allowed to
/// abort a scan; `every_rule_pattern_compiles` in `rules` fails the build long
/// before that could happen on an engagement.
pub fn compiled_rules() -> &'static [CompiledRule] {
    static CACHE: OnceLock<Vec<CompiledRule>> = OnceLock::new();
    CACHE.get_or_init(|| {
        rules::all()
            .iter()
            .filter_map(|rule| {
                Regex::new(rule.pattern)
                    .map_err(|e| tracing::error!(rule = rule.spec.id, error = %e, "rule dropped"))
                    .ok()
                    .map(|pattern| CompiledRule { rule, pattern, suppressors: rule.unless })
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_engine::codebase::{Provenance, SkipReason, WalkStop};
    use std::path::PathBuf;

    fn file(relative: &str, content: &str) -> SourceFile {
        let extension = relative.rsplit('.').next().unwrap_or("").to_string();
        SourceFile {
            path: PathBuf::from(format!("/repo/{relative}")),
            relative: relative.to_string(),
            extension,
            provenance: if relative.contains("test") {
                Provenance::Test
            } else {
                Provenance::Authored
            },
            size_bytes: content.len() as u64,
            content: content.to_string(),
        }
    }

    fn codebase_of(files: Vec<SourceFile>) -> Codebase {
        Codebase {
            root: PathBuf::from("/repo"),
            files,
            skipped: Vec::new(),
            stopped_because: WalkStop::Exhausted,
        }
    }

    fn scan(files: Vec<SourceFile>) -> Vec<Finding> {
        analyze(&codebase_of(files), uuid::Uuid::new_v4(), uuid::Uuid::new_v4())
    }

    fn titles(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.title.as_str()).collect()
    }

    fn has_rule(findings: &[Finding], title_fragment: &str) -> bool {
        findings.iter().any(|f| f.title.contains(title_fragment))
    }

    #[test]
    fn every_rule_compiles_into_the_cache() {
        assert_eq!(
            compiled_rules().len(),
            rules::all().len(),
            "a rule failed to compile and was silently dropped"
        );
    }

    #[test]
    fn a_request_value_concatenated_into_sql_is_reported() {
        let findings = scan(vec![file(
            "src/users.js",
            "app.get('/u', (req, res) => {\n\
             \x20 const id = req.query.id;\n\
             \x20 db.query('SELECT * FROM users WHERE id = ' + id);\n\
             });",
        )]);
        assert!(has_rule(&findings, "SQL query"), "got {:?}", titles(&findings));
        let f = findings.iter().find(|f| f.title.contains("SQL")).unwrap();
        assert_eq!(f.affected_component, "src/users.js:3");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.description.contains("`id` is assigned from"), "{}", f.description);
    }

    /// The single most important property of the engine: a parameterised query
    /// must produce silence.
    #[test]
    fn a_parameterised_query_is_not_reported() {
        let findings = scan(vec![file(
            "src/users.js",
            "const id = req.query.id;\n\
             db.query('SELECT * FROM users WHERE id = $1', [id]);",
        )]);
        assert!(!has_rule(&findings, "SQL query"), "got {:?}", titles(&findings));
    }

    #[test]
    fn a_constant_command_is_not_reported_as_injection() {
        let findings = scan(vec![file("src/ops.py", "os.system('ls -la /tmp')")]);
        assert!(!has_rule(&findings, "Operating-system command"));
    }

    #[test]
    fn a_command_built_from_a_request_value_is_reported() {
        let findings = scan(vec![file(
            "src/ops.py",
            "name = request.args.get('name')\nos.system('convert ' + name)",
        )]);
        assert!(has_rule(&findings, "Operating-system command"), "{:?}", titles(&findings));
    }

    #[test]
    fn a_sanitised_command_is_not_reported() {
        let findings = scan(vec![file(
            "src/ops.py",
            "name = request.args.get('name')\nos.system('convert ' + shlex.quote(name))",
        )]);
        assert!(!has_rule(&findings, "Operating-system command"), "{:?}", titles(&findings));
    }

    #[test]
    fn disabled_tls_verification_is_reported_whatever_its_argument() {
        let findings = scan(vec![file(
            "src/client.js",
            "const agent = new https.Agent({ rejectUnauthorized: false });",
        )]);
        assert!(has_rule(&findings, "TLS certificate verification"), "{:?}", titles(&findings));
        let f = findings.iter().find(|f| f.title.contains("TLS")).unwrap();
        // A configuration fact, so the engine states it at full confidence.
        assert!(f.ai_triage.as_ref().unwrap().is_false_positive_confidence < 0.05);
    }

    #[test]
    fn commented_out_code_produces_nothing() {
        let findings = scan(vec![file(
            "src/a.js",
            "// const agent = new https.Agent({ rejectUnauthorized: false });\n\
             /* rejectUnauthorized: false */\n\
             const x = 1;",
        )]);
        assert!(!has_rule(&findings, "TLS certificate verification"), "{:?}", titles(&findings));
    }

    #[test]
    fn generated_files_are_not_analysed_for_code_weaknesses() {
        let mut f = file("dist/app.js", "const a = new https.Agent({ rejectUnauthorized: false });");
        f.provenance = Provenance::Generated;
        assert!(!has_rule(&scan(vec![f]), "TLS certificate verification"));
    }

    #[test]
    fn test_code_is_excluded_by_default() {
        let findings = scan(vec![file(
            "src/client.test.js",
            "const agent = new https.Agent({ rejectUnauthorized: false });",
        )]);
        assert!(
            !has_rule(&findings, "TLS certificate verification"),
            "a test that disables verification is a test, {:?}",
            titles(&findings)
        );
    }

    /// A rule written for one language must not fire on another that spells a
    /// function the same way.
    #[test]
    fn rules_do_not_leak_across_languages() {
        let findings = scan(vec![file(
            "src/main.rs",
            "let s = format!(\"SELECT * FROM t WHERE a = {}\", x);\nconn.query(&s);",
        )]);
        assert!(!has_rule(&findings, "SQL query"), "Rust has no SQLi rule; {:?}", titles(&findings));
    }

    #[test]
    fn an_ignore_annotation_on_the_line_suppresses_the_finding() {
        let findings = scan(vec![file(
            "src/client.js",
            "const agent = new https.Agent({ rejectUnauthorized: false }); // sentinel:ignore",
        )]);
        assert!(!has_rule(&findings, "TLS certificate verification"));
    }

    #[test]
    fn an_ignore_annotation_on_the_previous_line_also_suppresses() {
        let findings = scan(vec![file(
            "src/client.js",
            "// sentinel:ignore\nconst agent = new https.Agent({ rejectUnauthorized: false });",
        )]);
        assert!(!has_rule(&findings, "TLS certificate verification"));
    }

    /// A blanket suppression must be written as one; naming a different rule
    /// must not silence this one.
    #[test]
    fn a_rule_specific_annotation_only_suppresses_that_rule() {
        let findings = scan(vec![file(
            "src/client.js",
            "const agent = new https.Agent({ rejectUnauthorized: false }); // sentinel:ignore SENTINEL-SQLI",
        )]);
        assert!(
            has_rule(&findings, "TLS certificate verification"),
            "an annotation naming another rule must not hide this one"
        );
    }

    #[test]
    fn repeated_matches_of_one_rule_are_capped_and_the_remainder_is_disclosed() {
        let body = (0..MAX_PER_RULE + 12)
            .map(|i| format!("const a{i} = new https.Agent({{ rejectUnauthorized: false }});"))
            .collect::<Vec<_>>()
            .join("\n");
        let findings = scan(vec![file("src/many.js", &body)]);
        let tls: Vec<_> = findings.iter().filter(|f| f.title.contains("TLS")).collect();
        assert_eq!(tls.len(), MAX_PER_RULE);
        assert!(
            tls.last().unwrap().description.contains("further place(s) not listed"),
            "the reader must be told the list was truncated"
        );
    }

    #[test]
    fn every_scan_records_what_the_engine_actually_read() {
        let findings = scan(vec![file("src/a.js", "const x = 1;")]);
        let record = findings
            .iter()
            .find(|f| f.kind == FindingKind::ScanInformation)
            .expect("a coverage record is always emitted");
        assert_eq!(record.title, "Static analysis coverage");
        assert!(record.description.contains("JavaScript: 1"));
        assert!(
            record.description.contains("examined on its own"),
            "the record must state the analysis's limits"
        );
    }

    #[test]
    fn an_incomplete_walk_is_disclosed_in_the_coverage_record() {
        let mut cb = codebase_of(vec![file("src/a.js", "const x = 1;")]);
        cb.stopped_because = WalkStop::FileCap;
        cb.skipped.push(("big.js".into(), SkipReason::TooLarge(2048)));

        let record = coverage_record(&cb, uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        assert!(record.description.contains("stopped early"));
        assert!(record.description.contains("big.js"));
        assert_eq!(record.kind, FindingKind::ScanInformation, "not a weakness");
    }

    /// A dynamic argument the engine could not trace must not be reported with
    /// the same confidence as one it did.
    #[test]
    fn an_untraced_dynamic_argument_is_downgraded() {
        let traced = scan(vec![file(
            "a.py",
            "name = request.args.get('n')\nos.system('x ' + name)",
        )]);
        let untraced = scan(vec![file("b.py", "os.system('x ' + cfg_value)")]);

        let conf = |fs: &[Finding]| {
            fs.iter()
                .find(|f| f.title.contains("Operating-system"))
                .and_then(|f| f.ai_triage.as_ref())
                .map(|t| t.is_false_positive_confidence)
        };
        let traced_conf = conf(&traced).expect("traced finding");
        let untraced_conf = conf(&untraced).expect("untraced finding");
        assert!(
            untraced_conf > traced_conf,
            "untraced {untraced_conf} should be less certain than traced {traced_conf}"
        );
    }

    /// The printed label has to move with the number. A finding reading
    /// "[Firm confidence]" beside a sentence admitting the source was never
    /// traced is telling the reader two different things.
    #[test]
    fn a_downgraded_finding_says_tentative_rather_than_firm() {
        let note = |fs: &[Finding]| {
            fs.iter()
                .find(|f| f.title.contains("Operating-system"))
                .and_then(|f| f.ai_triage.as_ref())
                .and_then(|t| t.triage_notes.clone())
                .expect("finding with a triage note")
        };

        let untraced = note(&scan(vec![file("b.py", "os.system('x ' + cfg_value)")]));
        assert!(untraced.starts_with("[Tentative confidence]"), "got {untraced}");
        assert!(untraced.contains("could not trace this argument"));

        let traced = note(&scan(vec![file(
            "a.py",
            "name = request.args.get('n')\nos.system('x ' + name)",
        )]));
        assert!(traced.starts_with("[Firm confidence]"), "got {traced}");
    }

    #[tokio::test]
    async fn a_target_with_no_repository_yields_nothing_rather_than_failing() {
        use chrono::Utc;
        let target = Target {
            id: uuid::Uuid::new_v4(),
            project_id: uuid::Uuid::new_v4(),
            name: "url only".into(),
            target_type: "Web App".into(),
            base_url: "https://example.test".into(),
            repo_ref: None,
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: None,
            created_at: Utc::now(),
        };
        let out = NativeSastAdapter.run(&target, "{}").await.unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn the_engine_is_always_available() {
        assert!(NativeSastAdapter.healthcheck().await.unwrap());
        assert_eq!(NativeSastAdapter.name(), CODE);
    }
}
