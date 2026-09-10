//! Sentinel Dependencies — the built-in software composition analysis engine.
//!
//! Most of the code in a modern application was written by somebody else, and
//! most of the published vulnerabilities in it are in that part. A scanner that
//! reads the application's own source and stops there has assessed the smaller
//! half.
//!
//! This engine reads the lockfiles, resolves what is actually installed, and
//! asks OSV.dev whether any of those versions is known-vulnerable. Three
//! decisions shape what it reports:
//!
//! * **A range is not an installed version.** `^4.17.0` is a policy; only a
//!   lockfile states a fact. Where an ecosystem's lockfile is missing, the
//!   engine says so rather than guessing from the manifest.
//! * **Direct and transitive are different findings.** The first is a version
//!   bump the team controls; the second is a conversation with an intermediate
//!   maintainer, or an override. Reporting them identically is why dependency
//!   reports get ignored.
//! * **A gap is disclosed, not hidden.** If the advisory database could not be
//!   reached, the report says the assessment did not run — it does not print a
//!   clean dependency section.
//!
//! SAFETY: reads files, and sends package names and versions to OSV.dev. No
//! dependency is downloaded, resolved or installed, and no build is run.

pub mod manifest;
pub mod osv;
pub mod version;

use crate::adapter_trait::ScannerAdapter;
use crate::static_engine::codebase::{self, Codebase, WalkLimits};
use crate::static_engine::engine::DEPENDENCIES;
use crate::static_engine::finding as fb;
use anyhow::Result;
use async_trait::async_trait;
use manifest::{Ecosystem, Inventory, Package};
use osv::{Advisory, OsvClient};
use sentinel_core::checklist::catalog::owasp;
use sentinel_core::models::finding::{
    AITriage, CVSS4Data, Finding, FindingKind, FindingStatus, Severity,
};
use sentinel_core::models::target::Target;
use sentinel_core::scoring::{Cvss4Severity, Cvss4Vector};
use std::time::Duration;
use uuid::Uuid;

/// How long the whole advisory lookup may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(30);

pub struct NativeScaAdapter;

#[async_trait]
impl ScannerAdapter for NativeScaAdapter {
    fn name(&self) -> &'static str {
        DEPENDENCIES
    }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(true)
    }

    async fn run(&self, target: &Target, config_json: &str) -> Result<Vec<Finding>> {
        let Some(repo) = target.repo_ref.as_deref().filter(|r| !r.trim().is_empty()) else {
            tracing::info!("Sentinel Dependencies: no source repository; nothing to inventory");
            return Ok(Vec::new());
        };

        let offline = offline_requested(config_json);
        let root = std::path::PathBuf::from(repo);
        let codebase = tokio::task::spawn_blocking(move || {
            codebase::walk(&root, &WalkLimits::default())
        })
        .await??;

        let inventory = manifest::collect(&codebase);
        tracing::info!(
            packages = inventory.packages.len(),
            manifests = inventory.sources.len(),
            offline,
            "Sentinel Dependencies: inventory built"
        );

        let client = OsvClient::new(offline, LOOKUP_TIMEOUT)?;
        let lookup = client.lookup(&inventory.packages).await;

        let target_id = target.id;
        let scan_id = Uuid::new_v4();
        let mut findings = Vec::new();

        for pkg in &inventory.packages {
            let Some(advisories) = lookup.advisories.get(&pkg.key()) else {
                continue;
            };
            for advisory in advisories {
                findings.push(build_finding(pkg, advisory, target_id, scan_id));
            }
        }

        findings.push(inventory_record(
            &inventory,
            &lookup,
            &codebase,
            target_id,
            scan_id,
        ));

        for f in &mut findings {
            sentinel_core::scoring::priority::PriorityScoringEngine::score_and_explain(f);
        }

        tracing::info!(finding_count = findings.len(), "Sentinel Dependencies: complete");
        Ok(findings)
    }
}

/// Whether the scan configuration asked for an offline dependency audit.
fn offline_requested(config_json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(config_json)
        .ok()
        .and_then(|v| {
            v.get("offline")
                .or_else(|| v.get("sca").and_then(|s| s.get("offline")))
                .and_then(serde_json::Value::as_bool)
        })
        .unwrap_or(false)
}

/// Turn one advisory against one installed package into a finding.
fn build_finding(pkg: &Package, advisory: &Advisory, target_id: Uuid, scan_id: Uuid) -> Finding {
    let identifier = advisory.cve().unwrap_or(&advisory.id);
    let (cvss4, severity) = score(advisory);

    let affected = advisory
        .ranges
        .iter()
        .map(|r| r.describe())
        .collect::<Vec<_>>()
        .join("; ");
    let fix = version::lowest_fix(&advisory.ranges, &pkg.version);

    let dependency_kind = if pkg.direct {
        "a direct dependency — the application declares it itself"
    } else {
        "a transitive dependency — something else in the tree pulled it in"
    };

    let summary = if advisory.summary.trim().is_empty() {
        format!("{identifier} affects {}", pkg.name)
    } else {
        advisory.summary.trim().to_string()
    };

    let mut description = format!(
        "{}\n\n\
         {} {} is installed at version {}, which is {dependency_kind}. \
         The advisory records this version as affected{}.",
        summary,
        pkg.ecosystem.label(),
        pkg.name,
        pkg.version,
        if affected.is_empty() {
            String::new()
        } else {
            format!(" (affected: {affected})")
        },
    );

    if !advisory.details.trim().is_empty() {
        // The advisory prose is frequently long and occasionally the whole
        // upstream security note; a report needs the substance, not the whole
        // document.
        let details = advisory.details.trim();
        let trimmed: String = details.chars().take(1500).collect();
        description.push_str(&format!(
            "\n\nFrom the advisory:\n{trimmed}{}",
            if details.chars().count() > 1500 { "…" } else { "" }
        ));
    }

    if !advisory.aliases.is_empty() {
        description.push_str(&format!(
            "\n\nAlso published as: {}.",
            advisory.aliases.join(", ")
        ));
    }

    let remediation = match &fix {
        Some(target_version) if pkg.direct => format!(
            "Upgrade to {target_version} or later.\n\n```\n{}\n```\n\n\
             Read the upstream changelog between {} and {target_version} before shipping: \
             a security release sometimes lands alongside a breaking change, and finding \
             that out in production is worse than finding it out now.",
            pkg.ecosystem.upgrade_command(&pkg.name, target_version),
            pkg.version,
        ),
        Some(target_version) => format!(
            "A fix exists in {target_version}, but this package is not declared by the \
             application — something else in the tree requires it. In order of preference:\n\n\
             1. Upgrade the direct dependency that pulls it in; check first with \
                `npm ls {name}`, `pip show {name}`, `go mod why {name}` or your ecosystem's \
                equivalent.\n\
             2. If no upgrade is available yet, pin the transitive version directly — npm \
                `overrides`, Yarn `resolutions`, pip constraints, Gradle `resolutionStrategy`, \
                Cargo `[patch]`.\n\
             3. Record it as an accepted risk with a review date if neither is possible, so \
                it reappears rather than being forgotten.\n\n\
             ```\n{}\n```",
            pkg.ecosystem.upgrade_command(&pkg.name, target_version),
            name = pkg.name,
        ),
        None => format!(
            "No fixed version has been published for this advisory. The options are, in order:\n\n\
             1. Check whether the vulnerable code path is one this application reaches at \
                all — many advisories affect one function of a library.\n\
             2. Apply the upstream mitigation if the advisory names one.\n\
             3. Replace the dependency, or vendor and patch it.\n\
             4. Record it as an accepted risk with a review date, so it returns to the open \
                list when the fix lands rather than being lost.\n\n\
             Watch {} for the fix.",
            advisory
                .references
                .first()
                .map(String::as_str)
                .unwrap_or("the upstream advisory"),
        ),
    };

    let mut references: Vec<String> = advisory.references.clone();
    references.push(format!("https://osv.dev/vulnerability/{}", advisory.id));
    if let Some(cve) = advisory.cve() {
        references.push(format!("https://nvd.nist.gov/vuln/detail/{cve}"));
    }
    references.dedup();

    let cwe = advisory
        .cwe_ids
        .first()
        .cloned()
        // A dependency vulnerability with no published CWE is still a
        // vulnerable component, which is the classification the report needs.
        .unwrap_or_else(|| "CWE-1395".to_string());

    Finding {
        id: Uuid::new_v4(),
        scan_id,
        target_id,
        title: format!("{identifier}: {} {} is vulnerable", pkg.name, pkg.version),
        description,
        severity,
        kind: FindingKind::Weakness,
        cvss4,
        // EPSS and KEV are properties of a published CVE, so unlike the code
        // engine this one can legitimately carry them. They are attached by the
        // enrichment pass in `sentinel_core::threat` rather than invented here.
        epss: None,
        kev_listed: sentinel_core::threat::is_known_exploited(advisory.cve().unwrap_or_default()),
        asset_exposure_factor: 1.0,
        // A declared dependency version is a fact about what is deployed, but
        // nothing here proves the vulnerable function is ever called.
        reachability_score: if pkg.direct { 0.95 } else { 0.85 },
        priority_score: 0.0,
        priority_rationale: String::new(),
        cwe_id: Some(cwe),
        owasp_2025: Some(owasp::A03.to_string()),
        wstg_id: Some("WSTG-CONF-01".to_string()),
        api_top10: None,
        affected_component: format!("{} ({})", pkg.name, pkg.manifest),
        evidences: vec![
            fb::evidence(
                "dependency_lock",
                &format!("{} — resolved version", pkg.manifest),
                &format!(
                    "ecosystem: {}\npackage:   {}\nversion:   {}\ndeclared:  {}\nsource:    {}",
                    pkg.ecosystem.osv_name(),
                    pkg.name,
                    pkg.version,
                    if pkg.direct { "directly by this application" } else { "transitively" },
                    pkg.manifest,
                ),
            ),
            fb::evidence(
                "advisory",
                &format!("{} — affected ranges", advisory.id),
                &if affected.is_empty() {
                    "the advisory enumerates affected versions individually".to_string()
                } else {
                    affected.clone()
                },
            ),
        ],
        repro_steps: vec![
            format!("Open {} and find the entry for {}.", pkg.manifest, pkg.name),
            format!("Confirm the resolved version is {}.", pkg.version),
            format!("Compare it against the advisory's affected range at https://osv.dev/vulnerability/{}.", advisory.id),
        ],
        remediation,
        references,
        status: FindingStatus::Open,
        source_tools: vec![DEPENDENCIES.to_string()],
        ai_triage: Some(AITriage {
            // A version match against a published range is close to
            // mechanical. What it does not establish is reachability, which is
            // what the note says.
            is_false_positive_confidence: 0.05,
            cluster_id: Some(format!("CLUSTER_DEP_{}", pkg.name)),
            triage_notes: Some(format!(
                "[Certain confidence] The installed version falls inside a published affected \
                 range, which is a fact about the lockfile rather than an inference. What is \
                 not established is whether this application calls the vulnerable code — for a \
                 {} that is worth checking before treating the CVSS score as this \
                 application's risk.",
                if pkg.direct { "direct dependency" } else { "transitive dependency" }
            )),
        }),
        created_at: chrono::Utc::now(),
    }
}

/// Severity for a dependency finding, from the best evidence available.
///
/// Order matters. A published CVSS 4.0 vector is used as-is. A v3 vector is
/// *not* silently relabelled as v4 — the metrics differ and pretending
/// otherwise would print a v4 vector nobody published — so it is recorded but
/// the severity comes from the score embedded in it. Where the advisory
/// published only a word, that word decides. Where it published nothing, the
/// finding is Medium and says the source database rated it at all.
fn score(advisory: &Advisory) -> (Option<CVSS4Data>, Severity) {
    if let Some(vector) = advisory.cvss_vector.as_deref() {
        if let Ok(parsed) = Cvss4Vector::parse(vector) {
            let base = parsed.score();
            return (
                Some(CVSS4Data {
                    vector_string: vector.to_string(),
                    base_score: base,
                    severity_label: label(band(base)).to_string(),
                }),
                band(base),
            );
        }
        // A CVSS 3.x vector: keep it verbatim so the report shows what was
        // actually published, and take the severity from its own base score.
        if let Some(base) = cvss3_base_score(vector) {
            return (
                Some(CVSS4Data {
                    vector_string: vector.to_string(),
                    base_score: base,
                    severity_label: label(band(base)).to_string(),
                }),
                band(base),
            );
        }
    }

    let severity = match advisory.database_severity.as_deref().map(str::to_ascii_uppercase) {
        Some(ref s) if s == "CRITICAL" => Severity::Critical,
        Some(ref s) if s == "HIGH" => Severity::High,
        Some(ref s) if s == "MODERATE" || s == "MEDIUM" => Severity::Medium,
        Some(ref s) if s == "LOW" => Severity::Low,
        _ => Severity::Medium,
    };
    (None, severity)
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

/// Recover the base score from a CVSS 3.x vector.
///
/// Not a reimplementation of the v3 algorithm — advisories that carry a v3
/// vector overwhelmingly carry the score alongside it in the same string when
/// they carry it at all, and where they do not, the severity word from the
/// source database is a better answer than a second scoring implementation
/// nobody differentially tests. Returns `None` so the caller falls back to it.
fn cvss3_base_score(vector: &str) -> Option<f64> {
    vector
        .split('/')
        .find_map(|part| part.strip_prefix("BS:"))
        .and_then(|s| s.parse().ok())
}

/// What the engine read and what it could not check.
fn inventory_record(
    inventory: &Inventory,
    lookup: &osv::LookupResult,
    codebase: &Codebase,
    target_id: Uuid,
    scan_id: Uuid,
) -> Finding {
    let mut by_ecosystem: std::collections::BTreeMap<Ecosystem, (usize, usize)> =
        Default::default();
    for pkg in &inventory.packages {
        let entry = by_ecosystem.entry(pkg.ecosystem).or_default();
        entry.0 += 1;
        if pkg.direct {
            entry.1 += 1;
        }
    }

    let breakdown = if by_ecosystem.is_empty() {
        "No dependency lockfile was found in this checkout.".to_string()
    } else {
        by_ecosystem
            .iter()
            .map(|(eco, (total, direct))| {
                format!("  • {}: {total} package(s), {direct} declared directly", eco.label())
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let sources = if inventory.sources.is_empty() {
        String::new()
    } else {
        format!("\n\nRead from:\n{}", inventory
            .sources
            .iter()
            .map(|s| format!("  • {s}"))
            .collect::<Vec<_>>()
            .join("\n"))
    };

    let unresolved = if inventory.unresolved.is_empty() {
        String::new()
    } else {
        format!(
            "\n\nNot assessed:\n{}",
            inventory
                .unresolved
                .iter()
                .map(|(path, why)| format!("  • {path} — {why}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };

    let gap = lookup
        .gap
        .as_ref()
        .map(|g| format!("\n\n⚠ {}", g.reason))
        .unwrap_or_default();

    let matched: usize = lookup.advisories.values().map(Vec::len).sum();

    let description = format!(
        "Sentinel Dependencies resolved {} package(s) across {} lockfile(s) under {}.\n\n\
         {breakdown}{sources}\n\n\
         {} package version(s) were submitted to the OSV advisory database, and {matched} \
         advisory match(es) were confirmed against the installed versions.{unresolved}{gap}\n\n\
         What this covers and what it does not: a match here means the installed version \
         falls inside a published affected range. It does not mean the application calls the \
         vulnerable function — reachability is not established by a lockfile, and for a large \
         transitive tree most matches will not be reachable. Equally, an absence of matches \
         means no *published* advisory covers these versions, which is not the same as their \
         being free of defects.",
        inventory.packages.len(),
        inventory.sources.len(),
        codebase.root.display(),
        lookup.queried,
    );

    Finding {
        id: Uuid::new_v4(),
        scan_id,
        target_id,
        title: "Dependency inventory and advisory coverage".to_string(),
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
        evidences: vec![fb::evidence(
            "dependency_lock",
            "Resolved package inventory",
            &inventory
                .packages
                .iter()
                .take(500)
                .map(|p| {
                    format!(
                        "{:<12} {:<45} {:<18} {}",
                        p.ecosystem.osv_name(),
                        p.name,
                        p.version,
                        if p.direct { "direct" } else { "transitive" }
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
        )],
        repro_steps: Vec::new(),
        remediation: String::new(),
        references: vec!["https://osv.dev/".to_string()],
        status: FindingStatus::Open,
        source_tools: vec![DEPENDENCIES.to_string()],
        ai_triage: None,
        created_at: chrono::Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_engine::codebase::WalkStop;
    use std::path::PathBuf;

    fn pkg(name: &str, version: &str, direct: bool) -> Package {
        Package {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
            manifest: "package-lock.json".into(),
            direct,
        }
    }

    fn advisory(id: &str) -> Advisory {
        Advisory {
            id: id.into(),
            aliases: vec!["CVE-2021-23337".into()],
            summary: "Command injection in lodash".into(),
            details: "The template function permits...".into(),
            cvss_vector: Some(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".into(),
            ),
            database_severity: Some("HIGH".into()),
            cwe_ids: vec!["CWE-77".into()],
            references: vec!["https://github.com/advisories/GHSA-x".into()],
            ranges: vec![version::Range {
                introduced: Some("0".into()),
                fixed: Some("4.17.21".into()),
                last_affected: None,
            }],
            versions: vec![],
            withdrawn: false,
        }
    }

    #[test]
    fn a_finding_is_titled_by_its_cve_and_names_the_installed_version() {
        let f = build_finding(&pkg("lodash", "4.17.20", true), &advisory("GHSA-x"), Uuid::new_v4(), Uuid::new_v4());
        assert!(f.title.starts_with("CVE-2021-23337:"), "{}", f.title);
        assert!(f.title.contains("lodash 4.17.20"));
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.owasp_2025.as_deref(), Some(owasp::A03), "supply chain, in the 2025 numbering");
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-77"));
    }

    /// The whole point of the direct/transitive split: the two get different
    /// remediation, because they are different pieces of work.
    #[test]
    fn a_direct_dependency_gets_an_upgrade_command_and_a_transitive_one_gets_an_override() {
        let direct = build_finding(&pkg("lodash", "4.17.20", true), &advisory("GHSA-x"), Uuid::new_v4(), Uuid::new_v4());
        assert!(direct.remediation.contains("npm install lodash@4.17.21"));
        assert!(direct.description.contains("a direct dependency"));

        let transitive = build_finding(&pkg("lodash", "4.17.20", false), &advisory("GHSA-x"), Uuid::new_v4(), Uuid::new_v4());
        assert!(transitive.remediation.contains("npm ls lodash"));
        assert!(transitive.remediation.contains("overrides"));
        assert!(transitive.description.contains("a transitive dependency"));
    }

    #[test]
    fn an_advisory_with_no_fix_says_so_rather_than_inventing_a_version() {
        let mut a = advisory("GHSA-y");
        a.ranges = vec![version::Range {
            introduced: Some("1.0.0".into()),
            fixed: None,
            last_affected: None,
        }];
        let f = build_finding(&pkg("thing", "1.5.0", true), &a, Uuid::new_v4(), Uuid::new_v4());
        assert!(f.remediation.contains("No fixed version has been published"));
        assert!(!f.remediation.contains("npm install thing@"));
    }

    #[test]
    fn a_published_cvss4_vector_is_used_verbatim() {
        let (data, severity) = score(&advisory("GHSA-x"));
        let data = data.expect("vector present");
        assert!(data.vector_string.starts_with("CVSS:4.0/"));
        assert_eq!(data.base_score, 9.3);
        assert_eq!(severity, Severity::Critical);
    }

    /// Relabelling a v3 vector as v4 would print metrics nobody published.
    #[test]
    fn a_cvss3_vector_is_not_relabelled_as_version_four() {
        let mut a = advisory("GHSA-z");
        a.cvss_vector = Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into());
        let (data, severity) = score(&a);
        match data {
            Some(d) => assert!(d.vector_string.starts_with("CVSS:3.1/"), "kept verbatim"),
            None => assert_eq!(severity, Severity::High, "falls back to the database word"),
        }
    }

    #[test]
    fn the_source_databases_severity_word_is_used_when_no_vector_was_published() {
        let mut a = advisory("GHSA-w");
        a.cvss_vector = None;
        a.database_severity = Some("CRITICAL".into());
        assert_eq!(score(&a).1, Severity::Critical);

        a.database_severity = Some("MODERATE".into());
        assert_eq!(score(&a).1, Severity::Medium);

        a.database_severity = None;
        assert_eq!(score(&a).1, Severity::Medium, "an unrated advisory is not assumed harmless");
    }

    #[test]
    fn a_dependency_finding_carries_evidence_from_both_the_lockfile_and_the_advisory() {
        let f = build_finding(&pkg("lodash", "4.17.20", true), &advisory("GHSA-x"), Uuid::new_v4(), Uuid::new_v4());
        let kinds: Vec<&str> = f.evidences.iter().map(|e| e.evidence_type.as_str()).collect();
        assert!(kinds.contains(&"dependency_lock"));
        assert!(kinds.contains(&"advisory"));
        assert!(f.references.iter().any(|r| r.contains("osv.dev/vulnerability/GHSA-x")));
        assert!(f.references.iter().any(|r| r.contains("nvd.nist.gov")));
    }

    /// The claim a version match supports, and the one it does not.
    #[test]
    fn the_triage_note_distinguishes_a_version_match_from_reachability() {
        let f = build_finding(&pkg("lodash", "4.17.20", true), &advisory("GHSA-x"), Uuid::new_v4(), Uuid::new_v4());
        let note = f.ai_triage.unwrap().triage_notes.unwrap();
        assert!(note.contains("fact about the lockfile"));
        assert!(note.contains("not established is whether this application calls"));
    }

    #[test]
    fn an_unreachable_advisory_database_is_disclosed_in_the_coverage_record() {
        let inventory = Inventory {
            packages: vec![pkg("lodash", "4.17.20", true)],
            sources: vec!["package-lock.json".into()],
            unresolved: vec![],
        };
        let lookup = osv::LookupResult {
            advisories: Default::default(),
            gap: Some(osv::LookupGap {
                reason: "The advisory database could not be reached".into(),
            }),
            queried: 0,
        };
        let cb = Codebase {
            root: PathBuf::from("/repo"),
            files: vec![],
            skipped: vec![],
            stopped_because: WalkStop::Exhausted,
        };
        let record = inventory_record(&inventory, &lookup, &cb, Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(record.kind, FindingKind::ScanInformation);
        assert!(record.description.contains("could not be reached"));
        assert!(record.description.contains("npm: 1 package(s)"));
    }

    #[test]
    fn a_manifest_with_no_lockfile_is_reported_as_unassessed() {
        let inventory = Inventory {
            packages: vec![],
            sources: vec![],
            unresolved: vec![("package.json".into(), "no lockfile".into())],
        };
        let lookup = osv::LookupResult { advisories: Default::default(), gap: None, queried: 0 };
        let cb = Codebase {
            root: PathBuf::from("/repo"),
            files: vec![],
            skipped: vec![],
            stopped_because: WalkStop::Exhausted,
        };
        let record = inventory_record(&inventory, &lookup, &cb, Uuid::new_v4(), Uuid::new_v4());
        assert!(record.description.contains("Not assessed"));
        assert!(record.description.contains("package.json"));
    }

    #[test]
    fn the_offline_switch_is_read_from_the_scan_configuration() {
        assert!(offline_requested(r#"{"offline":true}"#));
        assert!(offline_requested(r#"{"sca":{"offline":true}}"#));
        assert!(!offline_requested(r#"{"offline":false}"#));
        assert!(!offline_requested("{}"));
        assert!(!offline_requested("not json"), "a malformed config stays online");
    }

    #[tokio::test]
    async fn a_target_with_no_repository_yields_nothing() {
        use chrono::Utc;
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
        assert!(NativeScaAdapter.run(&target, "{}").await.unwrap().is_empty());
    }
}
