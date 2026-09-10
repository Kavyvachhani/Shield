//! Scan profiles — a saved answer to "how should this scan be run?".
//!
//! Configuring a scan means deciding which of fifteen engines to run, how hard
//! to crawl, how fast to send requests and whether to reach the network for
//! advisories. Those decisions are not per-target, they are per *kind of work*:
//! a quick triage before a call, a full assessment for a report, a source-only
//! review with no live traffic at all. Making them again from scratch every
//! time is how an analyst ends up leaving DAST off by accident on the run that
//! mattered.
//!
//! A profile is that set of decisions, named and reusable. Six ship built in,
//! covering the shapes of engagement the tool is actually used for; the analyst
//! can save their own, and can save one derived from a built-in preset with two
//! settings changed. Built-in profiles cannot be edited or deleted — an analyst
//! who has changed "Full assessment" to skip DAST and forgotten still expects
//! it to mean what it says.

use crate::state::{new_id, AppState, ScanProfileRecord};
use chrono::Utc;
use serde::Deserialize;
use tauri::State;

/// Every stage the pipeline knows how to run, in the order it runs them.
///
/// The single source of truth for what a profile may enable — a profile naming
/// a stage that does not exist would silently do nothing, and one that omits a
/// stage added later would silently stop running it.
pub const ALL_STAGES: &[&str] = &[
    // Built-in static engines — compiled in, always available.
    "code", "dependencies", "secrets", "infrastructure",
    // External static engines — skipped when the binary is absent.
    "semgrep", "trivy", "gitleaks", "osv", "trufflehog", "retirejs", "checkov",
    // Passive reconnaissance: reaches third-party data sources, never the
    // target, so it is not gated.
    "recon",
    // Live engines — every one of these is behind the RoE gate.
    "native", "zap_dast", "nuclei_dast", "nikto_dast", "testssl_dast",
];

/// Stages that read local files only.
pub const STATIC_STAGES: &[&str] = &[
    "code", "dependencies", "secrets", "infrastructure",
    "semgrep", "trivy", "gitleaks", "osv", "trufflehog", "retirejs", "checkov",
    "recon",
];

/// Stages that issue requests to the target, and are therefore gated.
pub const LIVE_STAGES: &[&str] = &[
    "native", "zap_dast", "nuclei_dast", "nikto_dast", "testssl_dast",
];

/// Stages that need no installed binary.
pub const BUILTIN_STAGES: &[&str] = &["code", "dependencies", "secrets", "infrastructure", "native"];

/// A built-in profile, before it becomes a record.
struct Preset {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    stages: &'static [&'static str],
    run_dast: bool,
    config_json: &'static str,
}

/// The profiles that ship with the application.
///
/// Each one answers a question somebody actually asks, and the description says
/// what it will and will not tell them — a profile whose limits are not stated
/// produces a report whose silence gets over-read.
const PRESETS: &[Preset] = &[
    Preset {
        id: "builtin-quick",
        name: "Quick triage",
        description:
            "The fastest useful answer. Runs only the engines compiled into the application \
             — code, dependencies, secrets, infrastructure and the live check engine — with a \
             shallow crawl and a gentle request rate. Finds configuration and known-pattern \
             weaknesses in a couple of minutes. It will not find anything that needs a deep \
             crawl or a third-party scanner, so a clean result here is a starting point, not \
             a conclusion.",
        stages: BUILTIN_STAGES,
        run_dast: true,
        config_json: r#"{"crawl":{"enabled":true,"maxPages":25,"maxDepth":2,"budgetSeconds":90,"maxLinksPerPage":40},"requestsPerSecond":3,"timeoutSeconds":10}"#,
    },
    Preset {
        id: "builtin-full",
        name: "Full assessment",
        description:
            "Everything, for the run a report is written from. Every built-in engine plus \
             every external scanner that is installed, a deep crawl, and the full live check \
             set. Expect this to take a while on a large application: the crawl is bounded by \
             page count and wall clock rather than by patience. Engines that are not installed \
             are skipped and recorded as coverage gaps rather than silently omitted.",
        stages: ALL_STAGES,
        run_dast: true,
        config_json: r#"{"crawl":{"enabled":true,"maxPages":400,"maxDepth":6,"budgetSeconds":900,"maxLinksPerPage":150},"requestsPerSecond":5,"timeoutSeconds":20}"#,
    },
    Preset {
        id: "builtin-code-review",
        name: "Source code review",
        description:
            "Reads the repository and sends nothing to the target. No live request is issued, \
             so this needs no signed Rules of Engagement and can be run against a checkout of \
             a system you are not authorised to test. Covers code, dependencies, secrets and \
             infrastructure, plus Semgrep, Trivy, Gitleaks, OSV-Scanner, TruffleHog and \
             Checkov where they are installed.",
        stages: STATIC_STAGES,
        run_dast: false,
        config_json: r#"{"crawl":{"enabled":false}}"#,
    },
    Preset {
        id: "builtin-perimeter",
        name: "External perimeter",
        description:
            "The live half only: the built-in check engine, ZAP, Nuclei, Nikto and testssl.sh. \
             For a target whose source you do not have, or an assessment scoped to what is \
             reachable from outside. Requires a signed Rules of Engagement, like every profile \
             that sends a request.",
        stages: &["recon", "native", "zap_dast", "nuclei_dast", "nikto_dast", "testssl_dast"],
        run_dast: true,
        config_json: r#"{"crawl":{"enabled":true,"maxPages":250,"maxDepth":5,"budgetSeconds":600,"maxLinksPerPage":120},"requestsPerSecond":5,"timeoutSeconds":20}"#,
    },
    Preset {
        id: "builtin-supply-chain",
        name: "Dependencies and supply chain",
        description:
            "What the application ships that it did not write: resolved dependency versions \
             matched against published advisories, committed credentials, and the \
             infrastructure the whole thing is deployed from. Runs the built-in dependency, \
             secret and infrastructure engines alongside Trivy, OSV-Scanner, retire.js, \
             TruffleHog and Checkov. No live traffic.",
        stages: &["dependencies", "secrets", "infrastructure", "trivy", "osv", "retirejs", "trufflehog", "checkov"],
        run_dast: false,
        config_json: r#"{"crawl":{"enabled":false}}"#,
    },
    Preset {
        id: "builtin-air-gapped",
        name: "Offline / air-gapped",
        description:
            "For a machine with no outbound network at all. Runs every static engine with the \
             advisory lookup switched off, so the dependency inventory is still built and \
             reported but nothing in it is checked against a vulnerability database — the \
             report says so explicitly rather than showing an empty dependency section. \
             Install Trivy for an offline advisory database if you need that half answered too.",
        stages: STATIC_STAGES,
        run_dast: false,
        config_json: r#"{"offline":true,"crawl":{"enabled":false}}"#,
    },
];

/// The built-in profiles as records.
pub fn builtin_profiles() -> Vec<ScanProfileRecord> {
    PRESETS
        .iter()
        .map(|p| ScanProfileRecord {
            id: p.id.to_string(),
            name: p.name.to_string(),
            description: p.description.to_string(),
            builtin: true,
            run_dast: p.run_dast,
            enabled_stages: p.stages.iter().map(|s| s.to_string()).collect(),
            config_json: p.config_json.to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .collect()
}

/// Built-in profiles first, then the analyst's own, newest last.
#[tauri::command]
pub async fn list_scan_profiles(
    state: State<'_, AppState>,
) -> Result<Vec<ScanProfileRecord>, String> {
    let mut out = builtin_profiles();
    let saved = state.scan_profiles.read().await;
    let mut mine: Vec<ScanProfileRecord> = saved.values().cloned().collect();
    mine.sort_by_key(|a| a.created_at);
    out.extend(mine);
    Ok(out)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveScanProfileInput {
    /// Present when updating one of the analyst's own profiles.
    pub id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub run_dast: bool,
    pub enabled_stages: Vec<String>,
    pub config_json: String,
}

/// Create or update a profile.
///
/// Validates rather than trusting: a stage name that does not exist would
/// silently never run, and malformed configuration JSON would fail at scan
/// time — after the analyst had signed the RoE and pressed start.
#[tauri::command]
pub async fn save_scan_profile(
    input: SaveScanProfileInput,
    state: State<'_, AppState>,
) -> Result<ScanProfileRecord, String> {
    let name = input.name.trim().to_string();
    if name.is_empty() {
        return Err("A profile needs a name so it can be told apart from the others.".into());
    }
    if let Some(id) = input.id.as_deref() {
        if id.starts_with("builtin-") {
            return Err(
                "The built-in profiles cannot be edited — an analyst who picks \"Full \
                 assessment\" expects it to mean what it says. Save this as a new profile \
                 instead."
                    .into(),
            );
        }
    }

    let unknown: Vec<&String> = input
        .enabled_stages
        .iter()
        .filter(|s| !ALL_STAGES.contains(&s.as_str()))
        .collect();
    if !unknown.is_empty() {
        return Err(format!(
            "This profile names {} engine(s) that do not exist: {}. A profile with an unknown \
             engine in it would run one fewer stage than it appears to.",
            unknown.len(),
            unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    if input.enabled_stages.is_empty() {
        return Err("A profile with no engines enabled would produce an empty report.".into());
    }
    serde_json::from_str::<serde_json::Value>(&input.config_json).map_err(|e| {
        format!(
            "The scan configuration is not valid JSON, so the scan would fail after the RoE \
             was signed rather than now: {e}"
        )
    })?;

    // A profile enabling only live stages while `runDast` is off would run
    // nothing at all and report a clean result.
    if !input.run_dast
        && input.enabled_stages.iter().all(|s| LIVE_STAGES.contains(&s.as_str()))
    {
        return Err(
            "Every engine in this profile is a live one, but dynamic testing is switched off, \
             so the scan would run nothing. Either enable dynamic testing or add a static \
             engine."
                .into(),
        );
    }

    let now = Utc::now();
    let mut profiles = state.scan_profiles.write().await;
    let record = match input.id.as_deref().and_then(|id| profiles.get(id).cloned()) {
        Some(existing) => ScanProfileRecord {
            name,
            description: input.description.unwrap_or_default(),
            run_dast: input.run_dast,
            enabled_stages: input.enabled_stages,
            config_json: input.config_json,
            updated_at: now,
            ..existing
        },
        None => ScanProfileRecord {
            id: new_id(),
            name,
            description: input.description.unwrap_or_default(),
            builtin: false,
            run_dast: input.run_dast,
            enabled_stages: input.enabled_stages,
            config_json: input.config_json,
            created_at: now,
            updated_at: now,
        },
    };

    state
        .store
        .save_scan_profile(&record)
        .map_err(|e| format!("The profile could not be saved to disk: {e}"))?;
    profiles.insert(record.id.clone(), record.clone());
    Ok(record)
}

#[tauri::command]
pub async fn delete_scan_profile(
    profile_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if profile_id.starts_with("builtin-") {
        return Err("The built-in profiles cannot be deleted.".into());
    }
    state
        .store
        .delete_scan_profile(&profile_id)
        .map_err(|e| format!("The profile could not be removed from disk: {e}"))?;
    state.scan_profiles.write().await.remove(&profile_id);
    Ok(())
}

/// One engine, described for the profile editor.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineDescriptor {
    pub stage: String,
    pub label: String,
    /// "builtin" | "external" | "live"
    pub category: String,
    /// True when the engine ships inside the application.
    pub built_in: bool,
    /// True when the engine sends requests to the target.
    pub reaches_target: bool,
    /// What it does, and what it needs.
    pub description: String,
    /// The binary that must be on PATH, for the engines that need one.
    pub requires_binary: Option<String>,
}

/// Everything the profile editor needs to describe the engine list.
///
/// Returned from the backend rather than hardcoded in the UI so that adding an
/// engine cannot leave the picker showing the old list.
#[tauri::command]
pub fn list_engines() -> Vec<EngineDescriptor> {
    ALL_STAGES.iter().map(|stage| descriptor(stage)).collect()
}

fn descriptor(stage: &str) -> EngineDescriptor {
    let (label, description, binary) = match stage {
        "code" => (
            "Sentinel Code",
            "Built-in source analysis across twelve languages, with intra-file dataflow so a \
             dangerous call is reported when untrusted data actually reaches it.",
            None,
        ),
        "dependencies" => (
            "Sentinel Dependencies",
            "Built-in lockfile resolution across nine ecosystems, matched against the OSV \
             advisory database. Needs network access for the advisory lookup; without it the \
             inventory is still built and the gap is reported.",
            None,
        ),
        "secrets" => (
            "Sentinel Secrets",
            "Built-in credential detection by provider format and by entropy. Never prints \
             what it finds, and never tests whether a credential still authenticates.",
            None,
        ),
        "infrastructure" => (
            "Sentinel Infrastructure",
            "Built-in analysis of Dockerfiles, Compose files, Kubernetes manifests, Terraform \
             and CI workflows.",
            None,
        ),
        "semgrep" => (
            "Semgrep",
            "Source analysis against Semgrep's public rule registry — far broader than the \
             built-in catalog, and complementary to it.",
            Some("semgrep"),
        ),
        "trivy" => (
            "Trivy",
            "Dependency and container vulnerabilities from Aqua's database, which works \
             offline once its database is cached.",
            Some("trivy"),
        ),
        "gitleaks" => ("Gitleaks", "Credential detection across the git history, not just the working tree.", Some("gitleaks")),
        "osv" => (
            "OSV-Scanner",
            "A second advisory database. Two databases disagreeing usefully is the reason to \
             run both.",
            Some("osv-scanner"),
        ),
        "trufflehog" => (
            "TruffleHog",
            "Asks the provider whether a discovered credential still authenticates. This is \
             the one engine that makes a live request on a credential's behalf.",
            Some("trufflehog"),
        ),
        "retirejs" => ("retire.js", "Vulnerable JavaScript libraries in what the browser actually receives.", Some("retire")),
        "checkov" => ("Checkov", "A large infrastructure-as-code policy set covering more providers than the built-in engine.", Some("checkov")),
        "recon" => (
            "Sentinel Recon",
            "Passive attack-surface discovery — subdomains, hosts and email addresses from \
             certificate transparency, passive DNS and public indexes. Sends nothing to the \
             target, so it runs without a signed authorisation. Needs at least one of \
             subfinder, theHarvester or amass installed.",
            Some("subfinder"),
        ),
        "native" => (
            "Sentinel Native",
            "The built-in live check engine: security headers, TLS, cookies, CORS, exposure \
             surface and content analysis, across every page it reaches.",
            None,
        ),
        "zap_dast" => ("OWASP ZAP", "Full passive and active dynamic scanning, including a browser-driven crawler for single-page applications.", Some("zap.sh")),
        "nuclei_dast" => ("Nuclei", "Community template matching for known vulnerable software and exposures.", Some("nuclei")),
        "nikto_dast" => ("Nikto", "Web server misconfiguration and forgotten-file discovery.", Some("nikto")),
        "testssl_dast" => ("testssl.sh", "Deep TLS assessment: what the server will actually negotiate, not just what its certificate says.", Some("testssl.sh")),
        other => (other, "No description available for this engine.", None),
    };

    EngineDescriptor {
        stage: stage.to_string(),
        label: label.to_string(),
        category: if BUILTIN_STAGES.contains(&stage) && !LIVE_STAGES.contains(&stage) {
            "builtin".into()
        } else if LIVE_STAGES.contains(&stage) {
            "live".into()
        } else {
            "external".into()
        },
        built_in: BUILTIN_STAGES.contains(&stage),
        reaches_target: LIVE_STAGES.contains(&stage),
        description: description.to_string(),
        requires_binary: binary.map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_stage_a_preset_names_is_a_stage_the_pipeline_runs() {
        for preset in PRESETS {
            for stage in preset.stages {
                assert!(
                    ALL_STAGES.contains(stage),
                    "{} enables {stage}, which the pipeline does not know",
                    preset.id
                );
            }
        }
    }

    #[test]
    fn the_stage_groups_partition_the_stage_list() {
        let grouped: HashSet<&str> =
            STATIC_STAGES.iter().chain(LIVE_STAGES.iter()).copied().collect();
        let all: HashSet<&str> = ALL_STAGES.iter().copied().collect();
        assert_eq!(grouped, all, "a stage belongs to exactly one of static and live");
        assert!(
            STATIC_STAGES.iter().all(|s| !LIVE_STAGES.contains(s)),
            "no stage may be both"
        );
    }

    #[test]
    fn every_preset_carries_a_description_that_states_its_limits() {
        for preset in PRESETS {
            assert!(
                preset.description.len() > 120,
                "{} does not explain what it will and will not find",
                preset.id
            );
            assert!(!preset.stages.is_empty(), "{} enables nothing", preset.id);
            serde_json::from_str::<serde_json::Value>(preset.config_json)
                .unwrap_or_else(|e| panic!("{} has invalid configuration JSON: {e}", preset.id));
        }
    }

    #[test]
    fn preset_ids_are_unique_and_marked_as_built_in() {
        let mut seen = HashSet::new();
        for p in builtin_profiles() {
            assert!(seen.insert(p.id.clone()), "duplicate preset id {}", p.id);
            assert!(p.id.starts_with("builtin-"), "{} is not marked built-in", p.id);
            assert!(p.builtin);
        }
    }

    /// A profile whose engines all reach the target, with dynamic testing off,
    /// would run nothing and report a clean result.
    #[test]
    fn a_source_only_preset_does_not_enable_dynamic_testing() {
        let review = PRESETS.iter().find(|p| p.id == "builtin-code-review").unwrap();
        assert!(!review.run_dast);
        assert!(review.stages.iter().all(|s| !LIVE_STAGES.contains(s)));
    }

    #[test]
    fn the_perimeter_preset_enables_dynamic_testing_and_leads_with_reconnaissance() {
        let perimeter = PRESETS.iter().find(|p| p.id == "builtin-perimeter").unwrap();
        assert!(perimeter.run_dast);
        assert_eq!(
            perimeter.stages.first(),
            Some(&"recon"),
            "an external assessment establishes the surface before testing it"
        );
        assert!(
            perimeter.stages.iter().filter(|s| **s != "recon").all(|s| LIVE_STAGES.contains(s)),
            "everything else in this profile reaches the target"
        );
    }

    #[test]
    fn the_offline_preset_switches_the_advisory_lookup_off() {
        let offline = PRESETS.iter().find(|p| p.id == "builtin-air-gapped").unwrap();
        let cfg: serde_json::Value = serde_json::from_str(offline.config_json).unwrap();
        assert_eq!(cfg["offline"], serde_json::Value::Bool(true));
    }

    /// The engine list drives the profile editor, so an engine missing from it
    /// is one the analyst can never enable.
    #[test]
    fn every_stage_has_a_descriptor_with_real_guidance() {
        let engines = list_engines();
        assert_eq!(engines.len(), ALL_STAGES.len());
        for e in &engines {
            assert!(
                e.description.len() > 40 && !e.description.starts_with("No description"),
                "{} has no usable description",
                e.stage
            );
            assert!(["builtin", "external", "live"].contains(&e.category.as_str()));
            // Only a compiled-in engine may claim to need no binary.
            if !e.built_in {
                assert!(
                    e.requires_binary.is_some(),
                    "{} is external but names no binary to install",
                    e.stage
                );
            }
        }
    }

    /// The scan console builds its stage cards from this list, mapping
    /// `built_in` to the tag it shows and `reaches_target` to whether the card
    /// renders locked behind the authorisation gate. It used to hold its own
    /// copy of that table, which is how the native engine once rendered as
    /// though it were doing nothing.
    ///
    /// Two properties the console depends on, neither obvious:
    ///
    /// * `built_in` and `reaches_target` are independent. Sentinel Native is
    ///   both — compiled in, and it sends requests — so a UI that derived one
    ///   from the other would either tag it as an external tool or leave a live
    ///   engine unlocked.
    /// * Every stage the console can be asked to draw a card for appears here,
    ///   because a card is only drawn for a descriptor this returns.
    #[test]
    fn the_engine_list_carries_what_the_console_needs_to_draw_a_stage_card() {
        let engines = list_engines();
        assert_eq!(engines.len(), ALL_STAGES.len());

        for e in &engines {
            assert!(!e.label.trim().is_empty(), "{} has no label to show", e.stage);
            assert_eq!(
                e.reaches_target,
                LIVE_STAGES.contains(&e.stage.as_str()),
                "{} disagrees with LIVE_STAGES about whether it reaches the target, \
                 which decides whether the console locks its card",
                e.stage
            );
        }

        let native = engines.iter().find(|e| e.stage == "native").expect("the native engine");
        assert!(
            native.built_in && native.reaches_target,
            "the native engine is compiled in *and* sends traffic; collapsing those two \
             into one flag mislabels it or leaves it ungated"
        );

        let zap = engines.iter().find(|e| e.stage == "zap_dast").expect("the ZAP engine");
        assert!(!zap.built_in && zap.reaches_target, "ZAP is an external live engine");

        let code = engines.iter().find(|e| e.stage == "code").expect("the code engine");
        assert!(code.built_in && !code.reaches_target, "the code engine reads local files only");
    }

    #[test]
    fn the_built_in_engines_are_exactly_the_ones_that_need_no_binary() {
        for e in list_engines() {
            assert_eq!(
                e.built_in,
                e.requires_binary.is_none(),
                "{} disagrees with itself about needing a binary",
                e.stage
            );
        }
    }
}
