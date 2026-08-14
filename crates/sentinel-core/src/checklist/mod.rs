//! Checklist coverage engine.
//!
//! Turns "which engines actually ran" + "what did they find" into an honest,
//! auditable coverage matrix over the WSTG v4.2 catalog. This is what lets the
//! client report state *every* check that was performed — including the ones
//! that came back clean, and the ones that require a human.

pub mod catalog;

use crate::models::finding::{Finding, Severity};
use catalog::{ChecklistItem, CoverageKind, CATEGORIES, WSTG_CATALOG};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// Outcome of a single checklist item for one assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// An engine covering this item ran and reported at least one finding.
    IssuesFound,
    /// An engine covering this item ran and reported nothing.
    Passed,
    /// No engine covering this item was available or executed.
    NotTested,
    /// The item can only be answered by an analyst; no automated verdict exists.
    ManualRequired,
}

impl CheckStatus {
    pub fn label(&self) -> &'static str {
        match self {
            CheckStatus::IssuesFound => "Issues Found",
            CheckStatus::Passed => "Passed",
            CheckStatus::NotTested => "Not Tested",
            CheckStatus::ManualRequired => "Manual Review Required",
        }
    }

    /// Hex colour used consistently across reports and the UI.
    pub fn color(&self) -> &'static str {
        match self {
            CheckStatus::IssuesFound => "#dc2626",
            CheckStatus::Passed => "#16a34a",
            CheckStatus::NotTested => "#94a3b8",
            CheckStatus::ManualRequired => "#d97706",
        }
    }
}

/// One row of the coverage matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub category_code: String,
    pub category: String,
    pub name: String,
    pub client_summary: String,
    pub coverage: CoverageKind,
    pub coverage_label: String,
    pub status: CheckStatus,
    pub status_label: String,
    /// Engines declared for this item that actually executed.
    pub engines_executed: Vec<String>,
    /// Engines declared for this item that did not execute (not installed, skipped).
    pub engines_missing: Vec<String>,
    pub owasp_2025: String,
    pub cwe: String,
    /// Number of findings attributed to this checklist item.
    pub finding_count: usize,
    /// Highest severity among attributed findings, if any.
    pub highest_severity: Option<Severity>,
}

/// Per-category rollup for report section headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySummary {
    pub category_code: String,
    pub category: String,
    pub total: usize,
    pub passed: usize,
    pub issues_found: usize,
    pub not_tested: usize,
    pub manual_required: usize,
}

/// The complete coverage assessment for one scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub results: Vec<CheckResult>,
    pub categories: Vec<CategorySummary>,
    pub total_checks: usize,
    pub passed: usize,
    pub issues_found: usize,
    pub not_tested: usize,
    pub manual_required: usize,
    /// Engines that executed during this assessment.
    pub engines_executed: Vec<String>,
    /// Engines referenced by the catalog that were unavailable.
    pub engines_unavailable: Vec<String>,
    /// Share of automatable checks that were actually exercised, 0.0–100.0.
    pub automated_coverage_pct: f64,
}

pub struct ChecklistEngine;

impl ChecklistEngine {
    /// Build the coverage matrix.
    ///
    /// * `engines_executed` — engine names that ran, matching `catalog::engine::*`
    ///   (matching is case-insensitive and substring-tolerant so "Semgrep SAST"
    ///   from a finding's `source_tools` still resolves to "Semgrep").
    /// * `findings` — deduplicated findings from the run.
    pub fn assess(engines_executed: &[String], findings: &[Finding]) -> CoverageReport {
        let executed: Vec<String> = engines_executed
            .iter()
            .map(|e| e.to_lowercase())
            .collect();

        let results: Vec<CheckResult> = WSTG_CATALOG
            .iter()
            .map(|item| Self::assess_item(item, &executed, findings))
            .collect();

        let categories = Self::summarize_categories(&results);

        let passed = results.iter().filter(|r| r.status == CheckStatus::Passed).count();
        let issues_found = results.iter().filter(|r| r.status == CheckStatus::IssuesFound).count();
        let not_tested = results.iter().filter(|r| r.status == CheckStatus::NotTested).count();
        let manual_required = results
            .iter()
            .filter(|r| r.status == CheckStatus::ManualRequired)
            .count();

        // Automated coverage measures only the checks a tool could ever answer.
        let automatable = results
            .iter()
            .filter(|r| r.coverage != CoverageKind::Manual)
            .count();
        let exercised = results
            .iter()
            .filter(|r| {
                r.coverage != CoverageKind::Manual
                    && matches!(r.status, CheckStatus::Passed | CheckStatus::IssuesFound)
            })
            .count();
        let automated_coverage_pct = if automatable == 0 {
            0.0
        } else {
            ((exercised as f64 / automatable as f64) * 1000.0).round() / 10.0
        };

        let mut unavailable: Vec<String> = results
            .iter()
            .flat_map(|r| r.engines_missing.iter().cloned())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        unavailable.sort();

        let mut executed_display: Vec<String> = engines_executed.to_vec();
        executed_display.sort();
        executed_display.dedup();

        CoverageReport {
            total_checks: results.len(),
            results,
            categories,
            passed,
            issues_found,
            not_tested,
            manual_required,
            engines_executed: executed_display,
            engines_unavailable: unavailable,
            automated_coverage_pct,
        }
    }

    fn assess_item(
        item: &ChecklistItem,
        executed_lower: &[String],
        findings: &[Finding],
    ) -> CheckResult {
        let mut engines_executed = Vec::new();
        let mut engines_missing = Vec::new();

        for engine in item.engines {
            if *engine == catalog::engine::ANALYST {
                // The analyst is never an "executed engine"; manual work is
                // reported separately so the matrix cannot overstate coverage.
                continue;
            }
            if engine_ran(engine, executed_lower) {
                engines_executed.push((*engine).to_string());
            } else {
                engines_missing.push((*engine).to_string());
            }
        }

        let attributed: Vec<&Finding> = findings
            .iter()
            .filter(|f| finding_matches_item(f, item))
            .collect();

        let finding_count = attributed.len();
        let highest_severity = attributed
            .iter()
            .map(|f| f.severity.clone())
            // Severity derives Ord with Critical first, so `min` is the worst.
            .min();

        let status = if finding_count > 0 {
            CheckStatus::IssuesFound
        } else if item.coverage == CoverageKind::Manual {
            CheckStatus::ManualRequired
        } else if engines_executed.is_empty() {
            CheckStatus::NotTested
        } else {
            CheckStatus::Passed
        };

        CheckResult {
            id: item.id.to_string(),
            category_code: item.category_code.to_string(),
            category: item.category.to_string(),
            name: item.name.to_string(),
            client_summary: item.client_summary.to_string(),
            coverage: item.coverage,
            coverage_label: item.coverage.label().to_string(),
            status,
            status_label: status.label().to_string(),
            engines_executed,
            engines_missing,
            owasp_2025: item.owasp_2025.to_string(),
            cwe: item.cwe.to_string(),
            finding_count,
            highest_severity,
        }
    }

    fn summarize_categories(results: &[CheckResult]) -> Vec<CategorySummary> {
        let mut by_code: BTreeMap<&str, CategorySummary> = BTreeMap::new();

        for (code, name) in CATEGORIES {
            by_code.insert(
                code,
                CategorySummary {
                    category_code: (*code).to_string(),
                    category: (*name).to_string(),
                    total: 0,
                    passed: 0,
                    issues_found: 0,
                    not_tested: 0,
                    manual_required: 0,
                },
            );
        }

        for r in results {
            if let Some(entry) = by_code.get_mut(r.category_code.as_str()) {
                entry.total += 1;
                match r.status {
                    CheckStatus::Passed => entry.passed += 1,
                    CheckStatus::IssuesFound => entry.issues_found += 1,
                    CheckStatus::NotTested => entry.not_tested += 1,
                    CheckStatus::ManualRequired => entry.manual_required += 1,
                }
            }
        }

        // Preserve WSTG's canonical category order rather than alphabetical.
        CATEGORIES
            .iter()
            .filter_map(|(code, _)| by_code.remove(code))
            .filter(|c| c.total > 0)
            .collect()
    }
}

/// Whether an engine name from the catalog appears in the executed set.
/// Tolerates decorated names such as "Semgrep SAST" or "OWASP ZAP Active Scan".
fn engine_ran(engine: &str, executed_lower: &[String]) -> bool {
    let needle = engine.to_lowercase();
    // "Sentinel Native" is also matched by the short form "native".
    let short = needle.rsplit(' ').next().unwrap_or(&needle).to_string();
    executed_lower
        .iter()
        .any(|e| e.contains(&needle) || e.contains(&short) || needle.contains(e.as_str()))
}

/// Attribute a finding to a checklist item.
///
/// Priority order: explicit WSTG id on the finding, then CWE, then OWASP
/// category as a last resort (only when the finding carries no better signal).
fn finding_matches_item(finding: &Finding, item: &ChecklistItem) -> bool {
    if let Some(wstg) = &finding.wstg_id {
        if !wstg.trim().is_empty() {
            return wstg.eq_ignore_ascii_case(item.id);
        }
    }
    if let Some(cwe) = &finding.cwe_id {
        if !cwe.trim().is_empty() {
            return cwe.eq_ignore_ascii_case(item.cwe);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{FindingStatus, Severity};
    use chrono::Utc;
    use uuid::Uuid;

    fn finding(wstg: Option<&str>, cwe: Option<&str>, sev: Severity) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            title: "t".into(),
            description: "d".into(),
            severity: sev,
            cvss4: None,
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.0,
            reachability_score: 1.0,
            priority_score: 5.0,
            cwe_id: cwe.map(str::to_string),
            owasp_2025: None,
            wstg_id: wstg.map(str::to_string),
            api_top10: None,
            affected_component: "/".into(),
            evidences: vec![],
            repro_steps: vec![],
            remediation: "fix".into(),
            references: vec![],
            status: FindingStatus::Open,
            source_tools: vec!["Sentinel Native".into()],
            ai_triage: None,
            priority_rationale: String::new(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn no_engines_means_nothing_is_claimed_as_passed() {
        let report = ChecklistEngine::assess(&[], &[]);
        assert_eq!(report.passed, 0, "cannot claim a pass without running anything");
        assert_eq!(report.automated_coverage_pct, 0.0);
        assert!(report.manual_required > 0);
        assert_eq!(
            report.total_checks,
            report.passed + report.issues_found + report.not_tested + report.manual_required
        );
    }

    #[test]
    fn executed_engine_marks_its_items_passed_when_clean() {
        let report = ChecklistEngine::assess(&["Sentinel Native".into()], &[]);
        let csp = report.results.iter().find(|r| r.id == "WSTG-CONF-12").unwrap();
        assert_eq!(csp.status, CheckStatus::Passed);
        assert!(csp.engines_executed.contains(&"Sentinel Native".to_string()));
    }

    #[test]
    fn manual_items_stay_manual_even_when_every_engine_runs() {
        let engines: Vec<String> = vec![
            "Sentinel Native".into(), "OWASP ZAP".into(), "Nuclei".into(),
            "Semgrep".into(), "Trivy".into(), "Gitleaks".into(),
        ];
        let report = ChecklistEngine::assess(&engines, &[]);
        let biz = report.results.iter().find(|r| r.id == "WSTG-BUSL-10").unwrap();
        assert_eq!(biz.status, CheckStatus::ManualRequired);
    }

    #[test]
    fn findings_flip_an_item_to_issues_found() {
        let f = finding(Some("WSTG-CONF-12"), None, Severity::Medium);
        let report = ChecklistEngine::assess(&["Sentinel Native".into()], &[f]);
        let csp = report.results.iter().find(|r| r.id == "WSTG-CONF-12").unwrap();
        assert_eq!(csp.status, CheckStatus::IssuesFound);
        assert_eq!(csp.finding_count, 1);
        assert_eq!(csp.highest_severity, Some(Severity::Medium));
    }

    #[test]
    fn cwe_attribution_works_when_no_wstg_id_present() {
        let f = finding(None, Some("CWE-1021"), Severity::Low);
        let report = ChecklistEngine::assess(&["Sentinel Native".into()], &[f]);
        let clickjacking = report.results.iter().find(|r| r.id == "WSTG-CLNT-09").unwrap();
        assert_eq!(clickjacking.status, CheckStatus::IssuesFound);
    }

    #[test]
    fn highest_severity_picks_the_worst_finding() {
        let f1 = finding(Some("WSTG-CONF-12"), None, Severity::Low);
        let f2 = finding(Some("WSTG-CONF-12"), None, Severity::Critical);
        let report = ChecklistEngine::assess(&["Sentinel Native".into()], &[f1, f2]);
        let csp = report.results.iter().find(|r| r.id == "WSTG-CONF-12").unwrap();
        assert_eq!(csp.highest_severity, Some(Severity::Critical));
        assert_eq!(csp.finding_count, 2);
    }

    #[test]
    fn decorated_engine_names_still_resolve() {
        let report = ChecklistEngine::assess(&["Semgrep SAST".into()], &[]);
        let sqli = report.results.iter().find(|r| r.id == "WSTG-INPV-05").unwrap();
        assert!(
            sqli.engines_executed.contains(&"Semgrep".to_string()),
            "'Semgrep SAST' should resolve to the Semgrep engine"
        );
    }

    #[test]
    fn category_rollups_add_up() {
        let report = ChecklistEngine::assess(&["Sentinel Native".into()], &[]);
        let summed: usize = report.categories.iter().map(|c| c.total).sum();
        assert_eq!(summed, report.total_checks);
        for c in &report.categories {
            assert_eq!(c.total, c.passed + c.issues_found + c.not_tested + c.manual_required);
        }
    }

    #[test]
    fn categories_follow_wstg_order() {
        let report = ChecklistEngine::assess(&[], &[]);
        let codes: Vec<&str> = report.categories.iter().map(|c| c.category_code.as_str()).collect();
        assert_eq!(codes.first(), Some(&"INFO"));
        let info_pos = codes.iter().position(|c| *c == "INFO").unwrap();
        let conf_pos = codes.iter().position(|c| *c == "CONF").unwrap();
        assert!(info_pos < conf_pos);
    }

    #[test]
    fn automated_coverage_never_counts_manual_items() {
        let engines: Vec<String> = vec![
            "Sentinel Native".into(), "OWASP ZAP".into(), "Nuclei".into(),
            "Semgrep".into(), "Trivy".into(), "Gitleaks".into(),
        ];
        let report = ChecklistEngine::assess(&engines, &[]);
        assert_eq!(
            report.automated_coverage_pct, 100.0,
            "with every engine present all automatable checks are exercised"
        );
        assert!(report.manual_required > 0, "manual items must remain outstanding");
    }
}
