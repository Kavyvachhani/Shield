use crate::state::{new_id, AppState, ReportRecord};
use chrono::Utc;
use sentinel_core::checklist::{ChecklistEngine, CoverageReport};
use sentinel_core::models::finding::Finding;
use sentinel_core::reporting::{ReportContext, ReportEngine};
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Debug, Deserialize)]
pub struct GenerateReportInput {
    pub scan_id: String,
    /// "client" | "developer" | "sarif" | "markdown" | "json"
    pub report_type: String,
    pub company_name: String,
    pub target_name: String,
    pub target_url: Option<String>,
    pub analyst: Option<String>,
    /// Base64 `data:image/...` logo. Non-image or remote values are ignored.
    pub logo_data_uri: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GenerateReportOutput {
    pub report_id: String,
    pub report_type: String,
    pub content: String,
    /// MIME type so the UI knows whether to render or download.
    pub content_type: String,
    pub suggested_filename: String,
    pub finding_count: usize,
}

/// Report types the engine can produce.
const REPORT_TYPES: &[&str] = &["client", "developer", "sarif", "markdown", "json"];

#[tauri::command]
pub async fn generate_report(
    input: GenerateReportInput,
    state: State<'_, AppState>,
) -> Result<GenerateReportOutput, String> {
    if !REPORT_TYPES.contains(&input.report_type.as_str()) {
        return Err(format!(
            "Unknown report type '{}'. Expected one of: {}",
            input.report_type,
            REPORT_TYPES.join(", ")
        ));
    }

    let findings: Vec<Finding> = {
        let store = state.findings.read().await;
        store
            .values()
            .filter(|s| s.scan_id == input.scan_id)
            .map(|s| s.finding.clone())
            .collect()
    };

    let ctx = build_context(&input, &state).await;
    let coverage = build_coverage(&input.scan_id, &findings, &state).await;

    let (content, content_type, extension) = match input.report_type.as_str() {
        "client" => (
            ReportEngine::client_report(&ctx, &findings, coverage.as_ref()),
            "text/html",
            "html",
        ),
        "developer" => (
            ReportEngine::developer_report(&ctx, &findings, coverage.as_ref()),
            "text/html",
            "html",
        ),
        "sarif" => (
            ReportEngine::generate_sarif_json(&findings),
            "application/sarif+json",
            "sarif",
        ),
        "markdown" => (
            ReportEngine::developer_markdown(&ctx, &findings),
            "text/markdown",
            "md",
        ),
        "json" => (
            ReportEngine::generate_json(&ctx, &findings, coverage.as_ref()),
            "application/json",
            "json",
        ),
        other => return Err(format!("Unhandled report type '{other}'")),
    };

    let suggested_filename = format!(
        "{}-{}-{}.{}",
        sanitize_filename(&input.company_name),
        input.report_type,
        Utc::now().format("%Y%m%d"),
        extension
    );

    let report = ReportRecord {
        id: new_id(),
        scan_id: input.scan_id.clone(),
        report_type: input.report_type.clone(),
        company_name: input.company_name.clone(),
        html_content: content.clone(),
        created_at: Utc::now(),
    };
    let report_id = report.id.clone();
    state.reports.write().await.insert(report_id.clone(), report);

    Ok(GenerateReportOutput {
        report_id,
        report_type: input.report_type,
        content,
        content_type: content_type.to_string(),
        suggested_filename,
        finding_count: findings.len(),
    })
}

/// The coverage matrix for a scan, or `None` when the scan is unknown.
#[tauri::command]
pub async fn get_coverage(
    scan_id: String,
    state: State<'_, AppState>,
) -> Result<CoverageReport, String> {
    let findings: Vec<Finding> = {
        let store = state.findings.read().await;
        store
            .values()
            .filter(|s| s.scan_id == scan_id)
            .map(|s| s.finding.clone())
            .collect()
    };
    build_coverage(&scan_id, &findings, &state)
        .await
        .ok_or_else(|| format!("No scan run recorded for '{scan_id}'"))
}

/// The full WSTG catalog, for the checklist screen before any scan has run.
#[tauri::command]
pub async fn get_checklist_catalog() -> Result<serde_json::Value, String> {
    serde_json::to_value(sentinel_core::checklist::catalog::WSTG_CATALOG)
        .map_err(|e| format!("Failed to serialise the checklist catalog: {e}"))
}

/// A sensible default folder to export into, resolved per platform.
///
/// Prefers the user's Downloads folder, then Documents, then the home
/// directory. Returned as a string so the UI can pre-fill an editable path.
#[tauri::command]
pub async fn default_export_dir() -> Result<String, String> {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
        .ok_or_else(|| "Could not determine your home directory".to_string())?;

    for candidate in ["Downloads", "Documents"] {
        let dir = home.join(candidate);
        if dir.is_dir() {
            return Ok(dir.to_string_lossy().to_string());
        }
    }
    Ok(home.to_string_lossy().to_string())
}

#[derive(Debug, Deserialize)]
pub struct ExportReportInput {
    pub report_id: String,
    pub export_path: String,
}

#[tauri::command]
pub async fn export_report(
    input: ExportReportInput,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let content = {
        let reports = state.reports.read().await;
        let report = reports
            .get(&input.report_id)
            .ok_or_else(|| format!("Report '{}' not found", input.report_id))?;
        report.html_content.clone()
    };

    let path = std::path::Path::new(&input.export_path);
    let allowed = ["html", "htm", "json", "sarif", "md", "markdown", "txt"];
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_lowercase)
        .unwrap_or_default();
    if !allowed.contains(&extension.as_str()) {
        return Err(format!(
            "Export path must end with one of: {}",
            allowed.join(", ")
        ));
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            return Err(format!(
                "Destination folder does not exist: {}",
                parent.display()
            ));
        }
    }

    std::fs::write(path, content.as_bytes())
        .map_err(|e| format!("Failed to write '{}': {e}", path.display()))?;

    Ok(format!("Report exported to {}", path.display()))
}

#[tauri::command]
pub async fn list_reports(
    scan_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<ReportRecord>, String> {
    let map = state.reports.read().await;
    let mut records: Vec<ReportRecord> = map
        .values()
        .filter(|r| r.scan_id == scan_id)
        .cloned()
        .collect();
    records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(records)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

async fn build_context(input: &GenerateReportInput, state: &State<'_, AppState>) -> ReportContext {
    let run = state.scan_runs.read().await.get(&input.scan_id).cloned();

    let target_url = input
        .target_url
        .clone()
        .unwrap_or_else(|| "(not recorded)".to_string());

    let mut ctx = ReportContext::new(&input.company_name, &input.target_name, &target_url);
    ctx.logo_data_uri = input.logo_data_uri.clone();
    if let Some(analyst) = &input.analyst {
        if !analyst.trim().is_empty() {
            ctx.analyst = analyst.clone();
        }
    }

    if let Some(run) = &run {
        ctx.assessment_start = run.started_at;
        ctx.assessment_end = run.completed_at.unwrap_or_else(Utc::now);
        ctx.engines_executed = run.engines_executed.clone();

        // Scope and authorisation detail comes from the signed RoE, so the
        // attestation block reflects what was actually agreed.
        if let Some(auth) = state.auth_records.read().await.get(&run.target_id) {
            ctx.allowed_domains = auth.scope.allowed_domains.clone();
            ctx.out_of_scope_paths = auth.scope.out_of_scope_paths.clone();
            ctx.rate_limit_rps = auth.scope.rate_limit_rps;
            ctx.roe_hash = Some(auth.roe_document_hash.clone());
        }
    }

    ctx
}

/// Coverage for a scan. Returns `None` when the scan run is unknown, so a report
/// can never present a coverage matrix for engines that were never recorded.
async fn build_coverage(
    scan_id: &str,
    findings: &[Finding],
    state: &State<'_, AppState>,
) -> Option<CoverageReport> {
    let engines = state.scan_engines.read().await.get(scan_id).cloned()?;
    Some(ChecklistEngine::assess(&engines, findings))
}

/// Reduce a company name to a filesystem-safe token.
pub fn sanitize_filename(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let collapsed = cleaned
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
        .to_lowercase();
    if collapsed.is_empty() {
        "report".to_string()
    } else {
        collapsed.chars().take(48).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_types_cover_both_audiences_and_machine_formats() {
        for expected in ["client", "developer", "sarif", "markdown", "json"] {
            assert!(REPORT_TYPES.contains(&expected), "{expected} must be offered");
        }
    }

    #[test]
    fn filenames_are_sanitised() {
        assert_eq!(sanitize_filename("Acme Corp"), "acme-corp");
        assert_eq!(sanitize_filename("Acme, Inc."), "acme-inc");
    }

    #[test]
    fn path_traversal_cannot_survive_filename_sanitisation() {
        let out = sanitize_filename("../../etc/passwd");
        assert!(!out.contains(".."));
        assert!(!out.contains('/'));
        assert_eq!(out, "etc-passwd");
    }

    #[test]
    fn empty_or_symbolic_names_fall_back_to_a_default() {
        assert_eq!(sanitize_filename(""), "report");
        assert_eq!(sanitize_filename("***"), "report");
    }

    #[test]
    fn very_long_names_are_truncated() {
        assert!(sanitize_filename(&"a".repeat(200)).len() <= 48);
    }
}
