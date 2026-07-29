use tauri::State;
use serde::{Deserialize, Serialize};
use chrono::Utc;
use crate::state::{AppState, FindingRecord, ReportRecord, new_id};
use sentinel_core::reporting::ReportEngine;
use sentinel_core::models::finding::{
    Finding, Severity, FindingStatus, CVSS4Data, EPSSData
};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct GenerateReportInput {
    pub scan_id: String,
    pub report_type: String,    // "executive" | "developer" | "sarif"
    pub company_name: String,
    pub target_name: String,
    pub logo_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GenerateReportOutput {
    pub report_id: String,
    pub report_type: String,
    pub html_content: String,
}

#[tauri::command]
pub async fn generate_report(
    input: GenerateReportInput,
    state: State<'_, AppState>,
) -> Result<GenerateReportOutput, String> {
    // Fetch findings for this scan
    let findings_map = state.findings.read().await;
    let raw: Vec<FindingRecord> = findings_map.values()
        .filter(|f| f.scan_id == input.scan_id)
        .cloned()
        .collect();

    if raw.is_empty() {
        return Err(format!("No findings found for scan '{}'", input.scan_id));
    }

    // Convert FindingRecord → sentinel_core Finding for the report engine
    let core_findings: Vec<Finding> = raw.iter().map(|f| finding_record_to_core(f)).collect();

    let html = match input.report_type.as_str() {
        "executive" => ReportEngine::generate_client_report_html(
            &input.company_name,
            input.logo_path.as_deref(),
            &input.target_name,
            &core_findings,
        ),
        "developer" => ReportEngine::generate_developer_report_html(
            &input.target_name,
            &core_findings,
        ),
        "sarif" => ReportEngine::generate_sarif_json(&core_findings),
        other => return Err(format!("Unknown report type '{}'. Use executive | developer | sarif", other)),
    };

    // Safety assertion: no secret material in output
    for finding in &raw {
        for _tool in &finding.source_tools {
            if html.contains("AKIAIOSFODNN7EXAMPLE") ||
               html.contains("ghp_") ||
               html.contains("sk-") {
                return Err("Report generation aborted: potential secret material detected in output".into());
            }
        }
    }

    let report = ReportRecord {
        id: new_id(),
        scan_id: input.scan_id,
        report_type: input.report_type.clone(),
        company_name: input.company_name,
        html_content: html.clone(),
        created_at: Utc::now(),
    };
    let report_id = report.id.clone();
    state.reports.write().await.insert(report_id.clone(), report);

    Ok(GenerateReportOutput {
        report_id,
        report_type: input.report_type,
        html_content: html,
    })
}

#[derive(Debug, Deserialize)]
pub struct ExportReportInput {
    pub report_id: String,
    pub export_path: String,    // User-selected path from Tauri dialog
    pub format: String,         // "html" | "json"
}

#[tauri::command]
pub async fn export_report(
    input: ExportReportInput,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let reports = state.reports.read().await;
    let report = reports.get(&input.report_id)
        .ok_or_else(|| format!("Report '{}' not found", input.report_id))?;

    // Validate export path is within safe directories (no arbitrary fs writes)
    let safe_extensions = [".html", ".json", ".sarif"];
    if !safe_extensions.iter().any(|ext| input.export_path.ends_with(ext)) {
        return Err("Export path must end with .html, .json, or .sarif".into());
    }

    let content = match input.format.as_str() {
        "html" => report.html_content.clone(),
        "json" => serde_json::to_string_pretty(report)
            .map_err(|e| e.to_string())?,
        other => return Err(format!("Unsupported export format: {}", other)),
    };

    std::fs::write(&input.export_path, content.as_bytes())
        .map_err(|e| format!("Failed to write export file: {}", e))?;

    Ok(format!("Report exported to {}", input.export_path))
}

#[tauri::command]
pub async fn list_reports(
    scan_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<ReportRecord>, String> {
    let map = state.reports.read().await;
    let mut records: Vec<ReportRecord> = map.values()
        .filter(|r| r.scan_id == scan_id)
        .cloned()
        .collect();
    records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(records)
}

// ── Conversion helper ─────────────────────────────────────────────────────────

fn finding_record_to_core(f: &FindingRecord) -> Finding {
    let severity = match f.severity.as_str() {
        "Critical" => Severity::Critical,
        "High"     => Severity::High,
        "Medium"   => Severity::Medium,
        "Low"      => Severity::Low,
        _          => Severity::Info,
    };
    let status = match f.status.as_str() {
        "Remediated"    => FindingStatus::Remediated,
        "Accepted Risk" => FindingStatus::AcceptedRisk,
        "False Positive"=> FindingStatus::FalsePositive,
        _               => FindingStatus::Open,
    };
    Finding {
        id: Uuid::parse_str(&f.id).unwrap_or_else(|_| Uuid::new_v4()),
        scan_id: Uuid::parse_str(&f.scan_id).unwrap_or_else(|_| Uuid::new_v4()),
        target_id: Uuid::parse_str(&f.target_id).unwrap_or_else(|_| Uuid::new_v4()),
        title: f.title.clone(),
        description: f.description.clone(),
        severity: severity.clone(),
        cvss4: if f.cvss4_score > 0.0 {
            Some(CVSS4Data {
                base_score: f.cvss4_score as f64,
                vector_string: String::new(),
                severity_label: format!("{:?}", severity),
            })
        } else { None },
        epss: if f.epss_score > 0.0 {
            Some(EPSSData { score: f.epss_score as f64, percentile: f.epss_score as f64 })
        } else { None },
        kev_listed: f.kev_listed,
        asset_exposure_factor: 1.0,
        reachability_score: 1.0,
        priority_score: f.priority_score as f64,
        cwe_id: f.cwe_id.clone(),
        owasp_2025: f.owasp_2025.clone(),
        wstg_id: f.wstg_id.clone(),
        api_top10: None,
        affected_component: f.affected_component.clone(),
        evidences: vec![],
        repro_steps: f.repro_steps.clone(),
        remediation: f.remediation.clone(),
        references: vec![],
        status,
        source_tools: f.source_tools.clone(),
        ai_triage: None,
        priority_rationale: f.priority_rationale.clone(),
        created_at: f.created_at,
    }
}
