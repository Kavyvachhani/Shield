use tauri::State;
use serde::Deserialize;
use chrono::Utc;
use crate::state::{AppState, FindingRecord};

#[derive(Debug, Deserialize)]
pub struct FindingFilter {
    pub target_id: Option<String>,
    pub scan_id: Option<String>,
    pub severity: Option<String>,
    pub owasp_2025: Option<String>,
    pub status: Option<String>,
    pub source_tool: Option<String>,
    pub min_priority: Option<f32>,
}

#[tauri::command]
pub async fn list_findings(
    filter: FindingFilter,
    state: State<'_, AppState>,
) -> Result<Vec<FindingRecord>, String> {
    let map = state.findings.read().await;
    let mut records: Vec<FindingRecord> = map.values()
        .filter(|f| {
            if let Some(tid) = &filter.target_id {
                if &f.target_id != tid { return false; }
            }
            if let Some(sid) = &filter.scan_id {
                if &f.scan_id != sid { return false; }
            }
            if let Some(sev) = &filter.severity {
                if f.severity.to_lowercase() != sev.to_lowercase() { return false; }
            }
            if let Some(owasp) = &filter.owasp_2025 {
                if !f.owasp_2025.as_deref().unwrap_or("").contains(owasp.as_str()) { return false; }
            }
            if let Some(status) = &filter.status {
                if f.status.to_lowercase() != status.to_lowercase() { return false; }
            }
            if let Some(tool) = &filter.source_tool {
                if !f.source_tools.iter().any(|t| t.to_lowercase().contains(&tool.to_lowercase())) { return false; }
            }
            if let Some(min_p) = filter.min_priority {
                if f.priority_score < min_p { return false; }
            }
            true
        })
        .cloned()
        .collect();

    // Sort by priority descending
    records.sort_by(|a, b| b.priority_score.partial_cmp(&a.priority_score)
        .unwrap_or(std::cmp::Ordering::Equal));
    Ok(records)
}

#[tauri::command]
pub async fn get_finding(
    finding_id: String,
    state: State<'_, AppState>,
) -> Result<FindingRecord, String> {
    state.findings.read().await
        .get(&finding_id)
        .cloned()
        .ok_or_else(|| format!("Finding '{}' not found", finding_id))
}

#[derive(Debug, Deserialize)]
pub struct TriageInput {
    pub finding_id: String,
    pub new_status: String,
    pub triage_note: String,
    pub analyst_name: String,
}

/// Triage a finding (change status + add audit note).
/// The note is stored in-record; in production this also appends to the audit ledger.
#[tauri::command]
pub async fn triage_finding(
    input: TriageInput,
    state: State<'_, AppState>,
) -> Result<FindingRecord, String> {
    let valid_statuses = ["Open", "In Progress", "Remediated", "Accepted Risk", "False Positive"];
    if !valid_statuses.contains(&input.new_status.as_str()) {
        return Err(format!("Invalid status '{}'. Must be one of: {:?}", input.new_status, valid_statuses));
    }
    if input.triage_note.trim().is_empty() {
        return Err("Triage note is required for all status changes.".into());
    }

    let mut map = state.findings.write().await;
    let finding = map.get_mut(&input.finding_id)
        .ok_or_else(|| format!("Finding '{}' not found", input.finding_id))?;

    finding.status = input.new_status;
    finding.triage_note = Some(format!(
        "[{}] {} — {}",
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        input.analyst_name,
        input.triage_note
    ));
    Ok(finding.clone())
}
