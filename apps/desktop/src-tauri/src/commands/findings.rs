use crate::state::{log_persist_error, status_from_label, to_record, AppState, FindingRecord};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Debug, Default, Deserialize)]
pub struct FindingFilter {
    pub target_id: Option<String>,
    pub scan_id: Option<String>,
    pub severity: Option<String>,
    pub owasp_2025: Option<String>,
    pub wstg_id: Option<String>,
    pub status: Option<String>,
    pub source_tool: Option<String>,
    pub min_priority: Option<f32>,
    /// Free-text match across title, location and description.
    pub search: Option<String>,
}

#[tauri::command]
pub async fn list_findings(
    filter: FindingFilter,
    state: State<'_, AppState>,
) -> Result<Vec<FindingRecord>, String> {
    let store = state.findings.read().await;
    let mut records: Vec<FindingRecord> = store
        .values()
        .map(|s| to_record(&s.finding, &s.scan_id, s.triage_note.clone()))
        .filter(|r| matches(r, &filter))
        .collect();

    records.sort_by(|a, b| {
        b.priority_score
            .partial_cmp(&a.priority_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.title.cmp(&b.title))
            .then(a.id.cmp(&b.id))
    });
    Ok(records)
}

/// Whether a finding satisfies every supplied filter clause.
pub fn matches(r: &FindingRecord, filter: &FindingFilter) -> bool {
    if let Some(v) = &filter.target_id {
        if &r.target_id != v {
            return false;
        }
    }
    if let Some(v) = &filter.scan_id {
        if &r.scan_id != v {
            return false;
        }
    }
    if let Some(v) = &filter.severity {
        if !r.severity.eq_ignore_ascii_case(v) {
            return false;
        }
    }
    if let Some(v) = &filter.owasp_2025 {
        if !r.owasp_2025.as_deref().unwrap_or("").contains(v.as_str()) {
            return false;
        }
    }
    if let Some(v) = &filter.wstg_id {
        if !r.wstg_id.as_deref().unwrap_or("").eq_ignore_ascii_case(v) {
            return false;
        }
    }
    if let Some(v) = &filter.status {
        if !r.status.eq_ignore_ascii_case(v) {
            return false;
        }
    }
    if let Some(v) = &filter.source_tool {
        let needle = v.to_lowercase();
        if !r.source_tools.iter().any(|t| t.to_lowercase().contains(&needle)) {
            return false;
        }
    }
    if let Some(v) = filter.min_priority {
        if r.priority_score < v {
            return false;
        }
    }
    if let Some(v) = &filter.search {
        let needle = v.trim().to_lowercase();
        if !needle.is_empty() {
            let haystack = format!(
                "{} {} {}",
                r.title.to_lowercase(),
                r.affected_component.to_lowercase(),
                r.description.to_lowercase()
            );
            if !haystack.contains(&needle) {
                return false;
            }
        }
    }
    true
}

#[tauri::command]
pub async fn get_finding(
    finding_id: String,
    state: State<'_, AppState>,
) -> Result<FindingRecord, String> {
    state
        .findings
        .read()
        .await
        .get(&finding_id)
        .map(|s| to_record(&s.finding, &s.scan_id, s.triage_note.clone()))
        .ok_or_else(|| format!("Finding '{finding_id}' not found"))
}

/// Full detail for one finding, including evidence bodies the table omits.
#[derive(Debug, Serialize)]
pub struct FindingDetail {
    pub record: FindingRecord,
    pub evidences: Vec<EvidenceView>,
}

#[derive(Debug, Serialize)]
pub struct EvidenceView {
    pub evidence_type: String,
    pub title: String,
    pub content: String,
    pub hash: String,
}

#[tauri::command]
pub async fn get_finding_detail(
    finding_id: String,
    state: State<'_, AppState>,
) -> Result<FindingDetail, String> {
    let store = state.findings.read().await;
    let stored = store
        .get(&finding_id)
        .ok_or_else(|| format!("Finding '{finding_id}' not found"))?;

    Ok(FindingDetail {
        record: to_record(&stored.finding, &stored.scan_id, stored.triage_note.clone()),
        evidences: stored
            .finding
            .evidences
            .iter()
            .map(|e| EvidenceView {
                evidence_type: e.evidence_type.clone(),
                title: e.title.clone(),
                content: e.content.clone(),
                hash: e.hash.clone(),
            })
            .collect(),
    })
}

#[derive(Debug, Deserialize)]
pub struct TriageInput {
    pub finding_id: String,
    pub new_status: String,
    pub triage_note: String,
    pub analyst_name: String,
}

/// Valid triage states, matching `state::status_label`.
pub const VALID_STATUSES: &[&str] = &[
    "Open",
    "In Progress",
    "Remediated",
    "Accepted Risk",
    "False Positive",
];

#[tauri::command]
pub async fn triage_finding(
    input: TriageInput,
    state: State<'_, AppState>,
) -> Result<FindingRecord, String> {
    let status = status_from_label(&input.new_status).ok_or_else(|| {
        format!(
            "Invalid status '{}'. Must be one of: {}",
            input.new_status,
            VALID_STATUSES.join(", ")
        )
    })?;
    if input.triage_note.trim().is_empty() {
        return Err("A triage note is required for every status change.".into());
    }
    if input.analyst_name.trim().is_empty() {
        return Err("The analyst name is required for the audit trail.".into());
    }

    let mut store = state.findings.write().await;
    let stored = store
        .get_mut(&input.finding_id)
        .ok_or_else(|| format!("Finding '{}' not found", input.finding_id))?;

    stored.finding.status = status;
    // Notes append rather than overwrite: the triage history is audit evidence.
    let entry = format!(
        "[{}] {} → {}: {}",
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        input.analyst_name.trim(),
        input.new_status,
        input.triage_note.trim()
    );
    stored.triage_note = Some(match &stored.triage_note {
        Some(existing) => format!("{existing}\n{entry}"),
        None => entry,
    });

    if let Err(e) = state.store.save_finding(&input.finding_id, stored) {
        log_persist_error("triage decision", &e);
    }

    Ok(to_record(&stored.finding, &stored.scan_id, stored.triage_note.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::to_record;
    use chrono::Utc;
    use sentinel_core::models::finding::{Finding, FindingStatus, Severity};
    use uuid::Uuid;

    fn record(title: &str, severity: Severity, score: f64, tool: &str) -> FindingRecord {
        let f = Finding {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            title: title.into(),
            description: "A description mentioning cookies.".into(),
            severity,
            cvss4: None,
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.0,
            reachability_score: 1.0,
            priority_score: score,
            cwe_id: Some("CWE-79".into()),
            owasp_2025: Some("A05:2025-Injection".into()),
            wstg_id: Some("WSTG-INPV-01".into()),
            api_top10: None,
            affected_component: "https://app.test/login".into(),
            evidences: vec![],
            repro_steps: vec![],
            remediation: "Fix".into(),
            references: vec![],
            status: FindingStatus::Open,
            source_tools: vec![tool.into()],
            ai_triage: None,
            priority_rationale: String::new(),
            created_at: Utc::now(),
        };
        to_record(&f, "scan-1", None)
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        let r = record("XSS", Severity::High, 8.0, "Sentinel Native");
        assert!(matches(&r, &FindingFilter::default()));
    }

    #[test]
    fn severity_filter_is_case_insensitive() {
        let r = record("XSS", Severity::High, 8.0, "Sentinel Native");
        let f = FindingFilter { severity: Some("high".into()), ..Default::default() };
        assert!(matches(&r, &f));
        let f = FindingFilter { severity: Some("Low".into()), ..Default::default() };
        assert!(!matches(&r, &f));
    }

    #[test]
    fn min_priority_excludes_lower_scored_findings() {
        let r = record("XSS", Severity::Medium, 4.0, "Sentinel Native");
        let f = FindingFilter { min_priority: Some(7.0), ..Default::default() };
        assert!(!matches(&r, &f));
    }

    #[test]
    fn source_tool_filter_matches_a_decorated_name() {
        let r = record("XSS", Severity::High, 8.0, "Semgrep SAST");
        let f = FindingFilter { source_tool: Some("semgrep".into()), ..Default::default() };
        assert!(matches(&r, &f));
    }

    #[test]
    fn search_covers_title_location_and_description() {
        let r = record("Reflected XSS", Severity::High, 8.0, "Sentinel Native");
        for needle in ["reflected", "app.test/login", "cookies"] {
            let f = FindingFilter { search: Some(needle.into()), ..Default::default() };
            assert!(matches(&r, &f), "search should match '{needle}'");
        }
        let f = FindingFilter { search: Some("nonexistent".into()), ..Default::default() };
        assert!(!matches(&r, &f));
    }

    #[test]
    fn blank_search_is_ignored_rather_than_excluding_everything() {
        let r = record("XSS", Severity::High, 8.0, "Sentinel Native");
        let f = FindingFilter { search: Some("   ".into()), ..Default::default() };
        assert!(matches(&r, &f));
    }

    #[test]
    fn wstg_filter_matches_exactly() {
        let r = record("XSS", Severity::High, 8.0, "Sentinel Native");
        let f = FindingFilter { wstg_id: Some("wstg-inpv-01".into()), ..Default::default() };
        assert!(matches(&r, &f));
        let f = FindingFilter { wstg_id: Some("WSTG-CONF-07".into()), ..Default::default() };
        assert!(!matches(&r, &f));
    }

    #[test]
    fn every_valid_status_round_trips() {
        for label in VALID_STATUSES {
            let parsed = status_from_label(label).expect("status must parse");
            assert_eq!(crate::state::status_label(&parsed), *label);
        }
    }

    #[test]
    fn unknown_statuses_are_rejected() {
        assert!(status_from_label("Wontfix").is_none());
    }
}
