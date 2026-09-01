use crate::commands::exceptions::{self, ExceptionView};
use crate::state::{log_persist_error, new_id, status_from_label, to_record, AppState, FindingRecord};
use chrono::Utc;
use sentinel_core::exceptions::ExceptionKind;
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct FindingDetail {
    pub record: FindingRecord,
    pub evidences: Vec<EvidenceView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct TriageInput {
    pub finding_id: String,
    pub new_status: String,
    pub triage_note: String,
    pub analyst_name: String,
    /// Review date for an acceptance, as an RFC 3339 timestamp. Optional; an
    /// acceptance without one stands until it is withdrawn.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// The outcome of a triage decision.
///
/// The updated finding is not the whole story any more. Dismissing or accepting
/// a weakness also writes a record against the target, and reopening one
/// withdraws it — the analyst needs to be told that happened, because it governs
/// what the *next* scan reports, not just this one.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageOutcome {
    pub finding: FindingRecord,
    /// The exception this decision recorded, when it recorded one.
    pub exception: Option<ExceptionView>,
    /// How many standing exceptions this decision withdrew.
    pub withdrawn: usize,
    /// Plain-language summary of what will happen on the next scan.
    pub effect: String,
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
) -> Result<TriageOutcome, String> {
    let status = status_from_label(&input.new_status).ok_or_else(|| {
        format!(
            "Invalid status '{}'. Must be one of: {}",
            input.new_status,
            VALID_STATUSES.join(", ")
        )
    })?;
    let note = exceptions::require("A triage note", &input.triage_note)?;
    let analyst = exceptions::require("The analyst name", &input.analyst_name)?;
    // Parsed before anything is mutated, so a bad date cannot leave the finding
    // half-triaged with no exception recorded against it.
    let expires_at = exceptions::parse_expiry(input.expires_at.as_deref())?;

    let (record, updated) = {
        let mut store = state.findings.write().await;
        let stored = store
            .get_mut(&input.finding_id)
            .ok_or_else(|| format!("Finding '{}' not found", input.finding_id))?;

        stored.finding.status = status.clone();
        // Notes append rather than overwrite: the triage history is audit evidence.
        let entry = format!(
            "[{}] {} → {}: {}",
            Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
            analyst,
            input.new_status,
            note
        );
        stored.triage_note = Some(match &stored.triage_note {
            Some(existing) => format!("{existing}\n{entry}"),
            None => entry,
        });

        if let Err(e) = state.store.save_finding(&input.finding_id, stored) {
            log_persist_error("triage decision", &e);
        }

        let record = sentinel_core::exceptions::from_triage(
            &stored.finding,
            &status,
            &note,
            &analyst,
            expires_at,
            new_id(),
        );
        (
            record,
            to_record(&stored.finding, &stored.scan_id, stored.triage_note.clone()),
        )
    };

    // A dismissal or an acceptance is recorded against the target so the next
    // scan honours it. Any other status withdraws a standing exception: moving a
    // finding back to Open, or marking it Remediated, has to let the re-test
    // raise it again — that is how a fix is proven rather than asserted.
    match record {
        Some(record) => {
            let kind = record.kind;
            let view = exceptions::upsert(&record, &state).await;
            Ok(TriageOutcome {
                finding: updated,
                effect: effect_of(kind, view.expires_at.is_some()),
                exception: Some(view),
                withdrawn: 0,
            })
        }
        None => {
            let withdrawn = exceptions::revoke_for(
                &updated.target_id,
                &updated.fingerprint,
                &state,
            )
            .await;
            Ok(TriageOutcome {
                effect: reopened_effect(&input.new_status, withdrawn),
                finding: updated,
                exception: None,
                withdrawn,
            })
        }
    }
}

/// What the analyst should expect to see on the next scan.
fn effect_of(kind: ExceptionKind, has_review_date: bool) -> String {
    match kind {
        ExceptionKind::FalsePositive => "Recorded against this target. The finding is removed from \
             every report, and the next scan will apply the same dismissal automatically — you will \
             not be asked about it again."
            .to_string(),
        ExceptionKind::AcceptedRisk => {
            let tail = if has_review_date {
                " The acceptance lapses on the review date, at which point the finding returns to the \
                 open list."
            } else {
                " It stands until you withdraw it."
            };
            format!(
                "Recorded against this target. The finding leaves the open counts, the posture score \
                 and the remediation roadmap, and is disclosed instead in the client report's \
                 accepted-risk register with this justification.{tail}"
            )
        }
    }
}

fn reopened_effect(status: &str, withdrawn: usize) -> String {
    if withdrawn == 0 {
        return format!(
            "Status set to {status}. Nothing is suppressed: the next scan re-tests this weakness, \
             which is how a fix is confirmed rather than assumed."
        );
    }
    format!(
        "Status set to {status}, and {withdrawn} standing exception{} withdrawn. This weakness will \
         be reported again on the next scan.",
        if withdrawn == 1 { "" } else { "s" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::to_record;
    use chrono::Utc;
    use sentinel_core::models::finding::{Finding, FindingStatus, Severity, FindingKind};
    use uuid::Uuid;

    fn record(title: &str, severity: Severity, score: f64, tool: &str) -> FindingRecord {
        let f = Finding {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            title: title.into(),
            description: "A description mentioning cookies.".into(),
            severity,
            kind: FindingKind::default(),
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
