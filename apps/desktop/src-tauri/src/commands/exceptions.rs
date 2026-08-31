//! Commands over the exception register.
//!
//! The register is what makes a triage decision permanent. A finding lives and
//! dies with the scan that raised it, so a status set on a finding is forgotten
//! the moment the target is re-scanned; a record here is held against the
//! *target* and keyed by a fingerprint that survives new ids, so the decision
//! is re-applied to every later scan automatically.
//!
//! Nothing in this module suppresses anything on its own. It records the
//! decision; `scan` applies it as findings arrive, and the report layer decides
//! how each kind is disclosed.

use crate::state::{log_persist_error, new_id, AppState};
use chrono::{DateTime, Utc};
use sentinel_core::exceptions::{ExceptionKind, ExceptionRecord};
use serde::{Deserialize, Serialize};
use tauri::State;

/// One row of the register as the UI renders it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExceptionView {
    pub id: String,
    pub target_id: String,
    pub fingerprint: String,
    /// "False Positive" | "Accepted Risk"
    pub kind: String,
    pub title: String,
    pub affected_component: String,
    pub severity: String,
    pub justification: String,
    pub raised_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether the exception is still in force right now.
    pub active: bool,
    /// Days until it lapses; negative once lapsed, absent when open-ended.
    pub days_until_expiry: Option<i64>,
}

impl From<&ExceptionRecord> for ExceptionView {
    fn from(r: &ExceptionRecord) -> Self {
        let now = Utc::now();
        Self {
            id: r.id.clone(),
            target_id: r.target_id.clone(),
            fingerprint: r.fingerprint.clone(),
            kind: r.kind.label().to_string(),
            title: r.title.clone(),
            affected_component: r.affected_component.clone(),
            severity: format!("{:?}", r.severity),
            justification: r.justification.clone(),
            raised_by: r.raised_by.clone(),
            created_at: r.created_at,
            expires_at: r.expires_at,
            active: r.is_active_at(now),
            days_until_expiry: r.days_until_expiry(now),
        }
    }
}

/// Every exception recorded against a target, newest decision first.
#[tauri::command]
pub async fn list_exceptions(
    target_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<ExceptionView>, String> {
    let register = state.exceptions.read().await;
    let mut rows: Vec<ExceptionView> = register
        .values()
        .filter(|r| r.target_id == target_id)
        .map(ExceptionView::from)
        .collect();
    rows.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.title.cmp(&b.title)));
    Ok(rows)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordExceptionInput {
    /// The finding the decision is being taken about.
    pub finding_id: String,
    /// "False Positive" | "Accepted Risk"
    pub kind: String,
    pub justification: String,
    pub raised_by: String,
    /// Optional review date for an acceptance, as an RFC 3339 timestamp.
    pub expires_at: Option<String>,
}

/// Record a decision against a finding, so it carries into every later scan.
///
/// This is the same operation `triage_finding` performs as a side effect; it is
/// exposed separately so the register screen can add or revise an entry without
/// having to locate the finding row it came from.
#[tauri::command]
pub async fn record_exception(
    input: RecordExceptionInput,
    state: State<'_, AppState>,
) -> Result<ExceptionView, String> {
    let kind = parse_kind(&input.kind)?;
    let justification = require("A justification", &input.justification)?;
    let raised_by = require("The name of the person accepting this", &input.raised_by)?;
    let expires_at = parse_expiry(input.expires_at.as_deref())?;

    let finding = {
        let store = state.findings.read().await;
        store
            .get(&input.finding_id)
            .map(|s| s.finding.clone())
            .ok_or_else(|| format!("Finding '{}' not found", input.finding_id))?
    };

    let record = sentinel_core::exceptions::from_triage(
        &finding,
        &kind.status(),
        &justification,
        &raised_by,
        expires_at,
        new_id(),
    )
    .ok_or_else(|| "That status does not create an exception.".to_string())?;

    let view = upsert(&record, &state).await;
    Ok(view)
}

/// Withdraw an exception. The weakness returns to the open list on the next scan.
#[tauri::command]
pub async fn revoke_exception(
    exception_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let removed = state.exceptions.write().await.remove(&exception_id);
    if removed.is_none() {
        return Err(format!("Exception '{exception_id}' not found"));
    }
    if let Err(e) = state.store.delete_exception(&exception_id) {
        log_persist_error("exception withdrawal", &e);
    }
    Ok(())
}

// ── Shared helpers, also used by the triage command ──────────────────────────

/// Insert or replace a record in both memory and the database.
///
/// Replacement is by `(target_id, fingerprint)` rather than by id: deciding the
/// same weakness twice is a revision of one entry, and keeping both would leave
/// the register asserting two different things about a single finding.
pub async fn upsert(record: &ExceptionRecord, state: &State<'_, AppState>) -> ExceptionView {
    let mut register = state.exceptions.write().await;

    let superseded: Vec<String> = register
        .values()
        .filter(|existing| {
            existing.target_id == record.target_id
                && existing.fingerprint == record.fingerprint
                && existing.id != record.id
        })
        .map(|existing| existing.id.clone())
        .collect();

    for id in superseded {
        register.remove(&id);
        if let Err(e) = state.store.delete_exception(&id) {
            log_persist_error("superseded exception", &e);
        }
    }

    register.insert(record.id.clone(), record.clone());
    if let Err(e) = state.store.save_exception(record) {
        log_persist_error("exception", &e);
    }

    ExceptionView::from(record)
}

/// Drop every exception covering a weakness, used when it is reopened.
pub async fn revoke_for(target_id: &str, fingerprint: &str, state: &State<'_, AppState>) -> usize {
    let mut register = state.exceptions.write().await;
    let matching: Vec<String> = register
        .values()
        .filter(|r| r.target_id == target_id && r.fingerprint == fingerprint)
        .map(|r| r.id.clone())
        .collect();

    for id in &matching {
        register.remove(id);
        if let Err(e) = state.store.delete_exception(id) {
            log_persist_error("withdrawn exception", &e);
        }
    }
    matching.len()
}

pub fn parse_kind(label: &str) -> Result<ExceptionKind, String> {
    match label {
        "False Positive" => Ok(ExceptionKind::FalsePositive),
        "Accepted Risk" => Ok(ExceptionKind::AcceptedRisk),
        other => Err(format!(
            "'{other}' is not an exception kind. Expected 'False Positive' or 'Accepted Risk'."
        )),
    }
}

/// Parse an optional review date, rejecting one already in the past.
///
/// An expiry behind us would suppress nothing and read, on the register, as an
/// acceptance that is simultaneously in force and lapsed.
pub fn parse_expiry(raw: Option<&str>) -> Result<Option<DateTime<Utc>>, String> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(raw)
        .map_err(|e| format!("'{raw}' is not a valid date: {e}"))?
        .with_timezone(&Utc);
    if parsed <= Utc::now() {
        return Err("The review date must be in the future.".to_string());
    }
    Ok(Some(parsed))
}

/// Require a non-blank field, with a message naming what is missing.
pub fn require(what: &str, value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{what} is required — an exception with no record of why cannot be audited."));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn both_exception_kinds_are_accepted_by_their_label() {
        assert_eq!(parse_kind("False Positive").unwrap(), ExceptionKind::FalsePositive);
        assert_eq!(parse_kind("Accepted Risk").unwrap(), ExceptionKind::AcceptedRisk);
    }

    /// `Remediated` is a fix, not an exception: suppressing the check that would
    /// prove the fix landed is exactly what re-testing exists to prevent.
    #[test]
    fn a_status_that_is_not_an_exception_is_rejected() {
        for label in ["Remediated", "Open", "In Progress", "Wontfix", ""] {
            assert!(parse_kind(label).is_err(), "{label} must not create an exception");
        }
    }

    #[test]
    fn an_absent_or_blank_expiry_means_open_ended() {
        assert!(parse_expiry(None).unwrap().is_none());
        assert!(parse_expiry(Some("   ")).unwrap().is_none());
    }

    #[test]
    fn a_future_review_date_is_accepted() {
        let when = (Utc::now() + Duration::days(90)).to_rfc3339();
        assert!(parse_expiry(Some(&when)).unwrap().is_some());
    }

    #[test]
    fn a_review_date_in_the_past_is_refused_rather_than_stored() {
        let when = (Utc::now() - Duration::days(1)).to_rfc3339();
        let err = parse_expiry(Some(&when)).unwrap_err();
        assert!(err.contains("must be in the future"), "{err}");
    }

    #[test]
    fn a_malformed_date_says_so_instead_of_being_ignored() {
        assert!(parse_expiry(Some("next tuesday")).is_err());
    }

    #[test]
    fn a_justification_and_an_owner_are_both_mandatory() {
        assert!(require("A justification", "   ").is_err());
        assert_eq!(require("A justification", "  no user input reaches it  ").unwrap(),
                   "no user input reaches it");
    }
}
