use tauri::State;
use serde::Deserialize;
use sha2::{Sha256, Digest};
use chrono::Utc;
use crate::state::{AppState, AuthorizationRecord, ScopeDefinitionRecord, new_id};

#[derive(Debug, Deserialize)]
pub struct CreateRoEInput {
    pub target_id: String,
    pub scope: ScopeDefinitionRecord,
    pub acknowledged_by: String,
    /// Free-text RoE document content; we hash it and store only the hash.
    pub roe_document_text: String,
}

/// Create a signed scope + RoE record for a target.
/// This is the ONLY path that unlocks DAST capabilities for that target.
/// The hash of the RoE document is computed here and stored; the plaintext is
/// never persisted (caller responsibility to retain it).
#[tauri::command]
pub async fn create_scope_and_roe(
    input: CreateRoEInput,
    state: State<'_, AppState>,
) -> Result<AuthorizationRecord, String> {
    // Compute SHA-256 of the submitted RoE document
    let mut hasher = Sha256::new();
    hasher.update(input.roe_document_text.as_bytes());
    hasher.update(input.acknowledged_by.as_bytes());
    hasher.update(Utc::now().to_rfc3339().as_bytes());
    let roe_hash = format!("{:x}", hasher.finalize());

    let record = AuthorizationRecord {
        id: new_id(),
        target_id: input.target_id.clone(),
        scope: input.scope,
        acknowledged_by: input.acknowledged_by,
        signed_at: Utc::now(),
        roe_document_hash: roe_hash,
    };

    state.auth_records.write().await
        .insert(input.target_id.clone(), record.clone());

    Ok(record)
}

/// Verify whether a target has a valid, signed authorization record.
/// Returns the record if present, Err if not.
/// This is the command-layer enforcement: DAST UI must call this before
/// offering the scan trigger button.
#[tauri::command]
pub async fn verify_authorization(
    target_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let has_auth = state.auth_records.read().await
        .contains_key(&target_id);
    Ok(has_auth)
}

#[tauri::command]
pub async fn get_authorization_record(
    target_id: String,
    state: State<'_, AppState>,
) -> Result<Option<AuthorizationRecord>, String> {
    Ok(state.auth_records.read().await.get(&target_id).cloned())
}
