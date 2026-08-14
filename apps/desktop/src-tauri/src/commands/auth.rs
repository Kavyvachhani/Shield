use tauri::State;
use serde::Deserialize;
use sha2::{Sha256, Digest};
use chrono::Utc;
use crate::state::{log_persist_error, AppState, AuthorizationRecord, ScopeDefinitionRecord, new_id};
use sentinel_core::auth::gate::AuthorizationGate;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
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
    // A scope that does not cover the target's own base URL produces an
    // engagement that can never scan anything: every dynamic stage is refused
    // and the run finishes in milliseconds with no findings and no visible
    // reason. Catch it here, while the analyst is still looking at the scope
    // form, rather than letting them discover it as a silently empty scan.
    let base_url = {
        let targets = state.targets.read().await;
        targets
            .get(&input.target_id)
            .map(|t| t.base_url.clone())
            .ok_or_else(|| format!("Target '{}' not found", input.target_id))?
    };
    if !AuthorizationGate::scope_covers_target(&base_url, &input.scope.allowed_domains) {
        let host = base_url
            .rsplit("://")
            .next()
            .unwrap_or(&base_url)
            .split('/')
            .next()
            .unwrap_or(&base_url);
        return Err(format!(
            "This scope would not authorize scanning the target itself. The target is \
             '{base_url}', but the allowed domains are {:?} — so every request to \
             '{host}' would be refused and the scan would find nothing. Add '{host}' \
             (or a parent domain of it) to the allowed domains.",
            input.scope.allowed_domains
        ));
    }

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

    // The signed authorisation is the record proving testing was permitted, so
    // it is written to disk before it is acknowledged in memory.
    if let Err(e) = state.store.save_auth_record(&input.target_id, &record) {
        log_persist_error("the signed authorisation record", &e);
    }
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
