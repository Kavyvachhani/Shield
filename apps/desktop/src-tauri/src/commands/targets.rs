use tauri::State;
use serde::{Deserialize, Serialize};
use crate::state::{log_persist_error, AppState, TargetRecord, new_id};
use chrono::Utc;
use sentinel_adapters::credentials::{CredentialKind, TargetCredential};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTargetInput {
    pub project_id: String,
    pub name: String,
    pub target_type: String,
    pub base_url: String,
    pub repo_ref: Option<String>,
    pub stack_description: Option<String>,
}

#[tauri::command]
pub async fn create_target(
    input: CreateTargetInput,
    state: State<'_, AppState>,
) -> Result<TargetRecord, String> {
    // Validate base_url is a well-formed URL
    if !input.base_url.starts_with("http://") && !input.base_url.starts_with("https://") {
        return Err("Target base URL must begin with http:// or https://".into());
    }
    let record = TargetRecord {
        id: new_id(),
        project_id: input.project_id,
        name: input.name,
        target_type: input.target_type,
        base_url: input.base_url,
        repo_ref: input.repo_ref,
        stack_description: input.stack_description,
        auth_keychain_handle: None,
        created_at: Utc::now(),
    };
    if let Err(e) = state.store.save_target(&record) {
        log_persist_error("target", &e);
    }
    state.targets.write().await.insert(record.id.clone(), record.clone());
    Ok(record)
}

#[tauri::command]
pub async fn list_targets(
    project_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<TargetRecord>, String> {
    let map = state.targets.read().await;
    let mut records: Vec<TargetRecord> = map.values()
        .filter(|t| t.project_id == project_id)
        .cloned()
        .collect();
    records.sort_by_key(|r| std::cmp::Reverse(r.created_at));
    Ok(records)
}

#[tauri::command]
pub async fn get_target(
    target_id: String,
    state: State<'_, AppState>,
) -> Result<TargetRecord, String> {
    state.targets.read().await
        .get(&target_id)
        .cloned()
        .ok_or_else(|| format!("Target '{}' not found", target_id))
}

#[tauri::command]
pub async fn update_target_repo(
    target_id: String,
    repo_ref: String,
    state: State<'_, AppState>,
) -> Result<TargetRecord, String> {
    let mut map = state.targets.write().await;
    let target = map.get_mut(&target_id)
        .ok_or_else(|| format!("Target '{}' not found", target_id))?;
    target.repo_ref = Some(repo_ref);
    if let Err(e) = state.store.save_target(target) {
        log_persist_error("target repository path", &e);
    }
    Ok(target.clone())
}

// ── Scan credentials ─────────────────────────────────────────────────────────
//
// The secret goes to the OS keychain and only the handle is stored on the
// target, so the engagement database never holds a password. Nothing in this
// module returns a secret back to the UI — once saved, it can be replaced or
// removed but not read.

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetCredentialsInput {
    pub target_id: String,
    /// "basic" | "bearer" | "cookie" | "header"
    pub kind: String,
    /// Username, for `basic`.
    pub username: Option<String>,
    /// Password, token, or cookie string, depending on `kind`.
    pub secret: String,
    /// Header name, for `header`. Defaults to `X-API-Key`.
    pub header_name: Option<String>,
}

/// What the UI may know about a stored credential: that one exists and how it
/// authenticates — never the secret itself.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub configured: bool,
    pub description: Option<String>,
}

#[tauri::command]
pub async fn set_target_credentials(
    input: SetCredentialsInput,
    state: State<'_, AppState>,
) -> Result<CredentialStatus, String> {
    let kind = CredentialKind::parse(&input.kind).map_err(|e| e.to_string())?;
    let credential = TargetCredential {
        kind,
        username: input.username,
        secret: input.secret,
        header_name: input.header_name,
    };
    // Validate before writing, so a bad credential never reaches the keychain.
    credential.validate().map_err(|e| e.to_string())?;

    let handle = TargetCredential::handle_for(&input.target_id);
    credential.store(&handle).map_err(|e| e.to_string())?;

    let mut map = state.targets.write().await;
    let target = map
        .get_mut(&input.target_id)
        .ok_or_else(|| format!("Target '{}' not found", input.target_id))?;
    target.auth_keychain_handle = Some(handle);
    if let Err(e) = state.store.save_target(target) {
        log_persist_error("target credential handle", &e);
    }

    Ok(CredentialStatus {
        configured: true,
        description: Some(credential.describe()),
    })
}

#[tauri::command]
pub async fn clear_target_credentials(
    target_id: String,
    state: State<'_, AppState>,
) -> Result<CredentialStatus, String> {
    let handle = TargetCredential::handle_for(&target_id);
    TargetCredential::delete(&handle).map_err(|e| e.to_string())?;

    let mut map = state.targets.write().await;
    let target = map
        .get_mut(&target_id)
        .ok_or_else(|| format!("Target '{}' not found", target_id))?;
    target.auth_keychain_handle = None;
    if let Err(e) = state.store.save_target(target) {
        log_persist_error("target credential handle", &e);
    }

    Ok(CredentialStatus { configured: false, description: None })
}

#[tauri::command]
pub async fn get_target_credential_status(
    target_id: String,
    state: State<'_, AppState>,
) -> Result<CredentialStatus, String> {
    let handle = {
        let map = state.targets.read().await;
        let target = map
            .get(&target_id)
            .ok_or_else(|| format!("Target '{}' not found", target_id))?;
        target.auth_keychain_handle.clone()
    };

    let Some(handle) = handle else {
        return Ok(CredentialStatus { configured: false, description: None });
    };

    // A handle recorded on the target but missing from the keychain means the
    // credential was removed out of band. Report it as absent rather than
    // erroring, so the analyst can simply re-enter it.
    match TargetCredential::load(&handle) {
        Ok(Some(cred)) => Ok(CredentialStatus {
            configured: true,
            description: Some(cred.describe()),
        }),
        Ok(None) => Ok(CredentialStatus { configured: false, description: None }),
        Err(e) => Err(e.to_string()),
    }
}
