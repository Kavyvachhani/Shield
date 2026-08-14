use tauri::State;
use serde::Deserialize;
use crate::state::{log_persist_error, AppState, TargetRecord, new_id};
use chrono::Utc;

#[derive(Debug, Deserialize)]
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
    records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
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
