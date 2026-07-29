use tauri::State;
use serde::Deserialize;
use crate::state::{AppState, ProjectRecord, new_id};
use chrono::Utc;

#[derive(Debug, Deserialize)]
pub struct CreateProjectInput {
    pub company_name: String,
    pub name: String,
    pub logo_path: Option<String>,
    pub primary_color: Option<String>,
}

#[tauri::command]
pub async fn create_project(
    input: CreateProjectInput,
    state: State<'_, AppState>,
) -> Result<ProjectRecord, String> {
    let record = ProjectRecord {
        id: new_id(),
        company_name: input.company_name,
        logo_path: input.logo_path,
        primary_color: input.primary_color,
        name: input.name,
        created_at: Utc::now(),
    };
    state.projects.write().await.insert(record.id.clone(), record.clone());
    Ok(record)
}

#[tauri::command]
pub async fn list_projects(state: State<'_, AppState>) -> Result<Vec<ProjectRecord>, String> {
    let map = state.projects.read().await;
    let mut records: Vec<ProjectRecord> = map.values().cloned().collect();
    records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(records)
}

#[tauri::command]
pub async fn get_project(
    project_id: String,
    state: State<'_, AppState>,
) -> Result<ProjectRecord, String> {
    state.projects.read().await
        .get(&project_id)
        .cloned()
        .ok_or_else(|| format!("Project '{}' not found", project_id))
}
