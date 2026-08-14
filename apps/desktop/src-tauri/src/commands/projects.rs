use tauri::State;
use serde::Deserialize;
use crate::state::{log_persist_error, AppState, ProjectRecord, new_id};
use chrono::Utc;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProjectInput {
    pub company_name: String,
    pub name: String,
    pub logo_path: Option<String>,
    /// Base64 `data:image/...` logo. Non-image and remote values are rejected.
    pub logo_data_uri: Option<String>,
    pub primary_color: Option<String>,
}

/// The largest logo we will store inline. A logo is a header image a few
/// hundred pixels wide; anything past this is a photograph pasted by mistake,
/// and embedding it would bloat every report and the engagement database.
const MAX_LOGO_BYTES: usize = 2 * 1024 * 1024;

/// Accept a logo only if the report engine would actually render it.
///
/// The check mirrors `sentinel_core::reporting::escape::image_data_uri` (PNG,
/// JPEG, GIF or WebP base64; SVG excluded because it can carry script). Doing it
/// here means the analyst is told at upload time, rather than silently getting a
/// report with no logo on it.
fn validate_logo(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.len() > MAX_LOGO_BYTES {
        return Err(format!(
            "Logo is too large ({} KB). Please use an image under {} KB.",
            trimmed.len() / 1024,
            MAX_LOGO_BYTES / 1024
        ));
    }
    sentinel_core::reporting::escape::image_data_uri(trimmed)
        .map(|_| trimmed.to_string())
        .ok_or_else(|| {
            "Unsupported logo format. Use a PNG, JPEG, GIF or WebP image (SVG is not accepted)."
                .to_string()
        })
}

#[tauri::command]
pub async fn create_project(
    input: CreateProjectInput,
    state: State<'_, AppState>,
) -> Result<ProjectRecord, String> {
    let logo_data_uri = match input.logo_data_uri.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(validate_logo(raw)?),
        _ => None,
    };

    let record = ProjectRecord {
        id: new_id(),
        company_name: input.company_name,
        logo_path: input.logo_path,
        logo_data_uri,
        primary_color: input.primary_color,
        name: input.name,
        created_at: Utc::now(),
    };
    if let Err(e) = state.store.save_project(&record) {
        log_persist_error("project", &e);
    }
    state.projects.write().await.insert(record.id.clone(), record.clone());
    Ok(record)
}

#[tauri::command]
pub async fn list_projects(state: State<'_, AppState>) -> Result<Vec<ProjectRecord>, String> {
    let map = state.projects.read().await;
    let mut records: Vec<ProjectRecord> = map.values().cloned().collect();
    records.sort_by_key(|r| std::cmp::Reverse(r.created_at));
    Ok(records)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetProjectLogoInput {
    pub project_id: String,
    /// `None` (or empty) clears the logo; reports then render without one.
    pub logo_data_uri: Option<String>,
}

/// Attach the client's logo to a project so every report generated for that
/// engagement is branded, and the analyst uploads it once rather than per report.
#[tauri::command]
pub async fn set_project_logo(
    input: SetProjectLogoInput,
    state: State<'_, AppState>,
) -> Result<ProjectRecord, String> {
    let logo = match input.logo_data_uri.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(validate_logo(raw)?),
        _ => None,
    };

    let mut projects = state.projects.write().await;
    let record = projects
        .get_mut(&input.project_id)
        .ok_or_else(|| format!("Project '{}' not found", input.project_id))?;

    record.logo_data_uri = logo;
    let updated = record.clone();
    drop(projects);

    if let Err(e) = state.store.save_project(&updated) {
        log_persist_error("project", &e);
    }
    Ok(updated)
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

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==";

    #[test]
    fn a_real_png_logo_is_accepted() {
        assert_eq!(validate_logo(PNG).unwrap(), PNG);
    }

    #[test]
    fn jpeg_gif_and_webp_are_accepted_too() {
        for prefix in [
            "data:image/jpeg;base64,",
            "data:image/gif;base64,",
            "data:image/webp;base64,",
        ] {
            let uri = format!("{prefix}iVBORw0KGgo=");
            assert!(validate_logo(&uri).is_ok(), "{prefix} should be a valid logo");
        }
    }

    #[test]
    fn svg_is_rejected_because_it_can_carry_script() {
        let err = validate_logo("data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=").unwrap_err();
        assert!(err.contains("SVG is not accepted"), "got: {err}");
    }

    #[test]
    fn a_remote_url_is_rejected_so_reports_stay_offline() {
        // A report that fetches its logo would leak the recipient's IP and
        // render blank without a network.
        assert!(validate_logo("https://acme.test/logo.png").is_err());
        assert!(validate_logo("/Users/analyst/logo.png").is_err());
    }

    #[test]
    fn an_oversized_logo_is_rejected_with_its_size() {
        let huge = format!("data:image/png;base64,{}", "A".repeat(MAX_LOGO_BYTES + 1));
        let err = validate_logo(&huge).unwrap_err();
        assert!(err.contains("too large"), "got: {err}");
    }
}
