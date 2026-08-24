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

/// Validate and normalize a target base URL.
///
/// A `starts_with("https://")` check is not validation: it accepts `https://`
/// with nothing after it, and it passes through malformed-but-parseable input
/// such as `https:///dev.example.com` verbatim. That second form does resolve
/// correctly — the URL spec ignores extra slashes after a special scheme — but
/// storing it as typed puts a triple slash into the scan console, the scope
/// banner and the client report, where it reads like a broken target and sends
/// anyone debugging a scan chasing the wrong thing.
///
/// Parse the URL properly, reject what has no host, and store the canonical
/// form so everything downstream displays one unambiguous URL.
fn validate_base_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Target base URL is required.".into());
    }

    let parsed = url::Url::parse(trimmed).map_err(|e| {
        format!("Target base URL '{trimmed}' is not a valid URL: {e}. Expected something like https://app.example.com")
    })?;

    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "Target base URL must use http or https, not '{other}'."
            ))
        }
    }

    // `Url::parse` already rejects an empty authority for http/https, but a
    // host that parses to nothing would leave every probe pointed at no host
    // at all, so refuse it explicitly rather than relying on that.
    if parsed.host_str().unwrap_or_default().is_empty() {
        return Err(format!("Target base URL '{trimmed}' has no host."));
    }

    // Canonical form, minus the bare trailing slash `Url` always adds to an
    // empty path — adapters append their own path separator, and a target
    // shown as `https://example.com` is what the analyst actually typed.
    let mut normalized = parsed.to_string();
    if parsed.path() == "/" && parsed.query().is_none() && parsed.fragment().is_none() {
        normalized.truncate(normalized.len() - 1);
    }
    Ok(normalized)
}

#[tauri::command]
pub async fn create_target(
    input: CreateTargetInput,
    state: State<'_, AppState>,
) -> Result<TargetRecord, String> {
    let base_url = validate_base_url(&input.base_url)?;
    let record = TargetRecord {
        id: new_id(),
        project_id: input.project_id,
        name: input.name,
        target_type: input.target_type,
        base_url,
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

#[cfg(test)]
mod base_url_tests {
    use super::validate_base_url;

    #[test]
    fn accepts_ordinary_targets_without_mangling_them() {
        for (input, expected) in [
            ("https://dev.industrility.com", "https://dev.industrility.com"),
            ("https://dev.industrility.com/", "https://dev.industrility.com"),
            ("http://localhost:8080", "http://localhost:8080"),
            ("https://10.0.0.5:8443/app", "https://10.0.0.5:8443/app"),
        ] {
            assert_eq!(validate_base_url(input).unwrap(), expected, "input {input}");
        }
    }

    /// The stray slash seen in a real engagement log. It resolves to the right
    /// host, so it must not be rejected — but it is normalized so it stops
    /// showing up as `https:///host` in the console and the client report.
    #[test]
    fn normalizes_a_stray_slash_after_the_scheme() {
        assert_eq!(
            validate_base_url("https:///dev.industrility.com").unwrap(),
            "https://dev.industrility.com"
        );
    }

    #[test]
    fn rejects_non_http_schemes_and_junk() {
        for url in [
            "ftp://example.com",
            "file:///etc/passwd",
            "example.com",
            "https://",
            "",
        ] {
            assert!(validate_base_url(url).is_err(), "should reject {url}");
        }
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(
            validate_base_url("  https://example.com  ").unwrap(),
            "https://example.com"
        );
    }

    /// Paths, queries and fragments are part of the target and must survive.
    #[test]
    fn preserves_path_and_query() {
        assert_eq!(
            validate_base_url("https://example.com/api/v2?tenant=acme").unwrap(),
            "https://example.com/api/v2?tenant=acme"
        );
    }
}
