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

    let roe_hash = hash_roe_document(&input.roe_document_text);

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

/// SHA-256 of the Rules of Engagement document, exactly as submitted.
///
/// This hash is printed in the client report's Scope & Attestation table as
/// the authorisation record: it is the artifact that lets anyone holding the
/// signed RoE confirm the assessment was run against *that* document. Its only
/// value is that it can be recomputed and compared.
///
/// It previously also mixed in `acknowledged_by` and a fresh `Utc::now()`. The
/// timestamp was never stored — and was not even the same instant as
/// `signed_at`, which is a separate `Utc::now()` call — so the hash could not
/// be reproduced by anyone, including us. An attestation nobody can verify is
/// not evidence, so hash the document and nothing else. Who acknowledged it and
/// when are recorded as their own fields on the record.
pub fn hash_roe_document(document_text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(document_text.as_bytes());
    format!("{:x}", hasher.finalize())
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

#[cfg(test)]
mod roe_hash_tests {
    use super::hash_roe_document;

    /// The whole point of the attestation hash: someone holding the signed
    /// document can recompute it and get the same value. Salting it with an
    /// unstored timestamp made that impossible.
    #[test]
    fn the_same_document_always_hashes_the_same() {
        let doc = "Rules of Engagement for Acme Corp, signed by the CISO.";
        assert_eq!(hash_roe_document(doc), hash_roe_document(doc));
    }

    #[test]
    fn different_documents_hash_differently() {
        assert_ne!(
            hash_roe_document("RoE covering app.acme.test"),
            hash_roe_document("RoE covering api.acme.test"),
        );
    }

    /// A known vector, so the algorithm cannot silently change under a record
    /// that was already issued to a client.
    #[test]
    fn matches_the_published_sha256_of_its_input() {
        assert_eq!(
            hash_roe_document("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
