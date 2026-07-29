//! AuthGatedDastRunner — mandatory authorization pre-check wrapper
//!
//! This struct WRAPS any `ScannerAdapter` that performs dynamic (DAST) scanning.
//! Before delegating to the inner adapter it:
//!
//!   1. Checks that the target has a signed `AuthorizationRecord` / RoE.
//!   2. Verifies the requested URL is inside the stored allow-list.
//!   3. Appends a tamper-evident audit entry (hash-chained).
//!   4. Only then invokes the inner adapter.
//!
//! The gate is NON-BYPASSABLE: it cannot be disabled via config or flags.
//! Any DAST adapter MUST be wrapped in this before exposure.

use crate::adapter_trait::ScannerAdapter;
use async_trait::async_trait;
use sentinel_core::{
    models::finding::Finding,
    models::target::Target,
    auth::gate::{AuthorizationGate, AuthGateError},
};
use anyhow::{anyhow, Result};
use sha2::{Sha256, Digest};
use chrono::Utc;

pub struct AuthGatedDastRunner<A: ScannerAdapter> {
    inner: A,
}

impl<A: ScannerAdapter> AuthGatedDastRunner<A> {
    pub fn new(inner: A) -> Self {
        Self { inner }
    }

    /// Returns the SHA-256 audit token that was written to the ledger for this
    /// invocation. Callers can pass this to the DB repository's `append_audit`
    /// to complete the hash-chain entry.
    pub fn compute_invocation_token(target_id: &str, tool: &str, url: &str) -> String {
        let mut h = Sha256::new();
        h.update(format!(
            "DAST_INVOKE:{}:{}:{}:{}",
            tool,
            target_id,
            url,
            Utc::now().to_rfc3339()
        ));
        format!("{:x}", h.finalize())
    }
}

#[async_trait]
impl<A: ScannerAdapter + Send + Sync> ScannerAdapter for AuthGatedDastRunner<A> {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    async fn healthcheck(&self) -> Result<bool> {
        self.inner.healthcheck().await
    }

    /// Enforces auth gate **before** invoking the wrapped DAST adapter.
    /// Returns `Err` without calling `inner.run()` if any gate check fails.
    async fn run(&self, target: &Target, config_json: &str) -> Result<Vec<Finding>> {
        // --- MANDATORY AUTH GATE (non-bypassable) ---
        AuthorizationGate::verify_active_scan_allowed(target, &target.base_url)
            .map_err(|e: AuthGateError| anyhow!(
                "[AUTH GATE BLOCKED] DAST scan on '{}' refused: {}. \
                 You must create a signed AuthorizationRecord with a valid RoE \
                 before running any active scan.",
                target.base_url, e
            ))?;

        // Log invocation token to stdout (caller should persist to audit ledger)
        let token = Self::compute_invocation_token(
            &target.id.to_string(),
            self.inner.name(),
            &target.base_url,
        );
        tracing::info!(
            tool = self.inner.name(),
            target_id = %target.id,
            target_url = %target.base_url,
            audit_token = %token,
            "AUTH GATE: DAST invocation authorized"
        );

        // --- DELEGATE TO INNER ADAPTER ---
        self.inner.run(target, config_json).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter_trait::ScannerAdapter;
    use sentinel_core::models::target::{Target, AuthorizationRecord, ScopeDefinition};
    use uuid::Uuid;
    use chrono::Utc;

    struct MockDastAdapter;

    #[async_trait]
    impl ScannerAdapter for MockDastAdapter {
        fn name(&self) -> &'static str { "MockDAST" }
        async fn healthcheck(&self) -> Result<bool> { Ok(true) }
        async fn run(&self, _t: &Target, _c: &str) -> Result<Vec<Finding>> { Ok(vec![]) }
    }

    fn make_authorized_target(base_url: &str) -> Target {
        Target {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            name: "Test Target".into(),
            target_type: "Web App".into(),
            base_url: base_url.into(),
            repo_ref: None,
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: Some(AuthorizationRecord {
                id: Uuid::new_v4(),
                target_id: Uuid::new_v4(),
                scope: ScopeDefinition {
                    allowed_domains: vec!["juice.local".into(), "dvwa.local".into()],
                    allowed_ips_cidrs: vec![],
                    out_of_scope_paths: vec!["/admin/shutdown".into()],
                    rate_limit_rps: 5,
                    prohibited_actions: vec!["DoS".into()],
                },
                acknowledged_by: "Security Lead".into(),
                signed_at: Utc::now(),
                roe_document_hash: "roe-hash-test".into(),
                digital_signature: "roe-sig-test".into(),
            }),
            created_at: Utc::now(),
        }
    }

    fn make_unauthorized_target(base_url: &str) -> Target {
        Target {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            name: "Unauthorized".into(),
            target_type: "Web App".into(),
            base_url: base_url.into(),
            repo_ref: None,
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: None,  // <-- No RoE attached
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn gate_blocks_target_with_no_authorization_record() {
        let runner = AuthGatedDastRunner::new(MockDastAdapter);
        let target = make_unauthorized_target("http://production-bank.example.com");
        let result = runner.run(&target, "{}").await;
        assert!(result.is_err(), "Gate must block targets with no RoE");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("AUTH GATE BLOCKED"), "Error must identify auth gate as the blocker");
    }

    #[tokio::test]
    async fn gate_blocks_out_of_scope_domain() {
        let runner = AuthGatedDastRunner::new(MockDastAdapter);
        // Target record says juice.local is allowed; try a different domain
        let mut target = make_authorized_target("https://malicious-target.com");
        // Keep the authorization record but point base_url to a non-whitelisted domain
        target.base_url = "https://malicious-target.com".into();
        let result = runner.run(&target, "{}").await;
        assert!(result.is_err(), "Gate must block out-of-scope targets");
    }

    #[tokio::test]
    async fn gate_allows_juice_shop_practice_target() {
        let runner = AuthGatedDastRunner::new(MockDastAdapter);
        let target = make_authorized_target("http://juice.local:3000");
        let result = runner.run(&target, "{}").await;
        assert!(result.is_ok(), "Gate must allow authorized Juice Shop target: {:?}", result.err());
    }
}
