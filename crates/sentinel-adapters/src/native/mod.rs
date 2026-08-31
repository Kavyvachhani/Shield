//! The Sentinel Native check engine.
//!
//! A built-in, zero-dependency assessment engine. Unlike the ZAP, Nuclei,
//! Semgrep, Trivy and Gitleaks adapters — which orchestrate a binary the user
//! must install — this engine ships inside the application. It is therefore the
//! one engine guaranteed to be available on every platform, including a fresh
//! Windows install with nothing else set up.
//!
//! Scope of the engine:
//!   • security response headers, CSP analysis, cookie attributes, caching
//!   • TLS certificate validity, trust, hostname coverage, key strength
//!   • sensitive file, backup, VCS, admin and diagnostic endpoint exposure
//!   • CORS policy, HTTP methods, Host header handling, open redirects
//!   • response body analysis: mixed content, SRI, tabnabbing, error leakage
//!   • information disclosure: leaked credentials, private key material,
//!     internal addressing, cloud metadata references, framework versions
//!
//! SAFETY GUARANTEES
//! ─────────────────
//! • Always wrapped in `AuthGatedDastRunner`; it cannot run without a signed RoE.
//! • Only GET, HEAD and OPTIONS are ever issued — enforced in `probe::Probe`.
//! • No payload, fuzzing, brute force or state-changing request is sent.
//! • Requests are rate limited to the RoE's requests-per-second ceiling.
//! • Out-of-scope hosts and paths are refused before a socket is opened.

pub mod active;
pub mod builder;
pub mod content;
pub mod disclosure;
pub mod exposure;
pub mod headers;
pub mod probe;
pub mod tls;

use crate::adapter_trait::ScannerAdapter;
use crate::dast_config::DastConfig;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use probe::Probe;
use sentinel_core::models::finding::Finding;
use sentinel_core::models::target::Target;
use uuid::Uuid;

/// Engine name, matching `sentinel_core::checklist::catalog::engine::NATIVE`.
pub const ENGINE_NAME: &str = "Sentinel Native";

/// Every check the native engine ships, across all modules.
///
/// A report is only as trustworthy as the metadata behind each finding, so this
/// exists to be audited: see `spec_audit` below.
pub fn all_specs() -> Vec<&'static builder::CheckSpec> {
    headers::SPECS
        .iter()
        .chain(tls::SPECS)
        .chain(content::SPECS)
        .chain(disclosure::SPECS)
        .chain(exposure::SPECS)
        .chain(active::SPECS)
        .collect()
}

pub struct NativeCheckAdapter;

#[async_trait]
impl ScannerAdapter for NativeCheckAdapter {
    fn name(&self) -> &'static str {
        "Sentinel Native"
    }

    /// The native engine is compiled in, so it is always available.
    async fn healthcheck(&self) -> Result<bool> {
        Ok(true)
    }

    async fn run(&self, target: &Target, config_json: &str) -> Result<Vec<Finding>> {
        let cfg = DastConfig::from_json(config_json)?;
        let scan_id = Uuid::new_v4();
        let target_id = target.id;

        let roe_rps = target
            .authorization_record
            .as_ref()
            .map(|a| a.scope.rate_limit_rps)
            .unwrap_or(5);
        let rps = cfg.effective_rps(roe_rps);

        let base_url = target.base_url.trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(anyhow!("target has no base URL; nothing for the native engine to assess"));
        }

        tracing::info!(
            target_url = %base_url,
            rate_limit_rps = rps,
            "Sentinel Native: starting assessment"
        );

        let probe = Probe::new(target, rps, cfg.timeout_seconds)?;
        let mut findings: Vec<Finding> = Vec::new();

        // ── 1. Fetch the root document; everything passive derives from it ───
        let root = match probe.get(&format!("{base_url}/")).await? {
            Some(r) => r,
            None => {
                return Err(anyhow!(
                    "could not reach {base_url} — the host may be down, or it is outside the authorized scope"
                ))
            }
        };
        tracing::info!(status = root.status, "Sentinel Native: root document fetched");

        // ── 2. Passive header, cookie and CSP analysis ───────────────────────
        findings.extend(headers::run(target_id, scan_id, &root));

        // ── 3. Passive body analysis ─────────────────────────────────────────
        findings.extend(content::run(target_id, scan_id, &root));

        // ── 3b. Information disclosure in the delivered content ──────────────
        findings.extend(disclosure::run(target_id, scan_id, &root));

        // ── 4. TLS certificate inspection (HTTPS targets only) ───────────────
        if let Some((host, port)) = https_host_port(&base_url) {
            match tls::observe(&host, port, cfg.timeout_seconds).await {
                Ok(Some(observation)) => {
                    findings.extend(tls::analyze(
                        &observation,
                        target_id,
                        scan_id,
                        chrono::Utc::now(),
                    ));
                }
                Ok(None) => tracing::info!(host, port, "Sentinel Native: no TLS service to inspect"),
                Err(e) => tracing::warn!(host, port, error = %e, "Sentinel Native: TLS inspection failed"),
            }
        }

        // ── 5. Safe active checks ────────────────────────────────────────────
        findings.extend(active::run(&probe, target_id, scan_id, &base_url, &root).await);

        // ── 6. Sensitive path and metafile exposure ──────────────────────────
        findings.extend(exposure::run(&probe, target_id, scan_id, &base_url).await);

        // ── 7. Score every finding before handing them back ──────────────────
        for finding in &mut findings {
            sentinel_core::scoring::priority::PriorityScoringEngine::score_and_explain(finding);
        }

        tracing::info!(
            finding_count = findings.len(),
            target_url = %base_url,
            "Sentinel Native: assessment complete"
        );
        Ok(findings)
    }
}

/// Extract (host, port) for TLS inspection, or `None` for non-HTTPS targets.
pub fn https_host_port(base_url: &str) -> Option<(String, u16)> {
    let parsed = url::Url::parse(base_url).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?.to_string();
    let port = parsed.port().unwrap_or(443);
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinel_core::models::target::{AuthorizationRecord, ScopeDefinition, Target};

    fn target(base_url: &str, authorized: bool) -> Target {
        Target {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            name: "t".into(),
            target_type: "Web App".into(),
            base_url: base_url.into(),
            repo_ref: None,
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: authorized.then(|| AuthorizationRecord {
                id: Uuid::new_v4(),
                target_id: Uuid::new_v4(),
                scope: ScopeDefinition {
                    allowed_domains: vec!["example.com".into()],
                    allowed_ips_cidrs: vec![],
                    out_of_scope_paths: vec![],
                    rate_limit_rps: 5,
                    prohibited_actions: vec![],
                },
                acknowledged_by: "lead".into(),
                signed_at: Utc::now(),
                roe_document_hash: "h".into(),
                digital_signature: "s".into(),
            }),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn https_targets_yield_a_host_and_default_port() {
        assert_eq!(
            https_host_port("https://app.example.com"),
            Some(("app.example.com".to_string(), 443))
        );
    }

    #[test]
    fn explicit_ports_are_preserved() {
        assert_eq!(
            https_host_port("https://app.example.com:8443"),
            Some(("app.example.com".to_string(), 8443))
        );
    }

    #[test]
    fn http_targets_have_no_tls_endpoint() {
        assert!(https_host_port("http://app.example.com").is_none());
    }

    #[tokio::test]
    async fn healthcheck_always_succeeds_because_the_engine_is_built_in() {
        assert!(NativeCheckAdapter.healthcheck().await.unwrap());
    }

    #[tokio::test]
    async fn empty_base_url_is_rejected() {
        let result = NativeCheckAdapter.run(&target("", true), "{}").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no base URL"));
    }

    #[tokio::test]
    async fn unreachable_target_reports_a_clear_error_rather_than_panicking() {
        // A reserved .invalid host can never resolve (RFC 2606).
        let t = target("https://unreachable.invalid", true);
        let result = NativeCheckAdapter.run(&t, "{}").await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("could not reach"), "unexpected error: {msg}");
    }

    #[test]
    fn engine_name_matches_the_checklist_catalog() {
        assert_eq!(ENGINE_NAME, sentinel_core::checklist::catalog::engine::NATIVE);
        assert_eq!(NativeCheckAdapter.name(), ENGINE_NAME);
    }
}
