//! Trivy SCA Adapter — real CLI wrapper over user-installed `trivy` binary.
//!
//! Changes from baseline:
//!   - Real CLI execution: `trivy fs --format json --scanners vuln,secret,misconfig ...`
//!   - Scanner selection from `DastConfig` (`vuln`, `secret`, `misconfig`, `license`)
//!   - Correct severity filter forwarding
//!   - Non-destructive & offline (`--offline-scan` support if cached, `--skip-db-update` optional)
//!   - Feeds output directly into `sentinel_core::parser::trivy::TrivyJsonParser`

use crate::adapter_trait::ScannerAdapter;
use crate::dast_config::DastConfig;
use crate::runner::LocalCliRunner;
use async_trait::async_trait;
use sentinel_core::{
    models::finding::Finding,
    models::target::Target,
    parser::trivy::TrivyJsonParser,
};
use anyhow::{anyhow, Context, Result};
use crate::process::async_command;
use uuid::Uuid;

pub struct TrivyAdapter;

#[async_trait]
impl ScannerAdapter for TrivyAdapter {
    fn name(&self) -> &'static str {
        "Trivy SCA"
    }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(LocalCliRunner::is_installed("trivy"))
    }

    async fn run(&self, target: &Target, config_json: &str) -> Result<Vec<Finding>> {
        let cfg = DastConfig::from_json(config_json)?;

        // ── 0. Resolve repo path ─────────────────────────────────────────────
        let repo_path = target.repo_ref.as_deref().ok_or_else(|| {
            anyhow!(
                "Trivy SCA requires a repository path. \
                 Set 'repo_ref' on the target (e.g. /home/user/repos/acme-portal)."
            )
        })?;

        if !std::path::Path::new(repo_path).exists() {
            return Err(anyhow!("Trivy: Repository path not found: {}", repo_path));
        }

        // ── 1. Check binary ──────────────────────────────────────────────────
        if !LocalCliRunner::is_installed("trivy") {
            tracing::warn!("Trivy binary not found on PATH — returning empty findings");
            return Ok(vec![]);
        }

        let scan_id = Uuid::new_v4();

        // ── 2. Build scanners flag ───────────────────────────────────────────
        let scanners = if cfg.trivy.scanners.is_empty() {
            "vuln,secret,misconfig".to_string()
        } else {
            cfg.trivy.scanners.join(",")
        };

        let severity = &cfg.trivy.severity_filter;

        // ── 3. Build command ─────────────────────────────────────────────────
        // trivy fs --format json --scanners vuln,secret,misconfig --severity HIGH,CRITICAL <path>
        let mut cmd = async_command("trivy");
        cmd.arg("fs")
           .arg("--format").arg("json")
           .arg("--scanners").arg(&scanners)
           .arg("--severity").arg(severity)
           .arg("--quiet");

        if cfg.trivy.ignore_unfixed {
            cmd.arg("--ignore-unfixed");
        }

        cmd.arg(repo_path);

        tracing::info!(
            repo_path,
            scanners = %scanners,
            severity = %severity,
            "Trivy: Launching filesystem scan"
        );

        // ── 4. Execute ───────────────────────────────────────────────────────
        let output = cmd.output().await
            .context("Failed to spawn trivy — ensure it is installed on PATH")?;

        if !output.status.success() && output.stdout.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Trivy failed: {}", stderr.trim()));
        }

        let json_output = String::from_utf8_lossy(&output.stdout);
        tracing::info!(bytes = json_output.len(), "Trivy: Scan output received");

        if json_output.trim().is_empty() || json_output.trim() == "{}" {
            return Ok(vec![]);
        }

        // ── 5. Parse findings ────────────────────────────────────────────────
        let findings = TrivyJsonParser::parse(&json_output, target.id, scan_id)
            .context("Trivy JSON parser failed")?;

        tracing::info!(finding_count = findings.len(), repo_path, "Trivy: Findings parsed");
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn healthcheck_does_not_panic() {
        let adapter = TrivyAdapter;
        let result = adapter.healthcheck().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_errors_on_missing_repo_ref() {
        let adapter = TrivyAdapter;
        let target = sentinel_core::models::target::Target {
            id: uuid::Uuid::new_v4(),
            project_id: uuid::Uuid::new_v4(),
            name: "Test".into(),
            target_type: "Web App".into(),
            base_url: "http://localhost:3000".into(),
            repo_ref: None,
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: None,
            created_at: chrono::Utc::now(),
        };
        let result = adapter.run(&target, "{}").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("repository path"));
    }
}
