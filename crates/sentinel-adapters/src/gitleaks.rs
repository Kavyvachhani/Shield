//! Gitleaks secret-scanning adapter.
//!
//! Invokes the user-installed `gitleaks` binary over the target's repository
//! and parses its JSON report. Nothing here fabricates a finding: if the binary
//! is absent the stage is skipped, and if the repository is clean the result is
//! an empty list.

use crate::adapter_trait::ScannerAdapter;
use crate::runner::LocalCliRunner;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use sentinel_core::models::finding::Finding;
use sentinel_core::models::target::Target;
use sentinel_core::parser::gitleaks::GitleaksJsonParser;
use tokio::process::Command;
use uuid::Uuid;

pub struct GitleaksAdapter;

#[async_trait]
impl ScannerAdapter for GitleaksAdapter {
    fn name(&self) -> &'static str {
        "Gitleaks Secret Scanner"
    }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(LocalCliRunner::is_installed("gitleaks"))
    }

    async fn run(&self, target: &Target, _config_json: &str) -> Result<Vec<Finding>> {
        // ── 0. Resolve repo path ─────────────────────────────────────────────
        let repo_path = target.repo_ref.as_deref().ok_or_else(|| {
            anyhow!(
                "Gitleaks requires a repository path. \
                 Set 'repo_ref' on the target (e.g. /home/user/repos/acme-portal)."
            )
        })?;

        if !std::path::Path::new(repo_path).exists() {
            return Err(anyhow!("Gitleaks: Repository path not found: {}", repo_path));
        }

        // ── 1. Check binary ──────────────────────────────────────────────────
        if !LocalCliRunner::is_installed("gitleaks") {
            return Err(anyhow!(
                "Gitleaks not found on PATH — install it to enable secret scanning."
            ));
        }

        let scan_id = Uuid::new_v4();

        // ── 2. Build command ─────────────────────────────────────────────────
        // `detect` reads git history; `--no-git` also covers files that were
        // never committed. Report goes to stdout so nothing is written to the
        // analyst's disk.
        let mut cmd = Command::new("gitleaks");
        cmd.arg("detect")
            .arg("--source")
            .arg(repo_path)
            .arg("--report-format")
            .arg("json")
            .arg("--report-path")
            .arg("-")
            .arg("--no-banner")
            .arg("--exit-code")
            .arg("0");

        tracing::info!(repo_path, "Gitleaks: launching secret scan");

        // ── 3. Execute ───────────────────────────────────────────────────────
        let output = cmd
            .output()
            .await
            .context("Failed to spawn gitleaks — ensure it is installed on PATH")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() && stdout.trim().is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Gitleaks failed: {}", stderr.trim()));
        }

        // A clean repository reports an empty array, or nothing at all.
        let trimmed = stdout.trim();
        if trimmed.is_empty() || trimmed == "[]" || trimmed == "null" {
            tracing::info!(repo_path, "Gitleaks: no secrets detected");
            return Ok(vec![]);
        }

        // ── 4. Parse findings ────────────────────────────────────────────────
        let findings = GitleaksJsonParser::parse(trimmed, target.id, scan_id)
            .context("Gitleaks JSON parser failed")?;

        tracing::info!(finding_count = findings.len(), repo_path, "Gitleaks: findings parsed");
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target_with_repo(repo: Option<String>) -> Target {
        Target {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            name: "Test".into(),
            target_type: "Web App".into(),
            base_url: "http://localhost:3000".into(),
            repo_ref: repo,
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: None,
            created_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn healthcheck_does_not_panic() {
        assert!(GitleaksAdapter.healthcheck().await.is_ok());
    }

    /// The adapter previously returned a hardcoded "Stripe key in
    /// src/config/stripe.ts" finding for every scan, regardless of the target —
    /// so a URL-only engagement with no repository at all still produced a
    /// fabricated Critical in the client report.
    #[tokio::test]
    async fn a_target_with_no_repository_yields_no_fabricated_finding() {
        let result = GitleaksAdapter.run(&target_with_repo(None), "{}").await;
        assert!(result.is_err(), "a scan with no repository must not invent a finding");
        assert!(
            result.unwrap_err().to_string().contains("repository path"),
            "the error should say what is missing"
        );
    }

    #[tokio::test]
    async fn a_missing_repository_path_is_reported() {
        let result = GitleaksAdapter
            .run(&target_with_repo(Some("/nonexistent/path/xyz".into())), "{}")
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    /// An empty gitleaks report must stay empty rather than becoming a finding.
    #[test]
    fn a_clean_report_parses_to_no_findings() {
        let findings =
            GitleaksJsonParser::parse("[]", Uuid::new_v4(), Uuid::new_v4()).expect("parse");
        assert!(findings.is_empty());
    }

    /// Real gitleaks output shape, so the parser stays wired to the tool's
    /// actual field names.
    #[test]
    fn a_real_gitleaks_report_parses_into_findings() {
        let raw = r#"[
          {
            "Description": "Stripe Access Token",
            "File": "src/config/billing.ts",
            "StartLine": 42,
            "Secret": "sk_live_examplevalue",
            "RuleID": "stripe-access-token"
          }
        ]"#;
        let findings =
            GitleaksJsonParser::parse(raw, Uuid::new_v4(), Uuid::new_v4()).expect("parse");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].affected_component.contains("src/config/billing.ts"));
        assert!(findings[0].affected_component.contains("42"));
        assert_eq!(findings[0].cwe_id.as_deref(), Some("CWE-798"));
        // The raw secret must never be carried into evidence.
        for e in &findings[0].evidences {
            assert!(
                !e.content.contains("sk_live_examplevalue"),
                "the secret itself leaked into evidence"
            );
        }
    }
}
