//! Nuclei DAST Adapter — tag-filtered, version-aware, non-destructive.
//!
//! Changes from baseline:
//!   - Tags filter: -tags <include_tags> (run only matching templates)
//!   - Exclude tags: -etags dos,fuzzing,intrusive (always excluded by default)
//!   - Custom template paths: additional -t entries
//!   - Version check: `nuclei -version` before scan; logged for audit
//!
//! We NEVER generate, modify, or bundle templates. We invoke the user's
//! installed nuclei binary with its own template set (usually ~/.nuclei-templates/).
//!
//! SAFETY GUARANTEES
//! ─────────────────
//! • ALWAYS wrapped in `AuthGatedDastRunner` before use.
//! • `-no-interactsh` disables out-of-band data exfiltration callbacks.
//! • `-etags dos,fuzzing,intrusive` excluded by default regardless of user config.
//! • Rate limiting: `-rl <rps>` clamped to signed RoE rate limit.

use crate::adapter_trait::ScannerAdapter;
use crate::dast_config::DastConfig;
use crate::runner::LocalCliRunner;
use async_trait::async_trait;
use sentinel_core::{
    models::finding::Finding,
    models::target::Target,
    parser::nuclei::NucleiJsonlParser,
};
use anyhow::{anyhow, Context, Result};
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use uuid::Uuid;

// Template tags that are ALWAYS excluded regardless of user configuration.
// These cover destructive, DoS, and exfiltration-risk template categories.
const ALWAYS_EXCLUDED_TAGS: &[&str] = &["dos", "fuzzing", "intrusive", "network", "file"];

pub struct NucleiDastAdapter;

impl NucleiDastAdapter {
    /// Run `nuclei -version` and return the version string for audit logging.
    pub async fn get_version() -> Result<String> {
        let output = Command::new("nuclei")
            .arg("-version")
            .output()
            .await
            .context("Failed to run nuclei -version")?;
        let raw = String::from_utf8_lossy(&output.stderr); // nuclei prints version to stderr
        let version = raw.lines()
            .find(|l| l.contains("Nuclei Engine Version") || l.contains("Version"))
            .unwrap_or("unknown version")
            .trim()
            .to_string();
        Ok(version)
    }

    /// Build the final exclude-tags list: always-excluded + user-configured.
    fn build_exclude_tags(user_excludes: Option<&str>) -> String {
        let mut tags: Vec<&str> = ALWAYS_EXCLUDED_TAGS.to_vec();
        if let Some(user) = user_excludes {
            for t in user.split(',').map(|s| s.trim()) {
                if !t.is_empty() && !tags.contains(&t) {
                    tags.push(t);
                }
            }
        }
        tags.join(",")
    }
}

#[async_trait]
impl ScannerAdapter for NucleiDastAdapter {
    fn name(&self) -> &'static str { "Nuclei" }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(LocalCliRunner::is_installed("nuclei"))
    }

    async fn run(&self, target: &Target, config_json: &str) -> Result<Vec<Finding>> {
        // ── 0. Verify tool installed ─────────────────────────────────────────
        if !LocalCliRunner::is_installed("nuclei") {
            return Err(anyhow!(
                "Nuclei binary not found on PATH. \
                 Install from https://github.com/projectdiscovery/nuclei/releases \
                 and ensure it is on your system PATH."
            ));
        }

        let cfg = DastConfig::from_json(config_json)?;
        let scan_id = Uuid::new_v4();
        let target_url = &target.base_url;

        // ── 1. Log nuclei version for audit trail ────────────────────────────
        match Self::get_version().await {
            Ok(version) => tracing::info!(nuclei_version = %version, "Nuclei: Version checked"),
            Err(e) => tracing::warn!("Nuclei: Could not determine version: {}", e),
        }

        // ── 2. Enforce RoE rate limit ────────────────────────────────────────
        let roe_rps = target.authorization_record.as_ref()
            .map(|a| a.scope.rate_limit_rps)
            .unwrap_or(5);
        let effective_rps = cfg.effective_rps(roe_rps);

        // ── 3. Build severity filter ─────────────────────────────────────────
        let severity = cfg.effective_nuclei_severity();

        // ── 4. Build exclude-tags (always includes dos,fuzzing,intrusive) ────
        let exclude_tags = Self::build_exclude_tags(cfg.nuclei.exclude_tags.as_deref());

        // ── 5. Build CLI command ─────────────────────────────────────────────
        //
        //   nuclei -u <target>
        //          -jsonl                   machine-readable output
        //          -severity <levels>       filter by severity
        //          -rl <rps>                rate limit from RoE
        //          -timeout <seconds>       per-request timeout
        //          -no-interactsh           disable OOB callbacks
        //          -silent                  clean JSONL stdout
        //          [-t <path>]              user template directory
        //          [-tags <tags>]           include-only filter
        //          -etags <tags>            always exclude destructive tags
        //
        let mut cmd = Command::new("nuclei");
        cmd.arg("-u").arg(target_url)
           .arg("-jsonl")
           .arg("-severity").arg(severity)
           .arg("-rl").arg(effective_rps.to_string())
           .arg("-timeout").arg(cfg.timeout_seconds.to_string())
           .arg("-no-interactsh")
           .arg("-silent")
           .arg("-etags").arg(&exclude_tags); // Always applied — non-destructive guarantee

        // Template directory (prefer structured config, fall back to legacy field)
        if let Some(tpl_path) = cfg.effective_nuclei_templates_path() {
            cmd.arg("-t").arg(tpl_path);
            tracing::info!(templates_path = tpl_path, "Nuclei: User template directory");
        }

        // Additional custom template paths
        for custom_path in &cfg.nuclei.custom_template_paths {
            cmd.arg("-t").arg(custom_path);
            tracing::info!(custom_path, "Nuclei: Adding custom template path");
        }

        // Include-only tag filter (AND filter)
        if let Some(tags) = &cfg.nuclei.include_tags {
            cmd.arg("-tags").arg(tags);
            tracing::info!(tags, "Nuclei: Tag filter applied");
        }

        tracing::info!(
            target_url,
            rate_limit_rps = effective_rps,
            severity,
            exclude_tags = %exclude_tags,
            "Nuclei: Launching subprocess"
        );

        // ── 6. Spawn process with piped stdout ───────────────────────────────
        let mut child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("Failed to spawn nuclei — ensure it is installed on PATH")?;

        let stdout = child.stdout.take()
            .ok_or_else(|| anyhow!("Failed to capture nuclei stdout"))?;

        // ── 7. Stream JSONL stdout line-by-line ──────────────────────────────
        let mut reader = BufReader::new(stdout).lines();
        let mut raw_jsonl = String::new();
        let mut line_count = 0usize;

        while let Some(line) = reader.next_line().await? {
            if line.trim().is_empty() { continue; }
            raw_jsonl.push_str(&line);
            raw_jsonl.push('\n');
            line_count += 1;
            tracing::debug!(line_number = line_count, "Nuclei: JSONL line received");
        }

        // ── 8. Wait for exit ─────────────────────────────────────────────────
        let status = child.wait().await
            .context("Nuclei process wait() failed")?;

        if !status.success() && raw_jsonl.is_empty() {
            tracing::warn!(
                exit_code = status.code().unwrap_or(-1),
                "Nuclei exited non-zero with no findings (no matching templates or target unreachable)"
            );
        }

        tracing::info!(lines = line_count, target_url, "Nuclei: JSONL stream complete");

        if raw_jsonl.is_empty() { return Ok(vec![]); }

        // ── 9. Parse via existing sentinel_core parser ───────────────────────
        let findings = NucleiJsonlParser::parse(&raw_jsonl, target.id, scan_id)
            .context("Nuclei JSONL parser failed")?;

        tracing::info!(finding_count = findings.len(), target_url, "Nuclei: Findings parsed");
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_tags_always_includes_dos() {
        let result = NucleiDastAdapter::build_exclude_tags(None);
        assert!(result.contains("dos"), "dos must always be excluded");
        assert!(result.contains("fuzzing"), "fuzzing must always be excluded");
        assert!(result.contains("intrusive"), "intrusive must always be excluded");
    }

    #[test]
    fn exclude_tags_merges_user_config_without_duplicates() {
        let result = NucleiDastAdapter::build_exclude_tags(Some("sqli,dos,custom-dangerous"));
        let count = result.split(',').filter(|&t| t == "dos").count();
        assert_eq!(count, 1, "dos should appear exactly once even if user adds it");
        assert!(result.contains("custom-dangerous"));
    }

    #[tokio::test]
    async fn healthcheck_does_not_panic() {
        let adapter = NucleiDastAdapter;
        let result = adapter.healthcheck().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_errors_when_nuclei_absent() {
        if LocalCliRunner::is_installed("nuclei") { return; }
        let adapter = NucleiDastAdapter;
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
        assert!(result.unwrap_err().to_string().contains("Nuclei binary not found on PATH"));
    }
}
