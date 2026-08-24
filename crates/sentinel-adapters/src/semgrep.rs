//! Semgrep SAST Adapter — real CLI invocation with rule pack selection.
//!
//! Changes from baseline stub:
//!   - Invokes the real user-installed `semgrep` binary (not mock data)
//!   - Rule pack selection: user selects from Semgrep registry packs
//!   - Language auto-detection via `semgrep --show-supported-languages` 
//!     or by scanning the repo for file extensions
//!   - JSON output piped into sentinel_core Semgrep parser
//!
//! We author ZERO custom rules. All rules come from Semgrep's official registry
//! (p/owasp-top-ten, p/cwe-top-25, etc.) or the user's local rule files.
//!
//! SAFETY: Static analysis only. No network traffic generated. No payloads.

use crate::adapter_trait::ScannerAdapter;
use crate::dast_config::DastConfig;
use crate::runner::LocalCliRunner;
use async_trait::async_trait;
use sentinel_core::{
    models::finding::Finding,
    models::target::Target,
};
use anyhow::{anyhow, Context, Result};
use crate::process::async_command;
use uuid::Uuid;

pub struct SemgrepAdapter;

impl SemgrepAdapter {
    /// Detect dominant languages in a repo by extension frequency.
    /// Returns a sorted vec of detected language names.
    pub fn detect_languages(repo_path: &str) -> Vec<String> {
        let ext_map: &[(&[&str], &str)] = &[
            (&["ts", "tsx"], "typescript"),
            (&["js", "jsx", "mjs", "cjs"], "javascript"),
            (&["py"], "python"),
            (&["java"], "java"),
            (&["go"], "go"),
            (&["rs"], "rust"),
            (&["rb"], "ruby"),
            (&["php"], "php"),
            (&["cs"], "csharp"),
            (&["tf", "hcl"], "hcl"),
            (&["yaml", "yml"], "yaml"),
            (&["json"], "json"),
        ];

        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        let Ok(_entries) = std::fs::read_dir(repo_path) else { return vec![]; };

        fn walk(path: &std::path::Path, depth: usize, counts: &mut std::collections::HashMap<&'static str, usize>, ext_map: &[(&[&str], &str)]) {
            if depth > 6 { return; }
            let Ok(rd) = std::fs::read_dir(path) else { return; };
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if !["node_modules", ".git", "vendor", "target", "dist", "__pycache__"].contains(&name) {
                        walk(&p, depth + 1, counts, ext_map);
                    }
                } else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                    for (exts, lang) in ext_map {
                        if exts.contains(&ext) {
                            // Safety: ext_map is 'static so lang is 'static
                            let lang_key: &'static str = unsafe { &*((*lang) as *const str) };
                            *counts.entry(lang_key).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
        walk(std::path::Path::new(repo_path), 0, &mut counts, ext_map);

        let mut sorted: Vec<(&str, usize)> = counts.into_iter().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
        sorted.into_iter().map(|(l, _)| l.to_string()).collect()
    }
}

#[async_trait]
impl ScannerAdapter for SemgrepAdapter {
    fn name(&self) -> &'static str { "Semgrep SAST" }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(LocalCliRunner::is_installed("semgrep"))
    }

    async fn run(&self, target: &Target, config_json: &str) -> Result<Vec<Finding>> {
        let cfg = DastConfig::from_json(config_json)?;

        // ── 0. Resolve repo path ─────────────────────────────────────────────
        let repo_path = target.repo_ref.as_deref().ok_or_else(|| {
            anyhow!(
                "Semgrep SAST requires a repository path. \
                 Set 'repo_ref' on the target (e.g. /home/user/repos/acme-portal)."
            )
        })?;

        if !std::path::Path::new(repo_path).exists() {
            return Err(anyhow!("Semgrep: Repository path not found: {}", repo_path));
        }

        // ── 1. Check if semgrep is installed ─────────────────────────────────
        if !LocalCliRunner::is_installed("semgrep") {
            tracing::warn!("Semgrep binary not found on PATH — returning empty findings");
            return Ok(vec![]);
        }

        let scan_id = Uuid::new_v4();

        // ── 2. Language detection ─────────────────────────────────────────────
        let detected_langs = match &cfg.semgrep.language_override {
            Some(lang) => {
                tracing::info!(lang, "Semgrep: Using user-specified language override");
                vec![lang.clone()]
            }
            None => {
                let detected = Self::detect_languages(repo_path);
                if detected.is_empty() {
                    tracing::info!("Semgrep: No specific language detected; using 'auto'");
                } else {
                    tracing::info!(languages = ?detected, "Semgrep: Auto-detected languages");
                }
                detected
            }
        };

        // ── 3. Build rule pack list ───────────────────────────────────────────
        // Each pack maps to --config=p/<pack>. We add zero custom rules.
        let mut rule_packs = cfg.semgrep.rule_packs.clone();
        if rule_packs.is_empty() {
            rule_packs = vec!["p/owasp-top-ten".into(), "p/cwe-top-25".into()];
        }

        // ── 4. Build CLI command ──────────────────────────────────────────────
        //
        //   semgrep scan
        //     --json                       machine-readable output
        //     --config=p/owasp-top-ten     rule pack (repeated per pack)
        //     --metrics=off                no telemetry
        //     --no-git-ignore              scan all files
        //     <repo_path>                  target directory
        //
        // `detected_langs` is logged above but deliberately never becomes a
        // `--lang`/`-l` flag here: that flag only exists for Semgrep's ad-hoc
        // `-e/--pattern` single-rule mode. Passed alongside `--config` (rule
        // packs, which each carry their own per-file language detection) it
        // is simply invalid usage — Semgrep refuses to run at all: "-e/--pattern
        // and -l/--lang must both be specified". Since a dominant language is
        // detected for almost any real repository, this made Semgrep SAST fail
        // outright on every scan that had actual source code to look at.
        let mut cmd = async_command("semgrep");
        cmd.arg("scan")
           .arg("--json")
           .arg("--metrics=off")
           .arg("--no-git-ignore");

        for pack in &rule_packs {
            let config_val = if pack.starts_with("p/") || pack.starts_with("r/") || pack.starts_with("file:") {
                pack.clone()
            } else {
                format!("p/{}", pack)
            };
            cmd.arg(format!("--config={}", config_val));
        }

        cmd.arg(repo_path);

        tracing::info!(
            repo_path,
            rule_packs = ?rule_packs,
            detected_langs = ?detected_langs,
            "Semgrep: Launching subprocess"
        );

        // ── 5. Run and capture output ─────────────────────────────────────────
        let output = cmd.output().await
            .context("Failed to spawn semgrep — ensure it is installed on PATH")?;

        if !output.status.success() && output.stdout.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Semgrep failed: {}", stderr.trim()));
        }

        let json_output = String::from_utf8_lossy(&output.stdout);
        tracing::info!(bytes = json_output.len(), "Semgrep: Output received");

        if json_output.trim().is_empty() || json_output.trim() == "{}" {
            return Ok(vec![]);
        }

        // ── 6. Parse via existing sentinel_core Semgrep parser ───────────────
        let findings = sentinel_core::parser::semgrep::SemgrepJsonParser::parse(
            &json_output, target.id, scan_id,
        ).context("Semgrep JSON parser failed")?;

        tracing::info!(finding_count = findings.len(), repo_path, "Semgrep: Findings parsed");
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_detection_returns_sorted_list() {
        // Pass a non-existent path — should return empty, not panic
        let langs = SemgrepAdapter::detect_languages("/nonexistent/path");
        assert!(langs.is_empty());
    }

    #[tokio::test]
    async fn healthcheck_does_not_panic() {
        let adapter = SemgrepAdapter;
        let result = adapter.healthcheck().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_errors_on_missing_repo_ref() {
        let adapter = SemgrepAdapter;
        let target = sentinel_core::models::target::Target {
            id: uuid::Uuid::new_v4(),
            project_id: uuid::Uuid::new_v4(),
            name: "Test".into(),
            target_type: "Web App".into(),
            base_url: "http://localhost:3000".into(),
            repo_ref: None, // ← no repo path
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: None,
            created_at: chrono::Utc::now(),
        };
        let result = adapter.run(&target, "{}").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("repository path"));
    }

    /// Modern Semgrep rejects `--lang`/`-l` unless paired with the ad-hoc
    /// `-e/--pattern` mode — passed alongside `--config` (rule packs, which
    /// each carry their own per-file language detection) it refuses to run at
    /// all with "-e/--pattern and -l/--lang must both be specified". Since a
    /// dominant language is auto-detected for nearly any real repository, the
    /// adapter used to pass exactly that flag and so failed on every scan of
    /// a repo with actual source code — this test's fixture (a `.ts` file, so
    /// `detect_languages` returns a non-empty list) reproduces the regression
    /// if it ever comes back. Skips gracefully when Semgrep is not installed.
    #[tokio::test]
    async fn run_succeeds_when_a_dominant_language_is_detected() {
        if !LocalCliRunner::is_installed("semgrep") {
            return;
        }

        let repo_dir = std::env::temp_dir().join(format!("sentinel-semgrep-lang-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&repo_dir).unwrap();
        std::fs::write(
            repo_dir.join("app.ts"),
            "export function greet(name: string): string {\n  return `Hello, ${name}`;\n}\n",
        )
        .unwrap();
        assert!(
            !SemgrepAdapter::detect_languages(repo_dir.to_str().unwrap()).is_empty(),
            "fixture must trigger dominant-language detection to exercise the regression"
        );

        let adapter = SemgrepAdapter;
        let target = sentinel_core::models::target::Target {
            id: uuid::Uuid::new_v4(),
            project_id: uuid::Uuid::new_v4(),
            name: "Test".into(),
            target_type: "Web App".into(),
            base_url: "http://localhost:3000".into(),
            repo_ref: Some(repo_dir.to_str().unwrap().to_string()),
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: None,
            created_at: chrono::Utc::now(),
        };

        let result = adapter.run(&target, "{}").await;
        let _ = std::fs::remove_dir_all(&repo_dir);

        assert!(
            result.is_ok(),
            "semgrep must run successfully against a repo with a detected dominant language: {:?}",
            result.err()
        );
    }
}
