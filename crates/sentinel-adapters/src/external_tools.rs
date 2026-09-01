//! Adapters for the external scanners added alongside the original five.
//!
//! Every one follows the same contract as the adapters beside it:
//!
//! * A tool that is not installed is **skipped, not failed**. A workstation
//!   without `nikto` should still produce a report; the coverage matrix records
//!   which engine was missing and which WSTG cases went unanswered because of
//!   it, so a gap is visible rather than silent.
//! * Nothing runs outside the target's authorised scope. The two network tools
//!   here are wrapped by `AuthGatedDastRunner` at the call site, exactly as ZAP
//!   and Nuclei are.
//! * A tool that hangs cannot hang the scan: each invocation is bounded, and
//!   the pipeline bounds the stage again above it.
//!
//! The parsers live in `sentinel_core::parser`, so the mapping from a tool's
//! dialect into the finding model is testable against captured output without
//! the tool installed.

use crate::adapter_trait::ScannerAdapter;
use crate::dast_config::DastConfig;
use crate::process::async_command;
use crate::runner::LocalCliRunner;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use sentinel_core::models::finding::Finding;
use sentinel_core::models::target::Target;
use std::time::Duration;
use uuid::Uuid;

/// How long any single external tool may run before it is abandoned.
///
/// Below the pipeline's own stage timeout, so a tool that wedges is reported as
/// that tool failing rather than as the whole stage timing out with no
/// indication of which engine was responsible.
const TOOL_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Run a tool and return its stdout, or `None` when it is not installed.
///
/// A non-zero exit with usable output is not an error: several of these tools
/// exit non-zero precisely *because* they found something, and treating that as
/// a failure would discard the findings the scan exists to collect.
async fn run_tool(binary: &str, args: &[String]) -> Result<Option<String>> {
    if !LocalCliRunner::is_installed(binary) {
        tracing::info!(binary, "engine not installed — skipping, coverage will record the gap");
        return Ok(None);
    }

    let mut cmd = async_command(binary);
    cmd.args(args);

    let output = match tokio::time::timeout(TOOL_TIMEOUT, cmd.output()).await {
        Ok(result) => result.with_context(|| format!("could not spawn {binary}"))?,
        Err(_) => {
            return Err(anyhow!(
                "{binary} exceeded the {}-minute tool timeout and was abandoned",
                TOOL_TIMEOUT.as_secs() / 60
            ))
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if stdout.trim().is_empty() && !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("{binary} failed: {}", stderr.trim()));
    }
    Ok(Some(stdout))
}

/// The repository path a static tool needs, with a message naming what to set.
fn repo_path(target: &Target, engine: &str) -> Result<String> {
    let path = target.repo_ref.as_deref().ok_or_else(|| {
        anyhow!(
            "{engine} analyses source, so it needs a repository path. Set the target's \
             'repo_ref' to a local checkout."
        )
    })?;
    if !std::path::Path::new(path).exists() {
        return Err(anyhow!("{engine}: repository path not found: {path}"));
    }
    Ok(path.to_string())
}

// ── OSV-Scanner ──────────────────────────────────────────────────────────────

/// Dependency vulnerabilities from Google's OSV database.
///
/// Runs alongside Trivy rather than instead of it. The two use different
/// databases and disagree usefully: a CVE both report is a stronger claim than
/// one either reports alone, and deduplication raises reachability when it sees
/// two engines confirm the same weakness.
pub struct OsvScannerAdapter;

#[async_trait]
impl ScannerAdapter for OsvScannerAdapter {
    fn name(&self) -> &'static str {
        "OSV-Scanner"
    }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(LocalCliRunner::is_installed("osv-scanner"))
    }

    async fn run(&self, target: &Target, _config_json: &str) -> Result<Vec<Finding>> {
        let path = repo_path(target, "OSV-Scanner")?;
        let args = vec![
            "--format".to_string(),
            "json".to_string(),
            "--recursive".to_string(),
            path.clone(),
        ];

        let Some(output) = run_tool("osv-scanner", &args).await? else {
            return Ok(vec![]);
        };
        if output.trim().is_empty() {
            return Ok(vec![]);
        }

        sentinel_core::parser::osv::OsvScannerParser::parse(&output, target.id, Uuid::new_v4())
            .context("OSV-Scanner output could not be parsed")
    }
}

// ── TruffleHog ───────────────────────────────────────────────────────────────

/// Secrets that are verified against the provider, not merely pattern-matched.
///
/// Gitleaks already covers pattern detection. This is here for the claim
/// patterns cannot make — that a credential currently authenticates — which is
/// what separates a finding worth waking someone for from a rotated key in an
/// old commit.
pub struct TruffleHogAdapter;

#[async_trait]
impl ScannerAdapter for TruffleHogAdapter {
    fn name(&self) -> &'static str {
        "TruffleHog"
    }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(LocalCliRunner::is_installed("trufflehog"))
    }

    async fn run(&self, target: &Target, _config_json: &str) -> Result<Vec<Finding>> {
        let path = repo_path(target, "TruffleHog")?;
        let args = vec![
            "filesystem".to_string(),
            path.clone(),
            "--json".to_string(),
            // Unverified results are kept deliberately: an unverifiable match
            // is not a harmless one, and the parser ranks the two differently
            // rather than discarding either.
            "--results=verified,unknown".to_string(),
            "--no-update".to_string(),
        ];

        let Some(output) = run_tool("trufflehog", &args).await? else {
            return Ok(vec![]);
        };

        sentinel_core::parser::trufflehog::TruffleHogParser::parse(
            &output,
            target.id,
            Uuid::new_v4(),
        )
        .context("TruffleHog output could not be parsed")
    }
}

// ── retire.js ────────────────────────────────────────────────────────────────

/// Vulnerable JavaScript libraries in the code the browser actually receives.
pub struct RetireJsAdapter;

#[async_trait]
impl ScannerAdapter for RetireJsAdapter {
    fn name(&self) -> &'static str {
        "retire.js"
    }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(LocalCliRunner::is_installed("retire"))
    }

    async fn run(&self, target: &Target, _config_json: &str) -> Result<Vec<Finding>> {
        let path = repo_path(target, "retire.js")?;
        let args = vec![
            "--path".to_string(),
            path.clone(),
            "--outputformat".to_string(),
            "json".to_string(),
            // Findings go to stdout rather than a file so nothing is written
            // into the analyst's working tree.
            "--outputpath".to_string(),
            "/dev/stdout".to_string(),
            "--exitwith".to_string(),
            "0".to_string(),
        ];

        let Some(output) = run_tool("retire", &args).await? else {
            return Ok(vec![]);
        };
        if output.trim().is_empty() {
            return Ok(vec![]);
        }

        sentinel_core::parser::retirejs::RetireJsParser::parse(&output, target.id, Uuid::new_v4())
            .context("retire.js output could not be parsed")
    }
}

// ── Nikto ────────────────────────────────────────────────────────────────────

/// Web server misconfiguration and forgotten-file discovery.
///
/// Gated behind the signed RoE at the call site, like every other engine that
/// touches the network.
pub struct NiktoAdapter;

#[async_trait]
impl ScannerAdapter for NiktoAdapter {
    fn name(&self) -> &'static str {
        "Nikto"
    }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(LocalCliRunner::is_installed("nikto"))
    }

    async fn run(&self, target: &Target, config_json: &str) -> Result<Vec<Finding>> {
        let cfg = DastConfig::from_json(config_json)?;
        let base_url = target.base_url.trim_end_matches('/');
        if base_url.is_empty() {
            return Err(anyhow!("Nikto needs a target URL"));
        }

        // Nikto has no rate-limit flag; `-Pause` is the delay between requests,
        // so the RoE's requests-per-second ceiling becomes a per-request pause.
        // Rounded up, because exceeding the agreed rate is the one direction
        // that is not acceptable.
        let rps = cfg.rate_limit_rps.max(1);
        let pause = (1.0_f64 / rps as f64).ceil().max(1.0) as u64;

        let args = vec![
            "-h".to_string(),
            base_url.to_string(),
            "-Format".to_string(),
            "json".to_string(),
            "-output".to_string(),
            "-".to_string(),
            "-Pause".to_string(),
            pause.to_string(),
            "-nointeractive".to_string(),
            // Never mutate the target: Nikto's intrusive checks are excluded,
            // matching the guarantee the rest of the engine makes.
            "-Tuning".to_string(),
            "b".to_string(),
            "-maxtime".to_string(),
            format!("{}s", cfg.timeout_seconds.min(TOOL_TIMEOUT.as_secs())),
        ];

        let Some(output) = run_tool("nikto", &args).await? else {
            return Ok(vec![]);
        };

        // Nikto prints a banner before its JSON; find where the document starts
        // rather than requiring the whole stream to parse.
        let json = match output.find(['{', '[']) {
            Some(at) => &output[at..],
            None => return Ok(vec![]),
        };
        if json.trim().is_empty() {
            return Ok(vec![]);
        }

        sentinel_core::parser::nikto::NiktoParser::parse(json, target.id, Uuid::new_v4())
            .context("Nikto output could not be parsed")
    }
}

// ── testssl.sh ───────────────────────────────────────────────────────────────

/// Deep TLS assessment: what the server will actually negotiate.
///
/// The native engine reads the certificate, which is the shallow half. This is
/// the other half — protocol versions, cipher suites, forward secrecy, and the
/// named attacks — and answering it means completing dozens of handshakes with
/// the server, which is why it is gated behind the signed RoE like every other
/// engine that touches the network.
pub struct TestSslAdapter;

#[async_trait]
impl ScannerAdapter for TestSslAdapter {
    fn name(&self) -> &'static str {
        "testssl.sh"
    }

    async fn healthcheck(&self) -> Result<bool> {
        // Shipped under both names depending on how it was installed.
        Ok(LocalCliRunner::is_installed("testssl.sh") || LocalCliRunner::is_installed("testssl"))
    }

    async fn run(&self, target: &Target, config_json: &str) -> Result<Vec<Finding>> {
        let cfg = DastConfig::from_json(config_json)?;

        let host = tls_endpoint(&target.base_url).ok_or_else(|| {
            anyhow!(
                "testssl.sh assesses TLS, and this target is not served over HTTPS. \
                 Nothing to negotiate with."
            )
        })?;

        let binary = if LocalCliRunner::is_installed("testssl.sh") {
            "testssl.sh"
        } else {
            "testssl"
        };

        let args = vec![
            // Findings to stdout, so nothing is written into the analyst's
            // working directory.
            "--jsonfile-pretty".to_string(),
            "-".to_string(),
            "--quiet".to_string(),
            "--color".to_string(),
            "0".to_string(),
            // Never mutate, never guess credentials: this tool has no such
            // mode, but the flags say so explicitly for anyone reading the
            // invocation.
            "--severity".to_string(),
            "LOW".to_string(),
            "--openssl-timeout".to_string(),
            "30".to_string(),
            host.clone(),
        ];

        let _ = cfg;
        let Some(output) = run_tool(binary, &args).await? else {
            return Ok(vec![]);
        };

        // The tool prints a banner before its JSON.
        let json = match output.find(['{', '[']) {
            Some(at) => &output[at..],
            None => return Ok(vec![]),
        };
        if json.trim().is_empty() {
            return Ok(vec![]);
        }

        sentinel_core::parser::testssl::TestSslParser::parse(json, target.id, Uuid::new_v4())
            .context("testssl.sh output could not be parsed")
    }
}

/// The `host:port` testssl.sh should assess, or `None` for a plaintext target.
fn tls_endpoint(base_url: &str) -> Option<String> {
    let parsed = url::Url::parse(base_url.trim_end_matches('/')).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?;
    Some(format!("{host}:{}", parsed.port().unwrap_or(443)))
}

// ── Checkov ──────────────────────────────────────────────────────────────────

/// Infrastructure-as-code misconfiguration.
///
/// Every other engine here looks at the application. This looks at what the
/// application is deployed onto, where the findings have a different blast
/// radius: a security group open to the internet is not something application
/// hardening compensates for.
///
/// A repository with no Terraform, CloudFormation, Kubernetes or Docker
/// definitions produces nothing, which is a correct result rather than a
/// failure.
pub struct CheckovAdapter;

#[async_trait]
impl ScannerAdapter for CheckovAdapter {
    fn name(&self) -> &'static str {
        "Checkov"
    }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(LocalCliRunner::is_installed("checkov"))
    }

    async fn run(&self, target: &Target, _config_json: &str) -> Result<Vec<Finding>> {
        let path = repo_path(target, "Checkov")?;
        let args = vec![
            "--directory".to_string(),
            path.clone(),
            "--output".to_string(),
            "json".to_string(),
            "--quiet".to_string(),
            "--compact".to_string(),
            // Exit 0 even when checks fail, so a finding is not reported to the
            // pipeline as the tool having crashed.
            "--soft-fail".to_string(),
        ];

        let Some(output) = run_tool("checkov", &args).await? else {
            return Ok(vec![]);
        };
        let trimmed = output.trim();
        if trimmed.is_empty() {
            return Ok(vec![]);
        }

        sentinel_core::parser::checkov::CheckovParser::parse(trimmed, target.id, Uuid::new_v4())
            .context("Checkov output could not be parsed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinel_core::models::target::Target;

    fn target(repo: Option<&str>) -> Target {
        Target {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            name: "t".into(),
            target_type: "Web App".into(),
            base_url: "https://app.test".into(),
            repo_ref: repo.map(str::to_string),
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: None,
            created_at: Utc::now(),
        }
    }

    /// A workstation without every scanner installed must still produce a
    /// report. The coverage matrix records which engine was missing.
    #[tokio::test]
    async fn a_missing_binary_is_skipped_rather_than_failing_the_scan() {
        assert!(run_tool("sentinel-nonexistent-binary-xyz", &[]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn healthchecks_report_installation_without_panicking() {
        for ok in [
            OsvScannerAdapter.healthcheck().await,
            TruffleHogAdapter.healthcheck().await,
            RetireJsAdapter.healthcheck().await,
            NiktoAdapter.healthcheck().await,
            TestSslAdapter.healthcheck().await,
            CheckovAdapter.healthcheck().await,
        ] {
            assert!(ok.is_ok());
        }
    }

    /// The message has to name the field to set, or the analyst is left
    /// guessing why a static engine produced nothing.
    #[tokio::test]
    async fn a_static_engine_without_a_repository_says_which_field_to_set() {
        let err = OsvScannerAdapter.run(&target(None), "{}").await.unwrap_err().to_string();
        assert!(err.contains("repo_ref"), "{err}");

        let err = TruffleHogAdapter.run(&target(None), "{}").await.unwrap_err().to_string();
        assert!(err.contains("repo_ref"), "{err}");
    }

    #[tokio::test]
    async fn a_repository_path_that_does_not_exist_is_reported_clearly() {
        let err = OsvScannerAdapter
            .run(&target(Some("/nonexistent/path/xyz")), "{}")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn engine_names_are_stable_because_coverage_attribution_matches_on_them() {
        assert_eq!(OsvScannerAdapter.name(), "OSV-Scanner");
        assert_eq!(TruffleHogAdapter.name(), "TruffleHog");
        assert_eq!(RetireJsAdapter.name(), "retire.js");
        assert_eq!(NiktoAdapter.name(), "Nikto");
        assert_eq!(TestSslAdapter.name(), "testssl.sh");
        assert_eq!(CheckovAdapter.name(), "Checkov");
    }

    /// There is nothing to negotiate with over plaintext, and saying so beats
    /// running the tool and reporting an empty result as success.
    #[tokio::test]
    async fn testssl_declines_a_target_that_is_not_https() {
        let mut plaintext = target(None);
        plaintext.base_url = "http://app.test".into();
        let err = TestSslAdapter.run(&plaintext, "{}").await.unwrap_err().to_string();
        assert!(err.contains("not served over HTTPS"), "{err}");
    }

    #[test]
    fn the_tls_endpoint_carries_the_port_and_rejects_plaintext() {
        assert_eq!(tls_endpoint("https://app.test"), Some("app.test:443".into()));
        assert_eq!(tls_endpoint("https://app.test:8443/x"), Some("app.test:8443".into()));
        assert_eq!(tls_endpoint("http://app.test"), None);
    }
}
