use sentinel_core::models::target::{Target, AuthorizationRecord, ScopeDefinition};
use sentinel_adapters::orchestrator::ScanOrchestrator;
use sentinel_adapters::dast_config::DastConfig;
use sentinel_core::reporting::{ReportContext, ReportEngine};
use sentinel_db::repository::{MemorySentinelRepository, SentinelRepository};
use uuid::Uuid;
use chrono::Utc;
use sha2::{Sha256, Digest};
use tokio::sync::mpsc;
use std::path::PathBuf;

/// Opt-in switch for this test. Unset, the test skips.
const ENV_ENABLE: &str = "SENTINEL_E2E_LIVE";
/// Web target to scan. Defaults to a local OWASP Juice Shop.
const ENV_TARGET_URL: &str = "SENTINEL_E2E_TARGET_URL";
/// Source repository to scan. Defaults to `scratch/target-repo` in this
/// workspace, which is gitignored and so exists only where someone made it.
const ENV_REPO_PATH: &str = "SENTINEL_E2E_REPO_PATH";

const DEFAULT_TARGET_URL: &str = "http://localhost:3000";

/// Resolve this test's inputs, or `None` when it should not run.
///
/// This test drives the real pipeline against a live web target and a real
/// checkout, so it needs both to be present. It used to hardcode one
/// developer's absolute path (`/Users/.../scratch/target-repo`) and a Juice
/// Shop on `localhost:3000`, neither of which exists anywhere else — including
/// CI, where `/scratch` is gitignored and Juice Shop is not running.
///
/// It did not fail there; it passed *vacuously*. Every adapter declined for a
/// missing binary or missing repository, the pipeline produced nothing, and the
/// assertions below — all of the form "no secret leaked into the report" — held
/// trivially over empty reports. Meanwhile on a machine that does have the
/// scanners installed it runs the full suite of them and takes many minutes,
/// making `cargo test --workspace` unusable.
///
/// So: run only when explicitly asked, and when asked, insist the inputs are
/// really there rather than quietly proving nothing.
fn live_config() -> Option<(String, PathBuf)> {
    if std::env::var(ENV_ENABLE).is_err() {
        eprintln!(
            "skipping live e2e: set {ENV_ENABLE}=1 to run it (needs a web target at \
             ${ENV_TARGET_URL} (default {DEFAULT_TARGET_URL}) and a source checkout at \
             ${ENV_REPO_PATH})"
        );
        return None;
    }

    let target_url =
        std::env::var(ENV_TARGET_URL).unwrap_or_else(|_| DEFAULT_TARGET_URL.to_string());

    let repo_path = std::env::var(ENV_REPO_PATH).map(PathBuf::from).unwrap_or_else(|_| {
        // Workspace-relative, so a checkout anywhere resolves the same.
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../scratch/target-repo")
    });

    assert!(
        repo_path.is_dir(),
        "{ENV_ENABLE} is set but the source repository '{}' does not exist. \
         Point {ENV_REPO_PATH} at a real checkout, or unset {ENV_ENABLE} to skip.",
        repo_path.display()
    );

    Some((target_url, repo_path))
}

#[tokio::test]
async fn test_e2e_real_run_against_juice_shop_and_local_repo() {
    let Some((target_url, repo_path)) = live_config() else {
        return;
    };
    let repo_path = repo_path.to_string_lossy().to_string();

    let project_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();

    let mut hasher = Sha256::new();
    hasher.update(b"RoE Agreement for Juice Shop & Target Repo");
    let roe_hash = format!("{:x}", hasher.finalize());

    let auth_record = AuthorizationRecord {
        id: Uuid::new_v4(),
        target_id,
        scope: ScopeDefinition {
            allowed_domains: vec!["localhost".into(), "127.0.0.1".into()],
            allowed_ips_cidrs: vec!["127.0.0.1/32".into()],
            out_of_scope_paths: vec!["/logout".into(), "/ftp".into()],
            rate_limit_rps: 10,
            prohibited_actions: vec!["DoS".into(), "Brute Force".into()],
        },
        acknowledged_by: "Security Lead Analyst".into(),
        signed_at: Utc::now(),
        roe_document_hash: roe_hash,
        digital_signature: "e2e_test_signature_valid".into(),
    };

    let target = Target {
        id: target_id,
        project_id,
        name: "OWASP Juice Shop & Local Repo".into(),
        target_type: "Web Application & Source Code".into(),
        base_url: target_url.clone(),
        repo_ref: Some(repo_path.clone()),
        stack_description: Some("Node.js / Express / Angular SPA".into()),
        auth_keychain_handle: None,
        authorization_record: Some(auth_record),
        created_at: Utc::now(),
    };

    // 2. Configure DAST & Scan Pipeline
    let cfg = DastConfig::default();
    let cfg_json = serde_json::to_string(&cfg).unwrap();

    let (tx, mut rx) = mpsc::channel::<sentinel_adapters::orchestrator::ScanProgressEvent>(100);

    // Spawn receiver task to print streamed events
    let stream_handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            println!("[STREAM EVENT] State: {:?}, Message: {}", event.state, event.message);
        }
    });

    let run_result = ScanOrchestrator::run_full_pipeline(&target, &cfg_json, true, Some(tx))
        .await
        .expect("ScanOrchestrator pipeline failed");

    stream_handle.await.ok();

    println!("Total Findings Generated & Deduplicated: {}", run_result.all_findings.len());

    // 3. Persist to DB Repository
    let repo = MemorySentinelRepository::new();
    repo.save_findings(&run_result.all_findings).await.unwrap();

    let reloaded = repo.get_findings_by_target(target_id).await.unwrap();
    assert_eq!(reloaded.len(), run_result.all_findings.len());

    // 4. Generate Reports, driven by the engines that genuinely executed
    let mut ctx = ReportContext::new("Acme Corp", &target.name, &target.base_url);
    ctx.engines_executed = run_result.engines_executed.clone();
    let coverage = run_result.coverage();
    let exec_report = ReportEngine::client_report(&ctx, &reloaded, Some(&coverage));
    let dev_report = ReportEngine::developer_report(&ctx, &reloaded, Some(&coverage));
    let sarif_report = ReportEngine::generate_sarif_json(&reloaded);

    // Coverage must never claim more than the engines that actually ran
    for engine in &coverage.engines_executed {
        assert!(
            run_result.engines_executed.contains(engine),
            "coverage claims engine '{engine}' that did not execute"
        );
    }

    // 5. Verify Security Assertions
    assert!(!exec_report.contains("AKIAIOSFODNN7EXAMPLE"), "Zero secret leak in Executive report");
    assert!(!dev_report.contains("AKIAIOSFODNN7EXAMPLE"), "Zero secret leak in Developer report");
    assert!(!sarif_report.contains("AKIAIOSFODNN7EXAMPLE"), "Zero secret leak in SARIF report");

    println!("E2E Real Run Completed Successfully!");
}
