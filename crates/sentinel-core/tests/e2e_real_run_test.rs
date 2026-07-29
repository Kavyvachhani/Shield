use sentinel_core::models::target::{Target, AuthorizationRecord, ScopeDefinition};
use sentinel_adapters::orchestrator::ScanOrchestrator;
use sentinel_adapters::dast_config::DastConfig;
use sentinel_core::reporting::ReportEngine;
use sentinel_db::repository::{MemorySentinelRepository, SentinelRepository};
use uuid::Uuid;
use chrono::Utc;
use sha2::{Sha256, Digest};
use tokio::sync::mpsc;

#[tokio::test]
async fn test_e2e_real_run_against_juice_shop_and_local_repo() {
    let project_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();

    let target_url = "http://localhost:3000";
    let repo_path = "/Users/kavy/VAPT/scratch/target-repo";

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
        base_url: target_url.into(),
        repo_ref: Some(repo_path.into()),
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

    // 4. Generate Reports
    let exec_report = ReportEngine::generate_client_report_html("Acme Corp", None, &target.name, &reloaded);
    let dev_report = ReportEngine::generate_developer_report_html(&target.name, &reloaded);
    let sarif_report = ReportEngine::generate_sarif_json(&reloaded);

    // 5. Verify Security Assertions
    assert!(!exec_report.contains("AKIAIOSFODNN7EXAMPLE"), "Zero secret leak in Executive report");
    assert!(!dev_report.contains("AKIAIOSFODNN7EXAMPLE"), "Zero secret leak in Developer report");
    assert!(!sarif_report.contains("AKIAIOSFODNN7EXAMPLE"), "Zero secret leak in SARIF report");

    println!("E2E Real Run Completed Successfully!");
}
