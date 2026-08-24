//! Real end-to-end scan: the same `ScanOrchestrator::run_full_pipeline` the
//! desktop app's `trigger_scan` command drives, run here without Tauri or a
//! UI in front of it, against a genuinely vulnerable, deliberately-insecure
//! target (OWASP Juice Shop) that is running and authorised for this purpose.
//!
//! Exercises every adapter that is actually installed: Semgrep, Trivy,
//! Gitleaks and Nuclei run for real; Sentinel Native always runs; ZAP is
//! skipped only if the binary is not on PATH.
//!
//! Run with:
//!   docker run -d -p 3000:3000 bkimminich/juice-shop
//!   git clone --depth 1 https://github.com/juice-shop/juice-shop.git /tmp/juice-shop
//!   cargo run -p sentinel-adapters --example e2e_live_scan -- \
//!       http://localhost:3000 /tmp/juice-shop <out_dir>

use chrono::Utc;
use sentinel_adapters::orchestrator::ScanOrchestrator;
use sentinel_core::checklist::ChecklistEngine;
use sentinel_core::models::target::{AuthorizationRecord, ScopeDefinition, Target};
use sentinel_core::reporting::{ReportContext, ReportEngine};
use std::path::PathBuf;
use uuid::Uuid;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let base_url = args.get(1).cloned().unwrap_or_else(|| "http://localhost:3000".into());
    let repo_ref = args.get(2).cloned();
    let out: PathBuf = args.get(3).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&out).expect("output directory");

    let host = url::Url::parse(&base_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "localhost".into());

    let target = Target {
        id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        name: "OWASP Juice Shop (local, authorised)".into(),
        target_type: "Web App".into(),
        base_url: base_url.clone(),
        repo_ref,
        stack_description: Some("Node.js / Express / Angular — OWASP Juice Shop".into()),
        auth_keychain_handle: None,
        authorization_record: Some(AuthorizationRecord {
            id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            scope: ScopeDefinition {
                allowed_domains: vec![host.clone(), "localhost".into(), "127.0.0.1".into()],
                allowed_ips_cidrs: vec!["127.0.0.1".into()],
                out_of_scope_paths: vec![],
                rate_limit_rps: 20,
                prohibited_actions: vec!["DoS".into(), "Destructive payloads".into()],
            },
            acknowledged_by: "SentinelVAPT end-to-end harness".into(),
            signed_at: Utc::now(),
            roe_document_hash: "e2e-harness-self-signed".into(),
            digital_signature: "e2e-harness-self-signed".into(),
        }),
        created_at: Utc::now(),
    };

    eprintln!("=== SentinelVAPT end-to-end run ===");
    eprintln!("target       : {base_url}");
    eprintln!("repo_ref     : {:?}", target.repo_ref);
    eprintln!();

    // `DastConfig::default()` (what "{}" resolves to) now scopes Nuclei to a
    // sensible tag set out of the box — see `NucleiConfig::default()` — so
    // the real default is used here rather than an override.
    let result = ScanOrchestrator::run_full_pipeline(&target, "{}", true, None)
        .await
        .expect("pipeline must not hard-fail");

    eprintln!("--- stage results ---");
    for s in &result.stage_results {
        let status = if s.skipped {
            format!("SKIPPED ({})", s.skip_reason.as_deref().unwrap_or("no reason given"))
        } else if let Some(e) = &s.error {
            format!("FAILED  ({e})")
        } else {
            format!("OK      ({} findings)", s.findings.len())
        };
        eprintln!("{:<14} {status}", s.stage.label());
    }
    eprintln!();
    eprintln!("engines_executed : {:?}", result.engines_executed);
    eprintln!("total findings   : {}", result.all_findings.len());

    let by_severity = |sev: sentinel_core::models::finding::Severity| {
        result.all_findings.iter().filter(|f| f.severity == sev).count()
    };
    use sentinel_core::models::finding::Severity::*;
    eprintln!(
        "severity split   : critical={} high={} medium={} low={} info={}",
        by_severity(Critical), by_severity(High), by_severity(Medium), by_severity(Low), by_severity(Info)
    );

    // ── Build the two report deliverables, exactly as generate_report does ──
    let coverage = ChecklistEngine::assess(&result.engines_executed, &result.all_findings);

    let mut ctx = ReportContext::new(
        "SentinelVAPT End-to-End Harness",
        "OWASP Juice Shop (local)",
        &base_url,
    );
    ctx.analyst = "Automated E2E Run".into();
    ctx.engines_executed = result.engines_executed.clone();
    ctx.allowed_domains = target
        .authorization_record
        .as_ref()
        .map(|a| a.scope.allowed_domains.clone())
        .unwrap_or_default();
    ctx.rate_limit_rps = 20;
    ctx.roe_hash = Some("e2e-harness-self-signed".into());
    ctx.assessment_start = result.started_at;
    ctx.assessment_end = result.completed_at;

    let client_html = ReportEngine::client_report(&ctx, &result.all_findings, Some(&coverage));
    let developer_html = ReportEngine::developer_report(&ctx, &result.all_findings, Some(&coverage));
    let sarif = ReportEngine::generate_sarif_json(&result.all_findings);
    let json = ReportEngine::generate_json(&ctx, &result.all_findings, Some(&coverage));

    std::fs::write(out.join("client-report.html"), &client_html).unwrap();
    std::fs::write(out.join("developer-report.html"), &developer_html).unwrap();
    std::fs::write(out.join("findings.sarif"), &sarif).unwrap();
    std::fs::write(out.join("findings.json"), &json).unwrap();

    eprintln!();
    eprintln!("wrote client-report.html    ({} bytes)", client_html.len());
    eprintln!("wrote developer-report.html ({} bytes)", developer_html.len());
    eprintln!("wrote findings.sarif        ({} bytes)", sarif.len());
    eprintln!("wrote findings.json         ({} bytes)", json.len());
    eprintln!("output dir: {}", out.display());
}
