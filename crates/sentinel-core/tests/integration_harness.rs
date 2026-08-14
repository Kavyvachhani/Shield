use sentinel_core::parser::semgrep::SemgrepJsonParser;
use sentinel_core::parser::zap::ZapJsonParser;
use sentinel_core::parser::trivy::TrivyJsonParser;
use sentinel_core::parser::gitleaks::GitleaksJsonParser;
use sentinel_core::parser::nuclei::NucleiJsonlParser;
use sentinel_core::parser::fixtures::*;
use sentinel_core::dedup::engine::DeduplicationEngine;
use sentinel_core::scoring::priority::PriorityScoringEngine;
use sentinel_core::reporting::{ReportContext, ReportEngine};
use sentinel_core::checklist::ChecklistEngine;
use sentinel_db::repository::{MemorySentinelRepository, SentinelRepository};
use uuid::Uuid;

#[tokio::test]
async fn test_end_to_end_integration_pipeline_harness() {
    let target_id = Uuid::new_v4();
    let scan_id = Uuid::new_v4();

    // 1. Ingest raw scanner fixtures (including intentional cross-scanner SQLi duplicate between Semgrep & ZAP)
    let semgrep_findings = SemgrepJsonParser::parse(SEMGREP_FIXTURE_JSON, target_id, scan_id).unwrap();
    let zap_findings = ZapJsonParser::parse(ZAP_FIXTURE_JSON, target_id, scan_id).unwrap();
    let trivy_findings = TrivyJsonParser::parse(TRIVY_FIXTURE_JSON, target_id, scan_id).unwrap();
    let gitleaks_findings = GitleaksJsonParser::parse(GITLEAKS_FIXTURE_JSON, target_id, scan_id).unwrap();
    let nuclei_findings = NucleiJsonlParser::parse(NUCLEI_FIXTURE_JSONL, target_id, scan_id).unwrap();

    let mut raw_findings = Vec::new();
    raw_findings.extend(semgrep_findings);
    raw_findings.extend(zap_findings);
    raw_findings.extend(trivy_findings);
    raw_findings.extend(gitleaks_findings);
    raw_findings.extend(nuclei_findings);

    assert_eq!(raw_findings.len(), 5);

    // 2. Deduplicate findings across scanners
    let mut deduplicated = DeduplicationEngine::deduplicate_findings(raw_findings);

    // 3. Score findings using CVSS 4.0 / EPSS priority score engine
    for f in deduplicated.iter_mut() {
        f.priority_score = PriorityScoringEngine::calculate_priority_score(f);
    }

    // Sort by Priority Score descending
    deduplicated.sort_by(|a, b| b.priority_score.partial_cmp(&a.priority_score).unwrap_or(std::cmp::Ordering::Equal));

    // 4. Persist deduplicated findings into DB
    let repo = MemorySentinelRepository::new();
    repo.save_findings(&deduplicated).await.unwrap();

    // 5. Reload findings from DB and verify integrity
    let reloaded = repo.get_findings_by_target(target_id).await.unwrap();
    assert!(!reloaded.is_empty());
    
    // Verify top finding has high priority score
    assert!(reloaded[0].priority_score >= 8.0);

    // 6. Generate BOTH reports plus the coverage matrix from persisted findings
    let ctx = ReportContext::new("Acme Corp", "Acme Portal", "https://portal.acme.test");
    let coverage = ChecklistEngine::assess(
        &["Sentinel Native".to_string(), "OWASP ZAP".to_string(), "Semgrep".to_string()],
        &reloaded,
    );
    let exec_report = ReportEngine::client_report(&ctx, &reloaded, Some(&coverage));
    let dev_report = ReportEngine::developer_report(&ctx, &reloaded, Some(&coverage));
    let sarif_report = ReportEngine::generate_sarif_json(&reloaded);

    // 7. Assert safety & reporting constraints
    // The client report must not expose developer-only technical detail
    assert!(!exec_report.contains("CVSS:4.0"));
    assert!(exec_report.contains("Executive Summary"));
    assert!(exec_report.contains("PCI DSS v4.0.1"));
    // The client report must show the full coverage matrix, not only failures
    assert!(exec_report.contains("Every Check We Performed"));

    // Assert developer report contains technical details and vector
    assert!(dev_report.contains("CVSS:4.0"));
    assert!(dev_report.contains("Technical Remediation Report"));
    assert!(dev_report.contains("How to fix"));

    // Neither report may contain executable markup, whatever the findings held
    assert!(!exec_report.contains("<script"));
    assert!(!dev_report.contains("<script"));

    // Assert SARIF JSON is valid
    assert!(sarif_report.contains("\"version\": \"2.1.0\""));

    // Assert no credential material leaked in any report
    assert!(!exec_report.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!dev_report.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!sarif_report.contains("AKIAIOSFODNN7EXAMPLE"));
}
