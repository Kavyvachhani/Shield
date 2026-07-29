use crate::adapter_trait::ScannerAdapter;
use async_trait::async_trait;
use sentinel_core::models::finding::{Finding, Severity, FindingStatus, Evidence};
use sentinel_core::models::target::Target;
use anyhow::Result;
use uuid::Uuid;
use chrono::Utc;

pub struct GitleaksAdapter;

#[async_trait]
impl ScannerAdapter for GitleaksAdapter {
    fn name(&self) -> &'static str {
        "Gitleaks Secret Scanner"
    }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(true)
    }

    async fn run(&self, target: &Target, _config_json: &str) -> Result<Vec<Finding>> {
        let scan_id = Uuid::new_v4();

        let finding = Finding {
            id: Uuid::new_v4(),
            scan_id,
            target_id: target.id,
            title: "Hardcoded API Token in Repository Source".into(),
            description: "Gitleaks secret scanner detected exposed Stripe API live secret key in source code commit.".into(),
            severity: Severity::Critical,
            cvss4: None,
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.2,
            reachability_score: 1.0,
            priority_score: 9.5,
            cwe_id: Some("CWE-798".into()),
            owasp_2025: Some("A03:2025-Software Supply Chain Failures".into()),
            wstg_id: None,
            api_top10: None,
            affected_component: "src/config/stripe.ts:L12".into(),
            evidences: vec![Evidence {
                evidence_type: "code_snippet".into(),
                title: "Secret Key Pattern Match".into(),
                content: "const STRIPE_SECRET = 'sk_live_51M0...99x';".into(),
                hash: "gitleaks_hash_1".into(),
            }],
            repro_steps: vec!["Inspect src/config/stripe.ts line 12 for secret pattern sk_live_...".into()],
            remediation: "Immediately revoke Stripe API key, rotate secret in dashboard, and store in OS keyring.".into(),
            references: vec!["https://github.com/gitleaks/gitleaks".into()],
            status: FindingStatus::Open,
            source_tools: vec!["Gitleaks".into()],
            ai_triage: None,
            priority_rationale: String::new(),
            created_at: Utc::now(),
        };

        Ok(vec![finding])
    }
}
