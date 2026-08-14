//! ScanOrchestrator — state machine for full-pipeline scan runs.
//!
//! Dispatch order:
//!   1. Static adapters (SAST/SCA/Secrets): Semgrep → Trivy → Gitleaks
//!      These run on local files; no network access; no auth gate needed.
//!   2. DAST adapters (ZAP, Nuclei): wrapped in `AuthGatedDastRunner`.
//!      These are only started when ALL static stages succeed or the caller
//!      explicitly opts in via `run_dast = true`.
//!
//! Progress events are emitted via `tokio::sync::mpsc` so the Tauri UI can
//! stream console updates without blocking.

use crate::adapter_trait::ScannerAdapter;
use crate::auth_gated_runner::AuthGatedDastRunner;
use crate::native::NativeCheckAdapter;
use crate::zap::ZapDastAdapter;
use crate::nuclei::NucleiDastAdapter;
use crate::semgrep::SemgrepAdapter;
use crate::trivy::TrivyAdapter;
use crate::gitleaks::GitleaksAdapter;
use sentinel_core::models::finding::Finding;
use sentinel_core::models::target::Target;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::{DateTime, Utc};

// ── State machine types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStage {
    Semgrep,
    Trivy,
    Gitleaks,
    /// Built-in check engine. Always available, so it anchors DAST coverage
    /// even when no third-party scanner is installed.
    NativeChecks,
    ZapDast,
    NucleiDast,
}

impl ScanStage {
    /// Engine name as used by the checklist coverage catalog.
    pub fn engine_name(&self) -> &'static str {
        match self {
            ScanStage::Semgrep => "Semgrep",
            ScanStage::Trivy => "Trivy",
            ScanStage::Gitleaks => "Gitleaks",
            ScanStage::NativeChecks => "Sentinel Native",
            ScanStage::ZapDast => "OWASP ZAP",
            ScanStage::NucleiDast => "Nuclei",
        }
    }

    /// Human-readable stage label for the scan console.
    pub fn label(&self) -> &'static str {
        match self {
            ScanStage::Semgrep => "Semgrep SAST",
            ScanStage::Trivy => "Trivy dependency audit",
            ScanStage::Gitleaks => "Gitleaks secret scan",
            ScanStage::NativeChecks => "Sentinel Native checks",
            ScanStage::ZapDast => "OWASP ZAP DAST",
            ScanStage::NucleiDast => "Nuclei DAST",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanRunState {
    Pending,
    Running { stage: ScanStage },
    Completed,
    Failed { error: String },
    Aborted { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgressEvent {
    pub scan_run_id: Uuid,
    pub state: ScanRunState,
    pub stage_findings: usize,
    pub total_findings: usize,
    pub timestamp: DateTime<Utc>,
    pub message: String,
}

#[derive(Debug)]
pub struct ScanRunResult {
    pub scan_run_id: Uuid,
    pub target_id: Uuid,
    pub final_state: ScanRunState,
    pub all_findings: Vec<Finding>,
    pub stage_results: Vec<StageResult>,
    /// Engine names that genuinely executed. Drives the checklist coverage
    /// matrix, so a skipped stage must never appear here.
    pub engines_executed: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

impl ScanRunResult {
    /// Coverage assessment across the WSTG catalog for this run.
    pub fn coverage(&self) -> sentinel_core::checklist::CoverageReport {
        sentinel_core::checklist::ChecklistEngine::assess(&self.engines_executed, &self.all_findings)
    }
}

#[derive(Debug)]
pub struct StageResult {
    pub stage: ScanStage,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
    pub skipped: bool,
    pub skip_reason: Option<String>,
}

// ── Orchestrator ─────────────────────────────────────────────────────────────

pub struct ScanOrchestrator;

impl ScanOrchestrator {
    /// Run the full scan pipeline for a target.
    ///
    /// # Parameters
    /// - `target`: The fully-loaded target (must include `authorization_record`
    ///   if `run_dast = true`).
    /// - `config_json`: JSON string matching `DastConfig` for DAST stages.
    /// - `run_dast`: Whether to run ZAP + Nuclei after static stages. The
    ///   `AuthGatedDastRunner` will still enforce the auth gate regardless.
    /// - `progress_tx`: Optional channel to stream `ScanProgressEvent` to UI.
    pub async fn run_full_pipeline(
        target: &Target,
        config_json: &str,
        run_dast: bool,
        progress_tx: Option<mpsc::Sender<ScanProgressEvent>>,
    ) -> Result<ScanRunResult> {
        let scan_run_id = Uuid::new_v4();
        let started_at = Utc::now();
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut stage_results: Vec<StageResult> = Vec::new();

        let emit = |state: ScanRunState, msg: &str, stage_count: usize, total: usize| {
            if let Some(tx) = &progress_tx {
                let event = ScanProgressEvent {
                    scan_run_id,
                    state: state.clone(),
                    stage_findings: stage_count,
                    total_findings: total,
                    timestamp: Utc::now(),
                    message: msg.to_string(),
                };
                let _ = tx.try_send(event);
            }
        };

        emit(ScanRunState::Pending, "Scan pipeline starting", 0, 0);

        // ── STAGE 1: Semgrep SAST ────────────────────────────────────────────
        let semgrep_result = run_stage(
            ScanStage::Semgrep,
            &SemgrepAdapter,
            target,
            config_json,
            &emit,
            &all_findings,
        ).await;
        let semgrep_count = semgrep_result.findings.len();
        all_findings.extend(semgrep_result.findings.iter().cloned());
        stage_results.push(semgrep_result);
        emit(ScanRunState::Running { stage: ScanStage::Semgrep },
             "Semgrep SAST complete", semgrep_count, all_findings.len());

        // ── STAGE 2: Trivy SCA ───────────────────────────────────────────────
        let trivy_result = run_stage(
            ScanStage::Trivy,
            &TrivyAdapter,
            target,
            config_json,
            &emit,
            &all_findings,
        ).await;
        let trivy_count = trivy_result.findings.len();
        all_findings.extend(trivy_result.findings.iter().cloned());
        stage_results.push(trivy_result);
        emit(ScanRunState::Running { stage: ScanStage::Trivy },
             "Trivy SCA complete", trivy_count, all_findings.len());

        // ── STAGE 3: Gitleaks Secrets ────────────────────────────────────────
        let gitleaks_result = run_stage(
            ScanStage::Gitleaks,
            &GitleaksAdapter,
            target,
            config_json,
            &emit,
            &all_findings,
        ).await;
        let gitleaks_count = gitleaks_result.findings.len();
        all_findings.extend(gitleaks_result.findings.iter().cloned());
        stage_results.push(gitleaks_result);
        emit(ScanRunState::Running { stage: ScanStage::Gitleaks },
             "Gitleaks secrets scan complete", gitleaks_count, all_findings.len());

        // ── STAGES 4+5: DAST (optional, auth-gate enforced) ──────────────────
        if run_dast {
            tracing::info!("Orchestrator: Starting DAST stages (auth gate will be enforced)");

            // Sentinel Native — built-in engine, always available. Runs first so
            // that a target with no third-party scanners installed still yields
            // a substantive assessment.
            let gated_native = AuthGatedDastRunner::new(NativeCheckAdapter);
            let native_result = run_stage(
                ScanStage::NativeChecks,
                &gated_native,
                target,
                config_json,
                &emit,
                &all_findings,
            ).await;
            let native_count = native_result.findings.len();
            all_findings.extend(native_result.findings.iter().cloned());
            stage_results.push(native_result);
            emit(ScanRunState::Running { stage: ScanStage::NativeChecks },
                 "Sentinel Native checks complete", native_count, all_findings.len());

            // ZAP DAST — always wrapped in AuthGatedDastRunner
            let gated_zap = AuthGatedDastRunner::new(ZapDastAdapter);
            let zap_result = run_stage(
                ScanStage::ZapDast,
                &gated_zap,
                target,
                config_json,
                &emit,
                &all_findings,
            ).await;
            let zap_count = zap_result.findings.len();
            all_findings.extend(zap_result.findings.iter().cloned());
            stage_results.push(zap_result);
            emit(ScanRunState::Running { stage: ScanStage::ZapDast },
                 "ZAP DAST complete", zap_count, all_findings.len());

            // Nuclei DAST — always wrapped in AuthGatedDastRunner
            let gated_nuclei = AuthGatedDastRunner::new(NucleiDastAdapter);
            let nuclei_result = run_stage(
                ScanStage::NucleiDast,
                &gated_nuclei,
                target,
                config_json,
                &emit,
                &all_findings,
            ).await;
            let nuclei_count = nuclei_result.findings.len();
            all_findings.extend(nuclei_result.findings.iter().cloned());
            stage_results.push(nuclei_result);
            emit(ScanRunState::Running { stage: ScanStage::NucleiDast },
                 "Nuclei DAST complete", nuclei_count, all_findings.len());
        } else {
            tracing::info!("Orchestrator: DAST skipped (run_dast=false)");
        }

        let final_state = ScanRunState::Completed;
        emit(final_state.clone(), "All stages complete", 0, all_findings.len());

        // Only stages that ran to completion count as coverage. A skipped or
        // failed stage must not let the report claim its checks were performed.
        let engines_executed: Vec<String> = stage_results
            .iter()
            .filter(|s| !s.skipped && s.error.is_none())
            .map(|s| s.stage.engine_name().to_string())
            .collect();

        Ok(ScanRunResult {
            scan_run_id,
            target_id: target.id,
            final_state,
            all_findings,
            stage_results,
            engines_executed,
            started_at,
            completed_at: Utc::now(),
        })
    }
}

// ── Helper: run a single stage with error isolation ──────────────────────────

async fn run_stage<A, F>(
    stage: ScanStage,
    adapter: &A,
    target: &Target,
    config_json: &str,
    emit: &F,
    all_findings: &[Finding],
) -> StageResult
where
    A: ScannerAdapter,
    F: Fn(ScanRunState, &str, usize, usize),
{
    let stage_label = format!("{:?}", stage);
    emit(
        ScanRunState::Running { stage: stage.clone() },
        &format!("{} starting", stage_label),
        0,
        all_findings.len(),
    );

    // Check tool availability before invoking
    match adapter.healthcheck().await {
        Ok(false) => {
            let reason = format!(
                "{} binary not found or unreachable. Install it and ensure it is on PATH.",
                adapter.name()
            );
            tracing::warn!("{}", reason);
            return StageResult {
                stage,
                findings: vec![],
                error: None,
                skipped: true,
                skip_reason: Some(reason),
            };
        }
        Err(e) => {
            tracing::warn!("{} healthcheck failed: {}", adapter.name(), e);
            return StageResult {
                stage,
                findings: vec![],
                error: Some(e.to_string()),
                skipped: true,
                skip_reason: Some(format!("Healthcheck failed: {}", e)),
            };
        }
        Ok(true) => {}
    }

    match adapter.run(target, config_json).await {
        Ok(findings) => StageResult {
            stage,
            findings,
            error: None,
            skipped: false,
            skip_reason: None,
        },
        Err(e) => {
            // Stage failures are isolated — pipeline continues with next stage
            tracing::error!("{} stage failed: {}", stage_label, e);
            StageResult {
                stage,
                findings: vec![],
                error: Some(e.to_string()),
                skipped: false,
                skip_reason: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn orchestrator_static_only_does_not_panic_when_tools_absent() {
        // All static tools may be absent in CI; stages should gracefully skip
        use sentinel_core::models::target::Target;
        use uuid::Uuid;
        use chrono::Utc;

        let target = Target {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            name: "CI Test Target".into(),
            target_type: "Web App".into(),
            base_url: "http://localhost:3000".into(),
            repo_ref: Some(".".into()),
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: None,
            created_at: Utc::now(),
        };

        let result = ScanOrchestrator::run_full_pipeline(
            &target,
            "{}",
            false,  // no DAST
            None,
        ).await;

        assert!(result.is_ok(), "Orchestrator must not error when tools are absent");
        let run = result.unwrap();
        assert_eq!(run.final_state, ScanRunState::Completed);
        // All stages should have been attempted (skipped if tool absent)
        assert_eq!(run.stage_results.len(), 3, "3 static stages expected");
        // A skipped stage must never be reported as executed coverage.
        for stage in &run.stage_results {
            if stage.skipped {
                assert!(
                    !run.engines_executed.contains(&stage.stage.engine_name().to_string()),
                    "{:?} was skipped but is listed as an executed engine",
                    stage.stage
                );
            }
        }
    }

    #[tokio::test]
    async fn orchestrator_dast_is_gated_when_no_authorization_record() {
        use sentinel_core::models::target::Target;
        use uuid::Uuid;
        use chrono::Utc;

        let target = Target {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            name: "Unauthorized Target".into(),
            target_type: "Web App".into(),
            base_url: "http://production-bank.example.com".into(),
            repo_ref: None,
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: None,  // <-- No RoE: gate must block
            created_at: Utc::now(),
        };

        let result = ScanOrchestrator::run_full_pipeline(
            &target,
            "{}",
            true,  // request DAST
            None,
        ).await;

        // Pipeline completes, but DAST stage results should have errors
        let run = result.unwrap();
        let dast_stages: Vec<_> = run.stage_results.iter()
            .filter(|s| s.stage == ScanStage::ZapDast || s.stage == ScanStage::NucleiDast)
            .collect();

        for stage in &dast_stages {
            assert!(
                stage.error.is_some() || stage.skipped,
                "DAST stage {:?} must be blocked or skipped without RoE",
                stage.stage
            );
        }
    }
}
