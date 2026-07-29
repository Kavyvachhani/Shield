use tauri::State;
use serde::Deserialize;
use chrono::Utc;
use crate::state::{AppState, ScanRunRecord, ScanRunStatus, FindingRecord, new_id};
use crate::event_bridge::*;

#[derive(Debug, Deserialize)]
pub struct TriggerScanInput {
    pub target_id: String,
    pub run_dast: bool,
    pub config_json: Option<String>,
}

/// Trigger the full ScanOrchestrator pipeline for a target.
///
/// SAFETY: If `run_dast = true`, the command layer checks for a signed
/// AuthorizationRecord BEFORE spawning any DAST work. If none exists,
/// the command returns Err immediately — the scan never starts.
#[tauri::command]
pub async fn trigger_scan(
    input: TriggerScanInput,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let target_id = input.target_id.clone();

    // ── COMMAND-LAYER AUTH GATE (non-bypassable for DAST) ─────────────────
    if input.run_dast {
        let has_roe = state.auth_records.read().await.contains_key(&target_id);
        if !has_roe {
            return Err(
                "DAST scan blocked: target has no signed Rules of Engagement (RoE). \
                 Complete the Authorization Gate flow before triggering DAST.".into()
            );
        }
    }

    let scan_run_id = new_id();
    let run_record = ScanRunRecord {
        id: scan_run_id.clone(),
        target_id: target_id.clone(),
        status: ScanRunStatus::Pending,
        run_dast: input.run_dast,
        started_at: Utc::now(),
        completed_at: None,
        finding_count: 0,
        error: None,
    };
    state.scan_runs.write().await.insert(scan_run_id.clone(), run_record);

    let scan_runs_clone = state.scan_runs.clone();
    let findings_clone = state.findings.clone();
    let auth_records_clone = state.auth_records.clone();
    let targets_clone = state.targets.clone();
    let _active_scans_clone = state.active_scans.clone();
    let config_json = input.config_json.unwrap_or_default();
    let run_dast = input.run_dast;
    let run_id_clone = scan_run_id.clone();
    let target_id_clone = target_id.clone();

    let join_handle = tokio::spawn(async move {
        use tauri::Emitter;

        {
            let mut runs = scan_runs_clone.write().await;
            if let Some(r) = runs.get_mut(&run_id_clone) {
                r.status = ScanRunStatus::Running;
            }
        }

        let _ = app.emit(EVENT_STAGE_UPDATE, ScanStageUpdatePayload {
            scan_run_id: run_id_clone.clone(),
            stage: "pipeline".into(),
            state: "running".into(),
            stage_findings: 0,
            total_findings: 0,
            timestamp: Utc::now(),
            message: "SentinelVAPT scan pipeline started".into(),
        });

        let target_record = {
            targets_clone.read().await.get(&target_id_clone).cloned()
        };

        let Some(target_rec) = target_record else {
            let err = format!("Target '{}' not found in state", target_id_clone);
            let mut runs = scan_runs_clone.write().await;
            if let Some(r) = runs.get_mut(&run_id_clone) {
                r.status = ScanRunStatus::Failed;
                r.error = Some(err.clone());
                r.completed_at = Some(Utc::now());
            }
            let _ = app.emit(EVENT_ERROR, ScanErrorPayload {
                scan_run_id: run_id_clone,
                error: err,
                stage: None,
                timestamp: Utc::now(),
            });
            return;
        };

        let auth_record = auth_records_clone.read().await.get(&target_id_clone).cloned();
        let core_target = build_core_target(&target_rec, auth_record);

        let stages = ["semgrep", "trivy", "gitleaks", "zap_dast", "nuclei_dast"];
        let stage_count = if run_dast { 5 } else { 3 };
        let mut cumulative_findings: Vec<FindingRecord> = Vec::new();

        for (idx, stage_name) in stages.iter().take(stage_count).enumerate() {
            let _ = app.emit(EVENT_STAGE_UPDATE, ScanStageUpdatePayload {
                scan_run_id: run_id_clone.clone(),
                stage: stage_name.to_string(),
                state: "running".into(),
                stage_findings: 0,
                total_findings: cumulative_findings.len(),
                timestamp: Utc::now(),
                message: format!("Starting {} scan...", stage_name),
            });

            let _ = app.emit(EVENT_LOG, ScanLogPayload {
                scan_run_id: run_id_clone.clone(),
                stage: stage_name.to_string(),
                level: "info".into(),
                message: format!("[{}] Invoking user-installed {} binary...", idx + 1, stage_name),
                timestamp: Utc::now(),
            });

            let stage_result = run_stage_for(stage_name, &core_target, &config_json).await;

            match stage_result {
                Ok(raw_findings) => {
                    let stage_finding_count = raw_findings.len();
                    for f in raw_findings {
                        let record = FindingRecord {
                            id: f.id.to_string(),
                            scan_id: run_id_clone.clone(),
                            target_id: target_id_clone.clone(),
                            title: f.title.clone(),
                            description: f.description.clone(),
                            severity: format!("{:?}", f.severity),
                            cvss4_score: f.cvss4.as_ref().map(|c| c.base_score as f32).unwrap_or(0.0),
                            epss_score: f.epss.as_ref().map(|e| e.score as f32).unwrap_or(0.0),
                            kev_listed: f.kev_listed,
                            priority_score: f.priority_score as f32,
                            cwe_id: f.cwe_id.clone(),
                            owasp_2025: f.owasp_2025.clone(),
                            wstg_id: f.wstg_id.clone(),
                            affected_component: f.affected_component.clone(),
                            repro_steps: f.repro_steps.clone(),
                            remediation: f.remediation.clone(),
                            status: "Open".into(),
                            source_tools: f.source_tools.clone(),
                            triage_note: None,
                            priority_rationale: f.priority_rationale.clone(),
                            created_at: f.created_at,
                        };
                        cumulative_findings.push(record.clone());
                        findings_clone.write().await.insert(record.id.clone(), record);
                    }

                    let _ = app.emit(EVENT_STAGE_UPDATE, ScanStageUpdatePayload {
                        scan_run_id: run_id_clone.clone(),
                        stage: stage_name.to_string(),
                        state: "done".into(),
                        stage_findings: stage_finding_count,
                        total_findings: cumulative_findings.len(),
                        timestamp: Utc::now(),
                        message: format!("{} complete: {} findings", stage_name, stage_finding_count),
                    });
                }
                Err(e) => {
                    let msg = e.to_string();
                    let is_skip = msg.contains("not found on PATH") || msg.contains("not found or unreachable");
                    let stage_state = if is_skip { "skipped" } else { "failed" };
                    let _ = app.emit(EVENT_STAGE_UPDATE, ScanStageUpdatePayload {
                        scan_run_id: run_id_clone.clone(),
                        stage: stage_name.to_string(),
                        state: stage_state.into(),
                        stage_findings: 0,
                        total_findings: cumulative_findings.len(),
                        timestamp: Utc::now(),
                        message: msg.clone(),
                    });
                    let _ = app.emit(EVENT_LOG, ScanLogPayload {
                        scan_run_id: run_id_clone.clone(),
                        stage: stage_name.to_string(),
                        level: if is_skip { "warn" } else { "error" }.into(),
                        message: msg,
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        let total = cumulative_findings.len();
        {
            let mut runs = scan_runs_clone.write().await;
            if let Some(r) = runs.get_mut(&run_id_clone) {
                r.status = ScanRunStatus::Completed;
                r.completed_at = Some(Utc::now());
                r.finding_count = total;
            }
        }

        let _ = app.emit(EVENT_COMPLETE, ScanCompletePayload {
            scan_run_id: run_id_clone.clone(),
            total_findings: total,
            stage_summary: vec![],
            duration_seconds: 0,
            completed_at: Utc::now(),
        });
    });

    state.active_scans.write().await
        .insert(scan_run_id.clone(), join_handle.abort_handle());

    Ok(scan_run_id)
}

#[tauri::command]
pub async fn cancel_scan(
    scan_run_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if let Some(handle) = state.active_scans.write().await.remove(&scan_run_id) {
        handle.abort();
    }
    if let Some(run) = state.scan_runs.write().await.get_mut(&scan_run_id) {
        run.status = ScanRunStatus::Cancelled;
        run.completed_at = Some(Utc::now());
    }
    Ok(())
}

#[tauri::command]
pub async fn get_scan_status(
    scan_run_id: String,
    state: State<'_, AppState>,
) -> Result<Option<ScanRunRecord>, String> {
    Ok(state.scan_runs.read().await.get(&scan_run_id).cloned())
}

fn build_core_target(
    rec: &crate::state::TargetRecord,
    auth: Option<crate::state::AuthorizationRecord>,
) -> sentinel_core::models::target::Target {
    use sentinel_core::models::target::{Target, AuthorizationRecord, ScopeDefinition};
    use uuid::Uuid;

    let core_auth = auth.map(|a| AuthorizationRecord {
        id: Uuid::parse_str(&a.id).unwrap_or_else(|_| Uuid::new_v4()),
        target_id: Uuid::parse_str(&a.target_id).unwrap_or_else(|_| Uuid::new_v4()),
        scope: ScopeDefinition {
            allowed_domains: a.scope.allowed_domains,
            allowed_ips_cidrs: a.scope.allowed_ips_cidrs,
            out_of_scope_paths: a.scope.out_of_scope_paths,
            rate_limit_rps: a.scope.rate_limit_rps,
            prohibited_actions: a.scope.prohibited_actions,
        },
        acknowledged_by: a.acknowledged_by,
        signed_at: a.signed_at,
        roe_document_hash: a.roe_document_hash,
        digital_signature: "command-layer-signed".into(),
    });

    Target {
        id: Uuid::parse_str(&rec.id).unwrap_or_else(|_| Uuid::new_v4()),
        project_id: Uuid::parse_str(&rec.project_id).unwrap_or_else(|_| Uuid::new_v4()),
        name: rec.name.clone(),
        target_type: rec.target_type.clone(),
        base_url: rec.base_url.clone(),
        repo_ref: rec.repo_ref.clone(),
        stack_description: rec.stack_description.clone(),
        auth_keychain_handle: rec.auth_keychain_handle.clone(),
        authorization_record: core_auth,
        created_at: rec.created_at,
    }
}

async fn run_stage_for(
    stage: &str,
    target: &sentinel_core::models::target::Target,
    config_json: &str,
) -> anyhow::Result<Vec<sentinel_core::models::finding::Finding>> {
    use sentinel_adapters::adapter_trait::ScannerAdapter;
    use sentinel_adapters::auth_gated_runner::AuthGatedDastRunner;

    match stage {
        "semgrep"     => sentinel_adapters::semgrep::SemgrepAdapter.run(target, config_json).await,
        "trivy"       => sentinel_adapters::trivy::TrivyAdapter.run(target, config_json).await,
        "gitleaks"    => sentinel_adapters::gitleaks::GitleaksAdapter.run(target, config_json).await,
        "zap_dast"    => AuthGatedDastRunner::new(sentinel_adapters::zap::ZapDastAdapter).run(target, config_json).await,
        "nuclei_dast" => AuthGatedDastRunner::new(sentinel_adapters::nuclei::NucleiDastAdapter).run(target, config_json).await,
        other => Err(anyhow::anyhow!("Unknown stage: {}", other)),
    }
}
