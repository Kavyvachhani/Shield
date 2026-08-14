use tauri::State;
use serde::Deserialize;
use chrono::Utc;
use crate::state::{log_persist_error, AppState, ScanRunRecord, ScanRunStatus, StoredFinding, new_id};
use crate::event_bridge::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerScanInput {
    pub target_id: String,
    pub run_dast: bool,
    pub config_json: Option<String>,
}

/// Stages that run on every scan. Semgrep, Trivy and Gitleaks need a source
/// repository and skip without one; Sentinel Native needs only the target URL,
/// so it is what makes a URL-only engagement produce results at all.
const BASELINE_STAGES: &[&str] = &["semgrep", "trivy", "gitleaks", "native"];

/// How long any single stage may run before the pipeline abandons it.
///
/// Generous enough for a real DAST pass over a large application, short enough
/// that a wedged scanner cannot hang the run for the rest of the session.
const STAGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Stages added when the analyst opts into active DAST.
const DAST_STAGES: &[&str] = &["zap_dast", "nuclei_dast"];

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
        engines_executed: Vec::new(),
        error: None,
    };
    if let Err(e) = state.store.save_scan_run(&run_record) {
        log_persist_error("scan run", &e);
    }
    state.scan_runs.write().await.insert(scan_run_id.clone(), run_record);

    let scan_runs_clone = state.scan_runs.clone();
    let findings_clone = state.findings.clone();
    let scan_engines_clone = state.scan_engines.clone();
    let store_clone = state.store.clone();
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

        // The stage-update above matches no card and writes no log line, so
        // without this the console stays completely blank until the first stage
        // reports — indistinguishable from a pipeline that never started.
        let _ = app.emit(EVENT_LOG, ScanLogPayload {
            scan_run_id: run_id_clone.clone(),
            stage: "pipeline".into(),
            level: "info".into(),
            message: format!(
                "Pipeline started for scan {} (DAST {})",
                run_id_clone,
                if run_dast { "enabled" } else { "disabled" }
            ),
            timestamp: Utc::now(),
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

        // The native engine is part of the baseline, not an opt-in extra: it
        // ships inside the app, so a target with no third-party scanners
        // installed still gets a real assessment rather than three skipped
        // stages. It stays wrapped in the RoE gate, which is what keeps it
        // honest — the gate refuses it when no authorization has been signed.
        let stages: Vec<&str> = BASELINE_STAGES
            .iter()
            .chain(if run_dast { DAST_STAGES } else { &[] })
            .copied()
            .collect();
        let mut total_findings = 0usize;
        let mut engines_executed: Vec<String> = Vec::new();

        for (idx, stage_name) in stages.iter().enumerate() {
            let _ = app.emit(EVENT_STAGE_UPDATE, ScanStageUpdatePayload {
                scan_run_id: run_id_clone.clone(),
                stage: stage_name.to_string(),
                state: "running".into(),
                stage_findings: 0,
                total_findings,
                timestamp: Utc::now(),
                message: format!("Starting {} scan...", engine_label(stage_name)),
            });

            let _ = app.emit(EVENT_LOG, ScanLogPayload {
                scan_run_id: run_id_clone.clone(),
                stage: stage_name.to_string(),
                level: "info".into(),
                message: format!("[{}] Invoking user-installed {} binary...", idx + 1, stage_name),
                timestamp: Utc::now(),
            });

            // A stage that never returns takes the whole pipeline with it: no
            // further events are emitted, so every remaining card sits on
            // "Waiting..." with an empty log and no way to tell a stalled scan
            // from a slow one. An external scanner blocked on input, or a host
            // that accepts a connection and then goes silent, both do this.
            // Bound every stage so the run always finishes and always reports.
            let stage_result = match tokio::time::timeout(
                STAGE_TIMEOUT,
                run_stage_for(stage_name, &core_target, &config_json),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!(
                    "{} exceeded the {}-minute stage timeout and was abandoned; \
                     the target may be dropping packets or the scanner may be waiting on input",
                    engine_label(stage_name),
                    STAGE_TIMEOUT.as_secs() / 60
                )),
            };

            match stage_result {
                Ok(raw_findings) => {
                    let stage_finding_count = raw_findings.len();
                    // The stage completed, so its engine counts as coverage even
                    // when it produced nothing — a clean pass is a real result.
                    engines_executed.push(engine_name(stage_name).to_string());

                    // Persist the stage's findings before updating memory, so a
                    // crash mid-pipeline still leaves completed stages on disk.
                    if let Err(e) = store_clone.save_findings(&run_id_clone, &raw_findings) {
                        log_persist_error("scan findings", &e);
                    }
                    {
                        let mut store = findings_clone.write().await;
                        for f in raw_findings {
                            store.insert(
                                f.id.to_string(),
                                StoredFinding {
                                    scan_id: run_id_clone.clone(),
                                    finding: f,
                                    triage_note: None,
                                },
                            );
                        }
                    }
                    total_findings += stage_finding_count;

                    let _ = app.emit(EVENT_STAGE_UPDATE, ScanStageUpdatePayload {
                        scan_run_id: run_id_clone.clone(),
                        stage: stage_name.to_string(),
                        state: "done".into(),
                        stage_findings: stage_finding_count,
                        total_findings,
                        timestamp: Utc::now(),
                        message: format!("{} complete: {} findings", engine_label(stage_name), stage_finding_count),
                    });
                }
                Err(e) => {
                    let msg = e.to_string();
                    // A missing scanner, an unreachable daemon, or a stage the
                    // RoE gate declined are all "this did not run" rather than
                    // "this broke" — surfacing them as failures reads as a bug
                    // in the app when it is really a setup or authorization
                    // state the analyst can act on.
                    let is_skip = msg.contains("not found on PATH")
                        || msg.contains("not found or unreachable")
                        || msg.contains("AUTH GATE BLOCKED")
                        || msg.contains("no source repository");
                    let stage_state = if is_skip { "skipped" } else { "failed" };
                    let _ = app.emit(EVENT_STAGE_UPDATE, ScanStageUpdatePayload {
                        scan_run_id: run_id_clone.clone(),
                        stage: stage_name.to_string(),
                        state: stage_state.into(),
                        stage_findings: 0,
                        total_findings,
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

        let total = total_findings;
        if let Err(e) = store_clone.save_scan_engines(&run_id_clone, &engines_executed) {
            log_persist_error("executed engine list", &e);
        }
        scan_engines_clone
            .write()
            .await
            .insert(run_id_clone.clone(), engines_executed.clone());
        {
            let mut runs = scan_runs_clone.write().await;
            if let Some(r) = runs.get_mut(&run_id_clone) {
                r.status = ScanRunStatus::Completed;
                r.completed_at = Some(Utc::now());
                r.finding_count = total;
                r.engines_executed = engines_executed;
                if let Err(e) = store_clone.save_scan_run(r) {
                    log_persist_error("completed scan run", &e);
                }
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
        "native"      => AuthGatedDastRunner::new(sentinel_adapters::native::NativeCheckAdapter).run(target, config_json).await,
        "trivy"       => sentinel_adapters::trivy::TrivyAdapter.run(target, config_json).await,
        "gitleaks"    => sentinel_adapters::gitleaks::GitleaksAdapter.run(target, config_json).await,
        "zap_dast"    => AuthGatedDastRunner::new(sentinel_adapters::zap::ZapDastAdapter).run(target, config_json).await,
        "nuclei_dast" => AuthGatedDastRunner::new(sentinel_adapters::nuclei::NucleiDastAdapter).run(target, config_json).await,
        other => Err(anyhow::anyhow!("Unknown stage: {}", other)),
    }
}

/// Engine name as used by the checklist coverage catalog.
fn engine_name(stage: &str) -> &'static str {
    match stage {
        "semgrep" => "Semgrep",
        "trivy" => "Trivy",
        "gitleaks" => "Gitleaks",
        "native" => "Sentinel Native",
        "zap_dast" => "OWASP ZAP",
        "nuclei_dast" => "Nuclei",
        _ => "Unknown",
    }
}

/// Human-readable stage label for the scan console.
fn engine_label(stage: &str) -> &'static str {
    match stage {
        "semgrep" => "Semgrep SAST",
        "trivy" => "Trivy dependency audit",
        "gitleaks" => "Gitleaks secret scan",
        "native" => "Sentinel Native checks",
        "zap_dast" => "OWASP ZAP DAST",
        "nuclei_dast" => "Nuclei DAST",
        _ => "Unknown stage",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_stage_maps_to_a_catalog_engine_name() {
        for stage in ["semgrep", "trivy", "gitleaks", "native", "zap_dast", "nuclei_dast"] {
            assert_ne!(engine_name(stage), "Unknown", "{stage} has no engine mapping");
            assert_ne!(engine_label(stage), "Unknown stage", "{stage} has no label");
        }
    }

    #[test]
    fn native_stage_name_matches_the_checklist_catalog() {
        assert_eq!(engine_name("native"), sentinel_core::checklist::catalog::engine::NATIVE);
    }

    /// The native engine is the only one that needs nothing installed and no
    /// source repository, so a scan that omits it produces nothing at all for a
    /// URL-only target. It previously sat behind a `.take(3)` that excluded it
    /// from every non-DAST run, which made the default scan look broken.
    #[test]
    fn a_default_scan_still_runs_the_native_engine() {
        assert!(
            BASELINE_STAGES.contains(&"native"),
            "native must run without opting into DAST, or a URL-only target yields no findings"
        );
    }

    #[test]
    fn dast_stages_are_additive_and_never_the_whole_run() {
        for stage in DAST_STAGES {
            assert!(
                !BASELINE_STAGES.contains(stage),
                "{stage} would run without the analyst opting into DAST"
            );
        }
        assert!(DAST_STAGES.contains(&"zap_dast") && DAST_STAGES.contains(&"nuclei_dast"));
    }

    /// End-to-end proof that a default scan of a URL-only target actually
    /// produces findings, exercised through the same `run_stage_for` the
    /// command uses. This is the scenario that was broken: an analyst enters a
    /// URL, signs the RoE, presses Start, and previously got three skipped
    /// stages and an empty findings table.
    #[tokio::test]
    async fn a_url_only_target_produces_findings_on_a_default_scan() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // A deliberately misconfigured server: no security headers at all.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let body = "<html><body><a href='http://evil.example' target='_blank'>x</a></body></html>";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: text/html\r\n\
                         Set-Cookie: session=abc123\r\n\
                         Server: nginx/1.18.0\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        let target_record = crate::state::TargetRecord {
            id: new_id(),
            project_id: new_id(),
            name: "Local test".into(),
            target_type: "Web App".into(),
            base_url: format!("http://{addr}"),
            repo_ref: None, // URL only — no source code, as in the failing case
            stack_description: None,
            auth_keychain_handle: None,
            created_at: Utc::now(),
        };

        let auth = crate::state::AuthorizationRecord {
            id: new_id(),
            target_id: target_record.id.clone(),
            scope: crate::state::ScopeDefinitionRecord {
                allowed_domains: vec!["127.0.0.1".into()],
                allowed_ips_cidrs: vec![],
                out_of_scope_paths: vec![],
                rate_limit_rps: 50,
                prohibited_actions: vec![],
            },
            acknowledged_by: "Test Analyst".into(),
            signed_at: Utc::now(),
            roe_document_hash: "hash".into(),
        };

        let core_target = build_core_target(&target_record, Some(auth));

        // Run exactly the stages a default (non-DAST) scan runs.
        let mut total = 0usize;
        let mut ran: Vec<&str> = Vec::new();
        for stage in BASELINE_STAGES {
            if let Ok(findings) = run_stage_for(stage, &core_target, "").await {
                ran.push(stage);
                total += findings.len();
            }
        }

        assert!(
            ran.contains(&"native"),
            "the native stage did not run; a URL-only scan cannot produce anything without it"
        );
        assert!(
            total > 0,
            "a default scan of a server with no security headers produced no findings"
        );
    }

    #[test]
    fn every_stage_that_can_run_has_a_label_and_engine_name() {
        for stage in BASELINE_STAGES.iter().chain(DAST_STAGES) {
            assert_ne!(engine_name(stage), "Unknown", "{stage} has no engine mapping");
            assert_ne!(engine_label(stage), "Unknown stage", "{stage} has no label");
        }
    }
}
