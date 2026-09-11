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
    /// The engines this run should use, from the selected scan profile.
    ///
    /// `None` means every stage, which is what a caller predating profiles
    /// intended and what the pipeline did before this existed. An explicitly
    /// empty list is rejected rather than silently running nothing.
    #[serde(default)]
    pub enabled_stages: Option<Vec<String>>,
}

/// Stages that run on every scan. Semgrep, Trivy and Gitleaks need a source
/// repository and skip without one; Sentinel Native needs only the target URL,
/// so it is what makes a URL-only engagement produce results at all.
const BASELINE_STAGES: &[&str] = &[
    // The four built-in static engines come first. They need no installed
    // binary, so they are the ones that actually run on a fresh machine — and
    // before they existed, a source checkout with none of the external
    // scanners present was assessed by nothing at all.
    "code", "dependencies", "secrets", "infrastructure",
    // The external engines then add what they add: a far larger rule registry,
    // a second vulnerability database, provider-verified secrets, and a
    // dedicated IaC policy set. Each skips cleanly when its binary is absent.
    "semgrep", "trivy", "gitleaks", "osv", "trufflehog", "retirejs", "checkov",
    // Passive reconnaissance. Sends nothing to the target — every source it
    // queries is a third party — so it sits with the static stages rather than
    // behind the RoE gate, and it runs whether or not dynamic testing is on.
    "recon",
    // Sentinel Native needs only the target URL, so it is what makes a
    // URL-only engagement produce results at all.
    "native",
];

/// The stages that read local files and can therefore run concurrently.
///
/// Network stages stay sequential: they all make requests to the same target,
/// and running them together would let their combined traffic exceed the rate
/// limit the Rules of Engagement agreed, which is a safety guarantee rather
/// than a performance setting.
const STATIC_STAGE_NAMES: &[&str] = &[
    "code", "dependencies", "secrets", "infrastructure",
    "semgrep", "trivy", "gitleaks", "osv", "trufflehog", "retirejs", "checkov",
    // Recon reaches the network, but only third-party data sources — never the
    // target — so its traffic cannot exceed the rate limit the RoE agreed and
    // it belongs in the concurrent block.
    "recon",
];

/// The static analysers, which run concurrently.
///
/// They read local files, touch no network and share no state, so running them
/// one after another was pure wasted wall clock — on a real repository each can
/// take a minute on its own. Network stages stay sequential below: they all
/// make requests to the same target, and running them together would let their
/// combined traffic exceed the rate limit the RoE agreed, which is a safety
/// guarantee rather than a performance setting.
const STATIC_STAGES: usize = 12;

/// How long any single stage may run before the pipeline abandons it.
///
/// Generous enough for a real DAST pass over a large application, short enough
/// that a wedged scanner cannot hang the run for the rest of the session.
const STAGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Stages added when the analyst opts into active DAST.
const DAST_STAGES: &[&str] = &["zap_dast", "nuclei_dast", "nikto_dast", "testssl_dast", "sqlmap_dast"];

/// Running totals a pipeline accumulates as its stages report.
///
/// These used to be loose `&mut` parameters threaded through
/// `process_stage_result`, which was already one argument over clippy's limit
/// before Critical/High counts and the per-stage summary needed adding too.
#[derive(Default)]
struct PipelineTally {
    total_findings: usize,
    /// Cumulative Critical + High. The scan console displays this; it was
    /// previously a hardcoded `0` in the UI.
    critical_high: usize,
    /// Engines that genuinely ran. Drives coverage reporting, so a skipped
    /// stage must never appear here.
    engines_executed: Vec<String>,
    /// One entry per stage, in completion order. Ships in the completion
    /// event, which used to send an empty vector on every scan.
    stage_summary: Vec<StageSummary>,
}

impl PipelineTally {
    /// Fold one stage's successful result into the running totals.
    fn record_stage_findings(
        &mut self,
        stage_name: &str,
        findings: &[sentinel_core::models::finding::Finding],
    ) {
        use sentinel_core::models::finding::Severity;

        self.engines_executed.push(engine_name(stage_name).to_string());
        self.total_findings += findings.len();
        self.critical_high += findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .count();
        self.stage_summary.push(StageSummary {
            stage: stage_name.to_string(),
            state: "done".into(),
            findings: findings.len(),
            error: None,
        });
    }
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

    // A scan that runs no engine would complete, report zero findings, and look
    // exactly like a clean result.
    if let Some(stages) = input.enabled_stages.as_ref() {
        if stages.is_empty() {
            return Err(
                "This scan profile enables no engines, so the run would report nothing found                  without having looked. Enable at least one engine before starting."
                    .into(),
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
    let exceptions_clone = state.exceptions.clone();
    let config_json = input.config_json.unwrap_or_default();
    let run_dast = input.run_dast;
    let enabled_stages = input.enabled_stages.clone();
    let run_id_clone = scan_run_id.clone();
    let target_id_clone = target_id.clone();

    // The pipeline task takes ownership of `app`; the supervisor below needs
    // its own handle to report a crash after that task is gone.
    let supervisor_app = app.clone();

    let join_handle = tokio::spawn(async move {
        use tauri::Emitter;

        let started_at = std::time::Instant::now();

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
            critical_high: 0,
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

        // Decisions the analyst has already taken about this target, indexed
        // ready to apply as each stage reports. Without this a re-scan raises
        // every dismissed false positive again with a fresh id, and the analyst
        // triages the same noise on every run.
        let register = {
            let all = exceptions_clone.read().await;
            sentinel_core::exceptions::ExceptionRegister::for_target(all.values(), &target_id_clone)
        };
        if !register.is_empty() {
            let _ = app.emit(EVENT_LOG, ScanLogPayload {
                scan_run_id: run_id_clone.clone(),
                stage: "pipeline".into(),
                level: "info".into(),
                message: format!(
                    "{} standing exception(s) will be applied to this scan's findings",
                    register.len()
                ),
                timestamp: Utc::now(),
            });
        }

        // The native engine is part of the baseline, not an opt-in extra: it
        // ships inside the app, so a target with no third-party scanners
        // installed still gets a real assessment rather than three skipped
        // stages. It stays wrapped in the RoE gate, which is what keeps it
        // honest — the gate refuses it when no authorization has been signed.
        // The profile's selection is applied here rather than at the call site
        // so that the order stays the pipeline's — a profile is a set of
        // engines, not a running order, and the concurrency below depends on
        // the static stages coming first.
        let selected: Vec<&str> = BASELINE_STAGES
            .iter()
            .chain(if run_dast { DAST_STAGES } else { &[] })
            .copied()
            .filter(|stage| match &enabled_stages {
                Some(list) => list.iter().any(|s| s == stage),
                None => true,
            })
            .collect();

        // A stage the profile switched off is not the same as a stage that
        // failed, and the coverage matrix has to be able to tell them apart —
        // so the run says plainly which engines it was asked not to use.
        let excluded: Vec<&str> = BASELINE_STAGES
            .iter()
            .chain(DAST_STAGES)
            .copied()
            .filter(|s| !selected.contains(s))
            .collect();
        if !excluded.is_empty() {
            let _ = app.emit(EVENT_LOG, ScanLogPayload {
                scan_run_id: run_id_clone.clone(),
                stage: "pipeline".into(),
                level: "info".into(),
                message: format!(
                    "{} engine(s) not run for this profile: {}. The coverage matrix records                      the checks they would have answered as untested.",
                    excluded.len(),
                    excluded.join(", ")
                ),
                timestamp: Utc::now(),
            });
        }

        let stages = selected;
        let mut tally = PipelineTally::default();

        // Semgrep, Trivy and Gitleaks are three independent local file
        // analyzers: none of them touches the network or shares state with
        // the others, so running them one after another was pure wasted wall
        // clock — on a real repository each can easily take a minute or more
        // on its own. They are always exactly the first three entries of
        // BASELINE_STAGES, so they run concurrently via `tokio::join!` here.
        // Native, ZAP and Nuclei stay sequential below: all three make real
        // requests to the same target, and running them concurrently would
        // let their combined traffic exceed the RoE's agreed rate limit,
        // which is a safety guarantee, not just a performance one.
        // Every stage in this list reads local files: none touches the network
        // or shares state with another, so running them one after another was
        // pure wasted wall clock. They are partitioned by name rather than by
        // position because a profile can switch any of them off.
        let (static_stages, network_stages): (Vec<&str>, Vec<&str>) =
            stages.iter().partition(|s| STATIC_STAGE_NAMES.contains(s));
        debug_assert!(
            static_stages.len() <= STATIC_STAGES,
            "the concurrent block must stay bounded"
        );

        for (idx, stage_name) in static_stages.iter().enumerate() {
            emit_stage_starting(&app, &run_id_clone, stage_name, idx, &tally);
        }
        // `join_all` rather than `tokio::join!`: the tuple form needs the stage
        // list to be known at compile time, and a scan profile decides it at
        // run time. The futures still run concurrently on this one task, and —
        // unlike spawning — they can borrow the target and the configuration
        // rather than each needing an owned copy.
        let static_results = futures_util::future::join_all(
            static_stages
                .iter()
                .map(|stage| run_stage_bounded(&app, &run_id_clone, stage, &core_target, &config_json)),
        )
        .await;

        for (stage_name, result) in static_stages.iter().copied().zip(static_results) {
            process_stage_result(
                &app, &store_clone, &findings_clone, &run_id_clone,
                stage_name, result, &mut tally, &register,
            ).await;
        }

        for (offset, stage_name) in network_stages.iter().enumerate() {
            let idx = offset + static_stages.len();
            emit_stage_starting(&app, &run_id_clone, stage_name, idx, &tally);

            // A stage that never returns takes the whole pipeline with it: no
            // further events are emitted, so every remaining card sits on
            // "Waiting..." with an empty log and no way to tell a stalled scan
            // from a slow one. An external scanner blocked on input, or a host
            // that accepts a connection and then goes silent, both do this.
            // Bound every stage so the run always finishes and always reports.
            let stage_result = run_stage_bounded(&app, &run_id_clone, stage_name, &core_target, &config_json).await;

            process_stage_result(
                &app, &store_clone, &findings_clone, &run_id_clone,
                stage_name, stage_result, &mut tally, &register,
            ).await;
        }

        let total = tally.total_findings;
        if let Err(e) = store_clone.save_scan_engines(&run_id_clone, &tally.engines_executed) {
            log_persist_error("executed engine list", &e);
        }
        scan_engines_clone
            .write()
            .await
            .insert(run_id_clone.clone(), tally.engines_executed.clone());
        {
            let mut runs = scan_runs_clone.write().await;
            if let Some(r) = runs.get_mut(&run_id_clone) {
                r.status = ScanRunStatus::Completed;
                r.completed_at = Some(Utc::now());
                r.finding_count = total;
                r.engines_executed = std::mem::take(&mut tally.engines_executed);
                if let Err(e) = store_clone.save_scan_run(r) {
                    log_persist_error("completed scan run", &e);
                }
            }
        }

        let _ = app.emit(EVENT_COMPLETE, ScanCompletePayload {
            scan_run_id: run_id_clone.clone(),
            total_findings: total,
            critical_high: tally.critical_high,
            // These two shipped as `vec![]` and `0` on every scan since the
            // event was introduced: the payload declared a per-stage breakdown
            // and a duration, and always asserted the scan found nothing in no
            // time at all.
            stage_summary: std::mem::take(&mut tally.stage_summary),
            duration_seconds: started_at.elapsed().as_secs(),
            completed_at: Utc::now(),
        });
    });

    state.active_scans.write().await
        .insert(scan_run_id.clone(), join_handle.abort_handle());

    // Supervise the pipeline task.
    //
    // The pipeline emits its own completion event on every path it can return
    // from — but a panic is not one of those paths. An adapter that indexes out
    // of bounds or unwraps a None takes the whole task down between its
    // "starting" event and its completion event, so the console keeps a stage
    // spinning and `isRunning` true forever: the 20s watchdog cannot help,
    // because events *did* arrive before the crash. Nothing ever tells the
    // analyst the scan is dead.
    //
    // Awaiting the join handle turns that silence into a reported failure, and
    // gives the run's registration in `active_scans` a single place to be
    // removed — it previously leaked an entry per scan for the session's life,
    // and `cancel_scan` on a finished run aborted an already-dead task.
    tokio::spawn({
        let scan_runs = state.scan_runs.clone();
        let store = state.store.clone();
        let active_scans = state.active_scans.clone();
        let run_id = scan_run_id.clone();
        async move {
            use tauri::Emitter;

            let outcome = join_handle.await;
            active_scans.write().await.remove(&run_id);

            let Err(join_err) = outcome else {
                return; // Ran to completion and reported itself.
            };

            // A cancelled task is `cancel_scan` doing its job; that command
            // already recorded the status and told the UI.
            if join_err.is_cancelled() {
                return;
            }

            let err = mark_run_crashed(&scan_runs, &store, &run_id, panic_detail(join_err)).await;

            let _ = supervisor_app.emit(EVENT_ERROR, ScanErrorPayload {
                scan_run_id: run_id,
                error: err,
                stage: None,
                timestamp: Utc::now(),
            });
        }
    });

    Ok(scan_run_id)
}

/// Record a crashed pipeline against its run and return the message to report.
///
/// Split out from the supervisor so the state transition can be tested without
/// standing up a Tauri app: the supervisor adds only the event emit on top.
async fn mark_run_crashed(
    scan_runs: &tokio::sync::RwLock<std::collections::HashMap<String, ScanRunRecord>>,
    store: &crate::store::Store,
    run_id: &str,
    detail: String,
) -> String {
    let err = format!(
        "The scan pipeline crashed and was stopped: {detail}. \
         Findings from stages that finished before the crash have been saved."
    );

    let mut runs = scan_runs.write().await;
    if let Some(r) = runs.get_mut(run_id) {
        r.status = ScanRunStatus::Failed;
        r.error = Some(err.clone());
        r.completed_at = Some(Utc::now());
        if let Err(e) = store.save_scan_run(r) {
            log_persist_error("crashed scan run", &e);
        }
    }
    err
}

/// One console line describing what the standing exceptions did to this stage.
fn exception_summary(applied: &sentinel_core::exceptions::ApplyOutcome) -> String {
    let mut parts = Vec::new();
    if applied.false_positives > 0 {
        parts.push(format!(
            "{} carried forward as previously dismissed",
            applied.false_positives
        ));
    }
    if applied.accepted_risks > 0 {
        parts.push(format!(
            "{} carried forward as accepted risk",
            applied.accepted_risks
        ));
    }
    if applied.lapsed > 0 {
        parts.push(format!(
            "{} exception(s) have lapsed, so those findings are open again",
            applied.lapsed
        ));
    }
    format!("Exception register applied: {}", parts.join("; "))
}

/// Best-effort description of what a panicking task panicked with.
///
/// `JoinError` prints only "task N panicked"; the message itself lives in the
/// boxed payload, and it is the only clue the analyst gets about which stage
/// broke.
fn panic_detail(join_err: tokio::task::JoinError) -> String {
    if !join_err.is_panic() {
        return join_err.to_string();
    }
    let payload = join_err.into_panic();
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panicked with a non-string payload".to_string()
    }
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
        // The in-memory record was updated but never written through, so a
        // cancelled scan came back from disk as Pending or Running on the next
        // launch — permanently, with no task behind it to ever finish it.
        if let Err(e) = state.store.save_scan_run(run) {
            log_persist_error("cancelled scan run", &e);
        }
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
    app: &tauri::AppHandle,
    run_id: &str,
    stage: &str,
    target: &sentinel_core::models::target::Target,
    config_json: &str,
) -> anyhow::Result<Vec<sentinel_core::models::finding::Finding>> {
    use sentinel_adapters::adapter_trait::ScannerAdapter;
    use sentinel_adapters::auth_gated_runner::AuthGatedDastRunner;

    match stage {
        // Built-in static engines: compiled in, so these never skip.
        "code"           => sentinel_adapters::static_engine::sast::NativeSastAdapter.run(target, config_json).await,
        "dependencies"   => sentinel_adapters::static_engine::sca::NativeScaAdapter.run(target, config_json).await,
        "secrets"        => sentinel_adapters::static_engine::secrets::NativeSecretsAdapter.run(target, config_json).await,
        "infrastructure" => sentinel_adapters::static_engine::iac::NativeIacAdapter.run(target, config_json).await,
        // Not behind the gate: every request it makes goes to a third-party
        // data source, and none to the target.
        "recon"          => sentinel_adapters::recon::ReconAdapter.run(target, config_json).await,
        "semgrep"     => sentinel_adapters::semgrep::SemgrepAdapter.run(target, config_json).await,
        "native"      => {
            use tauri::Emitter;
            let app_handle = app.clone();
            let rid = run_id.to_string();
            let reporter = std::sync::Arc::new(move |msg: &str| {
                let _ = app_handle.emit(EVENT_LOG, ScanLogPayload {
                    scan_run_id: rid.clone(),
                    stage: "native".to_string(),
                    level: "info".into(),
                    message: msg.to_string(),
                    timestamp: Utc::now(),
                });
            });
            AuthGatedDastRunner::new(sentinel_adapters::native::NativeCheckAdapter::with_reporter(reporter))
                .run(target, config_json)
                .await
        }
        "trivy"       => sentinel_adapters::trivy::TrivyAdapter.run(target, config_json).await,
        "gitleaks"    => sentinel_adapters::gitleaks::GitleaksAdapter.run(target, config_json).await,
        "osv"         => sentinel_adapters::external_tools::OsvScannerAdapter.run(target, config_json).await,
        "trufflehog"  => sentinel_adapters::external_tools::TruffleHogAdapter.run(target, config_json).await,
        "retirejs"    => sentinel_adapters::external_tools::RetireJsAdapter.run(target, config_json).await,
        "checkov"     => sentinel_adapters::external_tools::CheckovAdapter.run(target, config_json).await,
        "zap_dast"    => AuthGatedDastRunner::new(sentinel_adapters::zap::ZapDastAdapter).run(target, config_json).await,
        "nuclei_dast" => AuthGatedDastRunner::new(sentinel_adapters::nuclei::NucleiDastAdapter).run(target, config_json).await,
        // Nikto reaches the network, so it goes through the gate like every
        // other engine that does.
        "nikto_dast"  => AuthGatedDastRunner::new(sentinel_adapters::external_tools::NiktoAdapter).run(target, config_json).await,
        "testssl_dast" => AuthGatedDastRunner::new(sentinel_adapters::external_tools::TestSslAdapter).run(target, config_json).await,
        // sqlmap confirms SQL injection by exploiting it, so it reaches the
        // target and is gated like the rest.
        "sqlmap_dast" => AuthGatedDastRunner::new(sentinel_adapters::external_tools::SqlmapAdapter).run(target, config_json).await,
        other => Err(anyhow::anyhow!("Unknown stage: {}", other)),
    }
}

/// Run one stage, bounded by `STAGE_TIMEOUT` so a wedged scanner can never
/// hang the rest of the pipeline.
async fn run_stage_bounded(
    app: &tauri::AppHandle,
    run_id: &str,
    stage_name: &str,
    target: &sentinel_core::models::target::Target,
    config_json: &str,
) -> anyhow::Result<Vec<sentinel_core::models::finding::Finding>> {
    match tokio::time::timeout(STAGE_TIMEOUT, run_stage_for(app, run_id, stage_name, target, config_json)).await {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "{} exceeded the {}-minute stage timeout and was abandoned; \
             the target may be dropping packets or the scanner may be waiting on input",
            engine_label(stage_name),
            STAGE_TIMEOUT.as_secs() / 60
        )),
    }
}

/// Emit the "a stage is starting" event pair the scan console listens for.
fn emit_stage_starting(
    app: &tauri::AppHandle,
    run_id: &str,
    stage_name: &str,
    idx: usize,
    tally: &PipelineTally,
) {
    use tauri::Emitter;
    let _ = app.emit(EVENT_STAGE_UPDATE, ScanStageUpdatePayload {
        scan_run_id: run_id.to_string(),
        stage: stage_name.to_string(),
        state: "running".into(),
        stage_findings: 0,
        total_findings: tally.total_findings,
        critical_high: tally.critical_high,
        timestamp: Utc::now(),
        message: format!("Starting {} scan...", engine_label(stage_name)),
    });

    let _ = app.emit(EVENT_LOG, ScanLogPayload {
        scan_run_id: run_id.to_string(),
        stage: stage_name.to_string(),
        level: "info".into(),
        message: format!(
            "[{}] {}",
            idx + 1,
            if is_builtin(stage_name) {
                format!("Running built-in {}...", engine_label(stage_name))
            } else {
                format!("Invoking user-installed {stage_name} binary...")
            }
        ),
        timestamp: Utc::now(),
    });
}

/// Persist a completed stage's findings and emit its done/skipped/failed
/// event pair. Shared by the parallel static-analysis block and the
/// sequential network-stage loop so both classify and report identically.
#[allow(clippy::too_many_arguments)] // Every argument is a distinct collaborator
                                     // the stage needs; bundling them would only
                                     // move the list somewhere less visible.
async fn process_stage_result(
    app: &tauri::AppHandle,
    store: &crate::store::Store,
    findings: &tokio::sync::RwLock<std::collections::HashMap<String, StoredFinding>>,
    run_id: &str,
    stage_name: &str,
    result: anyhow::Result<Vec<sentinel_core::models::finding::Finding>>,
    tally: &mut PipelineTally,
    register: &sentinel_core::exceptions::ExceptionRegister,
) {
    use tauri::Emitter;

    match result {
        Ok(mut raw_findings) => {
            let stage_finding_count = raw_findings.len();

            // Apply the analyst's standing decisions before anything is counted
            // or stored. This is what makes an exception mean something across
            // scans: the finding is still recorded — the audit trail needs it —
            // but it arrives already carrying the status that was decided, so
            // the report layer suppresses or discloses it correctly and nobody
            // has to triage it a second time.
            let applied = register.apply(&mut raw_findings, Utc::now());
            for f in raw_findings.iter_mut() {
                if let Some(record) = register.covering(f, Utc::now()) {
                    f.description = format!(
                        "{}\n\nExempted: {} on {}, recorded by {}.",
                        f.description,
                        record.kind.label(),
                        record.created_at.format("%Y-%m-%d"),
                        record.raised_by,
                    );
                }
            }

            // The stage completed, so its engine counts as coverage even
            // when it produced nothing — a clean pass is a real result.
            tally.record_stage_findings(stage_name, &raw_findings);

            if applied.total_applied() > 0 || applied.lapsed > 0 {
                let _ = app.emit(EVENT_LOG, ScanLogPayload {
                    scan_run_id: run_id.to_string(),
                    stage: stage_name.to_string(),
                    level: "info".into(),
                    message: exception_summary(&applied),
                    timestamp: Utc::now(),
                });
            }

            // Persist the stage's findings before updating memory, so a
            // crash mid-pipeline still leaves completed stages on disk.
            if let Err(e) = store.save_findings(run_id, &raw_findings) {
                log_persist_error("scan findings", &e);
            }
            {
                let mut store = findings.write().await;
                for f in raw_findings {
                    let triage_note = register
                        .covering(&f, Utc::now())
                        .map(|record| record.triage_note());
                    store.insert(
                        f.id.to_string(),
                        StoredFinding {
                            scan_id: run_id.to_string(),
                            finding: f,
                            triage_note,
                        },
                    );
                }
            }
            let _ = app.emit(EVENT_STAGE_UPDATE, ScanStageUpdatePayload {
                scan_run_id: run_id.to_string(),
                stage: stage_name.to_string(),
                state: "done".into(),
                stage_findings: stage_finding_count,
                total_findings: tally.total_findings,
                critical_high: tally.critical_high,
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
            let is_skip = is_skip_message(&msg);
            let stage_state = if is_skip { "skipped" } else { "failed" };
            tally.stage_summary.push(StageSummary {
                stage: stage_name.to_string(),
                state: stage_state.into(),
                findings: 0,
                error: Some(msg.clone()),
            });
            let _ = app.emit(EVENT_STAGE_UPDATE, ScanStageUpdatePayload {
                scan_run_id: run_id.to_string(),
                stage: stage_name.to_string(),
                state: stage_state.into(),
                stage_findings: 0,
                total_findings: tally.total_findings,
                critical_high: tally.critical_high,
                timestamp: Utc::now(),
                message: msg.clone(),
            });
            let _ = app.emit(EVENT_LOG, ScanLogPayload {
                scan_run_id: run_id.to_string(),
                stage: stage_name.to_string(),
                level: if is_skip { "warn" } else { "error" }.into(),
                message: msg,
                timestamp: Utc::now(),
            });
        }
    }
}

/// Whether a stage error means "this did not run" (missing binary, no repo
/// configured, RoE gate declined it) rather than "this broke".
///
/// Semgrep, Trivy and Gitleaks report a missing `repo_ref` as "requires a
/// repository path". The OSV-Scanner, TruffleHog, retire.js and Checkov
/// adapters use the `repo_path()` helper in external_tools.rs, which emits
/// "analyses source, so it needs a repository path". Both wordings mean the
/// same thing to the analyst — nothing wrong with the tool, just nothing to
/// scan — so both must be treated as a skip, not a failure.
///
/// A `repo_ref` that was configured but points to a path that does not exist
/// is NOT classified as a skip: that is a real misconfiguration the analyst
/// needs to see and fix.
fn is_skip_message(msg: &str) -> bool {
    msg.contains("not found on PATH")
        || msg.contains("not found or unreachable")
        || msg.contains("AUTH GATE BLOCKED")
        // Semgrep / Trivy / Gitleaks wording (from their own adapters)
        || msg.contains("requires a repository path")
        // OSV-Scanner / TruffleHog / retire.js / Checkov wording (from repo_path() helper)
        || msg.contains("needs a repository path")
        || msg.contains("analyses source, so it needs a repository path")
        // Recon: no domain to resolve from the base URL — valid skip
        || msg.contains("no domain to enumerate")
}

/// Engine name as used by the checklist coverage catalog.
fn engine_name(stage: &str) -> &'static str {
    match stage {
        "code" => "Sentinel Code",
        "dependencies" => "Sentinel Dependencies",
        "secrets" => "Sentinel Secrets",
        "infrastructure" => "Sentinel Infrastructure",
        "recon" => "Sentinel Recon",
        "semgrep" => "Semgrep",
        "trivy" => "Trivy",
        "gitleaks" => "Gitleaks",
        "osv" => "OSV-Scanner",
        "trufflehog" => "TruffleHog",
        "retirejs" => "retire.js",
        "checkov" => "Checkov",
        "native" => "Sentinel Native",
        "zap_dast" => "OWASP ZAP",
        "nuclei_dast" => "Nuclei",
        "nikto_dast" => "Nikto",
        "testssl_dast" => "testssl.sh",
        "sqlmap_dast" => "sqlmap",
        _ => "Unknown",
    }
}

/// Whether this stage is compiled into the application rather than shelling
/// out to a binary the analyst had to install.
///
/// Only affects what the console says, but saying "invoking user-installed
/// recon binary" would send somebody looking for a binary that does not
/// exist when a stage reports nothing. Both `recon` and `native` are built-in
/// Rust adapters that ship inside the application.
fn is_builtin(stage: &str) -> bool {
    matches!(stage, "code" | "dependencies" | "secrets" | "infrastructure" | "recon" | "native")
}

/// Human-readable stage label for the scan console.
fn engine_label(stage: &str) -> &'static str {
    match stage {
        "code" => "Sentinel Code analysis",
        "dependencies" => "Sentinel dependency audit",
        "secrets" => "Sentinel secret scan",
        "infrastructure" => "Sentinel infrastructure audit",
        "recon" => "Passive attack-surface discovery",
        "semgrep" => "Semgrep SAST",
        "trivy" => "Trivy dependency audit",
        "gitleaks" => "Gitleaks secret scan",
        "osv" => "OSV-Scanner dependency audit",
        "trufflehog" => "TruffleHog verified secrets",
        "retirejs" => "retire.js client library audit",
        "checkov" => "Checkov infrastructure audit",
        "native" => "Sentinel Native checks",
        "zap_dast" => "OWASP ZAP DAST",
        "nuclei_dast" => "Nuclei DAST",
        "nikto_dast" => "Nikto web server scan",
        "testssl_dast" => "testssl.sh TLS assessment",
        "sqlmap_dast" => "sqlmap SQL injection confirmation",
        _ => "Unknown stage",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The failure this guards: adding a stage to `BASELINE_STAGES` without a
    /// matching arm in `run_stage_for` compiles, ships, and then fails at
    /// runtime with "Unknown stage" — on a real engagement, after the analyst
    /// has already signed the RoE and started the scan.
    #[test]
    fn every_declared_stage_is_one_the_pipeline_can_actually_run() {
        for stage in BASELINE_STAGES.iter().chain(DAST_STAGES) {
            assert_ne!(
                engine_name(stage),
                "Unknown",
                "{stage} is declared but has no engine name; coverage attribution would drop it"
            );
            assert_ne!(
                engine_label(stage),
                "Unknown stage",
                "{stage} is declared but has no console label"
            );
        }
    }

    /// Coverage attribution matches on the engine *name*, so a name here that
    /// does not appear in the catalogue means that engine runs, produces
    /// findings, and still shows as "Not tested" in the coverage matrix — a
    /// report that contradicts itself.
    #[test]
    fn every_engine_name_is_one_the_checklist_catalogue_knows() {
        use sentinel_core::checklist::catalog::WSTG_CATALOG;

        let known: Vec<&str> = WSTG_CATALOG
            .iter()
            .flat_map(|item| item.engines.iter().copied())
            .collect();

        for stage in BASELINE_STAGES.iter().chain(DAST_STAGES) {
            let name = engine_name(stage);
            assert!(
                known.contains(&name),
                "engine '{name}' (stage {stage}) is referenced by no checklist item, so it would \
                 contribute no coverage however many findings it produced"
            );
        }
    }

    /// The concurrent block indexes `stages[..STATIC_STAGES]` by position and
    /// names each one in a `tokio::join!`. If the constant and the list drift,
    /// a network engine gets run concurrently with the others — which would
    /// exceed the request rate the RoE agreed, and that is a safety guarantee
    /// rather than a performance setting.
    #[test]
    fn the_concurrent_block_covers_exactly_the_static_engines() {
        assert!(STATIC_STAGES < BASELINE_STAGES.len(), "the native engine runs sequentially");

        for stage in &BASELINE_STAGES[..STATIC_STAGES] {
            assert!(
                !stage.ends_with("_dast") && *stage != "native",
                "{stage} touches the network and must not run in the concurrent block"
            );
        }
        assert_eq!(
            BASELINE_STAGES[STATIC_STAGES], "native",
            "the sequential remainder must start at the native engine"
        );
    }

    /// The drift this guards, and why it is silent both ways.
    ///
    /// `profiles::ALL_STAGES` decides what a scan profile may switch on — it
    /// backs the engine picker in the UI and the validation in
    /// `save_scan_profile`. This file decides what the pipeline actually runs.
    /// Nothing connects the two, so each direction fails quietly:
    ///
    /// * A stage here but not in `ALL_STAGES` can never be switched off. It is
    ///   absent from the engine list, `save_scan_profile` rejects any profile
    ///   naming it, and it runs on every scan regardless — including the live
    ///   engines, where "cannot be switched off" means traffic the analyst did
    ///   not choose to send.
    /// * A stage in `ALL_STAGES` but not here is offered in the picker, saved
    ///   into a profile, and then silently does nothing. The scan reports
    ///   success and the report says the engine ran, because `enabled_stages`
    ///   only ever filters the list below — a name that is not in it is not a
    ///   missing engine, it is a no-op.
    ///
    /// Both are the kind of failure that surfaces on an engagement rather than
    /// in development, which is why this is an equality check and not a subset.
    #[test]
    fn the_stages_a_profile_can_select_are_exactly_the_stages_the_pipeline_runs() {
        use crate::commands::profiles::ALL_STAGES;

        let mut runnable: Vec<&str> =
            BASELINE_STAGES.iter().chain(DAST_STAGES).copied().collect();
        runnable.sort_unstable();

        let mut selectable: Vec<&str> = ALL_STAGES.to_vec();
        selectable.sort_unstable();

        let unselectable: Vec<&&str> =
            runnable.iter().filter(|s| !selectable.contains(s)).collect();
        assert!(
            unselectable.is_empty(),
            "{unselectable:?} run on every scan but no profile can switch them off \
             — add them to profiles::ALL_STAGES"
        );

        let inert: Vec<&&str> =
            selectable.iter().filter(|s| !runnable.contains(s)).collect();
        assert!(
            inert.is_empty(),
            "{inert:?} can be selected in a profile but the pipeline never runs them \
             — add them to BASELINE_STAGES or DAST_STAGES, or drop them from ALL_STAGES"
        );
    }

    /// `profiles` sorts stages into static and live to decide which ones the
    /// RoE gate applies to. That classification has to agree with this file's,
    /// or a live engine reaches a target under a profile that presented it as
    /// reading local files only.
    #[test]
    fn the_two_files_agree_on_which_stages_touch_the_target() {
        use crate::commands::profiles::{LIVE_STAGES, STATIC_STAGES as PROFILE_STATIC_STAGES};

        for stage in LIVE_STAGES {
            assert!(
                DAST_STAGES.contains(stage) || *stage == "native",
                "{stage} is gated as a live engine by profiles but is not one here"
            );
        }
        for stage in PROFILE_STATIC_STAGES {
            assert!(
                !DAST_STAGES.contains(stage) && *stage != "native",
                "{stage} is presented as a local-only engine but sends traffic to the target"
            );
        }
    }

    #[test]
    fn stage_names_are_unique() {
        let mut all: Vec<&str> = BASELINE_STAGES.iter().chain(DAST_STAGES).copied().collect();
        let before = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(before, all.len(), "a duplicated stage would run twice and double its findings");
    }

    /// A panicking stage takes the whole pipeline task down between its
    /// "starting" and "complete" events. Before the supervisor existed nothing
    /// noticed: no completion event, no error event, the console kept a stage
    /// spinning forever, and the 20s watchdog could not help because events
    /// *had* arrived before the crash.
    #[tokio::test]
    async fn a_panicking_pipeline_is_recorded_as_a_failed_run() {
        use std::collections::HashMap;
        use tokio::sync::RwLock;

        let store = crate::store::Store::in_memory().unwrap();
        let record = ScanRunRecord {
            id: "run-1".into(),
            target_id: "t1".into(),
            status: ScanRunStatus::Running,
            run_dast: false,
            started_at: Utc::now(),
            completed_at: None,
            finding_count: 0,
            engines_executed: Vec::new(),
            error: None,
        };
        store.save_scan_run(&record).unwrap();
        let runs = RwLock::new(HashMap::from([("run-1".to_string(), record)]));

        // Exactly how the supervisor obtains its detail string.
        let handle = tokio::spawn(async { panic!("adapter indexed out of bounds") });
        let join_err = handle.await.expect_err("task must have panicked");
        let reported = mark_run_crashed(&runs, &store, "run-1", panic_detail(join_err)).await;

        assert!(
            reported.contains("adapter indexed out of bounds"),
            "the report does not say what broke: {reported}"
        );

        let stored = runs.read().await;
        let r = stored.get("run-1").unwrap();
        assert_eq!(r.status, ScanRunStatus::Failed);
        assert!(r.completed_at.is_some(), "a crashed run never ended");

        // And it must survive a restart, or the run reappears as Running.
        let reloaded = store.load_all().unwrap();
        let persisted = reloaded.scan_runs.iter().find(|r| r.id == "run-1").unwrap();
        assert_eq!(persisted.status, ScanRunStatus::Failed, "the crash never reached disk");
    }

    /// `JoinError` renders only "task N panicked" — the message the analyst
    /// needs is in the boxed payload, and both panic payload shapes occur.
    #[tokio::test]
    async fn panic_detail_recovers_both_payload_shapes() {
        let literal = tokio::spawn(async { panic!("a static message") })
            .await
            .expect_err("must panic");
        assert_eq!(panic_detail(literal), "a static message");

        let owned = tokio::spawn(async { panic!("{}", format!("stage {} died", 3)) })
            .await
            .expect_err("must panic");
        assert_eq!(panic_detail(owned), "stage 3 died");
    }

    /// Cancellation is `cancel_scan` doing its job and is already recorded by
    /// that command; the supervisor must not overwrite it with a crash report.
    #[tokio::test]
    async fn a_cancelled_task_is_not_a_crash() {
        let handle = tokio::spawn(async {
            futures_sleep().await;
        });
        handle.abort();
        let join_err = handle.await.expect_err("must be cancelled");
        assert!(join_err.is_cancelled(), "abort must surface as cancellation");
        assert!(!join_err.is_panic(), "a cancellation must never look like a panic");
    }

    async fn futures_sleep() {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }

    /// The tally is what the completion event and the console pills report.
    /// Critical and High must accumulate across stages, and nothing below High
    /// may leak into that count.
    #[test]
    fn the_tally_accumulates_totals_and_counts_only_critical_and_high() {
        use sentinel_core::models::finding::Severity;

        let mut tally = PipelineTally::default();
        tally.record_stage_findings(
            "native",
            &[
                finding(Severity::Critical),
                finding(Severity::High),
                finding(Severity::Medium),
                finding(Severity::Low),
                finding(Severity::Info),
            ],
        );
        tally.record_stage_findings("semgrep", &[finding(Severity::High)]);
        // A clean pass still counts as coverage and still gets a summary row.
        tally.record_stage_findings("trivy", &[]);

        assert_eq!(tally.total_findings, 6);
        assert_eq!(tally.critical_high, 3, "Medium/Low/Info must not be counted");
        assert_eq!(
            tally.engines_executed,
            vec!["Sentinel Native", "Semgrep", "Trivy"],
            "a stage that ran clean is still coverage"
        );
        assert_eq!(tally.stage_summary.len(), 3, "every stage needs a summary row");
        assert_eq!(tally.stage_summary[2].findings, 0);
        assert!(tally.stage_summary.iter().all(|s| s.error.is_none()));
    }

    /// Minimal finding at a given severity — only `severity` matters here.
    fn finding(severity: sentinel_core::models::finding::Severity) -> sentinel_core::models::finding::Finding {
        use sentinel_core::models::finding::{Finding, FindingStatus, FindingKind};
        Finding {
            id: uuid::Uuid::new_v4(),
            scan_id: uuid::Uuid::new_v4(),
            target_id: uuid::Uuid::new_v4(),
            title: "t".into(),
            description: "d".into(),
            severity,
            kind: FindingKind::default(),
            cvss4: None,
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.0,
            reachability_score: 1.0,
            priority_score: 1.0,
            cwe_id: None,
            owasp_2025: None,
            wstg_id: None,
            api_top10: None,
            affected_component: "c".into(),
            evidences: vec![],
            repro_steps: vec![],
            remediation: "r".into(),
            references: vec![],
            status: FindingStatus::Open,
            source_tools: vec![],
            ai_triage: None,
            priority_rationale: "p".into(),
            created_at: Utc::now(),
        }
    }

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

    /// A URL-only target — the app's advertised no-setup scanning path — has no
    /// `repo_ref`, so Semgrep, Trivy and Gitleaks all decline with "requires a
    /// repository path", and OSV-Scanner/TruffleHog/retire.js/Checkov decline
    /// with "analyses source, so it needs a repository path". Both are expected
    /// behaviour and must show as a skipped stage rather than a red failure.
    #[test]
    fn missing_repo_ref_is_classified_as_skipped_not_failed() {
        // Semgrep / Trivy / Gitleaks wording
        for msg in [
            "Semgrep SAST requires a repository path. Set 'repo_ref' on the target (e.g. /home/user/repos/acme-portal).",
            "Trivy SCA requires a repository path. Set 'repo_ref' on the target (e.g. /home/user/repos/acme-portal).",
            "Gitleaks requires a repository path. Set 'repo_ref' on the target (e.g. /home/user/repos/acme-portal).",
        ] {
            assert!(is_skip_message(msg), "'{msg}' must be classified as a skip, not a failure");
        }
        // OSV-Scanner / TruffleHog / retire.js / Checkov wording (repo_path() helper)
        for msg in [
            "OSV-Scanner analyses source, so it needs a repository path. Set the target's 'repo_ref' to a local checkout.",
            "TruffleHog analyses source, so it needs a repository path. Set the target's 'repo_ref' to a local checkout.",
            "retire.js analyses source, so it needs a repository path. Set the target's 'repo_ref' to a local checkout.",
            "Checkov analyses source, so it needs a repository path. Set the target's 'repo_ref' to a local checkout.",
        ] {
            assert!(is_skip_message(msg), "'{msg}' (external tool) must be classified as a skip, not a failure");
        }
    }

    /// A `repo_ref` that was actually configured but points at a path that does
    /// not exist is a real misconfiguration, not the expected "nothing to scan"
    /// case above — it must keep surfacing as a failure so the analyst notices.
    #[test]
    fn a_repo_path_that_does_not_exist_still_fails_loudly() {
        assert!(!is_skip_message("Trivy: Repository path not found: /no/such/dir"));
        assert!(!is_skip_message("Gitleaks: Repository path not found: /no/such/dir"));
    }

    #[test]
    fn missing_binary_and_auth_gate_denial_are_still_classified_as_skips() {
        assert!(is_skip_message("semgrep not found on PATH"));
        assert!(is_skip_message("Trivy binary not found or unreachable."));
        assert!(is_skip_message("[AUTH GATE BLOCKED] DAST scan on 'x' refused: no RoE"));
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
