use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use sentinel_core::exceptions::ExceptionRecord;
use sentinel_core::models::finding::{Finding as CoreFinding, FindingStatus};

// ── Domain models mirrored for in-process state ──────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRecord {
    pub id: String,
    pub company_name: String,
    pub logo_path: Option<String>,
    /// The client's logo as a base64 `data:image/...` URI, stored inline so the
    /// branding survives a restart and travels with the engagement rather than
    /// depending on a file that may later move or be deleted.
    ///
    /// `default` keeps engagements saved before this field existed loadable.
    #[serde(default)]
    pub logo_data_uri: Option<String>,
    pub primary_color: Option<String>,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetRecord {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub target_type: String,
    pub base_url: String,
    pub repo_ref: Option<String>,
    pub stack_description: Option<String>,
    pub auth_keychain_handle: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeDefinitionRecord {
    pub allowed_domains: Vec<String>,
    pub allowed_ips_cidrs: Vec<String>,
    pub out_of_scope_paths: Vec<String>,
    pub rate_limit_rps: u32,
    pub prohibited_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationRecord {
    pub id: String,
    pub target_id: String,
    pub scope: ScopeDefinitionRecord,
    pub acknowledged_by: String,
    pub signed_at: DateTime<Utc>,
    pub roe_document_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScanRunStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRunRecord {
    pub id: String,
    pub target_id: String,
    pub status: ScanRunStatus,
    pub run_dast: bool,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub finding_count: usize,
    pub engines_executed: Vec<String>,
    pub error: Option<String>,
}

/// UI-facing projection of a finding.
///
/// The authoritative record is the full `sentinel_core` `Finding`, which is what
/// state actually stores — reports need its evidence, references and CVSS vector,
/// and a lossy store would silently degrade the developer report. This struct is
/// only the flattened shape the table view consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingRecord {
    pub id: String,
    pub scan_id: String,
    pub target_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub cvss4_score: f32,
    pub cvss4_vector: Option<String>,
    pub epss_score: f32,
    pub kev_listed: bool,
    pub priority_score: f32,
    pub cwe_id: Option<String>,
    pub owasp_2025: Option<String>,
    pub wstg_id: Option<String>,
    pub api_top10: Option<String>,
    pub affected_component: String,
    pub repro_steps: Vec<String>,
    pub remediation: String,
    pub references: Vec<String>,
    pub evidence_count: usize,
    pub false_positive_confidence: f32,
    pub status: String,
    pub source_tools: Vec<String>,
    pub triage_note: Option<String>,
    pub priority_rationale: String,
    /// Stable identity of this weakness across scans, so the UI can show which
    /// rows are covered by a standing exception.
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
}

/// Build the UI projection from the authoritative core finding.
pub fn to_record(
    f: &CoreFinding,
    scan_id: &str,
    triage_note: Option<String>,
) -> FindingRecord {
    FindingRecord {
        id: f.id.to_string(),
        scan_id: scan_id.to_string(),
        target_id: f.target_id.to_string(),
        title: f.title.clone(),
        description: f.description.clone(),
        severity: format!("{:?}", f.severity),
        cvss4_score: f.cvss4.as_ref().map(|c| c.base_score as f32).unwrap_or(0.0),
        cvss4_vector: f.cvss4.as_ref().map(|c| c.vector_string.clone()).filter(|v| !v.is_empty()),
        epss_score: f.epss.as_ref().map(|e| e.score as f32).unwrap_or(0.0),
        kev_listed: f.kev_listed,
        priority_score: f.priority_score as f32,
        cwe_id: f.cwe_id.clone(),
        owasp_2025: f.owasp_2025.clone(),
        wstg_id: f.wstg_id.clone(),
        api_top10: f.api_top10.clone(),
        affected_component: f.affected_component.clone(),
        repro_steps: f.repro_steps.clone(),
        remediation: f.remediation.clone(),
        references: f.references.clone(),
        evidence_count: f.evidences.len(),
        false_positive_confidence: f
            .ai_triage
            .as_ref()
            .map(|t| t.is_false_positive_confidence as f32)
            .unwrap_or(0.0),
        status: status_label(&f.status).to_string(),
        source_tools: f.source_tools.clone(),
        triage_note,
        priority_rationale: f.priority_rationale.clone(),
        fingerprint: sentinel_core::exceptions::fingerprint(f),
        created_at: f.created_at,
    }
}

pub fn status_label(status: &FindingStatus) -> &'static str {
    match status {
        FindingStatus::Open => "Open",
        FindingStatus::InProgress => "In Progress",
        FindingStatus::Remediated => "Remediated",
        FindingStatus::AcceptedRisk => "Accepted Risk",
        FindingStatus::FalsePositive => "False Positive",
    }
}

pub fn status_from_label(label: &str) -> Option<FindingStatus> {
    Some(match label {
        "Open" => FindingStatus::Open,
        "In Progress" => FindingStatus::InProgress,
        "Remediated" => FindingStatus::Remediated,
        "Accepted Risk" => FindingStatus::AcceptedRisk,
        "False Positive" => FindingStatus::FalsePositive,
        _ => return None,
    })
}

/// A stored finding: the authoritative core record plus per-engagement triage.
#[derive(Debug, Clone)]
pub struct StoredFinding {
    pub scan_id: String,
    pub finding: CoreFinding,
    pub triage_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRecord {
    pub id: String,
    pub scan_id: String,
    pub report_type: String,
    pub company_name: String,
    pub html_content: String,
    pub created_at: DateTime<Utc>,
}

// ── Shared in-memory state (backed by Arc<RwLock>) ───────────────────────────
// In production this wraps sentinel-db; here it provides immediate typed access.

pub struct AppState {
    pub projects: Arc<RwLock<HashMap<String, ProjectRecord>>>,
    pub targets: Arc<RwLock<HashMap<String, TargetRecord>>>,
    pub auth_records: Arc<RwLock<HashMap<String, AuthorizationRecord>>>,
    pub scan_runs: Arc<RwLock<HashMap<String, ScanRunRecord>>>,
    /// Authoritative findings, keyed by finding id.
    pub findings: Arc<RwLock<HashMap<String, StoredFinding>>>,
    /// Engines that genuinely executed, per scan run. Drives coverage reporting,
    /// so a skipped stage must never be recorded here.
    pub scan_engines: Arc<RwLock<HashMap<String, Vec<String>>>>,
    pub reports: Arc<RwLock<HashMap<String, ReportRecord>>>,
    /// The exception register, keyed by exception id.
    ///
    /// Held against the *target* rather than a scan, which is the whole point:
    /// a decision the analyst took on one scan has to still hold on the next
    /// one, where every finding id has changed.
    pub exceptions: Arc<RwLock<HashMap<String, ExceptionRecord>>>,
    /// Active scan task handles: scan_run_id → abort handle
    pub active_scans: Arc<RwLock<HashMap<String, tokio::task::AbortHandle>>>,
    /// Durable storage. Every mutation is written through so an engagement —
    /// above all the signed RoE — survives the app being closed.
    pub store: Arc<crate::store::Store>,
}

impl AppState {
    /// Build state backed by `store`, hydrated with everything already on disk.
    pub fn new(store: crate::store::Store) -> Self {
        let loaded = store.load_all().unwrap_or_else(|e| {
            // A failed load must not stop the app opening; the analyst can still
            // start fresh work, and nothing on disk has been destroyed.
            tracing_warn(&format!("could not load saved engagements: {e}"));
            crate::store::LoadedState::default()
        });

        
        Self {
            projects: Arc::new(RwLock::new(
                loaded.projects.into_iter().map(|p| (p.id.clone(), p)).collect(),
            )),
            targets: Arc::new(RwLock::new(
                loaded.targets.into_iter().map(|t| (t.id.clone(), t)).collect(),
            )),
            auth_records: Arc::new(RwLock::new(loaded.auth_records.into_iter().collect())),
            scan_runs: Arc::new(RwLock::new(
                reconcile_interrupted_scans(loaded.scan_runs, &store)
                    .into_iter()
                    .map(|r| (r.id.clone(), r))
                    .collect(),
            )),
            findings: Arc::new(RwLock::new(loaded.findings.into_iter().collect())),
            scan_engines: Arc::new(RwLock::new(loaded.scan_engines.into_iter().collect())),
            reports: Arc::new(RwLock::new(
                loaded.reports.into_iter().map(|r| (r.id.clone(), r)).collect(),
            )),
            exceptions: Arc::new(RwLock::new(
                loaded.exceptions.into_iter().map(|e| (e.id.clone(), e)).collect(),
            )),
            active_scans: Arc::new(RwLock::new(HashMap::new())),
            store: Arc::new(store),
        }
    }
}

/// Close out scan runs that were still open when the app last exited.
///
/// A scan's status is written as `Running` when its pipeline starts and
/// rewritten when it finishes. If the app is closed — or crashes — mid-scan,
/// that second write never happens, so the run is reloaded as `Running` on the
/// next launch with no task behind it. It then stays that way forever: nothing
/// ever completes it, and the engagement shows a scan permanently in progress.
///
/// There is no way to resume such a run, so record it honestly as failed and
/// say why, rather than leaving a permanent phantom in the engagement.
fn reconcile_interrupted_scans(
    runs: Vec<ScanRunRecord>,
    store: &crate::store::Store,
) -> Vec<ScanRunRecord> {
    runs.into_iter()
        .map(|mut r| {
            if !matches!(r.status, ScanRunStatus::Pending | ScanRunStatus::Running) {
                return r;
            }
            r.status = ScanRunStatus::Failed;
            r.completed_at = Some(Utc::now());
            r.error = Some(
                "Interrupted — SentinelVAPT closed while this scan was running. \
                 Findings from stages that completed before the exit were saved; \
                 re-run the scan to finish the remaining stages."
                    .to_string(),
            );
            if let Err(e) = store.save_scan_run(&r) {
                log_persist_error("interrupted scan run", &e);
            }
            r
        })
        .collect()
}

/// A write failure must never lose the analyst's work silently, but it also must
/// not crash the app mid-engagement — surface it and carry on in memory.
pub fn log_persist_error(what: &str, e: &anyhow::Error) {
    eprintln!("[SentinelVAPT] failed to persist {what}: {e:#}");
}

fn tracing_warn(msg: &str) {
    eprintln!("[SentinelVAPT] {msg}");
}

pub fn new_id() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod reconcile_tests {
    use super::*;

    fn run(id: &str, status: ScanRunStatus) -> ScanRunRecord {
        ScanRunRecord {
            id: id.into(),
            target_id: "t1".into(),
            status,
            run_dast: false,
            started_at: Utc::now(),
            completed_at: None,
            finding_count: 0,
            engines_executed: Vec::new(),
            error: None,
        }
    }

    /// A scan that was in flight when the app closed has no task behind it on
    /// the next launch, so leaving it `Running` leaves a phantom scan in the
    /// engagement that can never finish.
    #[test]
    fn an_in_flight_scan_is_closed_out_on_the_next_launch() {
        let store = crate::store::Store::in_memory().unwrap();
        let out = reconcile_interrupted_scans(
            vec![run("a", ScanRunStatus::Running), run("b", ScanRunStatus::Pending)],
            &store,
        );

        for r in &out {
            assert_eq!(r.status, ScanRunStatus::Failed, "run {} still open", r.id);
            assert!(r.completed_at.is_some(), "run {} has no end time", r.id);
            assert!(
                r.error.as_deref().unwrap_or_default().contains("Interrupted"),
                "run {} does not say why it ended: {:?}",
                r.id,
                r.error
            );
        }
    }

    /// Reconciliation must be a write-through, or the same phantom reappears
    /// on every subsequent launch.
    #[test]
    fn the_closed_out_status_is_persisted_not_just_patched_in_memory() {
        let store = crate::store::Store::in_memory().unwrap();
        store.save_scan_run(&run("a", ScanRunStatus::Running)).unwrap();

        let _ = reconcile_interrupted_scans(vec![run("a", ScanRunStatus::Running)], &store);

        let reloaded = store.load_all().unwrap();
        let a = reloaded.scan_runs.iter().find(|r| r.id == "a").expect("run a");
        assert_eq!(a.status, ScanRunStatus::Failed, "the fix did not reach disk");
    }

    /// Finished runs are history and must be left exactly as they are.
    #[test]
    fn settled_runs_are_left_untouched() {
        let store = crate::store::Store::in_memory().unwrap();
        let out = reconcile_interrupted_scans(
            vec![
                run("done", ScanRunStatus::Completed),
                run("failed", ScanRunStatus::Failed),
                run("cancelled", ScanRunStatus::Cancelled),
            ],
            &store,
        );
        assert_eq!(out[0].status, ScanRunStatus::Completed);
        assert_eq!(out[1].status, ScanRunStatus::Failed);
        assert_eq!(out[2].status, ScanRunStatus::Cancelled);
        assert!(out.iter().all(|r| r.error.is_none()), "history was rewritten");
    }
}
