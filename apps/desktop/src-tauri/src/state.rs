use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use sentinel_core::models::finding::{Finding as CoreFinding, FindingStatus};

// ── Domain models mirrored for in-process state ──────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub id: String,
    pub company_name: String,
    pub logo_path: Option<String>,
    pub primary_color: Option<String>,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct ScopeDefinitionRecord {
    pub allowed_domains: Vec<String>,
    pub allowed_ips_cidrs: Vec<String>,
    pub out_of_scope_paths: Vec<String>,
    pub rate_limit_rps: u32,
    pub prohibited_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

        let state = Self {
            projects: Arc::new(RwLock::new(
                loaded.projects.into_iter().map(|p| (p.id.clone(), p)).collect(),
            )),
            targets: Arc::new(RwLock::new(
                loaded.targets.into_iter().map(|t| (t.id.clone(), t)).collect(),
            )),
            auth_records: Arc::new(RwLock::new(loaded.auth_records.into_iter().collect())),
            scan_runs: Arc::new(RwLock::new(
                loaded.scan_runs.into_iter().map(|r| (r.id.clone(), r)).collect(),
            )),
            findings: Arc::new(RwLock::new(loaded.findings.into_iter().collect())),
            scan_engines: Arc::new(RwLock::new(loaded.scan_engines.into_iter().collect())),
            reports: Arc::new(RwLock::new(
                loaded.reports.into_iter().map(|r| (r.id.clone(), r)).collect(),
            )),
            active_scans: Arc::new(RwLock::new(HashMap::new())),
            store: Arc::new(store),
        };
        state
    }
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
