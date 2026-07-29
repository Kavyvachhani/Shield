use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

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
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    pub id: String,
    pub scan_id: String,
    pub target_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub cvss4_score: f32,
    pub epss_score: f32,
    pub kev_listed: bool,
    pub priority_score: f32,
    pub cwe_id: Option<String>,
    pub owasp_2025: Option<String>,
    pub wstg_id: Option<String>,
    pub affected_component: String,
    pub repro_steps: Vec<String>,
    pub remediation: String,
    pub status: String,
    pub source_tools: Vec<String>,
    pub triage_note: Option<String>,
    pub priority_rationale: String,
    pub created_at: DateTime<Utc>,
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
    pub findings: Arc<RwLock<HashMap<String, FindingRecord>>>,
    pub reports: Arc<RwLock<HashMap<String, ReportRecord>>>,
    /// Active scan task handles: scan_run_id → abort handle
    pub active_scans: Arc<RwLock<HashMap<String, tokio::task::AbortHandle>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            projects: Arc::new(RwLock::new(HashMap::new())),
            targets: Arc::new(RwLock::new(HashMap::new())),
            auth_records: Arc::new(RwLock::new(HashMap::new())),
            scan_runs: Arc::new(RwLock::new(HashMap::new())),
            findings: Arc::new(RwLock::new(HashMap::new())),
            reports: Arc::new(RwLock::new(HashMap::new())),
            active_scans: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

pub fn new_id() -> String {
    Uuid::new_v4().to_string()
}
