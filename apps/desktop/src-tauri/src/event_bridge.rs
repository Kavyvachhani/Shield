//! Tauri event bridge — converts ScanOrchestrator mpsc progress events
//! into typed Tauri window events the React frontend can listen to.
//!
//! Event names (all prefixed `sentinel://`):
//!   sentinel://scan/stage-update   → ScanStageUpdatePayload
//!   sentinel://scan/log            → ScanLogPayload  
//!   sentinel://scan/complete       → ScanCompletePayload
//!   sentinel://scan/error          → ScanErrorPayload

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Emitted every time a scan stage transitions or produces findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStageUpdatePayload {
    pub scan_run_id: String,
    pub stage: String,           // "semgrep" | "trivy" | "gitleaks" | "zap_dast" | "nuclei_dast"
    pub state: String,           // "pending" | "running" | "done" | "skipped" | "failed"
    pub stage_findings: usize,   // findings from this stage only
    pub total_findings: usize,   // cumulative total across all stages so far
    pub timestamp: DateTime<Utc>,
    pub message: String,
}

/// Individual log line from a running stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanLogPayload {
    pub scan_run_id: String,
    pub stage: String,
    pub level: String,    // "info" | "warn" | "error"
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

/// Emitted once when the full pipeline finishes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCompletePayload {
    pub scan_run_id: String,
    pub total_findings: usize,
    pub stage_summary: Vec<StageSummary>,
    pub duration_seconds: u64,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StageSummary {
    pub stage: String,
    pub state: String,
    pub findings: usize,
    pub error: Option<String>,
}

/// Emitted if the pipeline encounters a fatal error (e.g., auth gate block).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanErrorPayload {
    pub scan_run_id: String,
    pub error: String,
    pub stage: Option<String>,
    pub timestamp: DateTime<Utc>,
}

pub const EVENT_STAGE_UPDATE: &str = "sentinel://scan/stage-update";
pub const EVENT_LOG: &str = "sentinel://scan/log";
pub const EVENT_COMPLETE: &str = "sentinel://scan/complete";
pub const EVENT_ERROR: &str = "sentinel://scan/error";
