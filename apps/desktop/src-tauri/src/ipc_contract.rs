//! Guards the wire contract between the React frontend and the Tauri commands.
//!
//! `src/types.ts` is written entirely in camelCase, but the Rust structs are
//! snake_case and originally carried no `rename_all`, so every multi-word field
//! failed to cross the boundary — `create_project` rejected the frontend payload
//! with "missing field `company_name`" and the first screen of the app could not
//! be completed.
//!
//! The whole test suite passed while that was broken, because nothing exercised
//! serde at the IPC boundary. These tests use the literal JSON the frontend
//! sends and the literal keys it reads back, so a missing attribute fails here
//! rather than in front of a user.

use crate::commands::auth::CreateRoEInput;
use crate::commands::findings::{FindingFilter, TriageInput};
use crate::commands::projects::{CreateProjectInput, SetProjectLogoInput};
use crate::commands::reports::{ExportReportInput, GenerateReportInput};
use crate::commands::scan::TriggerScanInput;
use crate::commands::targets::CreateTargetInput;
use crate::state::{ProjectRecord, ScanRunRecord, ScanRunStatus, TargetRecord};
use chrono::Utc;
use serde_json::json;

// ── Inbound: payloads the frontend sends ─────────────────────────────────────

#[test]
fn create_project_accepts_the_frontend_payload() {
    // Exactly what ProjectSetupScreen.tsx sends.
    let input: CreateProjectInput = serde_json::from_value(json!({
        "companyName": "Acme Corporation",
        "name": "Q3 Assessment",
        "logoPath": null,
        "primaryColor": "#2563eb",
    }))
    .expect("frontend camelCase payload must deserialize");

    assert_eq!(input.company_name, "Acme Corporation");
    assert_eq!(input.name, "Q3 Assessment");
    assert_eq!(input.primary_color.as_deref(), Some("#2563eb"));
}

#[test]
fn set_project_logo_accepts_the_frontend_payload() {
    // Exactly what ReportBuilderScreen.tsx sends when a logo is uploaded.
    let input: SetProjectLogoInput = serde_json::from_value(json!({
        "projectId": "p-1",
        "logoDataUri": "data:image/png;base64,iVBORw0KGgo=",
    }))
    .expect("frontend camelCase payload must deserialize");

    assert_eq!(input.project_id, "p-1");
    assert!(input.logo_data_uri.unwrap().starts_with("data:image/png"));

    // Removing the logo sends null.
    let cleared: SetProjectLogoInput =
        serde_json::from_value(json!({ "projectId": "p-1", "logoDataUri": null })).unwrap();
    assert!(cleared.logo_data_uri.is_none());
}

#[test]
fn create_target_accepts_the_frontend_payload() {
    let input: CreateTargetInput = serde_json::from_value(json!({
        "projectId": "p-1",
        "name": "Storefront",
        "targetType": "Web App",
        "baseUrl": "https://example.com",
        "repoRef": "/src/app",
        "stackDescription": "Rails 7",
    }))
    .expect("frontend camelCase payload must deserialize");

    assert_eq!(input.project_id, "p-1");
    assert_eq!(input.target_type, "Web App");
    assert_eq!(input.base_url, "https://example.com");
    assert_eq!(input.repo_ref.as_deref(), Some("/src/app"));
    assert_eq!(input.stack_description.as_deref(), Some("Rails 7"));
}

#[test]
fn roe_input_accepts_the_frontend_payload() {
    // The RoE gate is the safety-critical path: if this payload cannot be
    // parsed, no authorization can ever be recorded and DAST stays locked.
    let input: CreateRoEInput = serde_json::from_value(json!({
        "targetId": "t-1",
        "scope": {
            "allowedDomains": ["example.com"],
            "allowedIpsCidrs": ["10.0.0.0/8"],
            "outOfScopePaths": ["/admin"],
            "rateLimitRps": 5,
            "prohibitedActions": ["dos"],
        },
        "acknowledgedBy": "A. Analyst",
        "roeDocumentText": "signed",
    }))
    .expect("frontend camelCase payload must deserialize");

    assert_eq!(input.target_id, "t-1");
    assert_eq!(input.acknowledged_by, "A. Analyst");
    assert_eq!(input.scope.allowed_domains, vec!["example.com"]);
    assert_eq!(input.scope.out_of_scope_paths, vec!["/admin"]);
    assert_eq!(input.scope.rate_limit_rps, 5);
}

#[test]
fn trigger_scan_accepts_the_frontend_payload() {
    let input: TriggerScanInput = serde_json::from_value(json!({
        "targetId": "t-1",
        "runDast": true,
        "configJson": null,
    }))
    .expect("frontend camelCase payload must deserialize");

    assert_eq!(input.target_id, "t-1");
    assert!(input.run_dast);
}

#[test]
fn triage_and_filter_accept_the_frontend_payload() {
    let input: TriageInput = serde_json::from_value(json!({
        "findingId": "f-1",
        "newStatus": "Remediated",
        "triageNote": "patched",
        "analystName": "A. Analyst",
    }))
    .expect("frontend camelCase payload must deserialize");
    assert_eq!(input.finding_id, "f-1");
    assert_eq!(input.new_status, "Remediated");
    assert_eq!(input.analyst_name, "A. Analyst");

    let filter: FindingFilter = serde_json::from_value(json!({
        "targetId": "t-1",
        "scanId": "s-1",
        "owasp2025": "A01",
        "wstgId": "WSTG-INFO-01",
        "sourceTool": "native",
        "minPriority": 4.0,
    }))
    .expect("frontend camelCase payload must deserialize");
    assert_eq!(filter.target_id.as_deref(), Some("t-1"));
    assert_eq!(filter.scan_id.as_deref(), Some("s-1"));
    assert_eq!(filter.owasp_2025.as_deref(), Some("A01"));
    assert_eq!(filter.wstg_id.as_deref(), Some("WSTG-INFO-01"));
    assert_eq!(filter.source_tool.as_deref(), Some("native"));
    assert_eq!(filter.min_priority, Some(4.0));
}

#[test]
fn report_inputs_accept_the_frontend_payload() {
    let input: GenerateReportInput = serde_json::from_value(json!({
        "scanId": "s-1",
        "reportType": "client",
        "companyName": "Acme",
        "targetName": "Storefront",
        "targetUrl": "https://example.com",
        "analyst": "A. Analyst",
        "logoDataUri": null,
    }))
    .expect("frontend camelCase payload must deserialize");
    assert_eq!(input.scan_id, "s-1");
    assert_eq!(input.report_type, "client");
    assert_eq!(input.company_name, "Acme");
    assert_eq!(input.target_name, "Storefront");

    let export: ExportReportInput = serde_json::from_value(json!({
        "reportId": "r-1",
        "exportPath": "/tmp/out.html",
    }))
    .expect("frontend camelCase payload must deserialize");
    assert_eq!(export.report_id, "r-1");
    assert_eq!(export.export_path, "/tmp/out.html");
}

#[test]
fn set_credentials_accepts_the_frontend_payload() {
    use crate::commands::targets::SetCredentialsInput;

    let input: SetCredentialsInput = serde_json::from_value(json!({
        "targetId": "t-1",
        "kind": "basic",
        "username": "admin",
        "secret": "hunter2",
        "headerName": null,
    }))
    .expect("frontend camelCase payload must deserialize");

    assert_eq!(input.target_id, "t-1");
    assert_eq!(input.kind, "basic");
    assert_eq!(input.username.as_deref(), Some("admin"));
    assert_eq!(input.secret, "hunter2");

    // The cookie form omits username entirely.
    let cookie: SetCredentialsInput = serde_json::from_value(json!({
        "targetId": "t-1",
        "kind": "cookie",
        "secret": "session=abc123",
    }))
    .expect("a credential without a username must still deserialize");
    assert_eq!(cookie.kind, "cookie");
    assert!(cookie.username.is_none());
}

#[test]
fn credential_status_never_carries_the_secret_to_the_frontend() {
    use crate::commands::targets::CredentialStatus;

    let status = CredentialStatus {
        configured: true,
        description: Some("HTTP Basic as 'admin'".into()),
    };
    let v = serde_json::to_value(&status).unwrap();
    assert_keys(&v, &["configured", "description"]);

    // The shape must not grow a secret-bearing field by accident.
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 2, "CredentialStatus gained a field: {:?}", obj.keys().collect::<Vec<_>>());
    assert!(!serde_json::to_string(&status).unwrap().contains("hunter2"));
}

// ── Outbound: keys the frontend reads back ───────────────────────────────────

/// Every key the frontend indexes must be present under that exact name.
fn assert_keys(value: &serde_json::Value, expected: &[&str]) {
    let obj = value.as_object().expect("record must serialize to an object");
    for key in expected {
        assert!(
            obj.contains_key(*key),
            "frontend reads `{key}`, but the record serialized as: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }
}

#[test]
fn project_record_serializes_the_keys_the_frontend_reads() {
    let record = ProjectRecord {
        id: "p-1".into(),
        company_name: "Acme".into(),
        logo_path: None,
        logo_data_uri: None,
        primary_color: None,
        name: "Q3".into(),
        created_at: Utc::now(),
    };
    let v = serde_json::to_value(&record).unwrap();
    assert_keys(&v, &["id", "companyName", "logoPath", "primaryColor", "name", "createdAt"]);
    assert_eq!(v["companyName"], "Acme");
}

#[test]
fn target_record_serializes_the_keys_the_frontend_reads() {
    let record = TargetRecord {
        id: "t-1".into(),
        project_id: "p-1".into(),
        name: "Storefront".into(),
        target_type: "Web App".into(),
        base_url: "https://example.com".into(),
        repo_ref: None,
        stack_description: None,
        auth_keychain_handle: None,
        created_at: Utc::now(),
    };
    let v = serde_json::to_value(&record).unwrap();
    assert_keys(
        &v,
        &[
            "id",
            "projectId",
            "name",
            "targetType",
            "baseUrl",
            "repoRef",
            "stackDescription",
            "authKeychainHandle",
            "createdAt",
        ],
    );
}

#[test]
fn scan_run_record_serializes_the_keys_the_frontend_reads() {
    let record = ScanRunRecord {
        id: "s-1".into(),
        target_id: "t-1".into(),
        status: ScanRunStatus::Running,
        run_dast: true,
        started_at: Utc::now(),
        completed_at: None,
        finding_count: 3,
        engines_executed: vec!["native".into()],
        error: None,
    };
    let v = serde_json::to_value(&record).unwrap();
    assert_keys(
        &v,
        &[
            "id",
            "targetId",
            "status",
            "runDast",
            "startedAt",
            "completedAt",
            "findingCount",
            "enginesExecuted",
            "error",
        ],
    );
    // types.ts declares ScanRunStatus as lowercase string literals.
    assert_eq!(v["status"], "running");
}

#[test]
fn coverage_report_serializes_the_keys_the_frontend_reads() {
    let report = sentinel_core::checklist::ChecklistEngine::assess(&[], &[]);
    let v = serde_json::to_value(&report).unwrap();
    assert_keys(
        &v,
        &[
            "results",
            "categories",
            "totalChecks",
            "passed",
            "issuesFound",
            "notTested",
            "manualRequired",
            "enginesExecuted",
            "enginesUnavailable",
            "automatedCoveragePct",
        ],
    );

    let first = &v["results"][0];
    assert_keys(
        first,
        &[
            "id",
            "categoryCode",
            "category",
            "name",
            "clientSummary",
            "coverage",
            "coverageLabel",
            "status",
            "statusLabel",
            "enginesExecuted",
            "enginesMissing",
            "owasp2025",
            "cwe",
            "findingCount",
        ],
    );
}


// ── Outbound: the scan event payloads the console listens for ────────────────
//
// These four events are the entire channel between a running pipeline and the
// scan console. Nothing else in the suite serializes them, so a renamed or
// added field reaches the frontend as `undefined` with no failing test — which
// is how `criticalHigh` came to be rendered as a hardcoded zero and
// `stageSummary`/`durationSeconds` shipped empty on every scan.

#[test]
fn stage_update_payload_serializes_the_keys_the_frontend_reads() {
    use crate::event_bridge::ScanStageUpdatePayload;
    let value = serde_json::to_value(ScanStageUpdatePayload {
        scan_run_id: "run-1".into(),
        stage: "native".into(),
        state: "done".into(),
        stage_findings: 3,
        total_findings: 7,
        critical_high: 2,
        timestamp: Utc::now(),
        message: "Sentinel Native checks complete: 3 findings".into(),
    })
    .unwrap();

    assert_keys(
        &value,
        &[
            "scanRunId",
            "stage",
            "state",
            "stageFindings",
            "totalFindings",
            "criticalHigh",
            "timestamp",
            "message",
        ],
    );
}

#[test]
fn complete_payload_serializes_the_keys_the_frontend_reads() {
    use crate::event_bridge::{ScanCompletePayload, StageSummary};
    let value = serde_json::to_value(ScanCompletePayload {
        scan_run_id: "run-1".into(),
        total_findings: 7,
        critical_high: 2,
        stage_summary: vec![StageSummary {
            stage: "native".into(),
            state: "done".into(),
            findings: 3,
            error: None,
        }],
        duration_seconds: 42,
        completed_at: Utc::now(),
    })
    .unwrap();

    assert_keys(
        &value,
        &[
            "scanRunId",
            "totalFindings",
            "criticalHigh",
            "stageSummary",
            "durationSeconds",
            "completedAt",
        ],
    );
    assert_keys(
        &value["stageSummary"][0],
        &["stage", "state", "findings", "error"],
    );
}

#[test]
fn log_and_error_payloads_serialize_the_keys_the_frontend_reads() {
    use crate::event_bridge::{ScanErrorPayload, ScanLogPayload};

    let log = serde_json::to_value(ScanLogPayload {
        scan_run_id: "run-1".into(),
        stage: "native".into(),
        level: "info".into(),
        message: "probing".into(),
        timestamp: Utc::now(),
    })
    .unwrap();
    assert_keys(&log, &["scanRunId", "stage", "level", "message", "timestamp"]);

    let err = serde_json::to_value(ScanErrorPayload {
        scan_run_id: "run-1".into(),
        error: "boom".into(),
        stage: None,
        timestamp: Utc::now(),
    })
    .unwrap();
    assert_keys(&err, &["scanRunId", "error", "stage", "timestamp"]);
}
