//! Durable storage for an engagement.
//!
//! Everything the analyst does — projects, targets, the signed Rules of
//! Engagement, scan runs, findings and generated reports — is written to a local
//! SQLite database as it happens, and reloaded on the next launch.
//!
//! The signed RoE in particular is the record proving testing was authorised, so
//! losing it on app exit is not acceptable.
//!
//! Design: reads are served from the in-memory `AppState` maps (fast, no async
//! SQL on hot paths); every mutation is written through to SQLite immediately.
//! Each row keeps its full record as JSON alongside indexed columns, so the
//! schema tolerates record changes without a migration for every field.

use crate::state::{
    AuthorizationRecord, ProjectRecord, ReportRecord, ScanRunRecord, StoredFinding, TargetRecord,
};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use sentinel_core::models::finding::Finding;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS projects (
    id           TEXT PRIMARY KEY,
    company_name TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    json         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id         TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    base_url   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    json       TEXT NOT NULL
);

-- One signed authorisation per target; re-signing replaces it.
CREATE TABLE IF NOT EXISTS auth_records (
    target_id         TEXT PRIMARY KEY,
    roe_document_hash TEXT NOT NULL,
    signed_at         TEXT NOT NULL,
    json              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id         TEXT PRIMARY KEY,
    target_id  TEXT NOT NULL,
    status     TEXT NOT NULL,
    started_at TEXT NOT NULL,
    json       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_engines (
    scan_id TEXT NOT NULL,
    engine  TEXT NOT NULL,
    PRIMARY KEY (scan_id, engine)
);

CREATE TABLE IF NOT EXISTS findings (
    id             TEXT PRIMARY KEY,
    scan_id        TEXT NOT NULL,
    target_id      TEXT NOT NULL,
    severity       TEXT NOT NULL,
    priority_score REAL NOT NULL,
    triage_note    TEXT,
    json           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL,
    report_type TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    json        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan   ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id);
CREATE INDEX IF NOT EXISTS idx_reports_scan    ON reports(scan_id);
"#;

/// Everything loaded from disk at startup.
#[derive(Debug, Default)]
pub struct LoadedState {
    pub projects: Vec<ProjectRecord>,
    pub targets: Vec<TargetRecord>,
    pub auth_records: Vec<(String, AuthorizationRecord)>,
    pub scan_runs: Vec<ScanRunRecord>,
    pub scan_engines: Vec<(String, Vec<String>)>,
    pub findings: Vec<(String, StoredFinding)>,
    pub reports: Vec<ReportRecord>,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Open (creating if needed) the engagement database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create data directory {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("could not open database {}", path.display()))?;
        conn.execute_batch(SCHEMA).context("could not apply the database schema")?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// An in-memory database, for tests.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Default database location per platform:
    ///   Windows  %APPDATA%\SentinelVAPT\engagements.db
    ///   macOS    ~/Library/Application Support/SentinelVAPT/engagements.db
    ///   Linux    ~/.local/share/SentinelVAPT/engagements.db
    pub fn default_path() -> PathBuf {
        let base = if cfg!(windows) {
            std::env::var_os("APPDATA").map(PathBuf::from)
        } else if cfg!(target_os = "macos") {
            std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
        } else {
            std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        };
        base.unwrap_or_else(std::env::temp_dir)
            .join("SentinelVAPT")
            .join("engagements.db")
    }

    // ── Writes ───────────────────────────────────────────────────────────────

    pub fn save_project(&self, r: &ProjectRecord) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO projects (id, company_name, created_at, json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET company_name=excluded.company_name, json=excluded.json",
            params![r.id, r.company_name, r.created_at.to_rfc3339(), serde_json::to_string(r)?],
        )?;
        Ok(())
    }

    pub fn save_target(&self, r: &TargetRecord) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO targets (id, project_id, base_url, created_at, json) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET base_url=excluded.base_url, json=excluded.json",
            params![r.id, r.project_id, r.base_url, r.created_at.to_rfc3339(), serde_json::to_string(r)?],
        )?;
        Ok(())
    }

    pub fn save_auth_record(&self, target_id: &str, r: &AuthorizationRecord) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO auth_records (target_id, roe_document_hash, signed_at, json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(target_id) DO UPDATE SET roe_document_hash=excluded.roe_document_hash,
               signed_at=excluded.signed_at, json=excluded.json",
            params![target_id, r.roe_document_hash, r.signed_at.to_rfc3339(), serde_json::to_string(r)?],
        )?;
        Ok(())
    }

    pub fn save_scan_run(&self, r: &ScanRunRecord) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO scan_runs (id, target_id, status, started_at, json) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET status=excluded.status, json=excluded.json",
            params![
                r.id,
                r.target_id,
                format!("{:?}", r.status),
                r.started_at.to_rfc3339(),
                serde_json::to_string(r)?
            ],
        )?;
        Ok(())
    }

    pub fn save_scan_engines(&self, scan_id: &str, engines: &[String]) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM scan_engines WHERE scan_id = ?1", params![scan_id])?;
        for engine in engines {
            tx.execute(
                "INSERT OR IGNORE INTO scan_engines (scan_id, engine) VALUES (?1, ?2)",
                params![scan_id, engine],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Persist a batch of findings in one transaction — a scan stage can produce
    /// hundreds, and a per-row commit would be needlessly slow.
    pub fn save_findings(&self, scan_id: &str, findings: &[Finding]) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        for f in findings {
            tx.execute(
                "INSERT INTO findings (id, scan_id, target_id, severity, priority_score, triage_note, json)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)
                 ON CONFLICT(id) DO UPDATE SET json=excluded.json",
                params![
                    f.id.to_string(),
                    scan_id,
                    f.target_id.to_string(),
                    format!("{:?}", f.severity),
                    f.priority_score,
                    serde_json::to_string(f)?
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Update one finding after triage.
    pub fn save_finding(&self, id: &str, stored: &StoredFinding) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO findings (id, scan_id, target_id, severity, priority_score, triage_note, json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET triage_note=excluded.triage_note, json=excluded.json",
            params![
                id,
                stored.scan_id,
                stored.finding.target_id.to_string(),
                format!("{:?}", stored.finding.severity),
                stored.finding.priority_score,
                stored.triage_note,
                serde_json::to_string(&stored.finding)?
            ],
        )?;
        Ok(())
    }

    pub fn save_report(&self, r: &ReportRecord) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO reports (id, scan_id, report_type, created_at, json) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET json=excluded.json",
            params![r.id, r.scan_id, r.report_type, r.created_at.to_rfc3339(), serde_json::to_string(r)?],
        )?;
        Ok(())
    }

    // ── Read-back ────────────────────────────────────────────────────────────

    /// Load the entire engagement history.
    ///
    /// A row that fails to deserialise (written by an older build with an
    /// incompatible shape) is skipped rather than aborting startup — losing one
    /// stale record is far better than an app that will not open.
    pub fn load_all(&self) -> Result<LoadedState> {
        let conn = self.lock()?;
        let mut out = LoadedState {
            projects: query_json(&conn, "SELECT json FROM projects")?,
            targets: query_json(&conn, "SELECT json FROM targets")?,
            scan_runs: query_json(&conn, "SELECT json FROM scan_runs")?,
            reports: query_json(&conn, "SELECT json FROM reports")?,
            ..Default::default()
        };

        {
            let mut stmt = conn.prepare("SELECT target_id, json FROM auth_records")?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
            for row in rows.flatten() {
                if let Ok(rec) = serde_json::from_str::<AuthorizationRecord>(&row.1) {
                    out.auth_records.push((row.0, rec));
                }
            }
        }

        {
            let mut stmt = conn.prepare(
                "SELECT scan_id, engine FROM scan_engines ORDER BY scan_id, engine",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
            let mut current: Option<(String, Vec<String>)> = None;
            for (scan_id, engine) in rows.flatten() {
                match &mut current {
                    Some((id, list)) if *id == scan_id => list.push(engine),
                    _ => {
                        if let Some(done) = current.take() {
                            out.scan_engines.push(done);
                        }
                        current = Some((scan_id, vec![engine]));
                    }
                }
            }
            if let Some(done) = current {
                out.scan_engines.push(done);
            }
        }

        {
            let mut stmt = conn.prepare("SELECT id, scan_id, triage_note, json FROM findings")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            for (id, scan_id, triage_note, json) in rows.flatten() {
                if let Ok(finding) = serde_json::from_str::<Finding>(&json) {
                    out.findings.push((id, StoredFinding { scan_id, finding, triage_note }));
                }
            }
        }

        Ok(out)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("the engagement database lock was poisoned"))
    }
}

fn query_json<T: serde::de::DeserializeOwned>(conn: &Connection, sql: &str) -> Result<Vec<T>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows
        .flatten()
        .filter_map(|json| serde_json::from_str::<T>(&json).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ScanRunStatus, ScopeDefinitionRecord};
    use chrono::Utc;
    use sentinel_core::models::finding::{FindingStatus, Severity};
    use uuid::Uuid;

    fn project() -> ProjectRecord {
        ProjectRecord {
            id: "p1".into(),
            company_name: "Acme Corp".into(),
            logo_path: None,
            logo_data_uri: None,
            primary_color: None,
            name: "Q3 assessment".into(),
            created_at: Utc::now(),
        }
    }

    fn target() -> TargetRecord {
        TargetRecord {
            id: "t1".into(),
            project_id: "p1".into(),
            name: "Portal".into(),
            target_type: "Web App".into(),
            base_url: "https://portal.acme.test".into(),
            repo_ref: None,
            stack_description: None,
            auth_keychain_handle: None,
            created_at: Utc::now(),
        }
    }

    fn auth() -> AuthorizationRecord {
        AuthorizationRecord {
            id: "a1".into(),
            target_id: "t1".into(),
            scope: ScopeDefinitionRecord {
                allowed_domains: vec!["portal.acme.test".into()],
                allowed_ips_cidrs: vec![],
                out_of_scope_paths: vec!["/admin/shutdown".into()],
                rate_limit_rps: 5,
                prohibited_actions: vec!["DoS".into()],
            },
            acknowledged_by: "Security Lead".into(),
            signed_at: Utc::now(),
            roe_document_hash: "deadbeef".into(),
        }
    }

    fn finding(title: &str, score: f64) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            title: title.into(),
            description: "d".into(),
            severity: Severity::High,
            cvss4: None,
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.0,
            reachability_score: 1.0,
            priority_score: score,
            cwe_id: Some("CWE-79".into()),
            owasp_2025: None,
            wstg_id: None,
            api_top10: None,
            affected_component: "https://portal.acme.test/x".into(),
            evidences: vec![],
            repro_steps: vec!["step".into()],
            remediation: "fix".into(),
            references: vec!["https://owasp.org".into()],
            status: FindingStatus::Open,
            source_tools: vec!["Sentinel Native".into()],
            ai_triage: None,
            priority_rationale: "because".into(),
            created_at: Utc::now(),
        }
    }

    fn scan_run() -> ScanRunRecord {
        ScanRunRecord {
            id: "s1".into(),
            target_id: "t1".into(),
            status: ScanRunStatus::Completed,
            run_dast: true,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            finding_count: 2,
            engines_executed: vec!["Sentinel Native".into()],
            error: None,
        }
    }

    #[test]
    fn an_engagement_survives_a_restart() {
        let store = Store::in_memory().unwrap();
        store.save_project(&project()).unwrap();
        store.save_target(&target()).unwrap();
        store.save_auth_record("t1", &auth()).unwrap();
        store.save_scan_run(&scan_run()).unwrap();
        store.save_scan_engines("s1", &["Sentinel Native".into(), "Semgrep".into()]).unwrap();
        store.save_findings("s1", &[finding("XSS", 8.0), finding("SQLi", 9.0)]).unwrap();

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.projects.len(), 1);
        assert_eq!(loaded.projects[0].company_name, "Acme Corp");
        assert_eq!(loaded.targets.len(), 1);
        assert_eq!(loaded.scan_runs.len(), 1);
        assert_eq!(loaded.findings.len(), 2);
    }

    #[test]
    fn the_signed_authorisation_survives_verbatim() {
        // This record is the evidence that testing was authorised; every field
        // must come back exactly as signed.
        let store = Store::in_memory().unwrap();
        let original = auth();
        store.save_auth_record("t1", &original).unwrap();

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.auth_records.len(), 1);
        let (target_id, restored) = &loaded.auth_records[0];
        assert_eq!(target_id, "t1");
        assert_eq!(restored.roe_document_hash, original.roe_document_hash);
        assert_eq!(restored.acknowledged_by, original.acknowledged_by);
        assert_eq!(restored.scope.allowed_domains, original.scope.allowed_domains);
        assert_eq!(restored.scope.out_of_scope_paths, original.scope.out_of_scope_paths);
        assert_eq!(restored.scope.rate_limit_rps, original.scope.rate_limit_rps);
    }

    #[test]
    fn findings_keep_their_evidence_and_taxonomy() {
        let store = Store::in_memory().unwrap();
        let mut f = finding("XSS", 8.0);
        f.evidences = vec![sentinel_core::models::finding::Evidence {
            evidence_type: "http_response".into(),
            title: "Headers".into(),
            content: "HTTP/1.1 200 OK".into(),
            hash: "abc".into(),
        }];
        store.save_findings("s1", &[f.clone()]).unwrap();

        let loaded = store.load_all().unwrap();
        let (_, stored) = &loaded.findings[0];
        assert_eq!(stored.finding.evidences.len(), 1);
        assert_eq!(stored.finding.cwe_id.as_deref(), Some("CWE-79"));
        assert_eq!(stored.finding.references.len(), 1);
        assert_eq!(stored.finding.repro_steps.len(), 1);
    }

    #[test]
    fn triage_notes_and_status_are_persisted() {
        let store = Store::in_memory().unwrap();
        let f = finding("XSS", 8.0);
        let id = f.id.to_string();
        store.save_findings("s1", std::slice::from_ref(&f)).unwrap();

        let mut updated = f;
        updated.status = FindingStatus::Remediated;
        store
            .save_finding(
                &id,
                &StoredFinding {
                    scan_id: "s1".into(),
                    finding: updated,
                    triage_note: Some("[2026-08-14] analyst → Remediated: patched".into()),
                },
            )
            .unwrap();

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.findings.len(), 1, "triage must update, not duplicate");
        let (_, stored) = &loaded.findings[0];
        assert_eq!(stored.finding.status, FindingStatus::Remediated);
        assert!(stored.triage_note.as_deref().unwrap().contains("patched"));
    }

    #[test]
    fn engines_executed_survive_so_coverage_stays_honest() {
        let store = Store::in_memory().unwrap();
        store.save_scan_engines("s1", &["Sentinel Native".into(), "Semgrep".into()]).unwrap();
        store.save_scan_engines("s2", &["Nuclei".into()]).unwrap();

        let loaded = store.load_all().unwrap();
        let map: std::collections::HashMap<_, _> = loaded.scan_engines.into_iter().collect();
        assert_eq!(map["s1"], vec!["Semgrep".to_string(), "Sentinel Native".to_string()]);
        assert_eq!(map["s2"], vec!["Nuclei".to_string()]);
    }

    #[test]
    fn re_signing_replaces_rather_than_duplicates() {
        let store = Store::in_memory().unwrap();
        store.save_auth_record("t1", &auth()).unwrap();
        let mut second = auth();
        second.roe_document_hash = "newhash".into();
        store.save_auth_record("t1", &second).unwrap();

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.auth_records.len(), 1);
        assert_eq!(loaded.auth_records[0].1.roe_document_hash, "newhash");
    }

    #[test]
    fn saving_the_same_record_twice_is_idempotent() {
        let store = Store::in_memory().unwrap();
        store.save_project(&project()).unwrap();
        store.save_project(&project()).unwrap();
        assert_eq!(store.load_all().unwrap().projects.len(), 1);
    }

    #[test]
    fn a_corrupt_row_is_skipped_rather_than_blocking_startup() {
        let store = Store::in_memory().unwrap();
        store.save_project(&project()).unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO projects (id, company_name, created_at, json) VALUES ('bad','x','2026-01-01','{not json')",
                [],
            )
            .unwrap();
        }
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.projects.len(), 1, "the valid project must still load");
    }

    #[test]
    fn a_real_file_round_trips_across_reopen() {
        let dir = std::env::temp_dir().join(format!("sentinel-store-test-{}", Uuid::new_v4()));
        let path = dir.join("engagements.db");

        {
            let store = Store::open(&path).unwrap();
            store.save_project(&project()).unwrap();
            store.save_auth_record("t1", &auth()).unwrap();
        }
        // Dropped and reopened, exactly as an app restart would.
        {
            let store = Store::open(&path).unwrap();
            let loaded = store.load_all().unwrap();
            assert_eq!(loaded.projects.len(), 1);
            assert_eq!(loaded.auth_records.len(), 1);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_default_path_is_absolute_and_app_scoped() {
        let path = Store::default_path();
        assert!(path.is_absolute(), "got {path:?}");
        assert!(path.to_string_lossy().contains("SentinelVAPT"));
        assert!(path.ends_with("engagements.db"));
    }
}
