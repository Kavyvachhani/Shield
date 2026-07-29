pub const MIGRATIONS: &[&str] = &[
    r#"
    CREATE TABLE IF NOT EXISTS companies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        logo_path TEXT,
        created_at TEXT NOT NULL
    );
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY,
        company_id TEXT NOT NULL,
        name TEXT NOT NULL,
        roe_document_hash TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE
    );
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS targets (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        name TEXT NOT NULL,
        target_type TEXT NOT NULL,
        base_url TEXT NOT NULL,
        repo_ref TEXT,
        stack_description TEXT,
        auth_keychain_handle TEXT, -- OS Keyring handle ONLY, NO plaintext secrets
        created_at TEXT NOT NULL,
        FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
    );
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS authorization_records (
        id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL UNIQUE,
        scope_json TEXT NOT NULL,
        acknowledged_by TEXT NOT NULL,
        signed_at TEXT NOT NULL,
        roe_document_hash TEXT NOT NULL,
        digital_signature TEXT NOT NULL,
        FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
    );
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS scan_runs (
        id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        profile_name TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL, -- "Pending", "Running", "Completed", "Failed", "Cancelled"
        stage_logs_json TEXT NOT NULL,
        FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
    );
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        target_id TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss4_json TEXT,
        epss_json TEXT,
        kev_listed INTEGER NOT NULL DEFAULT 0,
        asset_exposure_factor REAL NOT NULL DEFAULT 1.0,
        reachability_score REAL NOT NULL DEFAULT 1.0,
        priority_score REAL NOT NULL,
        cwe_id TEXT,
        owasp_2025 TEXT,
        wstg_id TEXT,
        api_top10 TEXT,
        affected_component TEXT NOT NULL,
        repro_steps_json TEXT NOT NULL,
        remediation TEXT NOT NULL,
        references_json TEXT NOT NULL,
        status TEXT NOT NULL,
        source_tools_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
        FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
    );
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS evidences (
        id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        evidence_type TEXT NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        hash TEXT NOT NULL,
        FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
    );
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS audit_log_entries (
        id TEXT PRIMARY KEY,
        prev_hash TEXT NOT NULL,
        action TEXT NOT NULL,
        target_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        hash TEXT NOT NULL
    );
    "#
];
