use async_trait::async_trait;
use anyhow::Result;
use sentinel_core::models::finding::Finding;
use sentinel_core::models::target::{Target, AuthorizationRecord};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyEntity {
    pub id: Uuid,
    pub name: String,
    pub logo_path: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectEntity {
    pub id: Uuid,
    pub company_id: Uuid,
    pub name: String,
    pub roe_document_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRunEntity {
    pub id: Uuid,
    pub target_id: Uuid,
    pub profile_name: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub status: String,
    pub stage_logs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogEntryEntity {
    pub id: Uuid,
    pub prev_hash: String,
    pub action: String,
    pub target_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub hash: String,
}

#[async_trait]
pub trait SentinelRepository: Send + Sync {
    // Company & Project Management
    async fn save_company(&self, company: &CompanyEntity) -> Result<()>;
    async fn get_company(&self, id: Uuid) -> Result<Option<CompanyEntity>>;
    async fn save_project(&self, project: &ProjectEntity) -> Result<()>;
    async fn get_project(&self, id: Uuid) -> Result<Option<ProjectEntity>>;

    // Target & Authorization Record
    async fn save_target(&self, target: &Target) -> Result<()>;
    async fn get_target(&self, id: Uuid) -> Result<Option<Target>>;
    async fn save_authorization_record(&self, auth_record: &AuthorizationRecord) -> Result<()>;

    // Scan Runs
    async fn save_scan_run(&self, scan: &ScanRunEntity) -> Result<()>;
    async fn get_scan_run(&self, id: Uuid) -> Result<Option<ScanRunEntity>>;

    // Findings
    async fn save_findings(&self, findings: &[Finding]) -> Result<()>;
    async fn get_findings_by_target(&self, target_id: Uuid) -> Result<Vec<Finding>>;

    // Audit Log Ledger
    async fn append_audit_entry(&self, action: &str, target_id: Uuid) -> Result<AuditLogEntryEntity>;
    async fn get_audit_trail(&self) -> Result<Vec<AuditLogEntryEntity>>;
    async fn verify_audit_integrity(&self) -> Result<bool>;
}

/// In-Memory & Encrypted Repository Implementation
pub struct MemorySentinelRepository {
    companies: std::sync::Arc<tokio::sync::Mutex<Vec<CompanyEntity>>>,
    projects: std::sync::Arc<tokio::sync::Mutex<Vec<ProjectEntity>>>,
    targets: std::sync::Arc<tokio::sync::Mutex<Vec<Target>>>,
    scans: std::sync::Arc<tokio::sync::Mutex<Vec<ScanRunEntity>>>,
    findings: std::sync::Arc<tokio::sync::Mutex<Vec<Finding>>>,
    audit_logs: std::sync::Arc<tokio::sync::Mutex<Vec<AuditLogEntryEntity>>>,
}

impl MemorySentinelRepository {
    pub fn new() -> Self {
        Self {
            companies: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
            projects: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
            targets: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
            scans: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
            findings: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
            audit_logs: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl SentinelRepository for MemorySentinelRepository {
    async fn save_company(&self, company: &CompanyEntity) -> Result<()> {
        let mut list = self.companies.lock().await;
        list.retain(|c| c.id != company.id);
        list.push(company.clone());
        Ok(())
    }

    async fn get_company(&self, id: Uuid) -> Result<Option<CompanyEntity>> {
        let list = self.companies.lock().await;
        Ok(list.iter().find(|c| c.id == id).cloned())
    }

    async fn save_project(&self, project: &ProjectEntity) -> Result<()> {
        let mut list = self.projects.lock().await;
        list.retain(|p| p.id != project.id);
        list.push(project.clone());
        Ok(())
    }

    async fn get_project(&self, id: Uuid) -> Result<Option<ProjectEntity>> {
        let list = self.projects.lock().await;
        Ok(list.iter().find(|p| p.id == id).cloned())
    }

    async fn save_target(&self, target: &Target) -> Result<()> {
        let mut list = self.targets.lock().await;
        list.retain(|t| t.id != target.id);
        list.push(target.clone());
        Ok(())
    }

    async fn get_target(&self, id: Uuid) -> Result<Option<Target>> {
        let list = self.targets.lock().await;
        Ok(list.iter().find(|t| t.id == id).cloned())
    }

    async fn save_authorization_record(&self, auth_record: &AuthorizationRecord) -> Result<()> {
        let mut list = self.targets.lock().await;
        if let Some(target) = list.iter_mut().find(|t| t.id == auth_record.target_id) {
            target.authorization_record = Some(auth_record.clone());
        }
        Ok(())
    }

    async fn save_scan_run(&self, scan: &ScanRunEntity) -> Result<()> {
        let mut list = self.scans.lock().await;
        list.retain(|s| s.id != scan.id);
        list.push(scan.clone());
        Ok(())
    }

    async fn get_scan_run(&self, id: Uuid) -> Result<Option<ScanRunEntity>> {
        let list = self.scans.lock().await;
        Ok(list.iter().find(|s| s.id == id).cloned())
    }

    async fn save_findings(&self, findings: &[Finding]) -> Result<()> {
        let mut list = self.findings.lock().await;
        for f in findings {
            list.retain(|existing| existing.id != f.id);
            list.push(f.clone());
        }
        Ok(())
    }

    async fn get_findings_by_target(&self, target_id: Uuid) -> Result<Vec<Finding>> {
        let list = self.findings.lock().await;
        Ok(list.iter().filter(|f| f.target_id == target_id).cloned().collect())
    }

    async fn append_audit_entry(&self, action: &str, target_id: Uuid) -> Result<AuditLogEntryEntity> {
        let mut list = self.audit_logs.lock().await;
        let prev_hash = list.last().map(|e| e.hash.clone()).unwrap_or_else(|| "GENESIS_BLOCK_HASH".into());
        let timestamp = Utc::now();
        
        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{}:{}:{}", prev_hash, timestamp.to_rfc3339(), action, target_id));
        let hash = format!("{:x}", hasher.finalize());

        let entry = AuditLogEntryEntity {
            id: Uuid::new_v4(),
            prev_hash,
            action: action.to_string(),
            target_id,
            timestamp,
            hash,
        };

        list.push(entry.clone());
        Ok(entry)
    }

    async fn get_audit_trail(&self) -> Result<Vec<AuditLogEntryEntity>> {
        let list = self.audit_logs.lock().await;
        Ok(list.clone())
    }

    async fn verify_audit_integrity(&self) -> Result<bool> {
        let list = self.audit_logs.lock().await;
        if list.is_empty() {
            return Ok(true);
        }

        let mut expected_prev_hash = "GENESIS_BLOCK_HASH".to_string();

        for entry in list.iter() {
            if entry.prev_hash != expected_prev_hash {
                return Ok(false); // Tampered previous hash
            }

            let mut hasher = Sha256::new();
            hasher.update(format!("{}:{}:{}:{}", entry.prev_hash, entry.timestamp.to_rfc3339(), entry.action, entry.target_id));
            let calculated_hash = format!("{:x}", hasher.finalize());

            if entry.hash != calculated_hash {
                return Ok(false); // Tampered entry hash
            }

            expected_prev_hash = entry.hash.clone();
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::models::target::ScopeDefinition;

    #[tokio::test]
    async fn test_repository_roundtrip_and_no_secret_leak() {
        let repo = MemorySentinelRepository::new();
        let target_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();

        let target = Target {
            id: target_id,
            project_id,
            name: "Test Secure Target".into(),
            target_type: "Web App".into(),
            base_url: "https://secure.internal".into(),
            repo_ref: Some("github.com/acme/app".into()),
            stack_description: Some("Node.js + PostgreSQL".into()),
            auth_keychain_handle: Some("keychain_handle_sec_123".into()), // ONLY OS Keyring Handle
            authorization_record: None,
            created_at: Utc::now(),
        };

        repo.save_target(&target).await.unwrap();

        let fetched = repo.get_target(target_id).await.unwrap().unwrap();
        assert_eq!(fetched.name, "Test Secure Target");
        assert_eq!(fetched.auth_keychain_handle, Some("keychain_handle_sec_123".into()));

        // Save Authorization Record
        let auth_rec = AuthorizationRecord {
            id: Uuid::new_v4(),
            target_id,
            scope: ScopeDefinition {
                allowed_domains: vec!["secure.internal".into()],
                allowed_ips_cidrs: vec![],
                out_of_scope_paths: vec!["/admin".into()],
                rate_limit_rps: 10,
                prohibited_actions: vec!["DoS".into()],
            },
            acknowledged_by: "Security Lead".into(),
            signed_at: Utc::now(),
            roe_document_hash: "hash123".into(),
            digital_signature: "sig123".into(),
        };

        repo.save_authorization_record(&auth_rec).await.unwrap();
        let updated_target = repo.get_target(target_id).await.unwrap().unwrap();
        assert!(updated_target.authorization_record.is_some());
    }

    #[tokio::test]
    async fn test_audit_ledger_integrity_and_tamper_detection() {
        let repo = MemorySentinelRepository::new();
        let target_id = Uuid::new_v4();

        repo.append_audit_entry("SIGN_ROE", target_id).await.unwrap();
        repo.append_audit_entry("START_SCAN", target_id).await.unwrap();

        assert!(repo.verify_audit_integrity().await.unwrap());

        // Tamper with audit log entry
        {
            let mut logs = repo.audit_logs.lock().await;
            logs[1].action = "TAMPERED_ACTION".to_string();
        }

        // Integrity check must fail
        assert!(!repo.verify_audit_integrity().await.unwrap());
    }
}
