use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeDefinition {
    pub allowed_domains: Vec<String>,
    pub allowed_ips_cidrs: Vec<String>,
    pub out_of_scope_paths: Vec<String>,
    pub rate_limit_rps: u32,
    pub prohibited_actions: Vec<String>, // e.g. ["DoS", "Destructive Payload", "Data Mutation"]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRecord {
    pub id: Uuid,
    pub target_id: Uuid,
    pub scope: ScopeDefinition,
    pub acknowledged_by: String,
    pub signed_at: DateTime<Utc>,
    pub roe_document_hash: String,
    pub digital_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub target_type: String, // "Web App", "REST API", "GraphQL", "Host"
    pub base_url: String,
    pub repo_ref: Option<String>,
    pub stack_description: Option<String>,
    pub auth_keychain_handle: Option<String>,
    pub authorization_record: Option<AuthorizationRecord>,
    pub created_at: DateTime<Utc>,
}
