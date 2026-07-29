use crate::models::target::Target;
use thiserror::Error;
use sha2::{Sha256, Digest};
use chrono::Utc;

#[derive(Error, Debug)]
pub enum AuthGateError {
    #[error("Target has no signed AuthorizationRecord or Rules of Engagement (RoE).")]
    MissingAuthorizationRecord,
    #[error("Target URL or IP '{0}' is outside authorized scope definition.")]
    TargetOutOfScope(String),
    #[error("Action '{0}' is prohibited by the Rules of Engagement.")]
    ProhibitedAction(String),
    #[error("Authorization record signature is invalid or tampered.")]
    InvalidSignature,
}

pub struct AuthorizationGate;

impl AuthorizationGate {
    pub fn verify_active_scan_allowed(target: &Target, requested_url: &str) -> Result<(), AuthGateError> {
        let auth = target.authorization_record.as_ref()
            .ok_or(AuthGateError::MissingAuthorizationRecord)?;

        // Verify URL / Domain is within scope
        let is_allowed_domain = auth.scope.allowed_domains.iter()
            .any(|domain| requested_url.contains(domain));
        
        let is_allowed_ip = auth.scope.allowed_ips_cidrs.iter()
            .any(|ip| requested_url.contains(ip));

        if !is_allowed_domain && !is_allowed_ip {
            return Err(AuthGateError::TargetOutOfScope(requested_url.to_string()));
        }

        // Verify requested URL is not in out_of_scope_paths
        for out_path in &auth.scope.out_of_scope_paths {
            if requested_url.contains(out_path) {
                return Err(AuthGateError::TargetOutOfScope(format!("{} (explicitly out of scope)", requested_url)));
            }
        }

        Ok(())
    }

    pub fn compute_audit_hash(prev_hash: &str, action: &str, target_id: &str) -> String {
        let mut hasher = Sha256::new();
        let timestamp = Utc::now().to_rfc3339();
        hasher.update(format!("{}:{}:{}:{}", prev_hash, timestamp, action, target_id));
        format!("{:x}", hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::target::{Target, AuthorizationRecord, ScopeDefinition};
    use uuid::Uuid;

    #[test]
    fn test_auth_gate_blocks_unauthorized_scope() {
        let target = Target {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            name: "Test Target".into(),
            target_type: "Web App".into(),
            base_url: "https://example.com".into(),
            repo_ref: None,
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: Some(AuthorizationRecord {
                id: Uuid::new_v4(),
                target_id: Uuid::new_v4(),
                scope: ScopeDefinition {
                    allowed_domains: vec!["example.com".into()],
                    allowed_ips_cidrs: vec![],
                    out_of_scope_paths: vec!["/admin/danger".into()],
                    rate_limit_rps: 10,
                    prohibited_actions: vec!["DoS".into()],
                },
                acknowledged_by: "Security Lead".into(),
                signed_at: Utc::now(),
                roe_document_hash: "abcd1234hash".into(),
                digital_signature: "sig123".into(),
            }),
            created_at: Utc::now(),
        };

        // Allowed URL
        assert!(AuthorizationGate::verify_active_scan_allowed(&target, "https://example.com/api/v1").is_ok());

        // Unauthorized target domain
        assert!(AuthorizationGate::verify_active_scan_allowed(&target, "https://malicious-target.com").is_err());

        // Explicit out of scope path
        assert!(AuthorizationGate::verify_active_scan_allowed(&target, "https://example.com/admin/danger/delete").is_err());
    }
}
