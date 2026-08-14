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

/// Does `host` fall under `pattern`, treating `pattern` as a domain and its
/// subdomains?
///
/// Matching is on parsed hosts, never on raw substrings. A substring test is
/// both too strict and dangerously too loose: `dev.example.com` fails to match
/// `Example.com` purely on case, while `example.com` would happily match
/// `evil-example.com.attacker.net` — letting a scan off its authorized scope,
/// which is the one thing this gate exists to prevent.
///
/// A leading `*.` or `.` on the pattern is accepted and ignored, since analysts
/// write scope both ways.
pub fn host_matches(host: &str, pattern: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern
        .trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if host.is_empty() || pattern.is_empty() {
        return false;
    }
    // Exact host, or a subdomain of it — the dot is required so that
    // "notexample.com" cannot match "example.com".
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

/// The host of a URL, lowercased. Falls back to treating the input as a bare
/// host when it has no scheme, which is how scope entries are usually written.
fn host_of(url_or_host: &str) -> Option<String> {
    if let Ok(parsed) = url::Url::parse(url_or_host) {
        if let Some(h) = parsed.host_str() {
            return Some(h.to_ascii_lowercase());
        }
    }
    let bare = url_or_host
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let bare = bare.split('/').next().unwrap_or("");
    let bare = bare.split('@').next_back().unwrap_or("");
    // Strip a port, but leave bracketed IPv6 literals alone.
    let bare = if bare.starts_with('[') {
        bare
    } else {
        bare.split(':').next().unwrap_or("")
    };
    if bare.is_empty() {
        None
    } else {
        Some(bare.to_ascii_lowercase())
    }
}

impl AuthorizationGate {
    pub fn verify_active_scan_allowed(target: &Target, requested_url: &str) -> Result<(), AuthGateError> {
        let auth = target.authorization_record.as_ref()
            .ok_or(AuthGateError::MissingAuthorizationRecord)?;

        let host = host_of(requested_url)
            .ok_or_else(|| AuthGateError::TargetOutOfScope(requested_url.to_string()))?;

        let is_allowed_domain = auth
            .scope
            .allowed_domains
            .iter()
            .filter_map(|d| host_of(d))
            .any(|pattern| host_matches(&host, &pattern));

        // An exact host match against an IP entry. CIDR ranges are matched by
        // the probe's scope rules, which own the address arithmetic; here a
        // literal address in the list is enough to authorize its own host.
        let is_allowed_ip = auth
            .scope
            .allowed_ips_cidrs
            .iter()
            .any(|entry| {
                let bare = entry.split('/').next().unwrap_or("").trim();
                !bare.is_empty() && bare.eq_ignore_ascii_case(&host)
            });

        if !is_allowed_domain && !is_allowed_ip {
            return Err(AuthGateError::TargetOutOfScope(format!(
                "{requested_url} (host '{host}' is not covered by the signed scope: {:?})",
                auth.scope.allowed_domains
            )));
        }

        // Out-of-scope entries describe paths, so compare against the path
        // rather than the whole URL — otherwise an entry like "/api" could be
        // matched by a hostname that merely contains it.
        let path = url::Url::parse(requested_url)
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| requested_url.to_string());
        for out_path in &auth.scope.out_of_scope_paths {
            let out_path = out_path.trim();
            if out_path.is_empty() {
                continue;
            }
            if path.starts_with(out_path) {
                return Err(AuthGateError::TargetOutOfScope(format!(
                    "{requested_url} (path '{out_path}' is explicitly out of scope)"
                )));
            }
        }

        Ok(())
    }

    /// Whether a scope would actually authorize scanning this target at all.
    ///
    /// Signing a Rules of Engagement whose scope does not cover the target's own
    /// base URL produces an engagement that can never scan anything — every
    /// dynamic stage is refused and the run finishes in milliseconds with no
    /// findings and no obvious reason. Callers use this to catch that at signing
    /// time, while the analyst is still looking at the scope form.
    pub fn scope_covers_target(base_url: &str, allowed_domains: &[String]) -> bool {
        let Some(host) = host_of(base_url) else { return false };
        allowed_domains
            .iter()
            .filter_map(|d| host_of(d))
            .any(|pattern| host_matches(&host, &pattern))
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

    fn target_with_scope(base_url: &str, domains: Vec<String>) -> Target {
        Target {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            name: "T".into(),
            target_type: "Web App".into(),
            base_url: base_url.into(),
            repo_ref: None,
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: Some(AuthorizationRecord {
                id: Uuid::new_v4(),
                target_id: Uuid::new_v4(),
                scope: ScopeDefinition {
                    allowed_domains: domains,
                    allowed_ips_cidrs: vec![],
                    out_of_scope_paths: vec![],
                    rate_limit_rps: 10,
                    prohibited_actions: vec![],
                },
                acknowledged_by: "KV".into(),
                signed_at: Utc::now(),
                roe_document_hash: "h".into(),
                digital_signature: "s".into(),
            }),
            created_at: Utc::now(),
        }
    }

    /// The real engagement that silently scanned nothing: scope written as
    /// "Industrility.com", target at "https://dev.industrility.com". Differing
    /// case and a subdomain meant the substring test refused every request, so
    /// the run completed in milliseconds with no findings and no explanation.
    #[test]
    fn a_subdomain_target_is_authorized_by_its_parent_domain_whatever_the_case() {
        let target = target_with_scope(
            "https://dev.industrility.com",
            vec!["Industrility.com".into()],
        );
        assert!(
            AuthorizationGate::verify_active_scan_allowed(&target, "https://dev.industrility.com/")
                .is_ok(),
            "a subdomain of the authorized domain must be in scope"
        );
    }

    /// Substring matching would authorize an attacker-controlled host that
    /// merely contains the authorized domain. This is the bypass the parsed
    /// host match exists to close.
    #[test]
    fn a_lookalike_host_containing_the_domain_is_refused() {
        let target = target_with_scope("https://example.com", vec!["example.com".into()]);

        for evil in [
            "https://evil-example.com.attacker.net/",
            "https://example.com.attacker.net/",
            "https://notexample.com/",
            "https://example.com.evil.io/x",
        ] {
            assert!(
                AuthorizationGate::verify_active_scan_allowed(&target, evil).is_err(),
                "{evil} must be refused — it is not the authorized host"
            );
        }
    }

    #[test]
    fn the_authorized_host_and_its_subdomains_are_allowed() {
        assert!(host_matches("example.com", "example.com"));
        assert!(host_matches("dev.example.com", "example.com"));
        assert!(host_matches("a.b.example.com", "example.com"));
        assert!(host_matches("EXAMPLE.com", "example.COM"));
        // Analysts write scope both ways.
        assert!(host_matches("dev.example.com", "*.example.com"));
        assert!(host_matches("dev.example.com", ".example.com"));
        // A trailing root dot is still the same host.
        assert!(host_matches("example.com.", "example.com"));

        assert!(!host_matches("example.com", "dev.example.com"));
        assert!(!host_matches("notexample.com", "example.com"));
        assert!(!host_matches("", "example.com"));
        assert!(!host_matches("example.com", ""));
    }

    #[test]
    fn a_scope_entry_written_as_a_url_still_matches() {
        // Analysts paste "https://industrility.com/" into the scope field.
        let target = target_with_scope(
            "https://dev.industrility.com",
            vec!["https://industrility.com/".into()],
        );
        assert!(AuthorizationGate::verify_active_scan_allowed(
            &target,
            "https://dev.industrility.com/health"
        )
        .is_ok());
    }

    #[test]
    fn out_of_scope_paths_are_matched_against_the_path_only() {
        let mut target = target_with_scope("https://example.com", vec!["example.com".into()]);
        if let Some(auth) = target.authorization_record.as_mut() {
            auth.scope.out_of_scope_paths = vec!["/admin".into()];
        }

        assert!(AuthorizationGate::verify_active_scan_allowed(
            &target,
            "https://example.com/admin/users"
        )
        .is_err());
        assert!(AuthorizationGate::verify_active_scan_allowed(
            &target,
            "https://example.com/public"
        )
        .is_ok());
    }

    #[test]
    fn scope_covers_target_catches_a_scope_that_can_never_scan() {
        // The exact combination the analyst signed.
        assert!(!AuthorizationGate::scope_covers_target(
            "https://dev.industrility.com",
            &["some-other-domain.com".into()]
        ));
        assert!(AuthorizationGate::scope_covers_target(
            "https://dev.industrility.com",
            &["Industrility.com".into()]
        ));
        assert!(AuthorizationGate::scope_covers_target(
            "https://dev.industrility.com",
            &["dev.industrility.com".into()]
        ));
        assert!(!AuthorizationGate::scope_covers_target(
            "https://dev.industrility.com",
            &[]
        ));
    }

    #[test]
    fn an_ip_target_is_authorized_by_a_literal_ip_entry() {
        let mut target = target_with_scope("http://127.0.0.1:8080", vec![]);
        if let Some(auth) = target.authorization_record.as_mut() {
            auth.scope.allowed_ips_cidrs = vec!["127.0.0.1".into()];
        }
        assert!(
            AuthorizationGate::verify_active_scan_allowed(&target, "http://127.0.0.1:8080/x")
                .is_ok()
        );
    }
}
