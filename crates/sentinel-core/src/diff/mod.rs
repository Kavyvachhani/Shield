//! Structural Response Diff Engine for Authorization & Access Control Analysis.
//!
//! Provides deep comparative analysis between HTTP responses across different
//! user identity contexts (e.g. User A vs User B vs Anonymous) to reliably detect
//! Broken Object Level Authorization (BOLA/IDOR) and Broken Function Level Authorization (BFLA).

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthVerdict {
    /// Object or function access was properly denied (401, 403, or 404).
    ProperlyEnforced,
    /// Second user successfully accessed another user's private object/data (BOLA/IDOR).
    PotentialBolaViolation,
    /// Low-privilege user or anonymous client accessed administrative functionality (BFLA).
    PrivilegeEscalation,
    /// Endpoint is publicly accessible without authentication.
    PublicEndpoint,
    /// Indeterminate difference (status or content shapes differed without clear auth indicators).
    Indeterminate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StructuralDiffResult {
    pub verdict: AuthVerdict,
    pub status_a: u16,
    pub status_b: u16,
    pub body_len_a: usize,
    pub body_len_b: usize,
    pub shared_json_keys: Vec<String>,
    pub schema_matched: bool,
    pub leak_indicators: Vec<String>,
    pub summary: String,
}

pub struct StructuralDiffEngine;

impl StructuralDiffEngine {
    /// Compare responses for the same resource under User A (owner) and User B (unauthorized replayer).
    pub fn compare_multi_user(
        status_a: u16,
        body_a: &str,
        status_b: u16,
        body_b: &str,
        owner_id: Option<&str>,
    ) -> StructuralDiffResult {
        let mut leak_indicators = Vec::new();

        // 1. Access denial check
        if status_b == 401 || status_b == 403 || status_b == 404 {
            return StructuralDiffResult {
                verdict: AuthVerdict::ProperlyEnforced,
                status_a,
                status_b,
                body_len_a: body_a.len(),
                body_len_b: body_b.len(),
                shared_json_keys: Vec::new(),
                schema_matched: false,
                leak_indicators,
                summary: format!("Access properly denied to second user with HTTP status {status_b}."),
            };
        }

        // 2. If User A succeeded (200) and User B also got 200 OK
        if status_a == 200 && status_b == 200 {
            // Check if owner identifier leaked in User B's response
            if let Some(id) = owner_id {
                if !id.is_empty() && body_b.contains(id) {
                    leak_indicators.push(format!("Owner identifier `{id}` echoed in unauthorized user response"));
                }
            }

            // Check JSON schema similarity
            let json_a: Result<Value, _> = serde_json::from_str(body_a);
            let json_b: Result<Value, _> = serde_json::from_str(body_b);

            if let (Ok(val_a), Ok(val_b)) = (json_a, json_b) {
                let keys_a = extract_json_keys(&val_a);
                let keys_b = extract_json_keys(&val_b);

                let shared: Vec<String> = keys_a
                    .iter()
                    .filter(|k| keys_b.contains(k))
                    .cloned()
                    .collect();

                let schema_matched = !keys_a.is_empty() && keys_a == keys_b;

                // If identical schema or owner ID leaked
                if !leak_indicators.is_empty() || (schema_matched && !val_b.is_null() && body_b.len() > 20) {
                    return StructuralDiffResult {
                        verdict: AuthVerdict::PotentialBolaViolation,
                        status_a,
                        status_b,
                        body_len_a: body_a.len(),
                        body_len_b: body_b.len(),
                        shared_json_keys: shared,
                        schema_matched,
                        leak_indicators: leak_indicators.clone(),
                        summary: "User B received HTTP 200 with matching object schema or owner data.".into(),
                    };
                }

                return StructuralDiffResult {
                    verdict: AuthVerdict::Indeterminate,
                    status_a,
                    status_b,
                    body_len_a: body_a.len(),
                    body_len_b: body_b.len(),
                    shared_json_keys: shared,
                    schema_matched,
                    leak_indicators,
                    summary: "Both requests succeeded but structural schemas diverged.".into(),
                };
            }

            // Plain text comparison
            if body_a == body_b && body_b.len() > 50 {
                return StructuralDiffResult {
                    verdict: AuthVerdict::PotentialBolaViolation,
                    status_a,
                    status_b,
                    body_len_a: body_a.len(),
                    body_len_b: body_b.len(),
                    shared_json_keys: Vec::new(),
                    schema_matched: true,
                    leak_indicators,
                    summary: "User B received byte-for-byte identical content to User A.".into(),
                };
            }
        }

        StructuralDiffResult {
            verdict: AuthVerdict::Indeterminate,
            status_a,
            status_b,
            body_len_a: body_a.len(),
            body_len_b: body_b.len(),
            shared_json_keys: Vec::new(),
            schema_matched: false,
            leak_indicators,
            summary: format!("Responses differed: {status_a} vs {status_b}."),
        }
    }
}

/// Recursively extract JSON property key paths (e.g. ["user", "user.id", "user.email"]).
fn extract_json_keys(val: &Value) -> Vec<String> {
    let mut keys = Vec::new();
    collect_keys(val, "", &mut keys);
    keys.sort();
    keys.dedup();
    keys
}

fn collect_keys(val: &Value, prefix: &str, acc: &mut Vec<String>) {
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let full_key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                acc.push(full_key.clone());
                collect_keys(v, &full_key, acc);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_keys(item, prefix, acc);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_denied_detection() {
        let res = StructuralDiffEngine::compare_multi_user(200, r#"{"id":123}"#, 403, "Forbidden", Some("123"));
        assert_eq!(res.verdict, AuthVerdict::ProperlyEnforced);
    }

    #[test]
    fn test_bola_violation_detection() {
        let user_a_body = r#"{"id":"123","email":"alice@example.com","data":"secret"}"#;
        let user_b_body = r#"{"id":"123","email":"alice@example.com","data":"secret"}"#;
        let res = StructuralDiffEngine::compare_multi_user(200, user_a_body, 200, user_b_body, Some("123"));
        assert_eq!(res.verdict, AuthVerdict::PotentialBolaViolation);
        assert!(res.schema_matched);
        assert!(!res.leak_indicators.is_empty());
    }
}
