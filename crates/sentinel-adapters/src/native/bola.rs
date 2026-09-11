//! Multi-User BOLA (Broken Object Level Authorization / IDOR) Verification.
//!
//! Performs cross-account identity replay on parameterized resources to confirm
//! whether an application enforces tenant and object-level authorization barriers.

use super::builder::{CheckSpec, NativeFinding};
use super::probe::{truncate, Probe};
use sentinel_core::diff::{AuthVerdict, StructuralDiffEngine};
use sentinel_core::identity::IdentityContext;
use sentinel_core::models::finding::Finding;
use uuid::Uuid;

pub const BOLA_VERIFIED: CheckSpec = CheckSpec {
    id: "NATIVE-BOLA-MULTIUSER-CONFIRMED",
    title: "Broken Object Level Authorization (BOLA/IDOR) Cross-Account Access Confirmed",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-639",
    wstg: "WSTG-ATHZ-04",
    owasp_2025: "A01:2025-Broken Access Control",
    api_top10: Some("API1:2023-Broken Object Level Authorization"),
    description: "The application allows one authenticated user (User B) to directly access and retrieve \
private resources belonging to another user (User A) simply by specifying User A's object identifier in \
the API request. A comparative structural response diff verified that the endpoint returned HTTP 200 with \
matching private object schema rather than enforcing access control.",
    remediation: "Enforce strict object-level authorization checks at the data-access layer for every request. \
Validate that the currently authenticated session owns or is explicitly authorized to access the requested resource ID, \
never relying solely on authentication status.",
    references: &[
        "https://owasp.org/www-project-api-security/",
        "https://portswigger.net/web-security/access-control/idor",
        "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
    ],
};

pub const SPECS: &[CheckSpec] = &[BOLA_VERIFIED];

/// Audit endpoints for BOLA vulnerabilities using multi-user contexts or anonymous replay.
pub async fn audit_bola(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    discovered: &[String],
    identities: Option<&IdentityContext>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Look for parameterized API routes (e.g. /api/users/1, /api/orders/42)
    for url in discovered {
        let Ok(parsed) = url::Url::parse(url) else { continue };
        let segments: Vec<&str> = parsed.path_segments().map(|s| s.collect()).unwrap_or_default();
        
        let id_idx = segments.iter().position(|seg| {
            seg.parse::<u64>().is_ok() || (seg.len() == 36 && seg.contains('-'))
        });

        let Some(idx) = id_idx else { continue };
        let original_id = segments[idx];

        // If we have multi-user credentials configured, test cross-account access
        if let Some(ctx) = identities {
            if let (Some(user_a), Some(user_b)) = (&ctx.user_a, &ctx.user_b) {
                let mut headers_a: Vec<(&str, &str)> = user_a.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                let cookie_a = user_a.cookie_header();
                if let Some(c) = &cookie_a {
                    headers_a.push(("Cookie", c.as_str()));
                }

                let mut headers_b: Vec<(&str, &str)> = user_b.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                let cookie_b = user_b.cookie_header();
                if let Some(c) = &cookie_b {
                    headers_b.push(("Cookie", c.as_str()));
                }

                let resp_a = probe.request("GET", url, &headers_a).await.ok().flatten();
                let resp_b = probe.request("GET", url, &headers_b).await.ok().flatten();

                if let (Some(resp_a), Some(resp_b)) = (resp_a, resp_b) {
                    let diff = StructuralDiffEngine::compare_multi_user(
                        resp_a.status,
                        &resp_a.body,
                        resp_b.status,
                        &resp_b.body,
                        Some(original_id),
                    );

                    if diff.verdict == AuthVerdict::PotentialBolaViolation {
                        findings.push(NativeFinding::build(
                            &BOLA_VERIFIED,
                            target_id,
                            scan_id,
                            url,
                            &format!(
                                "BOLA / IDOR confirmed on `{url}`: User B accessed User A's resource `{original_id}`. \
                                 User B received HTTP 200 with matching object schema ({} shared keys).",
                                diff.shared_json_keys.len()
                            ),
                            vec![
                                format!("# User A (Owner):"),
                                format!("curl -sSf '{url}' -H 'Authorization: Bearer <user_a_token>'"),
                                format!("# User B (Unauthorized Replayer):"),
                                format!("curl -sSf '{url}' -H 'Authorization: Bearer <user_b_token>'"),
                            ],
                            vec![
                                NativeFinding::evidence(
                                    "bola_structural_diff",
                                    "Cross-tenant response diff",
                                    &format!(
                                        "Verdict: {:?}\nStatus A: {}, Status B: {}\nShared keys: {:?}\nLeak indicators: {:?}",
                                        diff.verdict, diff.status_a, diff.status_b, diff.shared_json_keys, diff.leak_indicators
                                    ),
                                ),
                                NativeFinding::evidence(
                                    "unauthorized_user_response",
                                    "Unauthorized User B response body",
                                    &truncate(&resp_b.body, 200),
                                ),
                            ],
                        ));

                        if findings.len() >= 3 {
                            return findings;
                        }
                    }
                }
            }
        }
    }

    findings
}
