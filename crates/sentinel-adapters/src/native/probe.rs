//! Rate-limited, scope-aware HTTP probe client for the native check engine.
//!
//! Every request the native engine makes goes through this type, which is the
//! single place where the Rules of Engagement are turned into wire behaviour:
//!
//!   • requests per second are capped at the signed RoE rate limit
//!   • out-of-scope paths are refused before a socket is opened
//!   • hosts outside the allow-list are refused
//!   • only safe methods are permitted; no payloads are ever sent
//!   • redirects are captured rather than followed blindly, so a redirect
//!     off-scope cannot smuggle the scanner onto a third-party host

use crate::credentials::{CredentialKind, TargetCredential};
use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, StatusCode};
use sentinel_core::models::target::Target;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use url::Url;

/// Methods the native engine is permitted to issue. Anything that could create,
/// modify or destroy state is absent by construction.
const SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

/// Captured response, with the body truncated so a large download cannot
/// exhaust memory or bloat the evidence store.
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub headers: HeaderMap,
    pub body: String,
    pub body_truncated: bool,
    pub elapsed_ms: u128,
}

impl ProbeResponse {
    /// Case-insensitive header lookup returning the first value as a string.
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    /// All values for a header that may legitimately repeat (e.g. Set-Cookie).
    pub fn header_all(&self, name: &str) -> Vec<String> {
        self.headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(str::to_string)
            .collect()
    }

    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(name)
    }

    pub fn is_https(&self) -> bool {
        self.final_url.starts_with("https://")
    }

    /// A redacted request/response summary suitable for report evidence.
    pub fn evidence_summary(&self) -> String {
        let mut out = format!("HTTP {} {}\n", self.status, self.final_url);
        let mut names: Vec<&HeaderName> = self.headers.keys().collect();
        names.sort_by_key(|n| n.as_str());
        for name in names {
            if is_sensitive_header(name.as_str()) {
                out.push_str(&format!("{}: <redacted>\n", name));
                continue;
            }
            for value in self.headers.get_all(name) {
                let shown = value.to_str().unwrap_or("<non-utf8>");
                out.push_str(&format!("{}: {}\n", name, truncate(shown, 300)));
            }
        }
        out
    }
}

/// Headers whose values must never reach a report.
///
/// `set-cookie` belongs here as much as `cookie` does: the response header
/// carries the live session token, and a report is a document that gets emailed
/// around. Only the cookie name and its attributes are ever reported, which the
/// cookie checks render separately via `ParsedCookie::redacted`.
fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-csrf-token"
            | "x-xsrf-token"
    )
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max).collect();
    format!("{truncated}… [truncated]")
}

/// Simple token-bucket limiter shared by every request the engine issues.
struct RateLimiter {
    min_interval: Duration,
    last: Mutex<Option<Instant>>,
}

impl RateLimiter {
    fn new(rps: u32) -> Self {
        let rps = rps.max(1);
        Self {
            min_interval: Duration::from_secs_f64(1.0 / rps as f64),
            last: Mutex::new(None),
        }
    }

    async fn acquire(&self) {
        let mut guard = self.last.lock().await;
        if let Some(prev) = *guard {
            let elapsed = prev.elapsed();
            if elapsed < self.min_interval {
                tokio::time::sleep(self.min_interval - elapsed).await;
            }
        }
        *guard = Some(Instant::now());
    }
}

/// Scope rules distilled from the target's signed authorization record.
#[derive(Debug, Clone)]
pub struct ScopeRules {
    pub allowed_hosts: Vec<String>,
    pub out_of_scope_paths: Vec<String>,
}

impl ScopeRules {
    pub fn from_target(target: &Target) -> Self {
        let mut allowed_hosts: Vec<String> = target
            .authorization_record
            .as_ref()
            .map(|a| a.scope.allowed_domains.clone())
            .unwrap_or_default()
            .into_iter()
            .map(|d| d.trim().to_lowercase())
            .filter(|d| !d.is_empty())
            .collect();

        // The target's own host is implicitly in scope once an RoE exists;
        // without an RoE the auth gate blocks the engine before we get here.
        if let Ok(url) = Url::parse(&target.base_url) {
            if let Some(host) = url.host_str() {
                let host = host.to_lowercase();
                if !allowed_hosts.contains(&host) {
                    allowed_hosts.push(host);
                }
            }
        }

        let out_of_scope_paths = target
            .authorization_record
            .as_ref()
            .map(|a| a.scope.out_of_scope_paths.clone())
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();

        Self { allowed_hosts, out_of_scope_paths }
    }

    /// A URL is in scope when its host matches an allowed domain (exactly or as
    /// a subdomain) and its path is not explicitly excluded.
    pub fn permits(&self, url: &Url) -> Result<()> {
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("URL '{url}' has no host"))?
            .to_lowercase();

        let host_ok = self.allowed_hosts.iter().any(|allowed| {
            host == *allowed || host.ends_with(&format!(".{allowed}"))
        });
        if !host_ok {
            return Err(anyhow!(
                "host '{host}' is outside the authorized scope; refusing to probe"
            ));
        }

        let path = url.path();
        for excluded in &self.out_of_scope_paths {
            if path.starts_with(excluded.as_str()) {
                return Err(anyhow!(
                    "path '{path}' is explicitly out of scope under the signed RoE"
                ));
            }
        }
        Ok(())
    }
}

/// The probe client used by every native check.
pub struct Probe {
    client: Client,
    limiter: RateLimiter,
    scope: ScopeRules,
    max_body_bytes: usize,
    /// Credential replayed on every request, when the target has one stored.
    /// Applied as a request header only — it widens what the engine can read,
    /// never what it can change.
    credential: Option<TargetCredential>,
}

impl Probe {
    pub fn new(target: &Target, rps: u32, timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs.clamp(1, 120)))
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true) // we *report* TLS problems, so we must not abort on them
            .user_agent(
                "SentinelVAPT/1.0 (authorized security assessment; +https://github.com/sentinelvapt)",
            )
            .build()
            .context("failed to construct native probe HTTP client")?;

        // A credential is optional, and a keychain that cannot be read must not
        // abort the assessment — an unauthenticated scan is still a real scan,
        // so the failure is reported and the run continues.
        let credential = match target.auth_keychain_handle.as_deref() {
            Some(handle) => match TargetCredential::load(handle) {
                Ok(Some(cred)) => {
                    tracing::info!(auth = %cred.describe(), "native probe: scanning authenticated");
                    Some(cred)
                }
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(error = %e, "native probe: continuing unauthenticated");
                    None
                }
            },
            None => None,
        };

        Ok(Self {
            client,
            limiter: RateLimiter::new(rps),
            scope: ScopeRules::from_target(target),
            max_body_bytes: 512 * 1024,
            credential,
        })
    }

    /// Build a probe with an already-resolved credential, bypassing the
    /// keychain. Used by tests and by callers that hold the credential
    /// directly; `new` is the normal path.
    pub fn with_credential(
        target: &Target,
        rps: u32,
        timeout_secs: u64,
        credential: Option<TargetCredential>,
    ) -> Result<Self> {
        let mut probe = Self::new(target, rps, timeout_secs)?;
        probe.credential = credential;
        Ok(probe)
    }

    /// Whether this probe is replaying a credential, for reporting.
    pub fn is_authenticated(&self) -> bool {
        self.credential.is_some()
    }

    /// How the probe is authenticating, with no secret in the string.
    pub fn auth_description(&self) -> Option<String> {
        self.credential.as_ref().map(|c| c.describe())
    }

    pub fn scope(&self) -> &ScopeRules {
        &self.scope
    }

    /// Issue a single safe request. Returns `Ok(None)` when the URL is out of
    /// scope or the host is unreachable — neither is a scan-fatal condition.
    pub async fn request(
        &self,
        method: &str,
        url: &str,
        extra_headers: &[(&str, &str)],
    ) -> Result<Option<ProbeResponse>> {
        let method_upper = method.to_ascii_uppercase();
        if !SAFE_METHODS.contains(&method_upper.as_str()) {
            return Err(anyhow!(
                "native engine refuses non-safe method '{method_upper}'; only {SAFE_METHODS:?} are permitted"
            ));
        }

        let parsed = Url::parse(url).with_context(|| format!("invalid probe URL '{url}'"))?;
        if let Err(e) = self.scope.permits(&parsed) {
            tracing::debug!(%url, reason = %e, "native probe skipped: out of scope");
            return Ok(None);
        }

        self.limiter.acquire().await;

        let mut headers = HeaderMap::new();
        // The credential goes on first, so a check that deliberately sets its
        // own Authorization or Cookie header (the CORS and session checks do)
        // still overrides it rather than being silently overwritten.
        if let Some((name, value)) = self.credential.as_ref().and_then(|c| c.header()) {
            if let (Ok(name), Ok(mut value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(&value),
            ) {
                value.set_sensitive(true);
                headers.insert(name, value);
            }
        }
        for (name, value) in extra_headers {
            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else { continue };
            let Ok(value) = HeaderValue::from_str(value) else { continue };
            headers.insert(name, value);
        }

        let http_method = Method::from_bytes(method_upper.as_bytes())
            .with_context(|| format!("invalid HTTP method '{method_upper}'"))?;

        let mut builder = self.client.request(http_method, parsed.clone()).headers(headers);
        // Basic is encoded by the client rather than hand-rolled, so the
        // base64 and the `user:pass` framing follow RFC 7617 exactly.
        if let Some(cred) = self.credential.as_ref() {
            if cred.kind == CredentialKind::Basic {
                builder = builder.basic_auth(
                    cred.username.as_deref().unwrap_or_default(),
                    Some(cred.secret.as_str()),
                );
            }
        }

        let started = Instant::now();
        let response = match builder.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(%url, error = %e, "native probe request failed");
                return Ok(None);
            }
        };

        let status = response.status();
        let headers = response.headers().clone();
        let final_url = response.url().to_string();

        let bytes = match response.bytes().await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(%url, error = %e, "native probe body read failed");
                return Ok(None);
            }
        };
        let body_truncated = bytes.len() > self.max_body_bytes;
        let slice = &bytes[..bytes.len().min(self.max_body_bytes)];
        let body = String::from_utf8_lossy(slice).to_string();

        Ok(Some(ProbeResponse {
            url: url.to_string(),
            final_url,
            status: status.as_u16(),
            headers,
            body,
            body_truncated,
            elapsed_ms: started.elapsed().as_millis(),
        }))
    }

    pub async fn get(&self, url: &str) -> Result<Option<ProbeResponse>> {
        self.request("GET", url, &[]).await
    }

    pub async fn head(&self, url: &str) -> Result<Option<ProbeResponse>> {
        self.request("HEAD", url, &[]).await
    }

    pub async fn options(&self, url: &str) -> Result<Option<ProbeResponse>> {
        self.request("OPTIONS", url, &[]).await
    }
}

/// Whether a status code indicates the resource genuinely exists.
pub fn is_present(status: u16) -> bool {
    StatusCode::from_u16(status)
        .map(|s| s.is_success() || s == StatusCode::UNAUTHORIZED || s == StatusCode::FORBIDDEN)
        .unwrap_or(false)
}

/// Whether a status code indicates a readable resource (2xx only).
pub fn is_readable(status: u16) -> bool {
    (200..300).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinel_core::models::target::{AuthorizationRecord, ScopeDefinition, Target};
    use uuid::Uuid;

    fn target_with_scope(base_url: &str, domains: Vec<&str>, excluded: Vec<&str>) -> Target {
        Target {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            name: "t".into(),
            target_type: "Web App".into(),
            base_url: base_url.into(),
            repo_ref: None,
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: Some(AuthorizationRecord {
                id: Uuid::new_v4(),
                target_id: Uuid::new_v4(),
                scope: ScopeDefinition {
                    allowed_domains: domains.into_iter().map(str::to_string).collect(),
                    allowed_ips_cidrs: vec![],
                    out_of_scope_paths: excluded.into_iter().map(str::to_string).collect(),
                    rate_limit_rps: 5,
                    prohibited_actions: vec![],
                },
                acknowledged_by: "lead".into(),
                signed_at: Utc::now(),
                roe_document_hash: "h".into(),
                digital_signature: "s".into(),
            }),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn scope_allows_the_target_host() {
        let t = target_with_scope("https://app.example.com", vec![], vec![]);
        let rules = ScopeRules::from_target(&t);
        assert!(rules.permits(&Url::parse("https://app.example.com/x").unwrap()).is_ok());
    }

    #[test]
    fn scope_allows_subdomains_of_allowed_domains() {
        let t = target_with_scope("https://example.com", vec!["example.com"], vec![]);
        let rules = ScopeRules::from_target(&t);
        assert!(rules.permits(&Url::parse("https://api.example.com/v1").unwrap()).is_ok());
    }

    #[test]
    fn scope_blocks_unrelated_hosts() {
        let t = target_with_scope("https://example.com", vec!["example.com"], vec![]);
        let rules = ScopeRules::from_target(&t);
        assert!(rules.permits(&Url::parse("https://evil.test/x").unwrap()).is_err());
    }

    #[test]
    fn scope_blocks_lookalike_suffix_hosts() {
        let t = target_with_scope("https://example.com", vec!["example.com"], vec![]);
        let rules = ScopeRules::from_target(&t);
        // notexample.com must NOT match example.com
        assert!(rules.permits(&Url::parse("https://notexample.com/x").unwrap()).is_err());
    }

    #[test]
    fn scope_blocks_excluded_paths() {
        let t = target_with_scope("https://example.com", vec!["example.com"], vec!["/admin/danger"]);
        let rules = ScopeRules::from_target(&t);
        assert!(rules
            .permits(&Url::parse("https://example.com/admin/danger/delete").unwrap())
            .is_err());
        assert!(rules.permits(&Url::parse("https://example.com/admin/safe").unwrap()).is_ok());
    }

    #[tokio::test]
    async fn unsafe_methods_are_refused() {
        let t = target_with_scope("https://example.com", vec!["example.com"], vec![]);
        let probe = Probe::new(&t, 5, 5).unwrap();
        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            let result = probe.request(method, "https://example.com/", &[]).await;
            assert!(result.is_err(), "{method} must be refused by the native engine");
        }
    }

    #[tokio::test]
    async fn out_of_scope_url_returns_none_not_an_error() {
        let t = target_with_scope("https://example.com", vec!["example.com"], vec![]);
        let probe = Probe::new(&t, 5, 5).unwrap();
        let result = probe.get("https://someone-else.test/").await.unwrap();
        assert!(result.is_none(), "out-of-scope probes are skipped, not fatal");
    }

    #[tokio::test]
    async fn rate_limiter_spaces_requests() {
        let limiter = RateLimiter::new(4); // 250ms apart
        let start = Instant::now();
        limiter.acquire().await;
        limiter.acquire().await;
        limiter.acquire().await;
        assert!(
            start.elapsed() >= Duration::from_millis(400),
            "three requests at 4rps must take at least ~500ms, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn truncate_leaves_short_strings_alone() {
        assert_eq!(truncate("short", 10), "short");
        assert!(truncate(&"x".repeat(50), 10).contains("truncated"));
    }

    #[test]
    fn sensitive_headers_are_recognised() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("cookie"));
        assert!(!is_sensitive_header("content-type"));
    }

    #[test]
    fn set_cookie_values_are_redacted_from_evidence() {
        // A response header dump ends up verbatim in report evidence, so the
        // live session token must never survive it.
        let mut headers = HeaderMap::new();
        headers.insert("set-cookie", HeaderValue::from_static("SESSION=supersecrettoken; Path=/"));
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        let resp = ProbeResponse {
            url: "https://app.test/".into(),
            final_url: "https://app.test/".into(),
            status: 200,
            headers,
            body: String::new(),
            body_truncated: false,
            elapsed_ms: 1,
        };
        let evidence = resp.evidence_summary();
        assert!(!evidence.contains("supersecrettoken"), "session token leaked: {evidence}");
        assert!(evidence.contains("set-cookie: <redacted>"));
        assert!(evidence.contains("text/html"), "harmless headers should still be shown");
    }
}
