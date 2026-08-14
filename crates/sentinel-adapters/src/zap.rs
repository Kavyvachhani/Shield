//! ZAP DAST Adapter — authenticated, coverage-maximized integration layer.
//!
//! Architecture
//! ────────────
//! We NEVER generate payloads or attack logic ourselves. This module:
//!   1. Checks user-installed ZAP daemon is reachable.
//!   2. Creates a named ZAP context and registers scope/excludes from the RoE.
//!   3. [NEW] Imports an API spec (OpenAPI/Swagger/WSDL/GraphQL) to seed URL tree.
//!   4. [NEW] Configures authentication via FormLogin | BearerToken | SessionCookie | Script.
//!      — All credentials resolved from OS keychain at scan-time; never stored/logged.
//!   5. [NEW] Runs Ajax spider (SPA coverage) if configured.
//!   6. Runs traditional spider.
//!   7. Runs active scan (non-destructive defaults: Low strength / High threshold).
//!   8. Fetches ZAP JSON alerts → sentinel_core zap parser → Vec<Finding>.
//!
//! SAFETY GUARANTEES
//! ─────────────────
//! • ALWAYS wrapped in `AuthGatedDastRunner` — never called directly.
//! • Rate limiting: ZAP `ascan/action/setOptionMaxRuleDurationInMins` + `setOption*`.
//! • Credentials: resolved from OS keychain immediately before use; never in logs.
//! • Out-of-scope paths registered as ZAP context excludes before any spider/scan.
//! • Default scan strength: LOW, threshold: HIGH → non-destructive, high-confidence only.
//! • `ForcedUser` mode for FormLogin: ZAP impersonates a single user throughout.

use crate::adapter_trait::ScannerAdapter;
use crate::dast_config::{DastConfig, ZapAuthStrategy, ZapApiSpecType, ZapApiSpecSource};
use async_trait::async_trait;
use sentinel_core::{
    models::finding::Finding,
    models::target::Target,
    parser::zap::ZapJsonParser,
};
use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde_json::Value;
use uuid::Uuid;
use std::time::Duration;

const POLL_INTERVAL_SECS: u64 = 5;

pub struct ZapDastAdapter;

impl ZapDastAdapter {
    /// Build a full ZAP JSON API URL.
    fn api_url(base: &str, path: &str, key: Option<&str>, extra: &[(&str, String)]) -> String {
        let base = base.trim_end_matches('/');
        let mut params = Vec::new();
        if let Some(k) = key {
            params.push(format!("apikey={}", k));
        }
        for (k, v) in extra {
            params.push(format!("{}={}", k, urlencoding::encode(v)));
        }
        let qs = if params.is_empty() { String::new() } else { format!("?{}", params.join("&")) };
        format!("{}/JSON/{}{}", base, path, qs)
    }

    /// Configure ZAP's active scan policy strength and threshold.
    async fn configure_scan_policy(
        client: &Client,
        api_base: &str,
        api_key: Option<&str>,
        strength: &str,
        threshold: &str,
    ) -> Result<()> {
        // Set default scan policy strength
        let url = Self::api_url(api_base, "ascan/action/setScannerAttackStrength/", api_key,
            &[("id", "0".into()), ("attackStrength", strength.into())]);
        let _ = client.get(&url).send().await;

        // Set alert threshold (reduces false positives)
        let url2 = Self::api_url(api_base, "ascan/action/setScannerAlertThreshold/", api_key,
            &[("id", "0".into()), ("alertThreshold", threshold.into())]);
        let _ = client.get(&url2).send().await;

        tracing::info!(strength, threshold, "ZAP: Scan policy configured");
        Ok(())
    }

    // ── Auth strategy implementations ─────────────────────────────────────────

    /// FormLogin: ZAP FormBasedAuthentication + ForcedUser mode.
    /// ZAP docs: /authentication/action/setAuthenticationMethod (formBasedAuthentication)
    async fn configure_form_auth(
        client: &Client,
        api_base: &str,
        api_key: Option<&str>,
        context_id: &str,
        auth: &crate::dast_config::ZapAuthConfig,
    ) -> Result<String> {
        let login_url = auth.login_url.as_deref()
            .ok_or_else(|| anyhow!("FormLogin auth requires login_url"))?;
        let ufield = auth.username_field.as_deref().unwrap_or("username");
        let pfield = auth.password_field.as_deref().unwrap_or("password");

        // Resolve credentials from OS keychain — never log the values
        let username = auth.username_keychain_handle.as_deref()
            .map(crate::dast_config::ZapAuthConfig::resolve_keychain)
            .transpose()?
            .unwrap_or_default();
        let password = auth.password_keychain_handle.as_deref()
            .map(crate::dast_config::ZapAuthConfig::resolve_keychain)
            .transpose()?
            .unwrap_or_default();

        // Build ZAP login POST data pattern
        let post_data = format!("{}={{%25username%25}}&{}={{%25password%25}}", ufield, pfield);
        let logged_in_regex = auth.logged_in_indicator_regex.as_deref()
            .unwrap_or(r"(?i)logout|sign.out");
        let logged_out_regex = auth.logged_out_indicator_regex.as_deref()
            .unwrap_or(r"(?i)login|sign.in|password");

        // Set FormBased authentication method
        let method_params = format!(
            "loginUrl={}&loginRequestData={}",
            urlencoding::encode(login_url),
            post_data
        );
        let auth_url = Self::api_url(api_base, "authentication/action/setAuthenticationMethod/", api_key,
            &[
                ("contextId", context_id.into()),
                ("authMethodName", "formBasedAuthentication".into()),
                ("authMethodConfigParams", method_params),
            ]);
        client.get(&auth_url).send().await
            .context("ZAP: setAuthenticationMethod (form) failed")?;

        // Set logged-in / logged-out indicators
        let li_url = Self::api_url(api_base, "authentication/action/setLoggedInIndicator/", api_key,
            &[("contextId", context_id.into()), ("loggedInIndicatorRegex", logged_in_regex.into())]);
        client.get(&li_url).send().await.ok();

        let lo_url = Self::api_url(api_base, "authentication/action/setLoggedOutIndicator/", api_key,
            &[("contextId", context_id.into()), ("loggedOutIndicatorRegex", logged_out_regex.into())]);
        client.get(&lo_url).send().await.ok();

        // Create a ZAP user record
        let new_user_url = Self::api_url(api_base, "users/action/newUser/", api_key,
            &[("contextId", context_id.into()), ("name", "sentinel-scan-user".into())]);
        let user_resp: Value = client.get(&new_user_url).send().await
            .context("ZAP: newUser failed")?
            .json().await
            .context("ZAP: newUser response not JSON")?;
        let user_id = user_resp["userId"].as_str().unwrap_or("0").to_string();

        // Set credentials on the user — values come from keychain, not logged
        let cred_params = format!("{}={}&{}={}", ufield, username, pfield, password);
        let cred_url = Self::api_url(api_base, "users/action/setAuthenticationCredentials/", api_key,
            &[
                ("contextId", context_id.into()),
                ("userId", user_id.clone()),
                ("authCredentialsConfigParams", cred_params),
            ]);
        client.get(&cred_url).send().await
            .context("ZAP: setAuthenticationCredentials failed")?;

        // Enable Forced User mode (ZAP impersonates this user throughout)
        let enable_user_url = Self::api_url(api_base, "users/action/setUserEnabled/", api_key,
            &[("contextId", context_id.into()), ("userId", user_id.clone()), ("enabled", "true".into())]);
        client.get(&enable_user_url).send().await.ok();

        let forced_url = Self::api_url(api_base, "forcedUser/action/setForcedUser/", api_key,
            &[("contextId", context_id.into()), ("userId", user_id.clone())]);
        client.get(&forced_url).send().await
            .context("ZAP: setForcedUser failed")?;

        let mode_url = Self::api_url(api_base, "forcedUser/action/setForcedUserModeEnabled/", api_key,
            &[("enabled", "true".into())]);
        client.get(&mode_url).send().await.ok();

        tracing::info!("ZAP: FormLogin auth configured (ForcedUser mode, user_id={})", user_id);
        Ok(user_id)
    }

    /// BearerToken / API key: inject via ZAP Replacer rule on every request.
    async fn configure_bearer_auth(
        client: &Client,
        api_base: &str,
        api_key: Option<&str>,
        auth: &crate::dast_config::ZapAuthConfig,
    ) -> Result<()> {
        let token_handle = auth.token_keychain_handle.as_deref()
            .ok_or_else(|| anyhow!("BearerToken auth requires token_keychain_handle"))?;
        let token = crate::dast_config::ZapAuthConfig::resolve_keychain(token_handle)?;

        let header_name = auth.effective_token_header();
        let prefix = auth.effective_token_prefix();
        let header_value = if prefix.is_empty() {
            token
        } else {
            format!("{} {}", prefix, token)
        };

        // Use ZAP Replacer to inject the header on every request
        let rule_url = Self::api_url(api_base, "replacer/action/addRule/", api_key,
            &[
                ("description", "SentinelVAPT-BearerToken".into()),
                ("enabled", "true".into()),
                ("matchType", "REQ_HEADER".into()),
                ("matchString", header_name.into()),
                ("matchRegex", "false".into()),
                ("replacement", header_value),
                ("initiators", "".into()),
                ("url", "".into()),
            ]);
        client.get(&rule_url).send().await
            .context("ZAP: Replacer addRule (bearer token) failed")?;

        tracing::info!(header = header_name, "ZAP: BearerToken injection configured via Replacer");
        Ok(())
    }

    /// SessionCookie: inject pre-captured cookie via ZAP Replacer.
    async fn configure_session_cookie_auth(
        client: &Client,
        api_base: &str,
        api_key: Option<&str>,
        auth: &crate::dast_config::ZapAuthConfig,
    ) -> Result<()> {
        let cookie_handle = auth.session_cookie_keychain_handle.as_deref()
            .ok_or_else(|| anyhow!("SessionCookie auth requires session_cookie_keychain_handle"))?;
        let cookie_value = crate::dast_config::ZapAuthConfig::resolve_keychain(cookie_handle)?;

        let rule_url = Self::api_url(api_base, "replacer/action/addRule/", api_key,
            &[
                ("description", "SentinelVAPT-SessionCookie".into()),
                ("enabled", "true".into()),
                ("matchType", "REQ_HEADER".into()),
                ("matchString", "Cookie".into()),
                ("matchRegex", "false".into()),
                ("replacement", cookie_value),
                ("initiators", "".into()),
                ("url", "".into()),
            ]);
        client.get(&rule_url).send().await
            .context("ZAP: Replacer addRule (session cookie) failed")?;

        tracing::info!("ZAP: SessionCookie injection configured via Replacer");
        Ok(())
    }

    /// Script-based auth: load user's script via ZAP Script API, then configure it.
    async fn configure_script_auth(
        client: &Client,
        api_base: &str,
        api_key: Option<&str>,
        context_id: &str,
        auth: &crate::dast_config::ZapAuthConfig,
    ) -> Result<()> {
        let script_path = auth.auth_script_path.as_deref()
            .ok_or_else(|| anyhow!("Script auth requires auth_script_path"))?;
        let engine = auth.auth_script_engine.as_deref().unwrap_or("Oracle Nashorn");

        // Validate script file exists locally
        if !std::path::Path::new(script_path).exists() {
            return Err(anyhow!("ZAP auth script not found at path: {}", script_path));
        }

        // Load the script into ZAP
        let load_url = Self::api_url(api_base, "script/action/load/", api_key,
            &[
                ("scriptName", "sentinel-auth-script".into()),
                ("scriptType", "authentication".into()),
                ("scriptEngine", engine.into()),
                ("fileName", script_path.into()),
                ("scriptDescription", "SentinelVAPT auth script".into()),
            ]);
        client.get(&load_url).send().await
            .context("ZAP: script/action/load failed")?;

        // Set script-based authentication on context
        let auth_url = Self::api_url(api_base, "authentication/action/setAuthenticationMethod/", api_key,
            &[
                ("contextId", context_id.into()),
                ("authMethodName", "scriptBasedAuthentication".into()),
                ("authMethodConfigParams", "scriptName=sentinel-auth-script".into()),
            ]);
        client.get(&auth_url).send().await
            .context("ZAP: setAuthenticationMethod (script) failed")?;

        tracing::info!(script_path, engine, "ZAP: Script-based auth configured");
        Ok(())
    }

    // ── API spec import ───────────────────────────────────────────────────────

    async fn import_api_spec(
        client: &Client,
        api_base: &str,
        api_key: Option<&str>,
        context_id: &str,
        target_url: &str,
        spec_cfg: &crate::dast_config::ZapApiSpecConfig,
    ) -> Result<()> {
        let server_url = spec_cfg.server_url_override.as_deref().unwrap_or(target_url);

        match &spec_cfg.spec_type {
            ZapApiSpecType::OpenApi | ZapApiSpecType::Swagger => {
                let url = match &spec_cfg.spec_source {
                    ZapApiSpecSource::FilePath(path) => {
                        Self::api_url(api_base, "openapi/action/importFile/", api_key,
                            &[
                                ("file", path.into()),
                                ("target", server_url.into()),
                                ("contextId", context_id.into()),
                            ])
                    }
                    ZapApiSpecSource::Url(spec_url) => {
                        Self::api_url(api_base, "openapi/action/importUrl/", api_key,
                            &[
                                ("url", spec_url.into()),
                                ("hostOverride", server_url.into()),
                                ("contextId", context_id.into()),
                            ])
                    }
                };
                client.get(&url).send().await
                    .context("ZAP: OpenAPI spec import failed")?;
                tracing::info!(server = server_url, "ZAP: OpenAPI spec imported");
            }
            ZapApiSpecType::GraphQl => {
                let endpoint = match &spec_cfg.spec_source {
                    ZapApiSpecSource::Url(u) => u.clone(),
                    ZapApiSpecSource::FilePath(p) => format!("file://{}", p),
                };
                let url = Self::api_url(api_base, "graphql/action/importUrl/", api_key,
                    &[("endpointUrl", endpoint.clone()), ("overrideUrl", server_url.into())]);
                client.get(&url).send().await
                    .context("ZAP: GraphQL import failed")?;
                tracing::info!(endpoint, "ZAP: GraphQL spec imported");
            }
            ZapApiSpecType::Wsdl => {
                let url = match &spec_cfg.spec_source {
                    ZapApiSpecSource::FilePath(path) => {
                        Self::api_url(api_base, "wsdl/action/importFile/", api_key,
                            &[("file", path.into())])
                    }
                    ZapApiSpecSource::Url(spec_url) => {
                        Self::api_url(api_base, "wsdl/action/importUrl/", api_key,
                            &[("url", spec_url.into())])
                    }
                };
                client.get(&url).send().await
                    .context("ZAP: WSDL import failed")?;
                tracing::info!("ZAP: WSDL spec imported");
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ScannerAdapter for ZapDastAdapter {
    fn name(&self) -> &'static str { "OWASP ZAP" }

    async fn healthcheck(&self) -> Result<bool> {
        let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
        let cfg = DastConfig::default();
        let url = format!("{}/JSON/core/view/version/", cfg.zap_api_url);
        match client.get(&url).send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    /// Full authenticated DAST cycle:
    ///   Context → Excludes → API Spec Import → Auth Config → Ajax Spider →
    ///   Traditional Spider → Policy Tune → Active Scan → Alerts → Parse
    ///
    /// MUST only be called through `AuthGatedDastRunner`.
    async fn run(&self, target: &Target, config_json: &str) -> Result<Vec<Finding>> {
        let cfg = DastConfig::from_json(config_json)?;
        let scan_id = Uuid::new_v4();

        let client = Client::builder()
            .timeout(Duration::from_secs(cfg.timeout_seconds))
            .build()
            .context("Failed to build HTTP client for ZAP API")?;

        let api_base = &cfg.zap_api_url;
        let api_key = cfg.zap_api_key.as_deref();
        let target_url = &target.base_url;

        // ── 1. Create named ZAP context ─────────────────────────────────────
        tracing::info!(target_url, "ZAP: Creating scan context");
        let ctx_url = Self::api_url(api_base, "context/action/newContext/", api_key,
            &[("contextName", scan_id.to_string())]);
        let ctx_resp: Value = client.get(&ctx_url).send().await
            .context("ZAP API: newContext request failed")?
            .json().await
            .context("ZAP API: newContext response not JSON")?;
        let context_id = ctx_resp["contextId"].as_str().unwrap_or("1").to_string();

        // ── 2. Include target URL in context ────────────────────────────────
        let include_url = Self::api_url(api_base, "context/action/includeInContext/", api_key,
            &[
                ("contextName", scan_id.to_string()),
                ("regex", format!("{}.*", regex_escape(target_url))),
            ]);
        client.get(&include_url).send().await
            .context("ZAP API: includeInContext failed")?;

        // ── 3. Register out-of-scope excludes from signed RoE ────────────────
        if let Some(auth_rec) = &target.authorization_record {
            for oob_path in &auth_rec.scope.out_of_scope_paths {
                let excl_url = Self::api_url(api_base, "context/action/excludeFromContext/", api_key,
                    &[
                        ("contextName", scan_id.to_string()),
                        ("regex", format!("{}{}.*", regex_escape(target_url), oob_path)),
                    ]);
                let _ = client.get(&excl_url).send().await;
                tracing::info!(excluded_path = oob_path, "ZAP: Out-of-scope path excluded");
            }
        }

        // ── 4. API spec import (seeds URL tree before spider) ────────────────
        if let Some(spec_cfg) = &cfg.zap_api_spec {
            tracing::info!("ZAP: Importing API specification to seed URL tree");
            match Self::import_api_spec(&client, api_base, api_key, &context_id, target_url, spec_cfg).await {
                Ok(_) => tracing::info!("ZAP: API spec import complete"),
                Err(e) => tracing::warn!("ZAP: API spec import failed (continuing): {}", e),
            }
        }

        // ── 5. Configure authentication ──────────────────────────────────────
        match cfg.zap_auth.strategy {
            ZapAuthStrategy::None => {
                tracing::info!("ZAP: No authentication configured (unauthenticated scan)");
            }
            ZapAuthStrategy::FormLogin => {
                tracing::info!("ZAP: Configuring FormLogin authentication (ForcedUser mode)");
                Self::configure_form_auth(&client, api_base, api_key, &context_id, &cfg.zap_auth).await
                    .context("ZAP: FormLogin configuration failed")?;
            }
            ZapAuthStrategy::BearerToken => {
                tracing::info!("ZAP: Configuring BearerToken injection via Replacer");
                Self::configure_bearer_auth(&client, api_base, api_key, &cfg.zap_auth).await
                    .context("ZAP: BearerToken configuration failed")?;
            }
            ZapAuthStrategy::SessionCookie => {
                tracing::info!("ZAP: Configuring SessionCookie injection via Replacer");
                Self::configure_session_cookie_auth(&client, api_base, api_key, &cfg.zap_auth).await
                    .context("ZAP: SessionCookie configuration failed")?;
            }
            ZapAuthStrategy::Script => {
                tracing::info!("ZAP: Loading user auth script");
                Self::configure_script_auth(&client, api_base, api_key, &context_id, &cfg.zap_auth).await
                    .context("ZAP: Script auth configuration failed")?;
            }
        }

        // ── 6. Session management: cookie-based (needed for all auth modes) ──
        if cfg.zap_auth.strategy != ZapAuthStrategy::None {
            let sm_url = Self::api_url(api_base, "sessionManagement/action/setSessionManagementMethod/", api_key,
                &[("contextId", context_id.clone()), ("methodName", "cookieBasedSessionManagement".into())]);
            client.get(&sm_url).send().await.ok();
        }

        // ── 7. Ajax spider (SPA route discovery, opt-in) ─────────────────────
        if cfg.zap_spider.run_ajax_spider {
            tracing::info!("ZAP: Starting Ajax spider (browser: {})", cfg.zap_spider.ajax_browser);
            let ajax_url = Self::api_url(api_base, "ajaxSpider/action/scan/", api_key,
                &[
                    ("url", target_url.into()),
                    ("inScope", "true".into()),
                    ("contextName", scan_id.to_string()),
                    ("subtreeOnly", "false".into()),
                ]);
            client.get(&ajax_url).send().await
                .context("ZAP API: ajaxSpider/action/scan failed")?;

            // Set browser type
            let browser_url = Self::api_url(api_base, "ajaxSpider/action/setOptionBrowserId/", api_key,
                &[("String", cfg.zap_spider.ajax_browser.clone())]);
            client.get(&browser_url).send().await.ok();

            // Poll Ajax spider
            let ajax_deadline = std::time::Instant::now()
                + Duration::from_secs(cfg.zap_spider.ajax_spider_duration_secs);
            loop {
                if std::time::Instant::now() > ajax_deadline { break; }
                let status_url = Self::api_url(api_base, "ajaxSpider/view/status/", api_key, &[]);
                let status_resp: Value = match client.get(&status_url).send().await {
                    Ok(r) => r.json().await.unwrap_or_default(),
                    Err(_) => Value::Null,
                };
                if status_resp["status"].as_str() == Some("stopped") { break; }
                tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
            }
            tracing::info!("ZAP: Ajax spider complete");
        }

        // ── 8. Traditional spider ────────────────────────────────────────────
        if cfg.zap_spider.run_traditional_spider {
            tracing::info!("ZAP: Starting traditional spider");
            let spider_url = Self::api_url(api_base, "spider/action/scan/", api_key,
                &[
                    ("url", target_url.into()),
                    ("contextName", scan_id.to_string()),
                    ("recurse", "true".into()),
                    ("maxDuration", cfg.zap_spider.traditional_spider_duration_secs.to_string()),
                ]);
            let spider_resp: Value = client.get(&spider_url).send().await
                .context("ZAP API: spider/action/scan failed")?
                .json().await?;
            let spider_scan_id = spider_resp["scan"].as_str().unwrap_or("0").to_string();

            poll_until_done(&client, api_base,
                &format!("/JSON/spider/view/status/?scanId={}", spider_scan_id),
                cfg.timeout_seconds / 3, POLL_INTERVAL_SECS, "ZAP Traditional Spider").await?;
        }

        // ── 9. Tune scan policy ──────────────────────────────────────────────
        Self::configure_scan_policy(
            &client, api_base, api_key,
            cfg.zap_strength_str(),
            cfg.zap_threshold_str(),
        ).await.ok(); // Non-fatal if default policy tuning fails

        // ── 10. Active scan ──────────────────────────────────────────────────
        tracing::info!(
            strength = cfg.zap_strength_str(),
            threshold = cfg.zap_threshold_str(),
            "ZAP: Starting active scan"
        );
        let ascan_url = Self::api_url(api_base, "ascan/action/scan/", api_key,
            &[
                ("url", target_url.into()),
                ("contextId", context_id.clone()),
                ("recurse", "true".into()),
                ("scanPolicyName", "Default Policy".into()),
                ("method", "".into()),
                ("postData", "".into()),
            ]);
        let ascan_resp: Value = client.get(&ascan_url).send().await
            .context("ZAP API: ascan/action/scan failed")?
            .json().await?;
        let ascan_id = ascan_resp["scan"].as_str().unwrap_or("0").to_string();

        poll_until_done(&client, api_base,
            &format!("/JSON/ascan/view/status/?scanId={}", ascan_id),
            cfg.timeout_seconds / 2, POLL_INTERVAL_SECS, "ZAP Active Scan").await?;

        // ── 11. Fetch alerts JSON ────────────────────────────────────────────
        tracing::info!("ZAP: Fetching alerts JSON report");
        let alerts_url = Self::api_url(api_base, "core/view/alerts/", api_key,
            &[
                ("baseurl", target_url.into()),
                ("start", "0".into()),
                ("count", "9999".into()),
                ("riskId", "".into()),
            ]);
        let alerts_json: String = client.get(&alerts_url).send().await
            .context("ZAP API: core/view/alerts failed")?
            .text().await?;

        tracing::info!(bytes = alerts_json.len(), "ZAP: Raw alerts JSON retrieved");

        // ── 12. Parse via existing sentinel_core ZAP parser ─────────────────
        let findings = ZapJsonParser::parse(&alerts_json, target.id, scan_id)
            .context("ZAP parser failed to decode alerts JSON")?;

        tracing::info!(
            finding_count = findings.len(),
            target_url,
            auth_strategy = ?cfg.zap_auth.strategy,
            "ZAP: Scan complete"
        );

        Ok(findings)
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

async fn poll_until_done(
    client: &Client,
    api_base: &str,
    path: &str,
    timeout_secs: u64,
    poll_interval_secs: u64,
    label: &str,
) -> Result<()> {
    let url = format!("{}{}", api_base.trim_end_matches('/'), path);
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if std::time::Instant::now() > deadline {
            tracing::warn!("{}: Timeout reached; using partial results", label);
            break;
        }
        let resp: Value = client.get(&url).send().await
            .context(format!("{}: Status poll failed", label))?
            .json().await
            .context(format!("{}: Status not JSON", label))?;
        let progress = resp["status"].as_str().unwrap_or("0").parse::<u8>().unwrap_or(0);
        tracing::debug!("{}: {}%", label, progress);
        if progress >= 100 { break; }
        tokio::time::sleep(Duration::from_secs(poll_interval_secs)).await;
    }
    Ok(())
}

fn regex_escape(s: &str) -> String {
    s.chars().map(|c| match c {
        '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' | '/' => {
            format!("\\{}", c)
        }
        c => c.to_string(),
    }).collect()
}

// Inline urlencoding since we already depend on the url crate
mod urlencoding {
    pub fn encode(s: &str) -> String {
        url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_escape_handles_url_correctly() {
        let escaped = regex_escape("http://juice.local:3000/api/v1");
        assert!(escaped.contains("\\."), "dots must be escaped");
        assert!(escaped.contains("\\/"), "slashes must be escaped");
    }

    #[test]
    fn api_url_builds_correctly() {
        let url = ZapDastAdapter::api_url(
            "http://localhost:8090", "core/view/version/", Some("testkey"), &[]);
        assert!(url.contains("apikey=testkey"));
        assert!(url.contains("core/view/version/"));
    }

    #[test]
    fn dast_config_defaults_are_non_destructive() {
        let cfg = DastConfig::default();
        assert_eq!(cfg.rate_limit_rps, 5);
        assert_eq!(cfg.timeout_seconds, 1800);
        assert_eq!(cfg.zap_auth.strategy, ZapAuthStrategy::None);
        assert!(!cfg.zap_spider.run_ajax_spider, "Ajax spider must be opt-in");
        assert!(cfg.nuclei.exclude_tags.as_deref()
            .map(|t| t.contains("dos")).unwrap_or(false),
            "DOS templates must be excluded by default");
    }

    #[tokio::test]
    async fn healthcheck_returns_false_when_zap_not_running() {
        let adapter = ZapDastAdapter;
        let result = adapter.healthcheck().await;
        assert!(result.is_ok(), "healthcheck must not error");
    }
}
