//! DastConfig — complete per-scan configuration for all DAST adapters.
//!
//! All credential fields are **OS keychain handle strings**, never raw secrets.
//! At scan-time, the adapter resolves the handle via the OS keyring.
//! Defaults are deliberately conservative (non-destructive).

use serde::{Deserialize, Serialize};

// ── ZAP Authentication ────────────────────────────────────────────────────────

/// Which auth mechanism ZAP should use for this scan.
/// Defaults to `None` (current unauthenticated behavior, backward-compatible).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ZapAuthStrategy {
    #[default]
    None,
    /// ZAP FormBasedAuthentication: POST username+password to `login_url`.
    /// ZAP re-auths mid-scan using `logged_in_indicator_regex`.
    FormLogin,
    /// Inject Authorization header via ZAP Replacer on every request.
    BearerToken,
    /// Inject a pre-captured Cookie header via ZAP Replacer.
    SessionCookie,
    /// Execute a user-authored ZAP auth script. We author nothing.
    Script,
}

/// ZAP authentication configuration.
/// All credential values are keychain handle strings — resolved at scan-time.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZapAuthConfig {
    /// Which auth strategy to use.
    #[serde(default)]
    pub strategy: ZapAuthStrategy,

    // ── Form-based login ──────────────────────────────────────────────────────
    /// Full URL of the login POST endpoint.
    pub login_url: Option<String>,
    /// HTML form field name for username/email. e.g. "username"
    pub username_field: Option<String>,
    /// HTML form field name for password. e.g. "password"
    pub password_field: Option<String>,
    /// OS keychain service name under which the username is stored.
    /// Resolved at scan-time: `keyring::Entry::new(service, username_field)?.get_password()`
    pub username_keychain_handle: Option<String>,
    /// OS keychain service name under which the password is stored.
    pub password_keychain_handle: Option<String>,
    /// Regex present in responses when the user IS authenticated.
    /// ZAP uses this to detect session expiry and re-authenticate.
    /// Example: r"(?i)logout|sign.out|/dashboard"
    pub logged_in_indicator_regex: Option<String>,
    /// Regex present when NOT authenticated (login page indicator).
    /// Example: r"(?i)login|sign.in|password"
    pub logged_out_indicator_regex: Option<String>,

    // ── Bearer token / API key injection ─────────────────────────────────────
    /// OS keychain handle for the raw token value.
    pub token_keychain_handle: Option<String>,
    /// HTTP header to inject. Default: "Authorization"
    pub token_header: Option<String>,
    /// Prefix before the token. Default: "Bearer". Set "" for raw API keys.
    pub token_prefix: Option<String>,

    // ── Session cookie injection ──────────────────────────────────────────────
    /// OS keychain handle for a pre-captured session cookie string.
    /// Injected as a Cookie header on every ZAP request via ZAP Replacer.
    pub session_cookie_keychain_handle: Option<String>,

    // ── Script-based auth ─────────────────────────────────────────────────────
    /// Absolute path to a user-authored ZAP authentication script.
    /// Loaded via `script/action/load`; we execute verbatim, no authorship.
    pub auth_script_path: Option<String>,
    /// ZAP script engine. Options: "Oracle Nashorn" | "Graal.js" | "Jython"
    pub auth_script_engine: Option<String>,
}

impl ZapAuthConfig {
    /// Resolve a keychain handle to the actual secret value at scan-time.
    /// Returns Err if the handle is set but the keychain lookup fails.
    /// NEVER logs or returns the resolved value in error messages.
    pub fn resolve_keychain(handle: &str) -> anyhow::Result<String> {
        let entry = keyring::Entry::new("SentinelVAPT", handle)
            .map_err(|e| anyhow::anyhow!("Keychain entry creation failed for handle '{}': {}", handle, e))?;
        entry.get_password()
            .map_err(|_| anyhow::anyhow!(
                "Credential not found in OS keychain for handle '{}'. \
                 Store it with: sentinel-cli keychain set {}", handle, handle
            ))
    }

    /// Resolve the token header name (with default "Authorization").
    pub fn effective_token_header(&self) -> &str {
        self.token_header.as_deref().unwrap_or("Authorization")
    }

    /// Resolve the token prefix (with default "Bearer").
    pub fn effective_token_prefix(&self) -> &str {
        self.token_prefix.as_deref().unwrap_or("Bearer")
    }
}

// ── ZAP Spider Config ─────────────────────────────────────────────────────────

/// Controls the ZAP discovery / crawling phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZapSpiderConfig {
    /// Run ZAP's traditional link-following spider. Default: true.
    #[serde(default = "ZapSpiderConfig::default_run_traditional")]
    pub run_traditional_spider: bool,

    /// Run ZAP's Ajax spider (browser-driven, finds SPA routes).
    /// Requires geckodriver or chromedriver on PATH.
    /// Default: false (user must opt-in; needs browser driver installed).
    #[serde(default)]
    pub run_ajax_spider: bool,

    /// Max seconds for the traditional spider. Default: 120.
    #[serde(default = "ZapSpiderConfig::default_traditional_duration")]
    pub traditional_spider_duration_secs: u64,

    /// Max seconds for the Ajax spider. Default: 180.
    #[serde(default = "ZapSpiderConfig::default_ajax_duration")]
    pub ajax_spider_duration_secs: u64,

    /// Browser for Ajax spider.
    /// Options: "firefox-headless" | "chrome-headless" | "htmlunit" (no driver needed)
    /// Default: "firefox-headless"
    #[serde(default = "ZapSpiderConfig::default_ajax_browser")]
    pub ajax_browser: String,
}

impl Default for ZapSpiderConfig {
    fn default() -> Self {
        Self {
            run_traditional_spider: Self::default_run_traditional(),
            run_ajax_spider: false,
            traditional_spider_duration_secs: Self::default_traditional_duration(),
            ajax_spider_duration_secs: Self::default_ajax_duration(),
            ajax_browser: Self::default_ajax_browser(),
        }
    }
}

impl ZapSpiderConfig {
    fn default_run_traditional() -> bool { true }
    fn default_traditional_duration() -> u64 { 120 }
    fn default_ajax_duration() -> u64 { 180 }
    fn default_ajax_browser() -> String { "firefox-headless".into() }
}

// ── ZAP API Spec Import ───────────────────────────────────────────────────────

/// Import an API specification to seed ZAP's URL tree before scanning.
/// This gives ZAP endpoints it would never discover via spidering alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZapApiSpecConfig {
    pub spec_type: ZapApiSpecType,
    pub spec_source: ZapApiSpecSource,
    /// Override the server URL from the spec.
    /// Use when the spec declares a cloud URL but the target is local.
    pub server_url_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ZapApiSpecType {
    /// OpenAPI 3.x JSON or YAML
    OpenApi,
    /// Swagger 2.x JSON or YAML  
    Swagger,
    /// SOAP WSDL
    Wsdl,
    /// GraphQL — uses ZAP's graphql/action/importUrl
    GraphQl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZapApiSpecSource {
    /// Absolute local file path.
    FilePath(String),
    /// URL within the authorized scope.
    Url(String),
}

// ── ZAP Active Scan Tuning ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ZapScanStrength {
    #[default]
    Low,
    Medium,
    High,
    Insane,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ZapScanThreshold {
    Low,
    #[default]
    Medium,
    High,
}

// ── Nuclei Config ─────────────────────────────────────────────────────────────

/// Nuclei template selection — all tags come from the user's installed template set.
/// We author NO templates; these are filter flags over `nuclei-templates/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiConfig {
    /// Severity levels to include. Default: "critical,high,medium"
    #[serde(default = "NucleiConfig::default_severity")]
    pub severity_filter: String,

    /// User-supplied template directory (optional). None = nuclei's default ~/.nuclei-templates.
    pub templates_path: Option<String>,

    /// Tags to include (AND filter). e.g. "cve,owasp,sqli"
    /// Maps to: nuclei -tags <value>
    pub include_tags: Option<String>,

    /// Tags to exclude. e.g. "dos,fuzzing,intrusive"
    /// Maps to: nuclei -etags <value>
    pub exclude_tags: Option<String>,

    /// Additional user-supplied template directories (comma-separated paths).
    pub custom_template_paths: Vec<String>,
}

impl Default for NucleiConfig {
    fn default() -> Self {
        Self {
            severity_filter: Self::default_severity(),
            templates_path: None,
            include_tags: None,
            // Always exclude destructive templates by default (non-destructive guarantee)
            exclude_tags: Some("dos,fuzzing,intrusive".into()),
            custom_template_paths: vec![],
        }
    }
}

impl NucleiConfig {
    fn default_severity() -> String { "critical,high,medium".into() }
}

// ── Semgrep Config ────────────────────────────────────────────────────────────

/// Semgrep SAST rule pack selection.
/// All rule packs are from Semgrep's official registry; we author none.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepConfig {
    /// Rule packs to use. Default: OWASP Top 10 + CWE Top 25.
    /// Available: p/owasp-top-ten, p/cwe-top-25, p/javascript, p/python, etc.
    #[serde(default = "SemgrepConfig::default_rule_packs")]
    pub rule_packs: Vec<String>,

    /// Override language auto-detection. None = auto-detect.
    pub language_override: Option<String>,
}

impl Default for SemgrepConfig {
    fn default() -> Self {
        Self {
            rule_packs: Self::default_rule_packs(),
            language_override: None,
        }
    }
}

impl SemgrepConfig {
    fn default_rule_packs() -> Vec<String> {
        vec!["p/owasp-top-ten".into(), "p/cwe-top-25".into()]
    }
}

// ── Trivy Config ──────────────────────────────────────────────────────────────

/// Trivy scan mode selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrivyConfig {
    /// Which Trivy scanners to run. Default: all three.
    #[serde(default = "TrivyConfig::default_scanners")]
    pub scanners: Vec<String>,   // "vuln" | "secret" | "misconfig" | "license"

    /// Severity filter. Default: "CRITICAL,HIGH,MEDIUM"
    #[serde(default = "TrivyConfig::default_severity")]
    pub severity_filter: String,

    /// Show unfixed vulnerabilities. Default: true (show everything).
    #[serde(default = "TrivyConfig::default_ignore_unfixed")]
    pub ignore_unfixed: bool,
}

impl Default for TrivyConfig {
    fn default() -> Self {
        Self {
            scanners: Self::default_scanners(),
            severity_filter: Self::default_severity(),
            ignore_unfixed: Self::default_ignore_unfixed(),
        }
    }
}

impl TrivyConfig {
    fn default_scanners() -> Vec<String> {
        vec!["vuln".into(), "secret".into(), "misconfig".into()]
    }
    fn default_severity() -> String { "CRITICAL,HIGH,MEDIUM".into() }
    fn default_ignore_unfixed() -> bool { false }
}

// ── Main DastConfig ───────────────────────────────────────────────────────────

/// Master per-scan configuration. Deserialized from `config_json` in each adapter.
/// All limits come from the signed AuthorizationRecord; defaults are conservative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DastConfig {
    // ── Shared RoE limits ────────────────────────────────────────────────────
    /// Maximum requests per second. Clamped to RoE `rate_limit_rps`. Default: 5.
    #[serde(default = "DastConfig::default_rps")]
    pub rate_limit_rps: u32,

    /// Maximum wall-clock seconds the DAST job may run. Default: 1800 (30 min).
    #[serde(default = "DastConfig::default_timeout")]
    pub timeout_seconds: u64,

    // ── ZAP connection ───────────────────────────────────────────────────────
    /// Full URL of the user-installed ZAP daemon REST API. Default: http://localhost:8090.
    #[serde(default = "DastConfig::default_zap_api_url")]
    pub zap_api_url: String,

    /// Optional API key if the user configured one in ZAP.
    pub zap_api_key: Option<String>,

    // ── ZAP auth (NEW) ───────────────────────────────────────────────────────
    /// Authentication configuration. Default: None (unauthenticated).
    #[serde(default)]
    pub zap_auth: ZapAuthConfig,

    // ── ZAP spider (NEW) ─────────────────────────────────────────────────────
    #[serde(default)]
    pub zap_spider: ZapSpiderConfig,

    // ── ZAP API spec seeding (NEW) ───────────────────────────────────────────
    pub zap_api_spec: Option<ZapApiSpecConfig>,

    // ── ZAP active scan tuning ───────────────────────────────────────────────
    #[serde(default)]
    pub zap_ascan_strength: ZapScanStrength,
    #[serde(default)]
    pub zap_ascan_threshold: ZapScanThreshold,

    // ── Backward-compat alias (kept so existing serialized configs don't break) ──
    #[serde(default = "DastConfig::default_spider_duration_compat")]
    pub zap_spider_duration_seconds: u64,

    // ── Nuclei (NEW structured config) ───────────────────────────────────────
    #[serde(default)]
    pub nuclei: NucleiConfig,

    // ── Legacy Nuclei fields (kept for backward compat) ──────────────────────
    #[serde(default = "DastConfig::default_severity_filter")]
    pub nuclei_severity_filter: String,
    pub nuclei_templates_path: Option<String>,

    // ── Semgrep ──────────────────────────────────────────────────────────────
    #[serde(default)]
    pub semgrep: SemgrepConfig,

    // ── Trivy ────────────────────────────────────────────────────────────────
    #[serde(default)]
    pub trivy: TrivyConfig,
}

impl Default for DastConfig {
    fn default() -> Self {
        Self {
            rate_limit_rps: Self::default_rps(),
            timeout_seconds: Self::default_timeout(),
            zap_api_url: Self::default_zap_api_url(),
            zap_api_key: None,
            zap_auth: ZapAuthConfig::default(),
            zap_spider: ZapSpiderConfig::default(),
            zap_api_spec: None,
            zap_ascan_strength: ZapScanStrength::default(),
            zap_ascan_threshold: ZapScanThreshold::default(),
            zap_spider_duration_seconds: Self::default_spider_duration_compat(),
            nuclei: NucleiConfig::default(),
            nuclei_severity_filter: Self::default_severity_filter(),
            nuclei_templates_path: None,
            semgrep: SemgrepConfig::default(),
            trivy: TrivyConfig::default(),
        }
    }
}

impl DastConfig {
    pub fn default_rps() -> u32 { 5 }
    pub fn default_timeout() -> u64 { 1800 }
    pub fn default_zap_api_url() -> String { "http://localhost:8090".into() }
    pub fn default_spider_duration_compat() -> u64 { 120 }
    pub fn default_severity_filter() -> String { "critical,high,medium".into() }

    pub fn from_json(config_json: &str) -> anyhow::Result<Self> {
        if config_json.is_empty() {
            Ok(Self::default())
        } else {
            Ok(serde_json::from_str(config_json)?)
        }
    }

    /// Clamp RPS to the hard limit from the signed RoE. Never exceeds authorization.
    pub fn effective_rps(&self, roe_limit: u32) -> u32 {
        self.rate_limit_rps.min(roe_limit)
    }

    /// Effective Nuclei severity: prefer structured config, fall back to legacy field.
    pub fn effective_nuclei_severity(&self) -> &str {
        if self.nuclei.severity_filter != NucleiConfig::default_severity() {
            &self.nuclei.severity_filter
        } else {
            &self.nuclei_severity_filter
        }
    }

    /// Effective Nuclei templates path: prefer structured config, fall back to legacy.
    pub fn effective_nuclei_templates_path(&self) -> Option<&str> {
        self.nuclei.templates_path.as_deref()
            .or(self.nuclei_templates_path.as_deref())
    }

    /// ZAP active scan strength as a ZAP API string.
    pub fn zap_strength_str(&self) -> &'static str {
        match self.zap_ascan_strength {
            ZapScanStrength::Low    => "LOW",
            ZapScanStrength::Medium => "MEDIUM",
            ZapScanStrength::High   => "HIGH",
            ZapScanStrength::Insane => "INSANE",
        }
    }

    /// ZAP active scan threshold as a ZAP API string.
    pub fn zap_threshold_str(&self) -> &'static str {
        match self.zap_ascan_threshold {
            ZapScanThreshold::Low    => "LOW",
            ZapScanThreshold::Medium => "MEDIUM",
            ZapScanThreshold::High   => "HIGH",
        }
    }
}
