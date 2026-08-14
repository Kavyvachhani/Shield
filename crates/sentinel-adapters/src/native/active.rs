//! Safe active checks: transport enforcement, CORS, HTTP methods, Host header
//! handling and open redirects.
//!
//! "Active" here means an additional request is issued with a modified header or
//! query string. Every request is still GET/HEAD/OPTIONS, no payload is written,
//! and redirects are never followed — the probe client is configured with
//! `Policy::none()`, so an off-site Location is observed rather than requested.

use super::builder::{CheckSpec, NativeFinding};
use super::probe::{truncate, Probe, ProbeResponse};
use sentinel_core::models::finding::Finding;
use uuid::Uuid;

const OWASP_MISCONFIG: &str = "A02:2025-Security Misconfiguration";
const OWASP_ACCESS: &str = "A01:2025-Broken Access Control";
const OWASP_CRYPTO: &str = "A04:2025-Cryptographic Failures";
const OWASP_INJECTION: &str = "A05:2025-Injection";

/// A host that does not resolve and is not owned by anyone, used as the marker
/// for reflection tests. `.example` is reserved by RFC 2606 for exactly this.
const PROBE_ORIGIN: &str = "https://sentinel-probe.example";
const PROBE_HOST: &str = "sentinel-probe.example";

// ── Specifications ───────────────────────────────────────────────────────────

const NO_HTTPS: CheckSpec = CheckSpec {
    id: "NATIVE-NO-HTTPS",
    title: "Application Served over Unencrypted HTTP",
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-319",
    wstg: "WSTG-CRYP-03",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "The application answers over plaintext HTTP and does not redirect to HTTPS. Every \
request and response — including credentials, session cookies and personal data — travels in clear text \
and can be read or modified by anyone on the network path, from a shared Wi-Fi network to any upstream \
provider.",
    remediation: "Obtain a certificate (Let's Encrypt issues them free and automatically) and serve the \
application over HTTPS. Redirect all HTTP traffic to HTTPS with a 301, then enable HSTS so browsers stop \
attempting plaintext connections altogether.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ],
};

const NO_HTTPS_REDIRECT: CheckSpec = CheckSpec {
    id: "NATIVE-NO-HTTPS-REDIRECT",
    title: "HTTP Traffic Not Redirected to HTTPS",
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-319",
    wstg: "WSTG-CRYP-03",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "HTTPS is available, but the plaintext HTTP endpoint serves content instead of \
redirecting to it. A user or client that reaches the HTTP endpoint — by typing the hostname, following an \
old link, or being downgraded by an attacker — continues over an unencrypted channel without any warning.",
    remediation: "Return a 301 redirect to the HTTPS URL for every HTTP request, and serve no application \
content over HTTP. Enable HSTS on the HTTPS endpoint so subsequent visits skip the plaintext request entirely.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ],
};

const CORS_WILDCARD_CREDS: CheckSpec = CheckSpec {
    id: "NATIVE-CORS-CREDENTIALED-REFLECTION",
    title: "CORS Policy Reflects Arbitrary Origin with Credentials Allowed",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-942",
    wstg: "WSTG-CLNT-07",
    owasp_2025: OWASP_ACCESS,
    api_top10: Some("API8:2023-Security Misconfiguration"),
    description: "The server echoes any origin it is sent back in Access-Control-Allow-Origin while also \
sending Access-Control-Allow-Credentials: true. Any website a logged-in user visits can therefore make \
credentialed requests to this application and read the responses, exfiltrating that user's data from \
their browser without any interaction beyond visiting the attacker's page.",
    remediation: "Never reflect the request Origin. Compare it against a fixed server-side allow-list and \
echo it only on an exact match, or drop credentials support entirely. Note that \
`Access-Control-Allow-Origin: *` combined with credentials is rejected by browsers — reflection is what \
makes this exploitable, so removing the reflection is the fix.",
    references: &[
        "https://portswigger.net/web-security/cors",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing",
    ],
};

const CORS_NULL_ORIGIN: CheckSpec = CheckSpec {
    id: "NATIVE-CORS-NULL-ORIGIN",
    title: "CORS Policy Trusts the null Origin",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-942",
    wstg: "WSTG-CLNT-07",
    owasp_2025: OWASP_ACCESS,
    api_top10: Some("API8:2023-Security Misconfiguration"),
    description: "The server accepts `Origin: null` and echoes it back. The null origin is produced by \
sandboxed iframes and by documents loaded from data: or file: URLs, all of which an attacker can create. \
Trusting it is equivalent to trusting an arbitrary attacker-controlled page.",
    remediation: "Remove `null` from the accepted origin list. Validate Origin against an explicit \
allow-list of real origins and reject anything else, including null.",
    references: &["https://portswigger.net/web-security/cors"],
};

const CORS_WILDCARD: CheckSpec = CheckSpec {
    id: "NATIVE-CORS-WILDCARD",
    title: "CORS Policy Allows All Origins",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-942",
    wstg: "WSTG-CLNT-07",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: Some("API8:2023-Security Misconfiguration"),
    description: "`Access-Control-Allow-Origin: *` is returned, so any website may read responses from \
this endpoint. Browsers refuse to send credentials under a wildcard, so this is only a risk for data that \
is not already public — but it does mean any non-public data reachable without credentials is exposed to \
every origin.",
    remediation: "If the endpoint serves genuinely public data, the wildcard is acceptable and this can be \
accepted as a risk. Otherwise restrict Access-Control-Allow-Origin to the specific origins that need it.",
    references: &["https://portswigger.net/web-security/cors"],
};

const DANGEROUS_METHODS: CheckSpec = CheckSpec {
    id: "NATIVE-DANGEROUS-METHODS",
    title: "Unsafe HTTP Methods Advertised",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N",
    cwe: "CWE-650",
    wstg: "WSTG-CONF-06",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "The server advertises HTTP methods that allow content to be written or removed \
(PUT, DELETE, PATCH) or that echo the request back (TRACE). Where these are enabled at the web server \
rather than implemented by the application, they frequently bypass the application's own authorization \
checks entirely.",
    remediation: "Restrict the accepted methods to those the application actually implements — typically \
GET, HEAD, POST and OPTIONS. Disable TRACE (`TraceEnable off` in Apache; nginx does not implement it), and \
enforce the method allow-list at the reverse proxy so it applies regardless of application behaviour.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
    ],
};

const HOST_HEADER_REFLECTED: CheckSpec = CheckSpec {
    id: "NATIVE-HOST-HEADER-INJECTION",
    title: "Unvalidated Host Header Reflected in Response",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-644",
    wstg: "WSTG-INPV-17",
    owasp_2025: OWASP_INJECTION,
    api_top10: None,
    description: "The value of the Host request header is used to build absolute URLs in the response \
without validation. An attacker who can influence that header can make the application generate links \
pointing at a host they control. The classic impact is password-reset poisoning: the reset email contains \
an attacker's hostname, so a victim who clicks it hands over their reset token. It also enables web cache \
poisoning where a cache keys on the path alone.",
    remediation: "Do not build absolute URLs from the Host header. Configure the canonical hostname in \
application settings and use it for all generated links and redirects. At the web server, define an \
explicit default virtual host that rejects requests carrying an unrecognised Host.",
    references: &[
        "https://portswigger.net/web-security/host-header",
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection",
    ],
};

const OPEN_REDIRECT: CheckSpec = CheckSpec {
    id: "NATIVE-OPEN-REDIRECT",
    title: "Open Redirect via Unvalidated Redirect Parameter",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-601",
    wstg: "WSTG-CLNT-04",
    owasp_2025: OWASP_ACCESS,
    api_top10: None,
    description: "A query parameter controls the redirect destination without validation, so the \
application will forward visitors to any external site. Because the link genuinely starts on the trusted \
domain, it defeats the usual advice to check the hostname before clicking, and it is routinely used to \
make phishing links credible. Where the same parameter feeds an OAuth redirect_uri, it can also be used \
to capture authorization codes.",
    remediation: "Do not accept full URLs in redirect parameters. Accept a relative path only, or map an \
opaque key to a destination held server-side. If absolute URLs are unavoidable, validate the parsed host \
against an allow-list — check the parsed host, never a string prefix, which is bypassable with values \
such as `https://trusted.example.attacker.test`.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    ],
};

// ── Runner ───────────────────────────────────────────────────────────────────

/// Every check this module can raise.
///
/// Exposed so the spec audit can walk all shipped checks and confirm each
/// one carries a coherent CVSS vector, severity band and taxonomy — a
/// finding whose stated severity disagrees with its score misinforms the
/// reader of the report.
pub const SPECS: &[CheckSpec] = &[
    NO_HTTPS,
    NO_HTTPS_REDIRECT,
    CORS_WILDCARD_CREDS,
    CORS_NULL_ORIGIN,
    CORS_WILDCARD,
    DANGEROUS_METHODS,
    HOST_HEADER_REFLECTED,
    OPEN_REDIRECT,
];

pub async fn run(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    base_url: &str,
    root: &ProbeResponse,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let origin = base_url.trim_end_matches('/');

    findings.extend(check_transport(probe, target_id, scan_id, origin, root).await);
    findings.extend(check_cors(probe, target_id, scan_id, origin).await);
    findings.extend(check_methods(probe, target_id, scan_id, origin).await);
    findings.extend(check_host_header(probe, target_id, scan_id, origin).await);
    findings.extend(check_open_redirect(probe, target_id, scan_id, origin).await);

    findings
}

async fn check_transport(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    origin: &str,
    root: &ProbeResponse,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if origin.starts_with("https://") {
        // HTTPS is in use — confirm the plaintext endpoint redirects to it.
        let http_url = origin.replacen("https://", "http://", 1);
        if let Ok(Some(resp)) = probe.get(&http_url).await {
            let redirects_to_https = is_redirect(resp.status)
                && resp
                    .header("location")
                    .map(|l| l.to_lowercase().starts_with("https://"))
                    .unwrap_or(false);
            if !redirects_to_https && resp.status < 400 {
                findings.push(NativeFinding::build(
                    &NO_HTTPS_REDIRECT,
                    target_id,
                    scan_id,
                    &http_url,
                    &format!(
                        "The plaintext endpoint returned HTTP {} instead of redirecting to HTTPS.",
                        resp.status
                    ),
                    vec![format!("curl -sSI {http_url}")],
                    vec![NativeFinding::evidence(
                        "http_response",
                        "Plaintext HTTP response",
                        &resp.evidence_summary(),
                    )],
                ));
            }
        }
    } else if origin.starts_with("http://") && !root.is_https() {
        findings.push(NativeFinding::build(
            &NO_HTTPS,
            target_id,
            scan_id,
            origin,
            &format!("The application served HTTP {} over plaintext with no redirect to HTTPS.", root.status),
            vec![format!("curl -sSI {origin}")],
            vec![NativeFinding::evidence(
                "http_response",
                "Plaintext HTTP response",
                &root.evidence_summary(),
            )],
        ));
    }

    findings
}

async fn check_cors(probe: &Probe, target_id: Uuid, scan_id: Uuid, origin: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let url = format!("{origin}/");

    // 1. Arbitrary origin reflection.
    if let Ok(Some(resp)) = probe.request("GET", &url, &[("Origin", PROBE_ORIGIN)]).await {
        let acao = resp.header("access-control-allow-origin");
        let creds = resp
            .header("access-control-allow-credentials")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        match acao.as_deref() {
            Some(value) if value.trim() == PROBE_ORIGIN => {
                let spec = if creds { &CORS_WILDCARD_CREDS } else { &CORS_WILDCARD };
                let detail = if creds {
                    format!("The server echoed the submitted origin '{PROBE_ORIGIN}' and set Access-Control-Allow-Credentials: true.")
                } else {
                    format!("The server echoed the submitted origin '{PROBE_ORIGIN}' without credentials support.")
                };
                findings.push(NativeFinding::build(
                    spec,
                    target_id,
                    scan_id,
                    &url,
                    &detail,
                    vec![format!("curl -sSI -H 'Origin: {PROBE_ORIGIN}' {url}")],
                    vec![NativeFinding::evidence(
                        "http_response",
                        "CORS reflection response",
                        &resp.evidence_summary(),
                    )],
                ));
            }
            Some(value) if value.trim() == "*" => {
                findings.push(NativeFinding::build(
                    &CORS_WILDCARD,
                    target_id,
                    scan_id,
                    &url,
                    "Access-Control-Allow-Origin is set to '*'.",
                    vec![format!("curl -sSI -H 'Origin: {PROBE_ORIGIN}' {url}")],
                    vec![NativeFinding::evidence(
                        "http_response",
                        "CORS response",
                        &resp.evidence_summary(),
                    )],
                ));
            }
            _ => {}
        }
    }

    // 2. null origin trust.
    if let Ok(Some(resp)) = probe.request("GET", &url, &[("Origin", "null")]).await {
        if resp
            .header("access-control-allow-origin")
            .map(|v| v.trim().eq_ignore_ascii_case("null"))
            .unwrap_or(false)
        {
            findings.push(NativeFinding::build(
                &CORS_NULL_ORIGIN,
                target_id,
                scan_id,
                &url,
                "The server echoed 'null' in Access-Control-Allow-Origin.",
                vec![format!("curl -sSI -H 'Origin: null' {url}")],
                vec![NativeFinding::evidence(
                    "http_response",
                    "CORS null-origin response",
                    &resp.evidence_summary(),
                )],
            ));
        }
    }

    findings
}

async fn check_methods(probe: &Probe, target_id: Uuid, scan_id: Uuid, origin: &str) -> Vec<Finding> {
    let url = format!("{origin}/");
    let Ok(Some(resp)) = probe.options(&url).await else { return vec![] };

    let allow = resp
        .header("allow")
        .or_else(|| resp.header("access-control-allow-methods"));
    let Some(allow) = allow else { return vec![] };

    let dangerous = dangerous_methods(&allow);
    if dangerous.is_empty() {
        return vec![];
    }

    vec![NativeFinding::build(
        &DANGEROUS_METHODS,
        target_id,
        scan_id,
        &url,
        &format!(
            "The server advertised these unsafe methods: {}. Full Allow header: '{}'.",
            dangerous.join(", "),
            truncate(&allow, 200)
        ),
        vec![format!("curl -sSI -X OPTIONS {url}")],
        vec![NativeFinding::evidence(
            "http_response",
            "OPTIONS response",
            &resp.evidence_summary(),
        )],
    )]
}

async fn check_host_header(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    origin: &str,
) -> Vec<Finding> {
    let url = format!("{origin}/");
    let Ok(Some(resp)) = probe.request("GET", &url, &[("Host", PROBE_HOST)]).await else {
        return vec![];
    };

    let location = resp.header("location").unwrap_or_default();
    let reflected_in_location = location.contains(PROBE_HOST);
    // Only treat body reflection as meaningful when it appears in a URL context,
    // which is where the impact (poisoned links) actually arises.
    let reflected_in_body = resp.body.contains(&format!("//{PROBE_HOST}"));

    if !reflected_in_location && !reflected_in_body {
        return vec![];
    }

    let where_ = if reflected_in_location { "the Location header" } else { "an absolute URL in the response body" };
    let evidence = if reflected_in_location {
        format!("Location: {}", truncate(&location, 300))
    } else {
        extract_context(&resp.body, PROBE_HOST, 200)
    };

    vec![NativeFinding::build(
        &HOST_HEADER_REFLECTED,
        target_id,
        scan_id,
        &url,
        &format!(
            "A request carrying 'Host: {PROBE_HOST}' was answered with that hostname reflected in {where_}."
        ),
        vec![format!("curl -sSI -H 'Host: {PROBE_HOST}' {url}")],
        vec![NativeFinding::evidence("http_response", "Reflected Host header", &evidence)],
    )]
}

async fn check_open_redirect(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    origin: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let params = [
        "redirect", "redirect_uri", "redirect_url", "url", "next", "return",
        "returnUrl", "return_to", "target", "dest", "destination", "continue",
    ];

    for param in params {
        let url = format!("{origin}/?{param}={PROBE_ORIGIN}/");
        let Ok(Some(resp)) = probe.get(&url).await else { continue };
        if !is_redirect(resp.status) {
            continue;
        }
        let Some(location) = resp.header("location") else { continue };
        if !redirects_offsite(&location, PROBE_HOST) {
            continue;
        }

        findings.push(NativeFinding::build(
            &OPEN_REDIRECT,
            target_id,
            scan_id,
            &url,
            &format!(
                "The '{param}' parameter caused an HTTP {} redirect to the external host '{PROBE_HOST}'.",
                resp.status
            ),
            vec![
                format!("curl -sSI '{url}'"),
                "Confirm the Location header points at the externally supplied host".into(),
            ],
            vec![NativeFinding::evidence(
                "http_response",
                "Redirect response",
                &format!("HTTP {}\nLocation: {}", resp.status, truncate(&location, 300)),
            )],
        ));
        // One confirmed parameter is enough to prove the class; stop probing.
        break;
    }

    findings
}

// ── Helpers ──────────────────────────────────────────────────────────────────

pub fn is_redirect(status: u16) -> bool {
    (300..400).contains(&status)
}

/// Extract unsafe methods from an Allow / Access-Control-Allow-Methods header.
pub fn dangerous_methods(allow_header: &str) -> Vec<String> {
    const UNSAFE: &[&str] = &["PUT", "DELETE", "PATCH", "TRACE", "TRACK", "CONNECT"];
    let mut found: Vec<String> = allow_header
        .split(',')
        .map(|m| m.trim().to_ascii_uppercase())
        .filter(|m| UNSAFE.contains(&m.as_str()))
        .collect();
    found.sort();
    found.dedup();
    found
}

/// Whether a Location header genuinely sends the browser to `host`.
///
/// Compares the parsed host, so `https://trusted.example/?x=probe.example`
/// (which stays on-site) is not mistaken for an off-site redirect.
pub fn redirects_offsite(location: &str, host: &str) -> bool {
    let candidate = location.trim();

    // Protocol-relative form: //host/path
    if let Some(rest) = candidate.strip_prefix("//") {
        return host_of(rest) == host;
    }
    match url::Url::parse(candidate) {
        Ok(parsed) => parsed.host_str().map(|h| h == host).unwrap_or(false),
        // A relative Location cannot leave the origin.
        Err(_) => false,
    }
}

fn host_of(authority_and_path: &str) -> &str {
    authority_and_path
        .split('/')
        .next()
        .unwrap_or("")
        .split('@')
        .next_back()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
}

/// Pull a window of text around the first occurrence of `needle`.
pub fn extract_context(haystack: &str, needle: &str, window: usize) -> String {
    match haystack.find(needle) {
        None => String::new(),
        Some(idx) => {
            let start = idx.saturating_sub(window / 2);
            let end = (idx + needle.len() + window / 2).min(haystack.len());
            // Snap to char boundaries so multi-byte content cannot panic.
            let start = (start..=idx).find(|i| haystack.is_char_boundary(*i)).unwrap_or(idx);
            let end = (idx..=end).rev().find(|i| haystack.is_char_boundary(*i)).unwrap_or(idx);
            format!("…{}…", &haystack[start..end])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_methods_are_extracted() {
        let found = dangerous_methods("GET, HEAD, POST, PUT, DELETE, OPTIONS");
        assert_eq!(found, vec!["DELETE".to_string(), "PUT".to_string()]);
    }

    #[test]
    fn safe_method_lists_produce_nothing() {
        assert!(dangerous_methods("GET, HEAD, POST, OPTIONS").is_empty());
    }

    #[test]
    fn trace_is_treated_as_dangerous() {
        assert!(dangerous_methods("GET,TRACE").contains(&"TRACE".to_string()));
    }

    #[test]
    fn method_parsing_is_whitespace_and_case_tolerant() {
        assert_eq!(dangerous_methods("get , put , Delete"), vec!["DELETE".to_string(), "PUT".to_string()]);
    }

    #[test]
    fn offsite_redirect_is_detected() {
        assert!(redirects_offsite("https://sentinel-probe.example/", "sentinel-probe.example"));
        assert!(redirects_offsite("//sentinel-probe.example/path", "sentinel-probe.example"));
    }

    #[test]
    fn onsite_redirect_carrying_the_marker_in_a_query_is_not_offsite() {
        // The app echoed the parameter but still redirects to itself — not a finding.
        assert!(!redirects_offsite(
            "https://trusted.test/login?next=https://sentinel-probe.example/",
            "sentinel-probe.example"
        ));
    }

    #[test]
    fn relative_redirects_are_never_offsite() {
        assert!(!redirects_offsite("/dashboard", "sentinel-probe.example"));
        assert!(!redirects_offsite("dashboard", "sentinel-probe.example"));
    }

    #[test]
    fn userinfo_in_authority_does_not_spoof_the_host() {
        // https://sentinel-probe.example@trusted.test/ actually goes to trusted.test
        assert!(!redirects_offsite(
            "https://sentinel-probe.example@trusted.test/",
            "sentinel-probe.example"
        ));
    }

    #[test]
    fn redirect_status_range_is_correct() {
        assert!(is_redirect(301));
        assert!(is_redirect(302));
        assert!(is_redirect(307));
        assert!(!is_redirect(200));
        assert!(!is_redirect(404));
    }

    #[test]
    fn context_extraction_returns_a_window_around_the_match() {
        let body = "aaaaaaaaaa<link href=\"https://sentinel-probe.example/x\">bbbbbbbbbb";
        let ctx = extract_context(body, "sentinel-probe.example", 20);
        assert!(ctx.contains("sentinel-probe.example"));
        assert!(ctx.starts_with('…') && ctx.ends_with('…'));
    }

    #[test]
    fn context_extraction_handles_multibyte_content() {
        let body = "日本語テキスト https://sentinel-probe.example/ さらにテキスト";
        let ctx = extract_context(body, "sentinel-probe.example", 20);
        assert!(ctx.contains("sentinel-probe.example"));
    }

    #[test]
    fn context_extraction_of_a_missing_needle_is_empty() {
        assert_eq!(extract_context("nothing here", "absent", 20), "");
    }

    #[test]
    fn probe_markers_use_a_reserved_tld() {
        // RFC 2606 reserves .example so the probe can never contact a real host.
        assert!(PROBE_HOST.ends_with(".example"));
        assert!(PROBE_ORIGIN.ends_with(".example"));
    }
}
