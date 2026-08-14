//! Response-body analysis: mixed content, insecure forms, subresource
//! integrity, reverse tabnabbing, verbose errors and information leakage.
//!
//! Entirely passive — this module only reads a body that was already fetched.

use super::builder::{CheckSpec, NativeFinding};
use super::probe::{truncate, ProbeResponse};
use sentinel_core::models::finding::Finding;
use uuid::Uuid;

const OWASP_MISCONFIG: &str = "A02:2025-Security Misconfiguration";
const OWASP_CRYPTO: &str = "A04:2025-Cryptographic Failures";
const OWASP_INTEGRITY: &str = "A08:2025-Software or Data Integrity Failures";
const OWASP_EXCEPTIONS: &str = "A10:2025-Mishandling of Exceptional Conditions";

const MIXED_CONTENT: CheckSpec = CheckSpec {
    id: "NATIVE-MIXED-CONTENT",
    title: "Mixed Content: Active Resources Loaded over HTTP on an HTTPS Page",
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-319",
    wstg: "WSTG-CRYP-03",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "An HTTPS page references scripts, stylesheets or frames over plaintext HTTP. Because \
these resources execute in the page's origin, an attacker on the network path can replace one of them and \
run arbitrary code inside the secure page — defeating the protection HTTPS was meant to provide. Modern \
browsers block or upgrade most active mixed content, so this also frequently shows up as broken functionality.",
    remediation: "Change every subresource reference to https:// (or a protocol-relative path served over \
HTTPS). Add `Content-Security-Policy: upgrade-insecure-requests` as a safety net while the references are \
being fixed, and `block-all-mixed-content` once they are.",
    references: &[
        "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
    ],
};

const FORM_OVER_HTTP: CheckSpec = CheckSpec {
    id: "NATIVE-FORM-INSECURE",
    title: "Credentials Submitted over an Unencrypted Channel",
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-319",
    wstg: "WSTG-ATHN-01",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "A form containing a password field posts to a plaintext HTTP URL, or is served over \
HTTP. The credentials entered are transmitted in clear text and can be captured by anyone able to observe \
the connection.",
    remediation: "Serve every page containing a login form over HTTPS and set the form action to an HTTPS \
URL. Redirect the HTTP version of the page to HTTPS rather than serving the form over both.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel",
    ],
};

const SRI_MISSING: CheckSpec = CheckSpec {
    id: "NATIVE-SRI-MISSING",
    title: "Third-Party Script Loaded without Subresource Integrity",
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-353",
    wstg: "WSTG-CLNT-06",
    owasp_2025: OWASP_INTEGRITY,
    api_top10: None,
    description: "A script is loaded from an external origin without an `integrity` attribute. The \
application therefore executes whatever that third party serves, with full access to the page and its \
session. If the CDN or the vendor's build pipeline is compromised — the pattern behind several large \
supply-chain incidents — the malicious script runs in every visitor's browser with no signal to the site \
operator.",
    remediation: "Add `integrity=\"sha384-…\"` and `crossorigin=\"anonymous\"` to every external script and \
stylesheet tag so the browser refuses content that does not match the expected hash. For dependencies that \
change frequently, self-host a pinned copy instead.",
    references: &[
        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
    ],
};

const TABNABBING: CheckSpec = CheckSpec {
    id: "NATIVE-TABNABBING",
    title: "External Link Opens a New Tab without noopener",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1022",
    wstg: "WSTG-CLNT-14",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A link uses `target=\"_blank\"` to open an external site without `rel=\"noopener\"`. In \
older browsers the destination page receives a reference to the opener and can navigate the original tab \
to a phishing page while the user is looking at the new one — so they return to what appears to be your \
site asking them to log in again.",
    remediation: "Add `rel=\"noopener noreferrer\"` to every link using target=\"_blank\". Current browsers \
imply noopener for target=\"_blank\", but the attribute is still required for older clients and is trivial to add.",
    references: &[
        "https://owasp.org/www-community/attacks/Reverse_Tabnabbing",
    ],
};

const STACK_TRACE: CheckSpec = CheckSpec {
    id: "NATIVE-STACK-TRACE",
    title: "Stack Trace or Debug Output Returned to the Client",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-209",
    wstg: "WSTG-ERRH-02",
    owasp_2025: OWASP_EXCEPTIONS,
    api_top10: None,
    description: "The response contains a programming stack trace or framework debug page. These disclose \
internal file paths, library versions, database structure and sometimes fragments of configuration or \
credentials, giving an attacker a precise map of the technology in use and a head start on exploiting it. \
A visible debug page usually also means debug mode is enabled in production, which may expose an \
interactive console.",
    remediation: "Disable debug mode in production and install a global error handler that returns a \
generic message with a correlation identifier. Log the full detail server-side only, and make sure the \
correlation identifier — not the exception text — is what reaches the user.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces",
    ],
};

const COMMENT_LEAK: CheckSpec = CheckSpec {
    id: "NATIVE-COMMENT-LEAK",
    title: "Sensitive Information Disclosed in HTML Comments",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-615",
    wstg: "WSTG-INFO-05",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "HTML comments in the delivered page reference credentials, internal hosts, or \
development notes such as disabled security controls. Comments are visible to every visitor in the page \
source and routinely reveal internal endpoints and workarounds an attacker would otherwise never find.",
    remediation: "Strip comments from production markup during the build. Review the flagged comments and \
rotate anything credential-like they mention.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
    ],
};

const SESSION_IN_URL: CheckSpec = CheckSpec {
    id: "NATIVE-SESSION-IN-URL",
    title: "Session Token Exposed in URL",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-598",
    wstg: "WSTG-SESS-04",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "A session identifier or authentication token appears in a URL. URLs are written to \
browser history, server and proxy access logs, and are sent to third-party sites in the Referer header, so \
the token leaks to several parties who should never see it and typically remains valid when it does.",
    remediation: "Carry session state in cookies marked Secure, HttpOnly and SameSite — never in the query \
string or path. If a token must appear in a URL (for example a one-time email link), make it single-use and \
short-lived, and exchange it for a cookie-based session immediately on use.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables",
    ],
};

const AUTOCOMPLETE_ON: CheckSpec = CheckSpec {
    id: "NATIVE-PASSWORD-AUTOCOMPLETE",
    title: "Password Field Permits Autocomplete on a Shared-Use Form",
    cvss_vector: "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-522",
    wstg: "WSTG-ATHN-05",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "A password field does not set `autocomplete=\"off\"` or an equivalent value. On a shared \
or kiosk device the browser may store and later replay the credential for the next person to use the machine. \
Note that this is a low-priority observation: browser password managers are generally a net security benefit, \
and modern browsers ignore autocomplete=\"off\" on login forms deliberately.",
    remediation: "For ordinary login forms, no change is recommended — password managers encourage stronger, \
unique passwords. Set `autocomplete=\"new-password\"` on password-change fields, and consider \
`autocomplete=\"off\"` only on forms specifically intended for shared or kiosk devices.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/05-Testing_for_Vulnerable_Remember_Password",
    ],
};

/// Run every passive content check against one HTML response.
/// Every check this module can raise.
///
/// Exposed so the spec audit can walk all shipped checks and confirm each
/// one carries a coherent CVSS vector, severity band and taxonomy — a
/// finding whose stated severity disagrees with its score misinforms the
/// reader of the report.
pub const SPECS: &[CheckSpec] = &[
    MIXED_CONTENT,
    FORM_OVER_HTTP,
    SRI_MISSING,
    TABNABBING,
    STACK_TRACE,
    COMMENT_LEAK,
    SESSION_IN_URL,
    AUTOCOMPLETE_ON,
];

pub fn run(target_id: Uuid, scan_id: Uuid, resp: &ProbeResponse) -> Vec<Finding> {
    let mut findings = Vec::new();
    let url = resp.final_url.as_str();
    let body = &resp.body;

    let make = |spec: &CheckSpec, detail: String, steps: Vec<String>, evidence: String| {
        NativeFinding::build(
            spec,
            target_id,
            scan_id,
            url,
            &detail,
            steps,
            vec![NativeFinding::evidence("page_content", "Extract from response body", &evidence)],
        )
    };

    // Stack traces can appear on any content type, so check before the HTML gate.
    if let Some(marker) = detect_stack_trace(body) {
        findings.push(make(
            &STACK_TRACE,
            format!("The response body contains debug output matching '{marker}'."),
            vec![format!("curl -sS {url} | grep -iE 'traceback|stack trace|at [a-z.]+\\('")],
            truncate(&extract_around(body, marker, 400), 500),
        ));
    }

    if !is_html(resp) {
        return findings;
    }

    // ── Mixed content ────────────────────────────────────────────────────────
    if resp.is_https() {
        let insecure = find_insecure_subresources(body);
        if !insecure.is_empty() {
            findings.push(make(
                &MIXED_CONTENT,
                format!(
                    "{} active subresource(s) are referenced over http://: {}.",
                    insecure.len(),
                    truncate(&insecure.join(", "), 300)
                ),
                vec![format!("curl -sS {url} | grep -oE '(src|href)=\"http://[^\"]+\"'")],
                insecure.join("\n"),
            ));
        }
    }

    // ── Insecure credential submission ───────────────────────────────────────
    if let Some(detail) = detect_insecure_password_form(body, resp.is_https()) {
        findings.push(make(
            &FORM_OVER_HTTP,
            detail,
            vec![format!("curl -sS {url} | grep -iE '<form|type=\"password\"'")],
            truncate(&extract_around(body, "password", 300), 400),
        ));
    }

    // ── Subresource integrity ────────────────────────────────────────────────
    let unprotected = find_scripts_without_sri(body, resp.final_url.as_str());
    if !unprotected.is_empty() {
        findings.push(make(
            &SRI_MISSING,
            format!(
                "{} externally-hosted script(s) load without an integrity attribute: {}.",
                unprotected.len(),
                truncate(&unprotected.join(", "), 300)
            ),
            vec![format!("curl -sS {url} | grep -oE '<script[^>]+src=\"https?://[^\"]+\"[^>]*>'")],
            unprotected.join("\n"),
        ));
    }

    // ── Reverse tabnabbing ───────────────────────────────────────────────────
    let tabnab = find_unsafe_blank_links(body);
    if !tabnab.is_empty() {
        findings.push(make(
            &TABNABBING,
            format!(
                "{} link(s) use target=\"_blank\" without rel=\"noopener\": {}.",
                tabnab.len(),
                truncate(&tabnab.join(", "), 300)
            ),
            vec![format!("curl -sS {url} | grep -oE '<a[^>]+target=\"_blank\"[^>]*>'")],
            tabnab.join("\n"),
        ));
    }

    // ── Comment leakage ──────────────────────────────────────────────────────
    let leaky = find_sensitive_comments(body);
    if !leaky.is_empty() {
        findings.push(make(
            &COMMENT_LEAK,
            format!("{} HTML comment(s) reference sensitive material.", leaky.len()),
            vec![format!("curl -sS {url} | grep -oE '<!--.*-->'")],
            truncate(&leaky.join("\n"), 600),
        ));
    }

    // ── Session token in URL ─────────────────────────────────────────────────
    if let Some(param) = detect_session_in_url(&resp.final_url) {
        findings.push(make(
            &SESSION_IN_URL,
            format!("The URL carries a session-like parameter '{param}'."),
            vec!["Inspect the address bar after authenticating".into()],
            format!("URL: {}", truncate(&resp.final_url, 200)),
        ));
    }

    // ── Password autocomplete ────────────────────────────────────────────────
    if has_autocompletable_password_field(body) {
        findings.push(make(
            &AUTOCOMPLETE_ON,
            "A password input does not declare an autocomplete attribute.".into(),
            vec![format!("curl -sS {url} | grep -iE 'type=\"password\"'")],
            truncate(&extract_around(body, "type=\"password\"", 200), 300),
        ));
    }

    findings
}

// ── Detection helpers ────────────────────────────────────────────────────────

fn is_html(resp: &ProbeResponse) -> bool {
    resp.header("content-type")
        .map(|ct| ct.to_lowercase().contains("text/html"))
        .unwrap_or(false)
}

const STACK_TRACE_MARKERS: &[&str] = &[
    "traceback (most recent call last)",
    "stack trace:",
    "exception in thread",
    "java.lang.",
    "system.nullreferenceexception",
    "org.springframework",
    "at java.base/",
    "werkzeug debugger",
    "django.core.exceptions",
    "fatal error: uncaught",
    "warning: mysql_",
    "ora-0",
    "microsoft ole db provider",
    "unhandled exception",
    ".php on line",
    "node_modules/",
];

/// Return the first stack-trace marker present in the body.
pub fn detect_stack_trace(body: &str) -> Option<&'static str> {
    let lower = body.to_lowercase();
    STACK_TRACE_MARKERS
        .iter()
        .find(|marker| lower.contains(**marker))
        .copied()
}

/// Active subresources (script/iframe/link-stylesheet) loaded over plaintext HTTP.
pub fn find_insecure_subresources(body: &str) -> Vec<String> {
    let mut found = Vec::new();
    for tag in extract_tags(body, &["script", "iframe", "link"]) {
        let lower = tag.to_lowercase();
        // Stylesheets are active for this purpose; other link rels are not.
        if lower.starts_with("<link") && !lower.contains("stylesheet") {
            continue;
        }
        for attr in ["src=\"http://", "href=\"http://", "src='http://", "href='http://"] {
            if lower.contains(attr) {
                found.push(truncate(&tag, 160));
                break;
            }
        }
    }
    found.truncate(20);
    found
}

/// Detect a password form that would transmit credentials in clear text.
pub fn detect_insecure_password_form(body: &str, page_is_https: bool) -> Option<String> {
    let lower = body.to_lowercase();
    if !lower.contains("type=\"password\"") && !lower.contains("type='password'") {
        return None;
    }

    // A form action pointing explicitly at http:// is insecure regardless of
    // how the page itself was served.
    for tag in extract_tags(body, &["form"]) {
        let lower_tag = tag.to_lowercase();
        if lower_tag.contains("action=\"http://") || lower_tag.contains("action='http://") {
            return Some(format!(
                "A form containing a password field posts to a plaintext HTTP action: {}.",
                truncate(&tag, 200)
            ));
        }
    }

    if !page_is_https {
        return Some(
            "A password field is served on a page delivered over plaintext HTTP.".to_string(),
        );
    }
    None
}

/// External scripts lacking an integrity attribute.
pub fn find_scripts_without_sri(body: &str, page_url: &str) -> Vec<String> {
    let page_host = url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string));

    let mut found = Vec::new();
    for tag in extract_tags(body, &["script"]) {
        let lower = tag.to_lowercase();
        if !lower.contains("src=") {
            continue;
        }
        if lower.contains("integrity=") {
            continue;
        }
        let Some(src) = extract_attribute(&tag, "src") else { continue };
        // Only third-party origins matter: a same-origin script is covered by
        // the site's own deployment integrity.
        if !src.starts_with("http://") && !src.starts_with("https://") && !src.starts_with("//") {
            continue;
        }
        let src_host = url::Url::parse(&src)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .or_else(|| {
                src.strip_prefix("//")
                    .and_then(|rest| rest.split('/').next().map(str::to_string))
            });
        if src_host.is_some() && src_host == page_host {
            continue;
        }
        found.push(truncate(&src, 160));
    }
    found.truncate(20);
    found
}

/// Links opening a new tab without noopener protection.
pub fn find_unsafe_blank_links(body: &str) -> Vec<String> {
    let mut found = Vec::new();
    for tag in extract_tags(body, &["a"]) {
        let lower = tag.to_lowercase();
        if !lower.contains("target=\"_blank\"") && !lower.contains("target='_blank'") {
            continue;
        }
        if lower.contains("noopener") {
            continue;
        }
        // Only external destinations carry the risk.
        let Some(href) = extract_attribute(&tag, "href") else { continue };
        if !href.starts_with("http://") && !href.starts_with("https://") && !href.starts_with("//") {
            continue;
        }
        found.push(truncate(&href, 160));
    }
    found.truncate(20);
    found
}

const COMMENT_MARKERS: &[&str] = &[
    "password", "passwd", "secret", "api_key", "apikey", "api key", "token",
    "todo: remove", "fixme", "hack", "backdoor", "disabled security",
    "internal only", "do not deploy", "credential", "private key", "bearer ",
];

/// HTML comments referencing sensitive material.
pub fn find_sensitive_comments(body: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("<!--") {
        let after = &rest[start + 4..];
        let Some(end) = after.find("-->") else { break };
        let comment = &after[..end];
        let lower = comment.to_lowercase();
        if COMMENT_MARKERS.iter().any(|m| lower.contains(m)) {
            found.push(truncate(comment.trim(), 200));
        }
        rest = &after[end + 3..];
        if found.len() >= 10 {
            break;
        }
    }
    found
}

const SESSION_PARAMS: &[&str] = &[
    "sessionid", "session_id", "sid", "jsessionid", "phpsessid",
    "access_token", "auth_token", "authtoken", "apikey", "api_key", "jwt",
];

/// Detect a session-like parameter in a URL's query string.
pub fn detect_session_in_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    // jsessionid is conventionally a path parameter, not a query parameter.
    let path_lower = parsed.path().to_lowercase();
    if path_lower.contains(";jsessionid=") {
        return Some("jsessionid".to_string());
    }
    for (key, value) in parsed.query_pairs() {
        let k = key.to_lowercase();
        if SESSION_PARAMS.iter().any(|p| k == *p) && !value.is_empty() {
            return Some(key.to_string());
        }
    }
    None
}

/// A password input with no autocomplete attribute at all.
pub fn has_autocompletable_password_field(body: &str) -> bool {
    extract_tags(body, &["input"]).iter().any(|tag| {
        let lower = tag.to_lowercase();
        (lower.contains("type=\"password\"") || lower.contains("type='password'"))
            && !lower.contains("autocomplete=")
    })
}

// ── Lightweight tag scanning ─────────────────────────────────────────────────
//
// A full HTML parser is deliberately avoided: these checks only need to find
// opening tags and their attributes, and a dependency-free scanner keeps the
// native engine's footprint small enough to ship in the Windows build.

/// Extract opening tags for the named elements.
fn extract_tags(body: &str, names: &[&str]) -> Vec<String> {
    let mut tags = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &body[i..];
        let name_matches = names.iter().any(|n| {
            let with_space = format!("<{n} ");
            let with_close = format!("<{n}>");
            rest.len() >= with_space.len()
                && (rest[..with_space.len()].eq_ignore_ascii_case(&with_space)
                    || (rest.len() >= with_close.len()
                        && rest[..with_close.len()].eq_ignore_ascii_case(&with_close)))
        });
        if !name_matches {
            i += 1;
            continue;
        }
        match rest.find('>') {
            Some(end) => {
                tags.push(rest[..=end].to_string());
                i += end + 1;
            }
            None => break,
        }
        if tags.len() >= 200 {
            break;
        }
    }
    tags
}

/// Read an attribute value from a tag, tolerating single or double quotes.
fn extract_attribute(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_lowercase();
    for quote in ['"', '\''] {
        let needle = format!("{attr}={quote}");
        if let Some(start) = lower.find(&needle) {
            let value_start = start + needle.len();
            let remainder = &tag[value_start..];
            if let Some(end) = remainder.find(quote) {
                return Some(remainder[..end].to_string());
            }
        }
    }
    None
}

/// A window of text around the first occurrence of `needle` (case-insensitive).
fn extract_around(body: &str, needle: &str, window: usize) -> String {
    let lower = body.to_lowercase();
    let Some(idx) = lower.find(&needle.to_lowercase()) else {
        return truncate(body, window);
    };
    let start = idx.saturating_sub(window / 2);
    let end = (idx + needle.len() + window / 2).min(body.len());
    let start = (start..=idx).find(|i| body.is_char_boundary(*i)).unwrap_or(idx);
    let end = (idx..=end).rev().find(|i| body.is_char_boundary(*i)).unwrap_or(idx);
    body[start..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_traces_are_detected() {
        assert!(detect_stack_trace("Traceback (most recent call last):\n  File ...").is_some());
        assert!(detect_stack_trace("java.lang.NullPointerException").is_some());
        assert!(detect_stack_trace("<html><body>Welcome</body></html>").is_none());
    }

    #[test]
    fn insecure_subresources_are_found() {
        let body = r#"<script src="http://cdn.test/a.js"></script><script src="https://cdn.test/b.js"></script>"#;
        let found = find_insecure_subresources(body);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("http://cdn.test/a.js"));
    }

    #[test]
    fn non_stylesheet_links_are_not_mixed_content() {
        let body = r#"<link rel="alternate" href="http://old.test/feed.xml">"#;
        assert!(find_insecure_subresources(body).is_empty());
    }

    #[test]
    fn stylesheet_over_http_is_mixed_content() {
        let body = r#"<link rel="stylesheet" href="http://cdn.test/s.css">"#;
        assert_eq!(find_insecure_subresources(body).len(), 1);
    }

    #[test]
    fn password_form_posting_to_http_is_flagged_even_on_an_https_page() {
        let body = r#"<form action="http://insecure.test/login"><input type="password" name="p"></form>"#;
        let detail = detect_insecure_password_form(body, true).unwrap();
        assert!(detail.contains("plaintext HTTP action"));
    }

    #[test]
    fn password_form_on_http_page_is_flagged() {
        let body = r#"<form action="/login"><input type="password"></form>"#;
        assert!(detect_insecure_password_form(body, false).is_some());
    }

    #[test]
    fn secure_password_form_is_not_flagged() {
        let body = r#"<form action="/login"><input type="password"></form>"#;
        assert!(detect_insecure_password_form(body, true).is_none());
    }

    #[test]
    fn page_without_password_field_is_never_flagged() {
        assert!(detect_insecure_password_form("<form action=\"http://x.test/\"></form>", false).is_none());
    }

    #[test]
    fn external_scripts_without_sri_are_reported() {
        let body = r#"<script src="https://cdn.other.test/lib.js"></script>"#;
        let found = find_scripts_without_sri(body, "https://app.test/");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn same_origin_scripts_do_not_require_sri() {
        let body = r#"<script src="https://app.test/main.js"></script><script src="/local.js"></script>"#;
        assert!(find_scripts_without_sri(body, "https://app.test/").is_empty());
    }

    #[test]
    fn scripts_with_integrity_are_not_reported() {
        let body = r#"<script src="https://cdn.other.test/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>"#;
        assert!(find_scripts_without_sri(body, "https://app.test/").is_empty());
    }

    #[test]
    fn unsafe_blank_links_are_found() {
        let body = r#"<a href="https://external.test" target="_blank">x</a>"#;
        assert_eq!(find_unsafe_blank_links(body).len(), 1);
    }

    #[test]
    fn blank_links_with_noopener_are_safe() {
        let body = r#"<a href="https://external.test" target="_blank" rel="noopener noreferrer">x</a>"#;
        assert!(find_unsafe_blank_links(body).is_empty());
    }

    #[test]
    fn internal_blank_links_are_not_reported() {
        let body = r#"<a href="/docs" target="_blank">x</a>"#;
        assert!(find_unsafe_blank_links(body).is_empty());
    }

    #[test]
    fn sensitive_comments_are_extracted() {
        let body = "<!-- TODO: remove hardcoded password before launch --><!-- harmless note -->";
        let found = find_sensitive_comments(body);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("password"));
    }

    #[test]
    fn ordinary_comments_are_ignored() {
        assert!(find_sensitive_comments("<!-- layout starts here -->").is_empty());
    }

    #[test]
    fn session_tokens_in_query_strings_are_detected() {
        assert_eq!(
            detect_session_in_url("https://app.test/page?sessionid=abc123").as_deref(),
            Some("sessionid")
        );
        assert_eq!(
            detect_session_in_url("https://app.test/p?access_token=xyz").as_deref(),
            Some("access_token")
        );
    }

    #[test]
    fn jsessionid_path_parameter_is_detected() {
        assert_eq!(
            detect_session_in_url("https://app.test/page;jsessionid=ABC123").as_deref(),
            Some("jsessionid")
        );
    }

    #[test]
    fn ordinary_query_parameters_are_not_session_tokens() {
        assert!(detect_session_in_url("https://app.test/search?q=hello&page=2").is_none());
        // An empty value is not a token.
        assert!(detect_session_in_url("https://app.test/p?sid=").is_none());
    }

    #[test]
    fn autocomplete_detection_respects_the_attribute() {
        assert!(has_autocompletable_password_field(r#"<input type="password" name="p">"#));
        assert!(!has_autocompletable_password_field(
            r#"<input type="password" autocomplete="new-password">"#
        ));
    }

    #[test]
    fn tag_extraction_is_case_insensitive() {
        let tags = extract_tags(r#"<SCRIPT SRC="https://x.test/a.js"></SCRIPT>"#, &["script"]);
        assert_eq!(tags.len(), 1);
    }

    #[test]
    fn attribute_extraction_handles_both_quote_styles() {
        assert_eq!(
            extract_attribute(r#"<a href='https://x.test'>"#, "href").as_deref(),
            Some("https://x.test")
        );
        assert_eq!(
            extract_attribute(r#"<a href="https://y.test">"#, "href").as_deref(),
            Some("https://y.test")
        );
    }

    #[test]
    fn extract_around_handles_multibyte_bodies() {
        let body = "日本語 <input type=\"password\"> テキスト";
        let out = extract_around(body, "type=\"password\"", 40);
        assert!(out.contains("password"));
    }
}
