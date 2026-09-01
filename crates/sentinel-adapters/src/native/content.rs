//! Response-body analysis: mixed content, insecure forms, subresource
//! integrity, reverse tabnabbing, verbose errors and information leakage.
//!
//! Entirely passive — this module only reads a body that was already fetched.

use super::builder::{CheckSpec, NativeFinding};
use super::probe::{truncate, ProbeResponse};
use sentinel_core::models::finding::Finding;
use uuid::Uuid;

const OWASP_MISCONFIG: &str = "A02:2025-Security Misconfiguration";
const OWASP_ACCESS: &str = "A01:2025-Broken Access Control";
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
    // VC:L, not VC:H — a stack trace discloses paths, versions and structure. That
    // is partial disclosure; VC:H means total loss of confidentiality of the
    // vulnerable system's data, which a traceback does not cause.
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
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
    title: "Password Field Explicitly Opts Into Stored-Value Autocomplete",
    cvss_vector: "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-522",
    wstg: "WSTG-ATHN-05",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "A password input sets `autocomplete=\"on\"`, which asks the browser to offer previously \
stored passwords in this field. Where the field is collecting a *new* password — a registration or \
password-change form — that actively encourages the user to re-enter a credential they already use \
elsewhere, which is the reuse the form exists to prevent. On a shared or kiosk device it also makes the \
stored value available to the next person at the machine.\n\nThe absence of an autocomplete attribute is \
NOT reported: browser password managers are a net security gain, modern browsers ignore \
`autocomplete=\"off\"` on login forms, and flagging the default state produced a finding on virtually every \
login page assessed.",
    remediation: "Set `autocomplete=\"new-password\"` on registration and password-change fields, and \
`autocomplete=\"current-password\"` on the login field. Both are more specific than `on` and let a password \
manager behave correctly. Reserve `autocomplete=\"off\"` for forms genuinely intended for shared devices.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/05-Testing_for_Vulnerable_Remember_Password",
        "https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/autocomplete",
    ],
};

const FORM_NO_CSRF_TOKEN: CheckSpec = CheckSpec {
    id: "NATIVE-FORM-NO-CSRF-TOKEN",
    title: "State-Changing Form Without an Anti-CSRF Token",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-352",
    wstg: "WSTG-SESS-05",
    owasp_2025: OWASP_ACCESS,
    api_top10: None,
    description: "A form submits with `method=\"post\"` and carries no hidden field that looks like \
an anti-CSRF token. Without one, any site the user visits while logged in can submit the same form \
to this application on their behalf: the browser attaches the session cookie automatically, and the \
application cannot distinguish the forged request from a real one.\n\nModern browsers default \
cookies to `SameSite=Lax`, which blocks the classic cross-site POST and is why this is reported as \
a moderate rather than a severe issue. That default is a mitigation, not a control — it does not \
apply to a cookie explicitly set to `SameSite=None`, it does not cover same-site subdomain attacks, \
and it is not something the application gets to rely on for a client using an older browser.",
    remediation: "Issue a per-session token, render it into every state-changing form as a hidden \
field, and reject any POST whose token does not match the session. Most frameworks ship this: \
Django's `{% csrf_token %}`, Rails' `protect_from_forgery`, Spring Security's CSRF filter, \
`csurf` for Express. Set session cookies to `SameSite=Lax` or `Strict` as defence in depth, and \
for APIs consumed by script prefer a custom header the browser will not attach cross-origin.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
};

const IFRAME_NO_SANDBOX: CheckSpec = CheckSpec {
    id: "NATIVE-IFRAME-NO-SANDBOX",
    title: "Third-Party Frame Embedded Without a Sandbox",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1021",
    wstg: "WSTG-CLNT-13",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "An `<iframe>` loads content from another origin with no `sandbox` attribute. The \
framed document then runs with its full set of capabilities: it can run script, submit forms, open \
popups, trigger downloads, and navigate the top-level window away from your application — the last \
of which is a ready-made phishing primitive, because the address bar changes to somewhere the user \
did not choose to go while they believe they are still on your site.\n\nWhatever the third party \
serves, you are serving. If their content is compromised, it is compromised inside your page.",
    remediation: "Add a `sandbox` attribute listing only what the embedded content genuinely \
requires — `sandbox=\"allow-scripts\"` for an ordinary widget, adding `allow-same-origin` only if \
it must reach its own storage, and `allow-forms` only if it posts. Never combine `allow-scripts` \
with `allow-same-origin` for content you do not control: together they let the frame remove its own \
sandbox. Add `allow-top-navigation` only where it is deliberate, and pair the frame with a \
`Content-Security-Policy` `frame-src` directive naming the origins you permit.",
    references: &[
        "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#sandbox",
    ],
};

const LINK_DOWNGRADES_TRANSPORT: CheckSpec = CheckSpec {
    id: "NATIVE-LINK-DOWNGRADE",
    title: "Encrypted Page Links to Its Own Site over Plaintext HTTP",
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-319",
    wstg: "WSTG-CONF-07",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "A page served over HTTPS contains navigation links to `http://` URLs on its own \
site. Following one takes the user onto an unencrypted connection, and the request that does so \
carries their session cookie in clear text unless every cookie is marked Secure. An attacker on the \
network sees the request, and is positioned to answer it themselves before the server does.\n\nAn \
HSTS policy upgrades these links before they leave the browser, which is why the impact is limited \
where one is set — but only for a browser that has already seen the HSTS header for this host. The \
first visit, and any client that has never reached the site over HTTPS, is unprotected.",
    remediation: "Use protocol-relative or absolute HTTPS links, or better, root-relative paths so \
the scheme is inherited from the page. Add `Strict-Transport-Security` with `includeSubDomains` and \
submit the domain to the browser preload list, so a client is upgraded even on a first visit. \
`Content-Security-Policy: upgrade-insecure-requests` rewrites the remainder at load time as a \
backstop while the markup is corrected.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security",
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
    FORM_NO_CSRF_TOKEN,
    IFRAME_NO_SANDBOX,
    LINK_DOWNGRADES_TRANSPORT,
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

    // ── Cross-site request forgery ───────────────────────────────────────────
    let unprotected = find_posting_forms_without_tokens(body);
    if !unprotected.is_empty() {
        findings.push(make(
            &FORM_NO_CSRF_TOKEN,
            format!(
                "{} form(s) post without a hidden field that looks like an anti-CSRF token.",
                unprotected.len()
            ),
            vec![format!("curl -sS {url} | grep -iE '<form[^>]+post'")],
            unprotected.join("\n"),
        ));
    }

    // ── Framed third-party content ───────────────────────────────────────────
    let unsandboxed = find_unsandboxed_frames(body, resp.final_url.as_str());
    if !unsandboxed.is_empty() {
        findings.push(make(
            &IFRAME_NO_SANDBOX,
            format!(
                "{} cross-origin iframe(s) are embedded with no sandbox attribute: {}.",
                unsandboxed.len(),
                truncate(&unsandboxed.join(", "), 250)
            ),
            vec![format!("curl -sS {url} | grep -oE '<iframe[^>]+>'")],
            unsandboxed.join("\n"),
        ));
    }

    // ── Transport downgrade in navigation ────────────────────────────────────
    if resp.is_https() {
        let downgrades = find_plaintext_self_links(body, resp.final_url.as_str());
        if !downgrades.is_empty() {
            findings.push(make(
                &LINK_DOWNGRADES_TRANSPORT,
                format!(
                    "{} link(s) point at http:// URLs on this site: {}.",
                    downgrades.len(),
                    truncate(&downgrades.join(", "), 250)
                ),
                vec![format!("curl -sS {url} | grep -oE 'href=\"http://[^\"]+\"'")],
                downgrades.join("\n"),
            ));
        }
    }

    // ── Password autocomplete ────────────────────────────────────────────────
    if has_autocompletable_password_field(body) {
        findings.push(make(
            &AUTOCOMPLETE_ON,
            "A password input sets autocomplete=\"on\", asking the browser to offer stored passwords.".into(),
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

/// Markers that only appear in genuine debug output.
///
/// Two earlier entries were removed because they matched ordinary pages rather
/// than tracebacks, and each one raised a finding on most sites the engine saw:
///
/// * `node_modules/` appears in the `sourceMappingURL` comment and the vendor
///   chunk names of essentially every bundled JavaScript application. It is a
///   build artefact, not a leaked stack frame.
/// * `ora-0` was intended to catch Oracle `ORA-0xxxx` codes but is a substring
///   of ordinary words — "aurora-01", "fedora-0" — and matched them
///   case-insensitively. The Oracle codes are caught by `ORA-0` with its digits,
///   below, which cannot occur by accident in prose.
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
    "microsoft ole db provider",
    "unhandled exception",
    ".php on line",
    "call stack:",
    "psycopg2.errors",
    "system.data.sqlclient",
];

/// Oracle error codes, matched case-sensitively on the full `ORA-` prefix plus
/// five digits so they cannot be produced by ordinary words.
fn detect_oracle_error(body: &str) -> Option<&'static str> {
    let bytes = body.as_bytes();
    for (i, window) in bytes.windows(4).enumerate() {
        if window != b"ORA-" {
            continue;
        }
        let digits = bytes[i + 4..].iter().take(5).filter(|b| b.is_ascii_digit()).count();
        if digits == 5 {
            return Some("ORA-");
        }
    }
    None
}

/// Return the first stack-trace marker present in the body.
pub fn detect_stack_trace(body: &str) -> Option<&'static str> {
    let lower = body.to_lowercase();
    STACK_TRACE_MARKERS
        .iter()
        .find(|marker| lower.contains(**marker))
        .copied()
        .or_else(|| detect_oracle_error(body))
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
        // `noreferrer` implies `noopener` in every browser that supports it, so
        // a link carrying only `rel="noreferrer"` is protected. Matching on
        // "noopener" alone reported those as vulnerable — a false positive on
        // exactly the links a careful developer had already handled.
        if lower.contains("noopener") || lower.contains("noreferrer") {
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

/// Words that make an HTML comment worth reporting.
///
/// `hack` was removed: it is a substring of "hackathon", "growth hacking" and
/// any URL containing the word, and it raised a finding on marketing pages with
/// nothing sensitive in them at all. The remaining entries either name a secret
/// directly or are developer shorthand that does not occur in customer-facing
/// copy.
const COMMENT_MARKERS: &[&str] = &[
    "password", "passwd", "secret", "api_key", "apikey", "api key",
    "todo: remove", "fixme", "backdoor", "disabled security",
    "internal only", "do not deploy", "credential", "private key", "bearer ",
    "auth_token", "access_token", "connectionstring", "begin rsa",
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

/// Forms that POST without anything resembling an anti-CSRF token.
///
/// The token is matched by *name*, because its value is opaque and its field
/// name is the only thing conventions agree on. GET forms are excluded: they
/// should not change state, and reporting a search box would be noise.
pub fn find_posting_forms_without_tokens(body: &str) -> Vec<String> {
    const TOKEN_NAMES: &[&str] = &[
        "csrf", "xsrf", "authenticity_token", "__requestverificationtoken",
        "_token", "nonce", "anti-forgery", "antiforgery", "requestverificationtoken",
    ];

    let mut found = Vec::new();
    // Split on the opening tag and take everything up to the matching close, so
    // each chunk holds one form's inputs.
    for chunk in body.split("<form").skip(1) {
        let form = match chunk.find("</form") {
            Some(end) => &chunk[..end],
            // An unclosed form: look at a bounded window rather than the rest
            // of the document, which would drag in the next form's token.
            None => &chunk[..chunk.len().min(4000)],
        };
        let lower = form.to_lowercase();

        // Only state-changing submissions. A form with no method attribute
        // defaults to GET.
        if !lower.contains("method=\"post\"") && !lower.contains("method='post'") {
            continue;
        }
        if TOKEN_NAMES.iter().any(|name| lower.contains(name)) {
            continue;
        }

        let opening = form.find('>').map(|end| &form[..=end]).unwrap_or(form);
        found.push(truncate(&format!("<form{}", opening.trim()), 180));
        if found.len() >= 15 {
            break;
        }
    }
    found
}

/// Cross-origin iframes carrying no `sandbox` attribute.
///
/// Same-origin frames are excluded: a sandbox there would restrict the
/// application's own content, and the risk this check describes — a third party
/// running with full capability inside your page — does not apply.
pub fn find_unsandboxed_frames(body: &str, page_url: &str) -> Vec<String> {
    let page_host = url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string));

    let mut found = Vec::new();
    for tag in extract_tags(body, &["iframe"]) {
        let lower = tag.to_lowercase();
        if lower.contains("sandbox") {
            continue;
        }
        let Some(src) = extract_attribute(&tag, "src") else { continue };
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
        if found.len() >= 15 {
            break;
        }
    }
    found
}

/// `http://` links back to the page's own host.
///
/// Only same-host links are reported. A link to another site over plaintext is
/// that site's configuration to answer for, not this application's, and
/// reporting it would fill the finding with third-party URLs nobody here can
/// fix.
pub fn find_plaintext_self_links(body: &str, page_url: &str) -> Vec<String> {
    let Some(page_host) = url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
    else {
        return Vec::new();
    };

    let mut found = Vec::new();
    for tag in extract_tags(body, &["a", "link", "form"]) {
        for attr in ["href", "action"] {
            let Some(value) = extract_attribute(&tag, attr) else { continue };
            if !value.starts_with("http://") {
                continue;
            }
            let host = url::Url::parse(&value)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()));
            if host.as_deref() != Some(page_host.as_str()) {
                continue;
            }
            let entry = truncate(&value, 160);
            if !found.contains(&entry) {
                found.push(entry);
            }
        }
        if found.len() >= 15 {
            break;
        }
    }
    found
}

/// A password input that explicitly opts into unrestricted autocomplete.
///
/// This used to fire whenever a password field carried no `autocomplete`
/// attribute — which is the normal, recommended state of a login form, so it
/// raised a finding on virtually every application assessed. Browser vendors
/// and OWASP both now treat a managed password as a net security gain, and
/// modern browsers ignore `autocomplete="off"` on login forms outright.
///
/// What remains genuinely worth reporting is the opposite case: a field that
/// asks for a *new* or otherwise sensitive password and explicitly sets
/// `autocomplete="on"`, which tells the browser to offer previously stored
/// values in a context where reuse is exactly what the form is trying to avoid.
pub fn has_autocompletable_password_field(body: &str) -> bool {
    extract_tags(body, &["input"]).iter().any(|tag| {
        let lower = tag.to_lowercase();
        let is_password =
            lower.contains("type=\"password\"") || lower.contains("type='password'");
        let opts_in = lower.contains("autocomplete=\"on\"") || lower.contains("autocomplete='on'");
        is_password && opts_in
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

    /// The old rule fired on the *absence* of the attribute, which is the normal
    /// and recommended state of a login form — so it raised a finding on nearly
    /// every application assessed. Only the explicit opt-in is reported now.
    #[test]
    fn only_an_explicit_autocomplete_on_is_reported() {
        assert!(has_autocompletable_password_field(
            r#"<input type="password" autocomplete="on">"#
        ));
        assert!(has_autocompletable_password_field(
            r#"<input type='password' autocomplete='on'>"#
        ));

        for benign in [
            r#"<input type="password" name="p">"#,
            r#"<input type="password" autocomplete="new-password">"#,
            r#"<input type="password" autocomplete="current-password">"#,
            r#"<input type="password" autocomplete="off">"#,
        ] {
            assert!(
                !has_autocompletable_password_field(benign),
                "must not report {benign}"
            );
        }
    }

    /// `rel="noreferrer"` implies `noopener`, so a link carrying only that was
    /// protected all along and must not be reported.
    #[test]
    fn noreferrer_alone_protects_a_blank_target_link() {
        assert!(find_unsafe_blank_links(
            r#"<a href="https://other.test/" target="_blank" rel="noreferrer">x</a>"#
        )
        .is_empty());
        assert!(find_unsafe_blank_links(
            r#"<a href="https://other.test/" target="_blank" rel="noopener noreferrer">x</a>"#
        )
        .is_empty());
        // Still caught when neither is present.
        assert_eq!(
            find_unsafe_blank_links(r#"<a href="https://other.test/" target="_blank">x</a>"#).len(),
            1
        );
    }

    /// Both markers matched ordinary production pages and raised a stack-trace
    /// finding on sites that had never leaked one.
    #[test]
    fn bundler_paths_and_ordinary_words_are_not_stack_traces() {
        assert!(detect_stack_trace("//# sourceMappingURL=/static/node_modules/react/index.js.map").is_none());
        assert!(detect_stack_trace("<h1>Welcome to Aurora-01</h1>").is_none());
        assert!(detect_stack_trace("Fedora-05 release notes").is_none());
    }

    /// A real Oracle code still has to be caught.
    #[test]
    fn a_genuine_oracle_error_code_is_still_detected() {
        assert_eq!(
            detect_stack_trace("ORA-01722: invalid number"),
            Some("ORA-")
        );
        assert!(detect_stack_trace("ora-01722 lowercase prose").is_none());
    }

    #[test]
    fn marketing_copy_mentioning_hacking_is_not_a_leaked_comment() {
        assert!(find_sensitive_comments("<!-- our growth hacking playbook -->").is_empty());
        assert!(find_sensitive_comments("<!-- see /blog/hackathon-2024 -->").is_empty());
        // A genuinely sensitive comment still reports.
        assert_eq!(
            find_sensitive_comments("<!-- api_key=AKIA1234 -->").len(),
            1
        );
    }

    // ── CSRF ────────────────────────────────────────────────────────────────

    #[test]
    fn a_posting_form_with_no_token_is_reported() {
        let found = find_posting_forms_without_tokens(
            r#"<form method="post" action="/transfer"><input name="amount"></form>"#,
        );
        assert_eq!(found.len(), 1, "{found:?}");
    }

    #[test]
    fn a_form_carrying_any_conventional_token_name_is_protected() {
        for field in [
            r#"<input type="hidden" name="csrf_token" value="x">"#,
            r#"<input type="hidden" name="authenticity_token" value="x">"#,
            r#"<input type="hidden" name="__RequestVerificationToken" value="x">"#,
            r#"<input type="hidden" name="_token" value="x">"#,
        ] {
            let body = format!(r#"<form method="post" action="/t">{field}</form>"#);
            assert!(
                find_posting_forms_without_tokens(&body).is_empty(),
                "should be protected: {field}"
            );
        }
    }

    /// A search box is not a state-changing request, and reporting one would be
    /// noise on nearly every site.
    #[test]
    fn a_get_form_is_not_a_csrf_finding() {
        assert!(find_posting_forms_without_tokens(
            r#"<form method="get" action="/search"><input name="q"></form>"#
        )
        .is_empty());
        // No method attribute defaults to GET.
        assert!(find_posting_forms_without_tokens(r#"<form action="/search"></form>"#).is_empty());
    }

    /// Without a bounded window an unclosed form would absorb the next form's
    /// token and report the wrong one as protected.
    #[test]
    fn two_forms_are_judged_independently() {
        let body = r#"<form method="post"><input name="csrf_token"></form>
                      <form method="post" action="/b"><input name="x"></form>"#;
        let found = find_posting_forms_without_tokens(body);
        assert_eq!(found.len(), 1, "only the second form is unprotected: {found:?}");
        assert!(found[0].contains("/b"), "{found:?}");
    }

    // ── iframes ─────────────────────────────────────────────────────────────

    #[test]
    fn a_cross_origin_frame_without_sandbox_is_reported() {
        let found = find_unsandboxed_frames(
            r#"<iframe src="https://widget.other.test/w"></iframe>"#,
            "https://app.test/",
        );
        assert_eq!(found, vec!["https://widget.other.test/w".to_string()]);
    }

    #[test]
    fn a_sandboxed_or_same_origin_frame_is_not_reported() {
        assert!(find_unsandboxed_frames(
            r#"<iframe src="https://widget.other.test/w" sandbox="allow-scripts"></iframe>"#,
            "https://app.test/",
        )
        .is_empty());
        // Sandboxing your own content would restrict the application itself.
        assert!(find_unsandboxed_frames(
            r#"<iframe src="https://app.test/inner"></iframe>"#,
            "https://app.test/",
        )
        .is_empty());
    }

    // ── Transport downgrade ─────────────────────────────────────────────────

    #[test]
    fn a_plaintext_link_back_to_this_site_is_reported() {
        let found = find_plaintext_self_links(
            r#"<a href="http://app.test/legacy">old</a>"#,
            "https://app.test/",
        );
        assert_eq!(found, vec!["http://app.test/legacy".to_string()]);
    }

    /// Another site's transport is that site's configuration to answer for, and
    /// reporting it would fill the finding with URLs nobody here can fix.
    #[test]
    fn a_plaintext_link_to_another_site_is_not_this_applications_finding() {
        assert!(find_plaintext_self_links(
            r#"<a href="http://someone-else.test/x">x</a>"#,
            "https://app.test/",
        )
        .is_empty());
        assert!(find_plaintext_self_links(
            r#"<a href="https://app.test/fine">ok</a><a href="/relative">ok</a>"#,
            "https://app.test/",
        )
        .is_empty());
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
