//! Security response header, Content-Security-Policy and cookie checks.
//!
//! All checks in this module are passive: they analyse a response that was
//! already fetched. No additional request is issued and no payload is sent.

use super::builder::{CheckSpec, NativeFinding};
use super::probe::{truncate, ProbeResponse};
use sentinel_core::models::finding::Finding;
use uuid::Uuid;

const OWASP_MISCONFIG: &str = "A02:2025-Security Misconfiguration";
const OWASP_CRYPTO: &str = "A04:2025-Cryptographic Failures";

// ── Specifications ───────────────────────────────────────────────────────────

const HSTS_MISSING: CheckSpec = CheckSpec {
    id: "NATIVE-HSTS-MISSING",
    title: "HTTP Strict Transport Security (HSTS) Not Enforced",
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-319",
    wstg: "WSTG-CONF-07",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "The application is served over HTTPS but does not send a Strict-Transport-Security \
response header. Without HSTS a browser will still attempt an initial plaintext HTTP request, which \
an attacker positioned on the network can intercept and downgrade before the redirect to HTTPS occurs \
(an SSL-stripping attack).",
    remediation: "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS \
response. Once the policy has been verified in production, consider adding `preload` and submitting the \
domain to hstspreload.org so the protection applies even on a user's first visit.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
    ],
};

const HSTS_WEAK: CheckSpec = CheckSpec {
    id: "NATIVE-HSTS-WEAK",
    title: "HSTS Policy Too Short or Incomplete",
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-319",
    wstg: "WSTG-CONF-07",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "A Strict-Transport-Security header is present but its policy is weaker than the \
recommended baseline — either the max-age is below one year, or includeSubDomains is absent, leaving \
subdomains reachable over plaintext HTTP.",
    remediation: "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`. A max-age below \
31536000 (one year) shortens the window in which a returning visitor is protected.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
    ],
};

const CSP_MISSING: CheckSpec = CheckSpec {
    id: "NATIVE-CSP-MISSING",
    title: "Content-Security-Policy Header Absent",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1021",
    wstg: "WSTG-CONF-12",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "No Content-Security-Policy header is returned. CSP is the primary defence-in-depth \
control that limits the impact of a cross-site scripting flaw by restricting which script, style and \
frame sources a browser will load. Without it, any injection flaw escalates directly to full script \
execution in the user's session.",
    remediation: "Deploy a Content-Security-Policy. Start in report-only mode to find breakages: \
`Content-Security-Policy-Report-Only: default-src 'self'; object-src 'none'; base-uri 'self'; \
frame-ancestors 'none'`. Prefer a nonce- or hash-based script-src over allow-listing hosts, then switch \
to the enforcing header once the report endpoint is quiet.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    ],
};

const CSP_WEAK: CheckSpec = CheckSpec {
    id: "NATIVE-CSP-WEAK",
    title: "Content-Security-Policy Contains Unsafe Directives",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1021",
    wstg: "WSTG-CONF-12",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A Content-Security-Policy is present but contains directives that substantially \
weaken or negate its protection. Values such as 'unsafe-inline', 'unsafe-eval' or a wildcard source \
allow an attacker who finds an injection point to execute script despite the policy.",
    remediation: "Remove 'unsafe-inline' and 'unsafe-eval' from script-src and style-src; replace inline \
handlers with external files or per-response nonces. Replace wildcard sources with explicit origins. \
Always set `object-src 'none'` and `base-uri 'self'`, which cannot be inherited from default-src.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        "https://csp-evaluator.withgoogle.com/",
    ],
};

const XFO_MISSING: CheckSpec = CheckSpec {
    id: "NATIVE-CLICKJACKING",
    title: "Clickjacking Protection Missing (No frame-ancestors or X-Frame-Options)",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1021",
    wstg: "WSTG-CLNT-09",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "The response sets neither a CSP `frame-ancestors` directive nor an X-Frame-Options \
header, so the page can be embedded in an invisible frame on an attacker-controlled site. A victim can \
then be tricked into clicking controls they cannot see — approving a transfer or changing a setting — \
while believing they are interacting with the attacker's page.",
    remediation: "Add `Content-Security-Policy: frame-ancestors 'none'` (or `'self'` if the application \
frames itself) to every HTML response. Keep `X-Frame-Options: DENY` alongside it for older browsers that \
do not honour frame-ancestors.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
    ],
};

const XCTO_MISSING: CheckSpec = CheckSpec {
    id: "NATIVE-XCTO-MISSING",
    title: "X-Content-Type-Options Header Missing (MIME Sniffing Permitted)",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-430",
    wstg: "WSTG-CONF-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "The response does not send `X-Content-Type-Options: nosniff`. Browsers may therefore \
ignore the declared Content-Type and infer the type from the content itself, so a file uploaded as a \
harmless type can be re-interpreted as HTML or JavaScript and executed in the site's origin.",
    remediation: "Send `X-Content-Type-Options: nosniff` on every response, and make sure user-uploaded \
content is served with an accurate Content-Type from a separate origin or with Content-Disposition: attachment.",
    references: &["https://owasp.org/www-project-secure-headers/#x-content-type-options"],
};

const REFERRER_MISSING: CheckSpec = CheckSpec {
    id: "NATIVE-REFERRER-POLICY",
    title: "Referrer-Policy Not Set or Overly Permissive",
    // UI:P — nothing leaks until a user navigates off-site and carries the
    // referrer with them, so the disclosure is contingent on user interaction.
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-200",
    wstg: "WSTG-CONF-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "No restrictive Referrer-Policy is set, so the browser may send the full URL of the \
current page — including any identifiers or tokens embedded in the path or query string — to third-party \
sites in the Referer header when a user follows an external link or loads an external resource.",
    remediation: "Send `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer` where no \
referrer is needed). Independently, stop placing session tokens or record identifiers in URLs.",
    references: &["https://owasp.org/www-project-secure-headers/#referrer-policy"],
};

const PERMISSIONS_MISSING: CheckSpec = CheckSpec {
    id: "NATIVE-PERMISSIONS-POLICY",
    title: "Permissions-Policy Header Not Set",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-16",
    wstg: "WSTG-CONF-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "No Permissions-Policy header is present. This header lets the application explicitly \
disable powerful browser features (camera, microphone, geolocation, payment) for itself and any embedded \
frames, reducing what an injected script or a compromised third-party frame can reach.",
    remediation: "Send a restrictive default such as \
`Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()` and enable only the \
features the application genuinely uses.",
    references: &["https://owasp.org/www-project-secure-headers/#permissions-policy"],
};

const SERVER_BANNER: CheckSpec = CheckSpec {
    id: "NATIVE-BANNER-DISCLOSURE",
    title: "Server Software Version Disclosed in Response Headers",
    // A version string is not protected data, so there is no confidentiality
    // impact to the vulnerable system. VC:L scored this 6.9 (Medium), which
    // put a banner on the same footing as a real data exposure.
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-200",
    wstg: "WSTG-INFO-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "Response headers disclose the exact server or framework version in use. This does not \
create a vulnerability on its own, but it lets an attacker skip reconnaissance and go straight to exploits \
matching the disclosed version, and it makes the host easy to find in mass-scanning datasets.",
    remediation: "Suppress version detail in banners: `server_tokens off` (nginx), \
`ServerTokens Prod` and `ServerSignature Off` (Apache), and remove `X-Powered-By`, `X-AspNet-Version` and \
`X-AspNetMvc-Version` at the application or reverse-proxy layer.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
    ],
};

const COOKIE_INSECURE: CheckSpec = CheckSpec {
    id: "NATIVE-COOKIE-INSECURE",
    title: "Session Cookie Missing Secure Attribute",
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-614",
    wstg: "WSTG-SESS-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A cookie that appears to carry session state is set without the `Secure` attribute. \
The browser will therefore send it over plaintext HTTP, allowing anyone on the network path to capture \
the session identifier and impersonate the user.",
    remediation: "Add the `Secure` attribute to every cookie carrying session or authentication state, \
and serve the application exclusively over HTTPS with HSTS enabled.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies",
    ],
};

const COOKIE_NO_HTTPONLY: CheckSpec = CheckSpec {
    id: "NATIVE-COOKIE-HTTPONLY",
    title: "Session Cookie Missing HttpOnly Attribute",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1004",
    wstg: "WSTG-SESS-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A session cookie is set without the `HttpOnly` attribute, so it is readable from \
JavaScript via document.cookie. Any cross-site scripting flaw anywhere in the application can then \
exfiltrate the session token directly, turning a contained XSS into full account takeover.",
    remediation: "Add the `HttpOnly` attribute to all session and authentication cookies. Application \
JavaScript should never need to read them; if it does, move that state to a separate non-session cookie.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies",
    ],
};

const COOKIE_NO_SAMESITE: CheckSpec = CheckSpec {
    id: "NATIVE-COOKIE-SAMESITE",
    title: "Session Cookie Missing or Weak SameSite Attribute",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1275",
    wstg: "WSTG-SESS-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A session cookie does not declare a `SameSite` attribute, or declares `SameSite=None`. \
Without at least `Lax`, the cookie is attached to cross-site requests, which is the precondition for \
cross-site request forgery.",
    remediation: "Set `SameSite=Lax` on session cookies (or `Strict` where no cross-site navigation flow \
is required). Use `SameSite=None; Secure` only for cookies that genuinely must travel cross-site, and pair \
it with anti-CSRF tokens.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
};

const SESSION_LONG_LIVED: CheckSpec = CheckSpec {
    id: "NATIVE-SESSION-LIFETIME",
    title: "Session Cookie Persists Far Beyond a Working Session",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-613",
    wstg: "WSTG-SESS-07",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "The session cookie is issued as a persistent cookie with a lifetime measured in days rather than as a browser-session cookie. It therefore survives the browser being closed, and any party who later obtains the stored cookie — on a shared or stolen device, from a backup, or through client-side disclosure — can resume the session without ever seeing a credential. A long cookie lifetime also widens the window in which a session stolen by any other means stays usable.",
    remediation: "Issue session cookies without `Max-Age` or `Expires` so the browser discards them when it closes, and enforce both an idle timeout and an absolute timeout on the server. Where a \"remember me\" feature genuinely needs persistence, use a separate long-lived token that is exchanged for a fresh short session and can be revoked independently.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    ],
};

const CACHE_SENSITIVE: CheckSpec = CheckSpec {
    id: "NATIVE-CACHE-CONTROL",
    title: "Authenticated Response Cacheable by Browsers and Proxies",
    cvss_vector: "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-525",
    wstg: "WSTG-ATHN-06",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A response that sets a session cookie does not send cache-suppressing headers. Shared \
proxies and the browser's on-disk cache may retain the page, leaving personal data readable by the next \
person to use the device or by an unrelated user behind the same proxy.",
    remediation: "Send `Cache-Control: no-store` (plus `Pragma: no-cache` for HTTP/1.0 intermediaries) on \
every authenticated or personalised response.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses",
    ],
};

// ── Checks ───────────────────────────────────────────────────────────────────

/// Run every passive header/cookie check against one response.
/// Every check this module can raise.
///
/// Exposed so the spec audit can walk all shipped checks and confirm each
/// one carries a coherent CVSS vector, severity band and taxonomy — a
/// finding whose stated severity disagrees with its score misinforms the
/// reader of the report.
pub const SPECS: &[CheckSpec] = &[
    HSTS_MISSING,
    HSTS_WEAK,
    CSP_MISSING,
    CSP_WEAK,
    XFO_MISSING,
    XCTO_MISSING,
    REFERRER_MISSING,
    PERMISSIONS_MISSING,
    SERVER_BANNER,
    COOKIE_INSECURE,
    COOKIE_NO_HTTPONLY,
    COOKIE_NO_SAMESITE,
    SESSION_LONG_LIVED,
    CACHE_SENSITIVE,
];

pub fn run(target_id: Uuid, scan_id: Uuid, resp: &ProbeResponse) -> Vec<Finding> {
    let mut findings = Vec::new();
    let url = resp.final_url.as_str();
    let ev = |content: &str| NativeFinding::evidence("http_response", "Response headers", content);

    let make = |spec: &CheckSpec, detail: String, steps: Vec<String>, evidence: Vec<_>| {
        NativeFinding::build(spec, target_id, scan_id, url, &detail, steps, evidence)
    };

    // ── HSTS (only meaningful over HTTPS) ────────────────────────────────────
    if resp.is_https() {
        match resp.header("strict-transport-security") {
            None => findings.push(make(
                &HSTS_MISSING,
                "No Strict-Transport-Security header was returned on an HTTPS response.".into(),
                vec![format!("curl -sSI {url} | grep -i strict-transport-security")],
                vec![ev(&resp.evidence_summary())],
            )),
            Some(value) => {
                if let Some(detail) = weak_hsts(&value) {
                    findings.push(make(
                        &HSTS_WEAK,
                        detail,
                        vec![format!("curl -sSI {url} | grep -i strict-transport-security")],
                        vec![ev(&format!("Strict-Transport-Security: {}", truncate(&value, 300)))],
                    ));
                }
            }
        }
    }

    // ── CSP ──────────────────────────────────────────────────────────────────
    let csp = resp
        .header("content-security-policy")
        .or_else(|| resp.header("content-security-policy-report-only"));
    match &csp {
        None => findings.push(make(
            &CSP_MISSING,
            "Neither Content-Security-Policy nor Content-Security-Policy-Report-Only was returned."
                .into(),
            vec![format!("curl -sSI {url} | grep -i content-security-policy")],
            vec![ev(&resp.evidence_summary())],
        )),
        Some(policy) => {
            let issues = analyze_csp(policy);
            if !issues.is_empty() {
                findings.push(make(
                    &CSP_WEAK,
                    issues.join(" "),
                    vec![
                        format!("curl -sSI {url} | grep -i content-security-policy"),
                        "Paste the policy into https://csp-evaluator.withgoogle.com/ to confirm".into(),
                    ],
                    vec![ev(&format!(
                        "Content-Security-Policy: {}",
                        truncate(policy, 1000)
                    ))],
                ));
            }
        }
    }

    // ── Clickjacking ─────────────────────────────────────────────────────────
    let frame_ancestors_set = csp
        .as_ref()
        .map(|p| p.to_lowercase().contains("frame-ancestors"))
        .unwrap_or(false);
    let xfo = resp.header("x-frame-options");
    if !frame_ancestors_set && xfo.is_none() && is_html(resp) {
        findings.push(make(
            &XFO_MISSING,
            "Neither CSP frame-ancestors nor X-Frame-Options was present on an HTML response.".into(),
            vec![format!("curl -sSI {url} | grep -iE 'x-frame-options|frame-ancestors'")],
            vec![ev(&resp.evidence_summary())],
        ));
    }

    // ── X-Content-Type-Options ───────────────────────────────────────────────
    let nosniff = resp
        .header("x-content-type-options")
        .map(|v| v.to_lowercase().contains("nosniff"))
        .unwrap_or(false);
    if !nosniff {
        findings.push(make(
            &XCTO_MISSING,
            "Header absent or not set to 'nosniff'.".into(),
            vec![format!("curl -sSI {url} | grep -i x-content-type-options")],
            vec![ev(&resp.evidence_summary())],
        ));
    }

    // ── Referrer-Policy ──────────────────────────────────────────────────────
    let referrer_ok = resp
        .header("referrer-policy")
        .map(|v| is_strict_referrer_policy(&v))
        .unwrap_or(false);
    if !referrer_ok {
        let observed = resp
            .header("referrer-policy")
            .map(|v| format!("Referrer-Policy is '{}'.", truncate(&v, 100)))
            .unwrap_or_else(|| "No Referrer-Policy header was returned.".to_string());
        findings.push(make(
            &REFERRER_MISSING,
            observed,
            vec![format!("curl -sSI {url} | grep -i referrer-policy")],
            vec![ev(&resp.evidence_summary())],
        ));
    }

    // ── Permissions-Policy (informational) ───────────────────────────────────
    if resp.header("permissions-policy").is_none() && is_html(resp) {
        findings.push(make(
            &PERMISSIONS_MISSING,
            "No Permissions-Policy header was returned.".into(),
            vec![format!("curl -sSI {url} | grep -i permissions-policy")],
            vec![ev(&resp.evidence_summary())],
        ));
    }

    // ── Version banners ──────────────────────────────────────────────────────
    let mut banners = Vec::new();
    for header in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"] {
        if let Some(value) = resp.header(header) {
            if discloses_version(&value) {
                banners.push(format!("{header}: {}", truncate(&value, 120)));
            }
        }
    }
    if !banners.is_empty() {
        findings.push(make(
            &SERVER_BANNER,
            format!("Version-bearing headers observed — {}.", banners.join("; ")),
            vec![format!("curl -sSI {url} | grep -iE 'server|x-powered-by|x-aspnet'")],
            vec![ev(&banners.join("\n"))],
        ));
    }

    // ── Cookies ──────────────────────────────────────────────────────────────
    let set_cookies = resp.header_all("set-cookie");
    let mut saw_session_cookie = false;
    for raw in &set_cookies {
        let cookie = ParsedCookie::parse(raw);
        if !cookie.looks_like_session() {
            continue;
        }
        saw_session_cookie = true;
        // Only the cookie name and its attributes reach the report — never the value.
        let redacted = cookie.redacted();

        if !cookie.secure && resp.is_https() {
            findings.push(make(
                &COOKIE_INSECURE,
                format!("Cookie '{}' is set without the Secure attribute.", cookie.name),
                vec![format!("curl -sSI {url} | grep -i set-cookie")],
                vec![NativeFinding::evidence("http_response", "Set-Cookie (value redacted)", &redacted)],
            ));
        }
        if !cookie.http_only {
            findings.push(make(
                &COOKIE_NO_HTTPONLY,
                format!("Cookie '{}' is set without the HttpOnly attribute.", cookie.name),
                vec![format!("curl -sSI {url} | grep -i set-cookie")],
                vec![NativeFinding::evidence("http_response", "Set-Cookie (value redacted)", &redacted)],
            ));
        }
        // A persistent session cookie outlives the browser. Anything past a
        // working day is treated as persistence rather than a session; a cookie
        // with no lifetime at all is the correct case and is not flagged.
        const A_WORKING_DAY: i64 = 12 * 60 * 60;
        if let Some(lifetime) = cookie.lifetime_seconds() {
            if lifetime > A_WORKING_DAY {
                findings.push(make(
                    &SESSION_LONG_LIVED,
                    format!(
                        "Cookie '{}' is issued with a lifetime of {} ({} seconds), so it survives the browser closing.",
                        cookie.name,
                        humanise_duration(lifetime),
                        lifetime
                    ),
                    vec![format!("curl -sSI {url} | grep -i set-cookie")],
                    vec![NativeFinding::evidence("http_response", "Set-Cookie (value redacted)", &redacted)],
                ));
            }
        }
        match cookie.same_site.as_deref() {
            None => findings.push(make(
                &COOKIE_NO_SAMESITE,
                format!("Cookie '{}' declares no SameSite attribute.", cookie.name),
                vec![format!("curl -sSI {url} | grep -i set-cookie")],
                vec![NativeFinding::evidence("http_response", "Set-Cookie (value redacted)", &redacted)],
            )),
            Some(v) if v.eq_ignore_ascii_case("none") => findings.push(make(
                &COOKIE_NO_SAMESITE,
                format!("Cookie '{}' declares SameSite=None, permitting cross-site transmission.", cookie.name),
                vec![format!("curl -sSI {url} | grep -i set-cookie")],
                vec![NativeFinding::evidence("http_response", "Set-Cookie (value redacted)", &redacted)],
            )),
            _ => {}
        }
    }

    // ── Cache-Control on session-bearing responses ───────────────────────────
    if saw_session_cookie && !suppresses_cache(resp) {
        findings.push(make(
            &CACHE_SENSITIVE,
            "The response sets a session cookie but does not send Cache-Control: no-store.".into(),
            vec![format!("curl -sSI {url} | grep -iE 'cache-control|pragma'")],
            vec![ev(&resp.evidence_summary())],
        ));
    }

    findings
}

// ── Analysis helpers ─────────────────────────────────────────────────────────

fn is_html(resp: &ProbeResponse) -> bool {
    resp.header("content-type")
        .map(|ct| ct.to_lowercase().contains("text/html"))
        .unwrap_or(false)
}

/// Returns a description of the weakness when the HSTS policy is below baseline.
pub fn weak_hsts(value: &str) -> Option<String> {
    let lower = value.to_lowercase();
    let max_age = lower
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("max-age="))
        .and_then(|v| v.trim().parse::<u64>().ok());

    let mut problems = Vec::new();
    match max_age {
        None => problems.push("no max-age directive is present".to_string()),
        Some(age) if age < 31_536_000 => problems.push(format!(
            "max-age is {age} seconds, below the recommended 31536000 (one year)"
        )),
        Some(_) => {}
    }
    if !lower.contains("includesubdomains") {
        problems.push("includeSubDomains is absent, so subdomains are not covered".to_string());
    }

    if problems.is_empty() {
        None
    } else {
        Some(format!("HSTS policy '{}' — {}.", truncate(value, 120), problems.join("; ")))
    }
}

/// Identify directives that materially weaken a Content-Security-Policy.
pub fn analyze_csp(policy: &str) -> Vec<String> {
    let lower = policy.to_lowercase();
    let mut issues = Vec::new();

    if lower.contains("'unsafe-inline'") {
        issues.push("'unsafe-inline' permits inline scripts or styles, which defeats the policy's XSS protection.".to_string());
    }
    if lower.contains("'unsafe-eval'") {
        issues.push("'unsafe-eval' permits eval() and equivalents, allowing string-to-code execution.".to_string());
    }
    if directive_has_wildcard(&lower, "default-src") || directive_has_wildcard(&lower, "script-src") {
        issues.push("A wildcard (*) source allows scripts from any origin.".to_string());
    }
    if lower.contains("data:") && (lower.contains("script-src") || lower.contains("default-src")) {
        issues.push("A data: scheme source in a script context allows inline payloads to be loaded as script.".to_string());
    }
    if !lower.contains("object-src") {
        issues.push("object-src is not set; plugin content is not restricted (it does not inherit from default-src in all browsers).".to_string());
    }
    if !lower.contains("base-uri") {
        issues.push("base-uri is not set, so an injected <base> tag can redirect every relative URL on the page.".to_string());
    }

    issues
}

/// Whether a named directive contains a bare `*` source.
fn directive_has_wildcard(lower_policy: &str, directive: &str) -> bool {
    lower_policy
        .split(';')
        .map(str::trim)
        .filter(|d| d.starts_with(directive))
        .any(|d| {
            d.trim_start_matches(directive)
                .split_whitespace()
                .any(|token| token == "*")
        })
}

fn is_strict_referrer_policy(value: &str) -> bool {
    let v = value.to_lowercase();
    v.contains("no-referrer")
        || v.contains("same-origin")
        || v.contains("strict-origin")
}

fn suppresses_cache(resp: &ProbeResponse) -> bool {
    resp.header("cache-control")
        .map(|v| {
            let v = v.to_lowercase();
            v.contains("no-store") || (v.contains("no-cache") && v.contains("private"))
        })
        .unwrap_or(false)
}

/// Whether a banner string carries a version number worth reporting.
pub fn discloses_version(value: &str) -> bool {
    // A digit followed by a dot and another digit is the signal (e.g. nginx/1.18.0).
    let bytes: Vec<char> = value.chars().collect();
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i].is_ascii_digit() && bytes[i + 1] == '.' && bytes[i + 2].is_ascii_digit() {
            return true;
        }
    }
    // ASP.NET-style headers disclose the stack even without a dotted version.
    value.to_lowercase().contains("asp.net")
}

/// Render a duration in seconds as the largest sensible unit, for report prose.
fn humanise_duration(seconds: i64) -> String {
    const DAY: i64 = 86_400;
    const HOUR: i64 = 3_600;
    if seconds >= DAY {
        let days = seconds / DAY;
        format!("{days} day{}", if days == 1 { "" } else { "s" })
    } else {
        let hours = seconds / HOUR;
        format!("{hours} hour{}", if hours == 1 { "" } else { "s" })
    }
}

/// A parsed Set-Cookie header.
#[derive(Debug, Clone)]
pub struct ParsedCookie {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub attributes: Vec<String>,
}

impl ParsedCookie {
    pub fn parse(raw: &str) -> Self {
        let mut parts = raw.split(';');
        let name = parts
            .next()
            .and_then(|nv| nv.split('=').next())
            .unwrap_or("")
            .trim()
            .to_string();

        let mut secure = false;
        let mut http_only = false;
        let mut same_site = None;
        let mut attributes = Vec::new();

        for part in raw.split(';').skip(1) {
            let attr = part.trim();
            let lower = attr.to_lowercase();
            if lower == "secure" {
                secure = true;
            } else if lower == "httponly" {
                http_only = true;
            } else if let Some(v) = lower.strip_prefix("samesite=") {
                same_site = Some(v.trim().to_string());
            }
            attributes.push(attr.to_string());
        }

        Self { name, secure, http_only, same_site, attributes }
    }

    /// How long the browser is told to keep this cookie, in seconds.
    ///
    /// `None` means the cookie carries neither `Max-Age` nor `Expires`, which
    /// makes it a browser-session cookie: it is discarded when the browser
    /// closes. That is the desirable case for a session cookie, so callers must
    /// not treat `None` as "no limit".
    ///
    /// `Max-Age` wins over `Expires` where both appear, as RFC 6265 requires.
    pub fn lifetime_seconds(&self) -> Option<i64> {
        for attr in &self.attributes {
            let lower = attr.to_lowercase();
            if let Some(v) = lower.strip_prefix("max-age=") {
                return v.trim().parse::<i64>().ok();
            }
        }
        for attr in &self.attributes {
            let lower = attr.to_lowercase();
            if let Some(v) = lower.strip_prefix("expires=") {
                // Set-Cookie dates are RFC 1123; a past date is a deletion, and
                // a negative result is meaningful, so it is not clamped here.
                if let Ok(when) = chrono::DateTime::parse_from_rfc2822(v.trim()) {
                    return Some((when.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds());
                }
            }
        }
        None
    }

    /// Heuristic: does this cookie carry session or authentication state?
    pub fn looks_like_session(&self) -> bool {
        let n = self.name.to_lowercase();
        // __Host-/__Secure- prefixed cookies are session-grade by convention.
        n.starts_with("__host-")
            || n.starts_with("__secure-")
            || ["sess", "sid", "auth", "token", "jwt", "login", "user", "csrf", "xsrf", "remember"]
                .iter()
                .any(|marker| n.contains(marker))
    }

    /// Name and attributes only — the value is never included.
    pub fn redacted(&self) -> String {
        let mut out = format!("Set-Cookie: {}=<redacted>", self.name);
        for attr in &self.attributes {
            out.push_str("; ");
            out.push_str(attr);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsts_baseline_policy_is_accepted() {
        assert!(weak_hsts("max-age=31536000; includeSubDomains").is_none());
        assert!(weak_hsts("max-age=63072000; includeSubDomains; preload").is_none());
    }

    #[test]
    fn hsts_short_max_age_is_flagged() {
        let issue = weak_hsts("max-age=600; includeSubDomains").unwrap();
        assert!(issue.contains("below the recommended"));
    }

    #[test]
    fn hsts_without_include_subdomains_is_flagged() {
        let issue = weak_hsts("max-age=31536000").unwrap();
        assert!(issue.contains("includeSubDomains"));
    }

    #[test]
    fn csp_unsafe_inline_and_eval_are_flagged() {
        let issues = analyze_csp("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'");
        assert!(issues.iter().any(|i| i.contains("unsafe-inline")));
        assert!(issues.iter().any(|i| i.contains("unsafe-eval")));
    }

    #[test]
    fn csp_wildcard_script_src_is_flagged() {
        let issues = analyze_csp("default-src 'self'; script-src *; object-src 'none'; base-uri 'self'");
        assert!(issues.iter().any(|i| i.contains("wildcard")));
    }

    #[test]
    fn csp_wildcard_detection_does_not_fire_on_wildcard_hostnames() {
        // *.example.com is an allow-listed host pattern, not a bare wildcard.
        let issues = analyze_csp("script-src 'self' *.example.com; object-src 'none'; base-uri 'self'");
        assert!(
            !issues.iter().any(|i| i.contains("wildcard")),
            "a wildcard hostname must not be reported as a bare wildcard source: {issues:?}"
        );
    }

    #[test]
    fn strong_csp_reports_no_issues() {
        let issues = analyze_csp(
            "default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        );
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");
    }

    #[test]
    fn csp_missing_object_src_and_base_uri_are_flagged() {
        let issues = analyze_csp("default-src 'self'");
        assert!(issues.iter().any(|i| i.contains("object-src")));
        assert!(issues.iter().any(|i| i.contains("base-uri")));
    }

    #[test]
    fn cookie_attributes_are_parsed() {
        let c = ParsedCookie::parse("JSESSIONID=abc123; Path=/; Secure; HttpOnly; SameSite=Lax");
        assert_eq!(c.name, "JSESSIONID");
        assert!(c.secure);
        assert!(c.http_only);
        assert_eq!(c.same_site.as_deref(), Some("lax"));
    }

    #[test]
    fn a_browser_session_cookie_declares_no_lifetime() {
        let c = ParsedCookie::parse("SESSIONID=abc; Path=/; HttpOnly; Secure");
        assert_eq!(c.lifetime_seconds(), None, "no Max-Age and no Expires is a session cookie");
    }

    #[test]
    fn max_age_is_read_as_the_lifetime() {
        let c = ParsedCookie::parse("SESSIONID=abc; Max-Age=2592000; Path=/");
        assert_eq!(c.lifetime_seconds(), Some(2_592_000));
    }

    /// RFC 6265 gives Max-Age precedence when both attributes are present.
    #[test]
    fn max_age_wins_over_expires() {
        let c = ParsedCookie::parse(
            "SESSIONID=abc; Expires=Wed, 09 Jun 2100 10:18:14 GMT; Max-Age=60",
        );
        assert_eq!(c.lifetime_seconds(), Some(60));
    }

    #[test]
    fn an_expires_date_is_read_as_a_lifetime_from_now() {
        let future = chrono::Utc::now() + chrono::Duration::days(30);
        let raw = format!("SESSIONID=abc; Expires={}", future.format("%a, %d %b %Y %H:%M:%S +0000"));
        let seconds = ParsedCookie::parse(&raw).lifetime_seconds().expect("a date must parse");
        // Allow a little slack for the clock moving between the two calls.
        assert!((2_591_000..=2_592_100).contains(&seconds), "got {seconds}");
    }

    #[test]
    fn a_malformed_lifetime_is_ignored_rather_than_guessed() {
        assert_eq!(ParsedCookie::parse("SID=a; Max-Age=soon").lifetime_seconds(), None);
        assert_eq!(ParsedCookie::parse("SID=a; Expires=never").lifetime_seconds(), None);
    }

    #[test]
    fn durations_read_naturally_in_prose() {
        assert_eq!(humanise_duration(86_400), "1 day");
        assert_eq!(humanise_duration(2_592_000), "30 days");
        assert_eq!(humanise_duration(50_400), "14 hours");
    }

    #[test]
    fn cookie_redaction_never_leaks_the_value() {
        let c = ParsedCookie::parse("session=SUPERSECRETVALUE; Path=/; HttpOnly");
        let redacted = c.redacted();
        assert!(!redacted.contains("SUPERSECRETVALUE"));
        assert!(redacted.contains("session=<redacted>"));
        assert!(redacted.contains("HttpOnly"));
    }

    #[test]
    fn session_cookie_heuristic_matches_common_names() {
        for name in ["JSESSIONID", "PHPSESSID", "auth_token", "__Host-session", "csrf_token"] {
            let c = ParsedCookie::parse(&format!("{name}=x"));
            assert!(c.looks_like_session(), "{name} should be treated as session-bearing");
        }
        let c = ParsedCookie::parse("theme=dark");
        assert!(!c.looks_like_session(), "a preference cookie is not session state");
    }

    #[test]
    fn version_disclosure_requires_a_version_number() {
        assert!(discloses_version("nginx/1.18.0"));
        assert!(discloses_version("Apache/2.4.41 (Ubuntu)"));
        assert!(discloses_version("ASP.NET"));
        assert!(!discloses_version("nginx"));
        assert!(!discloses_version("cloudflare"));
    }

    #[test]
    fn referrer_policy_strictness_is_evaluated() {
        assert!(is_strict_referrer_policy("strict-origin-when-cross-origin"));
        assert!(is_strict_referrer_policy("no-referrer"));
        assert!(!is_strict_referrer_policy("unsafe-url"));
        assert!(!is_strict_referrer_policy("origin-when-cross-origin"));
    }
}
