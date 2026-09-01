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

const COOP_MISSING: CheckSpec = CheckSpec {
    id: "NATIVE-COOP-MISSING",
    title: "Cross-Origin-Opener-Policy Not Set",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1021",
    wstg: "WSTG-CLNT-13",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "The document does not set Cross-Origin-Opener-Policy, so it shares a browsing-context \
group with any page that opens it. A window opened by, or opening, this document keeps a live reference to \
it and can read cross-origin properties the browser would otherwise partition — the basis of \
cross-window attacks such as XS-Leaks, and the reason a page without it cannot use the \
cross-origin-isolated APIs at all.",
    remediation: "Send `Cross-Origin-Opener-Policy: same-origin` on top-level documents. Where a \
third-party flow depends on the opener reference — a payment or OAuth popup that calls back into the \
opener — use `same-origin-allow-popups` on the pages involved rather than dropping the header everywhere.",
    references: &[
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    ],
};

const CORP_MISSING: CheckSpec = CheckSpec {
    id: "NATIVE-CORP-MISSING",
    title: "Cross-Origin-Resource-Policy Not Set",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-829",
    wstg: "WSTG-CLNT-13",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "The response does not set Cross-Origin-Resource-Policy, so any other site may embed it \
as a subresource. For a document or an API response this permits cross-site script inclusion and the \
side-channel measurement of response size and timing that Spectre-class attacks depend on.",
    remediation: "Send `Cross-Origin-Resource-Policy: same-origin` on documents and API responses, and \
`same-site` where subdomains legitimately embed the resource. Use `cross-origin` only for assets that are \
deliberately public, such as a CDN-hosted font or image.",
    references: &[
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
    ],
};

const XSS_FILTER_ENABLED: CheckSpec = CheckSpec {
    id: "NATIVE-XSS-FILTER-ENABLED",
    title: "Legacy X-XSS-Protection Filter Enabled",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1173",
    wstg: "WSTG-CONF-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "The response enables the legacy browser XSS auditor with `X-XSS-Protection: 1`. The \
header is deprecated and every current browser has removed the filter, but where it is still honoured it \
does harm rather than good: the auditor's own heuristics have been used to *introduce* vulnerabilities by \
selectively neutralising legitimate script on the page, and `mode=block` turns a false match into a \
same-origin denial of service. This is why the header's own specification now recommends disabling it.\
\n\nSetting it to `1` is a misconfiguration, not a missing control — the absence of the header is not \
reported.",
    remediation: "Set `X-XSS-Protection: 0` to disable the legacy auditor explicitly, and rely on a \
Content-Security-Policy for actual XSS mitigation. Removing the header entirely is also acceptable; \
setting it to `0` is preferred because it states the intent for any intermediary that would otherwise \
add a default.",
    references: &[
        "https://owasp.org/www-project-secure-headers/#x-xss-protection",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
    ],
};

const COOKIE_NO_PREFIX: CheckSpec = CheckSpec {
    id: "NATIVE-COOKIE-PREFIX",
    title: "Session Cookie Without a __Host- or __Secure- Prefix",
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1275",
    wstg: "WSTG-SESS-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A session cookie is issued over HTTPS without a `__Host-` or `__Secure-` name prefix. \
The prefixes are enforced by the browser itself rather than by the application: `__Secure-` refuses the \
cookie unless it is set over HTTPS with the Secure attribute, and `__Host-` additionally requires \
Path=/ and forbids a Domain attribute, which is what prevents a compromised or attacker-controlled \
sibling subdomain from overwriting the session cookie of the parent site.\n\nWithout a prefix, a \
weakness anywhere on a sibling subdomain — an abandoned marketing site, a staging host, a takeover of a \
dangling DNS record — can be used to fixate the session cookie for the main application.",
    remediation: "Rename the session cookie to `__Host-<name>` and set it with `Secure; Path=/` and no \
`Domain` attribute. Where a Domain attribute is genuinely required so subdomains can read the cookie, use \
`__Secure-<name>` instead. Both are a one-line change at the point the cookie is issued and need no \
client-side support.",
    references: &[
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes",
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    ],
};

const CSP_REPORT_ONLY_ONLY: CheckSpec = CheckSpec {
    id: "NATIVE-CSP-REPORT-ONLY",
    title: "Content-Security-Policy Present but Not Enforced",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-693",
    wstg: "WSTG-CONF-12",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A Content-Security-Policy is set, but only through \
`Content-Security-Policy-Report-Only`. That header does exactly what its name says: the browser \
evaluates the policy, reports what would have been blocked, and then loads it anyway. Nothing is \
prevented.\n\nThis is normally a deployment that stalled. Report-only is the correct way to roll a \
policy out — you watch the reports, fix what breaks, then switch to enforcement — and the last step \
is easy to forget once the reports go quiet. The result looks protected to anyone reading the \
headers and protects nothing.",
    remediation: "Once the report stream is clean, send the same policy under \
`Content-Security-Policy`. Keeping both is a reasonable end state: enforce the policy you are \
confident in, and continue to trial a stricter one under report-only. If the reports are not clean \
yet, the finding stands — the application is currently unprotected regardless of the reason.",
    references: &[
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only",
    ],
};

const COOKIE_BROAD_DOMAIN: CheckSpec = CheckSpec {
    id: "NATIVE-COOKIE-BROAD-DOMAIN",
    title: "Session Cookie Scoped to the Parent Domain",
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1275",
    wstg: "WSTG-SESS-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A session cookie is issued with an explicit `Domain` attribute naming a parent \
domain, so the browser sends it to every subdomain of that parent — not just the application that \
issued it.\n\nThat turns every other subdomain into part of this application's attack surface. A \
marketing site on a shared platform, a staging host, a status page run by a third party, or a \
dangling DNS record an attacker can claim: any of them receives the live session cookie of every \
user who visits it, and a cross-site scripting flaw on any of them reads it.\n\nSubdomains are \
also not an origin boundary for cookies in the other direction — a compromised sibling can set \
cookies the parent will accept, which is how session fixation works across a domain family.",
    remediation: "Drop the `Domain` attribute so the cookie is host-only, which is the default and \
the correct behaviour for a session. Combine it with the `__Host-` name prefix, which the browser \
enforces: a `__Host-` cookie is rejected outright unless it is Secure, `Path=/` and has no Domain \
attribute at all, so the mistake cannot be reintroduced later. Where subdomains genuinely need a \
shared session, issue a separate token scoped to that purpose rather than widening the primary one.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#define_where_cookies_are_sent",
    ],
};

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
    COOP_MISSING,
    CORP_MISSING,
    XSS_FILTER_ENABLED,
    COOKIE_NO_PREFIX,
    CSP_REPORT_ONLY_ONLY,
    COOKIE_BROAD_DOMAIN,
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
    let enforced_csp = resp.header("content-security-policy");
    let report_only_csp = resp.header("content-security-policy-report-only");

    // A policy that is only in report-only mode prevents nothing, however good
    // it is. Reported separately from "no policy at all", because the fix is
    // different: one is writing a policy, the other is finishing a rollout.
    if enforced_csp.is_none() {
        if let Some(policy) = &report_only_csp {
            findings.push(make(
                &CSP_REPORT_ONLY_ONLY,
                "A policy is served under Content-Security-Policy-Report-Only, with no enforcing \
                 Content-Security-Policy header alongside it."
                    .into(),
                vec![format!("curl -sSI {url} | grep -i content-security-policy")],
                vec![ev(&format!(
                    "Content-Security-Policy-Report-Only: {}",
                    truncate(policy, 1000)
                ))],
            ));
        }
    }

    let csp = enforced_csp.clone().or_else(|| report_only_csp.clone());
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

    // ── Cross-origin isolation ───────────────────────────────────────────────
    // Only on documents: COOP governs the browsing context, which a stylesheet
    // or an image does not have one of.
    if is_html(resp) && resp.header("cross-origin-opener-policy").is_none() {
        findings.push(make(
            &COOP_MISSING,
            "No Cross-Origin-Opener-Policy header was returned on an HTML document.".into(),
            vec![format!("curl -sSI {url} | grep -i cross-origin-opener-policy")],
            vec![ev(&resp.evidence_summary())],
        ));
    }
    if resp.header("cross-origin-resource-policy").is_none() {
        findings.push(make(
            &CORP_MISSING,
            "No Cross-Origin-Resource-Policy header was returned.".into(),
            vec![format!("curl -sSI {url} | grep -i cross-origin-resource-policy")],
            vec![ev(&resp.evidence_summary())],
        ));
    }

    // ── Legacy XSS auditor ───────────────────────────────────────────────────
    // Reported only when it is switched on. Its absence is the correct state,
    // and the header's own guidance is now to disable it.
    if let Some(value) = resp.header("x-xss-protection") {
        if enables_legacy_xss_filter(&value) {
            findings.push(make(
                &XSS_FILTER_ENABLED,
                format!("X-XSS-Protection is set to '{}'.", truncate(&value, 100)),
                vec![format!("curl -sSI {url} | grep -i x-xss-protection")],
                vec![ev(&format!("X-XSS-Protection: {}", truncate(&value, 200)))],
            ));
        }
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
        if let Some(domain) = cookie.domain() {
            findings.push(make(
                &COOKIE_BROAD_DOMAIN,
                format!(
                    "Cookie '{}' is issued with Domain={}, so the browser sends it to every \
                     subdomain of that parent rather than only to this host.",
                    cookie.name, domain
                ),
                vec![format!("curl -sSI {url} | grep -i set-cookie")],
                vec![NativeFinding::evidence("http_response", "Set-Cookie (value redacted)", &redacted)],
            ));
        }

        // The prefixes are only meaningful over HTTPS — the browser rejects a
        // prefixed cookie set over plaintext, so demanding one there would be
        // advice that cannot be followed.
        if resp.is_https() && !cookie.has_security_prefix() {
            findings.push(make(
                &COOKIE_NO_PREFIX,
                format!(
                    "Session cookie '{}' carries neither the __Host- nor the __Secure- name prefix.",
                    cookie.name
                ),
                vec![format!("curl -sSI {url} | grep -i set-cookie")],
                vec![NativeFinding::evidence("http_response", "Set-Cookie (value redacted)", &redacted)],
            ));
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
///
/// Every rule here is evaluated against the *directive that actually governs
/// script execution*, not against the policy string as a whole. Two of them
/// previously matched anywhere in the policy and produced findings on
/// well-built policies:
///
/// * `data:` was reported whenever the substring appeared alongside any
///   script-ish directive, so the entirely normal `img-src 'self' data:` — used
///   by nearly every application that inlines an icon — was reported as
///   "a data: source in a script context". It is now only reported when `data:`
///   is a source of the directive that governs scripts.
/// * A missing `object-src` was reported unconditionally, including on policies
///   with `default-src 'none'`, where plugin content is already blocked and
///   adding `object-src` would change nothing.
pub fn analyze_csp(policy: &str) -> Vec<String> {
    let lower = policy.to_lowercase();
    let mut issues = Vec::new();

    // The directive that governs scripts: script-src when present, otherwise
    // whatever default-src falls back to.
    let script_context = directive_sources(&lower, "script-src")
        .or_else(|| directive_sources(&lower, "script-src-elem"))
        .or_else(|| directive_sources(&lower, "default-src"));

    if lower.contains("'unsafe-inline'") {
        issues.push("'unsafe-inline' permits inline scripts or styles, which defeats the policy's XSS protection.".to_string());
    }
    if lower.contains("'unsafe-eval'") {
        issues.push("'unsafe-eval' permits eval() and equivalents, allowing string-to-code execution.".to_string());
    }
    if directive_has_wildcard(&lower, "default-src") || directive_has_wildcard(&lower, "script-src") {
        issues.push("A wildcard (*) source allows scripts from any origin.".to_string());
    }
    if script_context
        .as_ref()
        .is_some_and(|sources| sources.iter().any(|s| s == "data:"))
    {
        issues.push("A data: scheme source is allowed in the script context, so an inline payload can be loaded as script.".to_string());
    }
    // `object-src` only matters when something could otherwise load plugin
    // content. A restrictive `default-src` already covers it in every browser
    // that implements the fallback, so demanding the directive there is noise.
    let default_blocks_everything = directive_sources(&lower, "default-src")
        .is_some_and(|sources| sources.iter().any(|s| s == "'none'"));
    if !lower.contains("object-src") && !default_blocks_everything {
        issues.push("object-src is not set and default-src does not block plugin content, so <object> and <embed> sources are unrestricted.".to_string());
    }
    if !lower.contains("base-uri") {
        issues.push("base-uri is not set, so an injected <base> tag can redirect every relative URL on the page.".to_string());
    }
    if !lower.contains("frame-ancestors") {
        issues.push("frame-ancestors is not set, so framing is governed only by the legacy X-Frame-Options header.".to_string());
    }
    if !lower.contains("form-action") {
        issues.push("form-action is not set, so an injected <form> can post the page's input to an attacker-controlled endpoint.".to_string());
    }

    issues
}

/// The source list of a named directive, if the policy declares it.
///
/// Matching is on the whole directive name, so looking up `script-src` does not
/// return the sources of `script-src-elem`.
fn directive_sources(lower_policy: &str, directive: &str) -> Option<Vec<String>> {
    lower_policy
        .split(';')
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .find(|d| {
            let mut tokens = d.split_whitespace();
            tokens.next() == Some(directive)
        })
        .map(|d| d.split_whitespace().skip(1).map(str::to_string).collect())
}

/// Whether a named directive contains a bare `*` source.
fn directive_has_wildcard(lower_policy: &str, directive: &str) -> bool {
    directive_sources(lower_policy, directive)
        .is_some_and(|sources| sources.iter().any(|token| token == "*"))
}

/// Whether a Referrer-Policy value actually protects the URL from leaking.
///
/// The substring test this replaces accepted `no-referrer-when-downgrade`,
/// because it contains "no-referrer" — but that value sends the full URL to
/// every other HTTPS origin, which is precisely what the check exists to catch.
/// Values are now compared as whole tokens against the list that is genuinely
/// safe.
fn is_strict_referrer_policy(value: &str) -> bool {
    const STRICT: &[&str] = &[
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    ];
    // A policy may list several values as a fallback chain; the last one the
    // browser understands wins, so every token has to be acceptable.
    let tokens: Vec<String> = value
        .split(',')
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    !tokens.is_empty() && tokens.iter().all(|t| STRICT.contains(&t.as_str()))
}

/// Whether the response tells caches not to retain it.
///
/// `no-store` is the correct directive and is accepted on its own. The
/// `private, no-cache` pairing is also accepted: a shared cache will not store
/// it and a private one must revalidate, which is the behaviour the check is
/// asking for. A `Pragma: no-cache` sent alongside either is honoured too, for
/// the HTTP/1.0 intermediaries that still exist behind some corporate proxies.
fn suppresses_cache(resp: &ProbeResponse) -> bool {
    let cache_control = resp.header("cache-control").unwrap_or_default().to_lowercase();
    if cache_control.contains("no-store") {
        return true;
    }
    let pragma_no_cache = resp
        .header("pragma")
        .map(|v| v.to_lowercase().contains("no-cache"))
        .unwrap_or(false);
    cache_control.contains("no-cache") && (cache_control.contains("private") || pragma_no_cache)
}

/// Whether an X-XSS-Protection value switches the legacy auditor on.
///
/// `0` is the recommended value and must not be reported; only `1`, with or
/// without a mode, enables the filter this check exists to warn about.
pub fn enables_legacy_xss_filter(value: &str) -> bool {
    value
        .split(';')
        .next()
        .map(|first| first.trim() == "1")
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

    /// The explicit `Domain` attribute, when the cookie widens its own scope.
    ///
    /// A cookie with no Domain is host-only, which is the correct default and
    /// is not reported. A leading dot is historical syntax meaning the same
    /// thing as without one, so it is stripped before comparison.
    pub fn domain(&self) -> Option<String> {
        self.attributes.iter().find_map(|attr| {
            let lower = attr.to_lowercase();
            let value = lower.strip_prefix("domain=")?.trim().trim_start_matches('.');
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        })
    }

    /// Whether the cookie name carries a browser-enforced security prefix.
    pub fn has_security_prefix(&self) -> bool {
        let n = self.name.to_lowercase();
        n.starts_with("__host-") || n.starts_with("__secure-")
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
            "default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none'; \
             base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        );
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");
    }

    /// `img-src 'self' data:` is how almost every application inlines an icon.
    /// Reporting it as "a data: source in a script context" made the CSP check
    /// fire on policies that were doing the right thing.
    #[test]
    fn a_data_source_outside_the_script_context_is_not_reported() {
        let issues = analyze_csp(
            "default-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; \
             base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        );
        assert!(
            !issues.iter().any(|i| i.contains("data:")),
            "img-src data: is not a script source: {issues:?}"
        );
    }

    #[test]
    fn a_data_source_in_the_script_context_is_still_reported() {
        let issues = analyze_csp("default-src 'self'; script-src 'self' data:");
        assert!(issues.iter().any(|i| i.contains("script context")), "{issues:?}");

        // And through the default-src fallback when script-src is absent.
        let inherited = analyze_csp("default-src 'self' data:");
        assert!(inherited.iter().any(|i| i.contains("script context")), "{inherited:?}");
    }

    /// `default-src 'none'` already blocks plugin content, so demanding a
    /// separate object-src there is advice with no effect.
    #[test]
    fn object_src_is_not_demanded_when_default_src_blocks_everything() {
        let issues = analyze_csp(
            "default-src 'none'; script-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        );
        assert!(
            !issues.iter().any(|i| i.contains("object-src")),
            "unexpected: {issues:?}"
        );
    }

    #[test]
    fn a_named_directive_does_not_match_a_longer_one() {
        // script-src-elem must not be read as script-src.
        let issues = analyze_csp("default-src 'self'; script-src-elem 'self' data:");
        assert!(issues.iter().any(|i| i.contains("script context")), "{issues:?}");
    }

    #[test]
    fn csp_missing_object_src_and_base_uri_are_flagged() {
        let issues = analyze_csp("default-src 'self'");
        assert!(issues.iter().any(|i| i.contains("object-src")));
        assert!(issues.iter().any(|i| i.contains("base-uri")));
    }

    /// A cookie with no Domain is host-only, which is the correct default.
    #[test]
    fn only_an_explicit_domain_attribute_widens_a_cookie() {
        assert_eq!(
            ParsedCookie::parse("sid=x; Domain=example.com; Path=/").domain(),
            Some("example.com".to_string())
        );
        // A leading dot is historical syntax for the same thing.
        assert_eq!(
            ParsedCookie::parse("sid=x; Domain=.example.com").domain(),
            Some("example.com".to_string())
        );
        assert!(ParsedCookie::parse("sid=x; Path=/; Secure").domain().is_none());
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
        // The substring test this replaced accepted this value because it
        // contains "no-referrer", while it in fact sends the full URL to every
        // other HTTPS origin — a false negative on exactly the leak the check
        // exists to find.
        assert!(!is_strict_referrer_policy("no-referrer-when-downgrade"));
        // A fallback chain is only as strict as its weakest member.
        assert!(!is_strict_referrer_policy("no-referrer, unsafe-url"));
        assert!(is_strict_referrer_policy("no-referrer, strict-origin-when-cross-origin"));
        assert!(!is_strict_referrer_policy(""));
    }
}
