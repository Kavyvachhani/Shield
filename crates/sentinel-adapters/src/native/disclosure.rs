//! Information-disclosure checks over the response body.
//!
//! Everything here reads bytes the server already returned to an anonymous
//! visitor. No request is made that the rest of the engine has not already
//! made, and no payload is sent — these are pure analyses of a page that any
//! browser would receive.
//!
//! The class matters more than it looks. A credential compiled into a
//! JavaScript bundle, an internal hostname in a comment, or a cloud metadata
//! address referenced from client-side code are all findings an attacker gets
//! for free by pressing Ctrl-U, and none of them are visible to a scanner that
//! only reads response headers.
//!
//! Precision is the design constraint. Each detector matches a shape that does
//! not occur by accident — a provider's own key prefix, an RFC 1918 address in
//! a header value, a PEM block header — because a disclosure check that fires
//! on ordinary prose is worse than no check at all.

use super::builder::{CheckSpec, NativeFinding};
use super::probe::{truncate, ProbeResponse};
use sentinel_core::models::finding::Finding;
use uuid::Uuid;

const OWASP_MISCONFIG: &str = "A02:2025-Security Misconfiguration";
const OWASP_ACCESS: &str = "A01:2025-Broken Access Control";
const OWASP_INJECTION: &str = "A05:2025-Injection";
const OWASP_CRYPTO: &str = "A04:2025-Cryptographic Failures";

const SECRET_IN_CONTENT: CheckSpec = CheckSpec {
    id: "NATIVE-SECRET-IN-CONTENT",
    title: "Credential or API Key Exposed in Client-Delivered Content",
    // Confidentiality high: a live provider credential served to every visitor
    // is a direct loss of the secret. Integrity low rather than high — what the
    // key permits is provider-dependent and not established by this check.
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-798",
    wstg: "WSTG-INFO-05",
    owasp_2025: OWASP_CRYPTO,
    api_top10: Some("API8:2023-Security Misconfiguration"),
    description: "A string matching a well-known credential format was found in content served to any \
visitor — page source, an inline script or a JavaScript bundle. Anything delivered to the browser is \
public: minification, bundling and obfuscation change nothing, because the browser must be able to read \
the value in order to use it.\n\nSecrets reach client bundles routinely, usually through a build step that \
inlines an environment variable intended for the server. The credential should be treated as compromised \
from the moment it was first served, not from the moment it is discovered.",
    remediation: "Revoke and reissue the credential now — removing it from the page does not \
un-disclose it, and the old value remains in every CDN cache, browser cache and archive that holds a copy \
of the file. Then move the call that needs it behind a server-side endpoint so the secret never reaches \
the client, and add a secret scanner to CI so the next one is caught before it ships. Where a public \
client-side key is genuinely required, restrict it at the provider by referrer, origin and scope.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/798.html",
    ],
};

const PRIVATE_KEY_EXPOSED: CheckSpec = CheckSpec {
    id: "NATIVE-PRIVATE-KEY-EXPOSED",
    title: "Private Key Material Served to the Client",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-522",
    wstg: "WSTG-INFO-05",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "The response contains a PEM private-key block. A private key served over HTTP is \
disclosed to everyone who requests the resource, and depending on what it protects it may permit \
decryption of recorded traffic, impersonation of the service, or signing of artefacts that downstream \
systems trust.",
    remediation: "Treat the key as compromised. Revoke it, issue a replacement, and rotate anything the \
old key signed or protected. Then remove it from the document root and from version control history — a \
key deleted from the working tree but left in the repository's history is still disclosed to anyone who \
can clone it.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
    ],
};

const INTERNAL_HOST_DISCLOSURE: CheckSpec = CheckSpec {
    id: "NATIVE-INTERNAL-HOST-DISCLOSURE",
    title: "Internal Hostname or Private IP Address Disclosed",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-200",
    wstg: "WSTG-INFO-05",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "The response discloses a private (RFC 1918) IP address or an internal-only hostname. \
On its own this is not exploitable, but it hands an attacker the internal addressing scheme for free: it \
tells them what to aim a server-side request forgery at, which subnets to probe once they gain a foothold, \
and which names to try against an internal DNS resolver.",
    remediation: "Strip internal addressing from responses. The usual sources are a reverse proxy adding \
`X-Backend-Server` or `Via`, an error page echoing an upstream address, and absolute internal URLs left in \
templates or configuration served to the client. Configure the proxy to suppress those headers and use \
relative or public URLs in templates.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
    ],
};

const CLOUD_METADATA_REFERENCE: CheckSpec = CheckSpec {
    id: "NATIVE-CLOUD-METADATA-REFERENCE",
    title: "Cloud Instance Metadata Endpoint Referenced in Client Content",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-918",
    wstg: "WSTG-INPV-19",
    owasp_2025: OWASP_ACCESS,
    api_top10: None,
    description: "Content served to the browser references the cloud instance metadata service \
(169.254.169.254, or the equivalent GCP/Azure address). The metadata service issues short-lived \
credentials for the instance's role and is the standard objective of a server-side request forgery: an \
application that fetches a URL supplied by a user, and can reach this address, can be made to hand those \
credentials to an attacker.\n\nThe reference itself is a signal, not proof — but it indicates code that \
talks to the metadata service, which is where the SSRF review should start.",
    remediation: "Require IMDSv2 (session-token bound) on AWS and reject IMDSv1 outright; the equivalent \
on GCP and Azure is to require the metadata header. Block egress to the link-local range from any process \
that fetches user-supplied URLs, and validate outbound URLs against an allow-list of hosts rather than a \
deny-list of addresses, which decimal, octal and DNS-rebinding encodings defeat.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
};

const GENERATOR_DISCLOSURE: CheckSpec = CheckSpec {
    id: "NATIVE-GENERATOR-DISCLOSURE",
    title: "Application Framework and Version Disclosed in Page Metadata",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-200",
    wstg: "WSTG-INFO-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A `<meta name=\"generator\">` tag names the CMS or framework and its exact version. \
That turns targeting into a lookup: an attacker matches the version against public advisories and knows \
which exploits to try before sending a single unusual request, and it lets an automated scanner classify \
the site as vulnerable without probing at all.",
    remediation: "Remove the generator meta tag — most platforms expose a setting or a one-line filter for \
it. Keeping the version private is not a substitute for patching, but it removes the free reconnaissance \
that decides whether an opportunistic attacker bothers with you at all.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
    ],
};

pub(super) const SOURCE_MAP_EXPOSED: CheckSpec = CheckSpec {
    id: "NATIVE-SOURCEMAP-EXPOSED",
    title: "Source Map Publicly Readable",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-540",
    wstg: "WSTG-CONF-04",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A JavaScript source map is readable by anonymous visitors. A source map is the \
original, unminified source — including comments, internal module names, directory structure and \
any code the bundler tree-shook out of the shipped file but left in the map. It reverses the only \
practical benefit minification gives an attacker, and hands over the client-side codebase as it \
was written.\n\nThis is almost always an accident: the bundler emits maps for debugging and the \
deployment copies the whole output directory.",
    remediation: "Stop publishing maps to production, or upload them to your error-tracking service \
and serve them only to authenticated staff. In webpack set `devtool: false` for the production \
build, or `hidden-source-map` to keep the map for upload without a `sourceMappingURL` comment \
pointing at it. In Vite set `build.sourcemap: false`. If a map has been public, treat anything \
sensitive visible in it — endpoint names, feature flags, comments about unreleased work — as \
disclosed.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
    ],
};

const JWT_IN_CONTENT: CheckSpec = CheckSpec {
    id: "NATIVE-JWT-IN-CONTENT",
    title: "JSON Web Token Embedded in Client-Delivered Content",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-522",
    wstg: "WSTG-SESS-09",
    owasp_2025: OWASP_CRYPTO,
    api_top10: Some("API2:2023-Broken Authentication"),
    description: "A JSON Web Token appears in content served to the browser. A JWT is signed, not \
encrypted: its payload is base64url and readable by anyone holding the token, so whatever claims it \
carries — user id, email, role, tenant, internal identifiers — are disclosed to every reader of \
this page.\n\nIf the token is a live session token, embedding it in markup also puts it somewhere a \
cross-site scripting payload can read and a proxy or browser cache can retain, which is precisely \
what an HttpOnly cookie exists to prevent.",
    remediation: "Do not render tokens into markup. Issue session state as a `__Host-` prefixed \
cookie with Secure, HttpOnly and SameSite, so script cannot read it. If a token genuinely has to \
reach client-side code, keep it in memory for the lifetime of the page rather than in the document, \
in localStorage or in a URL. Rotate any token that has been served this way, and check whether it \
also reached your access logs and CDN cache.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    ],
};

const INSECURE_BROWSER_STORAGE: CheckSpec = CheckSpec {
    id: "NATIVE-INSECURE-BROWSER-STORAGE",
    title: "Session or Credential Material Written to Browser Storage",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-922",
    wstg: "WSTG-CLNT-12",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "Client-side code writes something that looks like a token or credential into \
`localStorage` or `sessionStorage`. Both are readable by any JavaScript running on the origin, so a \
single cross-site scripting flaw anywhere on the site — including in a third-party script you did \
not write — reads the value directly. `localStorage` additionally survives the browser closing, so \
the value persists on a shared machine.\n\nThis is the trade-off a cookie with HttpOnly is designed \
to remove: script cannot read an HttpOnly cookie, which is what stops an XSS from becoming an \
account takeover.",
    remediation: "Move session state into a `__Host-` prefixed cookie with `Secure; HttpOnly; \
SameSite=Lax`, and let the browser attach it rather than the application. Where a value must be \
reachable from script, hold it in a closure or module scope for the page's lifetime instead of \
persisting it, and keep its lifetime short.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage",
    ],
};

const POSTMESSAGE_WILDCARD: CheckSpec = CheckSpec {
    id: "NATIVE-POSTMESSAGE-WILDCARD",
    title: "Cross-Window Message Sent to Any Origin",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-346",
    wstg: "WSTG-CLNT-11",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "`postMessage` is called with `\"*\"` as the target origin. That tells the browser \
to deliver the message to whatever document currently occupies the target window, regardless of who \
it is. If an attacker can influence what loads there — an opener, an iframe whose src they control, \
a window that has since navigated — they receive whatever the message contains, which is frequently \
a token or user data.\n\nThe mirror image matters too: a `message` listener that does not check \
`event.origin` will act on anything any site sends it.",
    remediation: "Name the origin explicitly: `target.postMessage(data, 'https://app.example.com')`. \
On the receiving side, check `event.origin` against an allow-list as the first line of the handler \
and return early otherwise — never inspect the payload before validating the sender.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#web-messaging",
    ],
};

const INSECURE_WEBSOCKET: CheckSpec = CheckSpec {
    id: "NATIVE-INSECURE-WEBSOCKET",
    title: "Plaintext WebSocket Referenced from an Encrypted Page",
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-319",
    wstg: "WSTG-CLNT-10",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "A page served over HTTPS opens a WebSocket over `ws://` rather than `wss://`. The \
socket carries application traffic — often including the session token used to authenticate it — in \
clear text, so anyone positioned on the network reads and can modify it. The encrypted page gives \
the user no indication that part of the session is not encrypted at all.\n\nModern browsers block \
this as mixed content, which means the feature is also simply broken for most users; the risk lands \
on whoever is running a client that still permits it.",
    remediation: "Use `wss://` and terminate TLS at the same place the HTTPS site terminates it. \
Build the URL from the page's own scheme rather than hardcoding it, so a deployment cannot drift \
back: `new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + \
'/socket')`. Verify the Origin header server-side on the upgrade request — WebSockets are not \
covered by the same-origin policy.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#websockets",
    ],
};

const DOM_XSS_SINK: CheckSpec = CheckSpec {
    id: "NATIVE-DOM-XSS-SINK",
    title: "URL-Derived Data Reaches a DOM Injection Sink",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-79",
    wstg: "WSTG-CLNT-01",
    owasp_2025: OWASP_INJECTION,
    api_top10: None,
    description: "Client-side code reads a value out of the URL — `location.hash`, `location.search` \
or `document.URL` — and passes it to a sink that parses HTML or evaluates code, such as `innerHTML`, \
`document.write` or `eval`. That is the shape of DOM-based cross-site scripting: the payload never \
reaches the server, so no server-side filter or WAF sees it, and nothing in a server log records \
the attack.\n\nThis check reports the *pattern*, not a proven exploit. Whether it is reachable \
depends on whether the value is sanitised between the source and the sink, which needs a human to \
read the surrounding code.",
    remediation: "Assign untrusted values with `textContent` or `setAttribute` rather than \
`innerHTML`, and never pass them to `eval`, `Function`, `setTimeout` with a string body, or \
`document.write`. Where HTML genuinely has to be constructed, run it through DOMPurify first. \
Enabling Trusted Types (`Content-Security-Policy: require-trusted-types-for 'script'`) makes the \
unsafe assignment throw rather than execute, which turns this class of bug into a test failure.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
    ],
};

/// Every check this module can raise.
///
/// Exposed so the spec audit can walk all shipped checks and confirm each one
/// carries a coherent CVSS vector, severity band and taxonomy.
pub const SPECS: &[CheckSpec] = &[
    SECRET_IN_CONTENT,
    PRIVATE_KEY_EXPOSED,
    INTERNAL_HOST_DISCLOSURE,
    CLOUD_METADATA_REFERENCE,
    GENERATOR_DISCLOSURE,
    SOURCE_MAP_EXPOSED,
    JWT_IN_CONTENT,
    INSECURE_BROWSER_STORAGE,
    POSTMESSAGE_WILDCARD,
    INSECURE_WEBSOCKET,
    DOM_XSS_SINK,
];

/// Run every disclosure check against one response.
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
            vec![NativeFinding::evidence(
                "page_content",
                "Extract from response (secret material redacted)",
                &evidence,
            )],
        )
    };

    // ── Credential material ──────────────────────────────────────────────────
    let secrets = detect_secrets(body);
    if !secrets.is_empty() {
        let kinds: Vec<&str> = secrets.iter().map(|s| s.kind).collect();
        findings.push(make(
            &SECRET_IN_CONTENT,
            format!(
                "{} credential-shaped string(s) were found in content served to the client: {}.",
                secrets.len(),
                kinds.join(", ")
            ),
            vec![
                format!("curl -sS {url} | grep -oE 'AKIA[0-9A-Z]{{16}}|gh[pousr]_[A-Za-z0-9]{{36}}'"),
                "Search the built JavaScript bundles for the same value".into(),
            ],
            secrets
                .iter()
                .map(|s| format!("{}: {}", s.kind, s.redacted))
                .collect::<Vec<_>>()
                .join("\n"),
        ));
    }

    if let Some(kind) = detect_private_key(body) {
        findings.push(make(
            &PRIVATE_KEY_EXPOSED,
            format!("The response body contains a {kind} block."),
            vec![format!("curl -sS {url} | grep -- '-----BEGIN'")],
            format!("{kind} present; key material deliberately not reproduced in this report."),
        ));
    }

    // ── Internal addressing ──────────────────────────────────────────────────
    // Headers are checked as well as the body: a reverse proxy leaking its
    // backend address does it in a header, where a body-only check never looks.
    let mut internal: Vec<String> = detect_private_addresses(body);
    for header in ["via", "x-backend-server", "x-served-by", "x-real-ip", "x-upstream", "x-host"] {
        if let Some(value) = resp.header(header) {
            for hit in detect_private_addresses(&value) {
                internal.push(format!("{header}: {hit}"));
            }
        }
    }
    internal.truncate(10);
    if !internal.is_empty() {
        findings.push(make(
            &INTERNAL_HOST_DISCLOSURE,
            format!("{} internal address reference(s) were disclosed.", internal.len()),
            vec![format!(
                "curl -sSi {url} | grep -oE '(10|127|192\\.168)\\.[0-9]+\\.[0-9]+\\.[0-9]+'"
            )],
            internal.join("\n"),
        ));
    }

    // ── Cloud metadata ───────────────────────────────────────────────────────
    if let Some(provider) = detect_metadata_reference(body) {
        findings.push(make(
            &CLOUD_METADATA_REFERENCE,
            format!("Client-delivered content references the {provider} instance metadata endpoint."),
            vec![format!("curl -sS {url} | grep -F '169.254.169.254'")],
            truncate(&extract_context(body, "169.254.169.254", 200), 300),
        ));
    }

    // ── Client-side patterns ─────────────────────────────────────────────────
    let jwts = detect_jwts(body);
    if !jwts.is_empty() {
        findings.push(make(
            &JWT_IN_CONTENT,
            format!(
                "{} JSON Web Token(s) were found in content served to the browser.",
                jwts.len()
            ),
            vec![format!("curl -sS {url} | grep -oE 'eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.'")],
            jwts.join("\n"),
        ));
    }

    let storage = detect_storage_of_secrets(body);
    if !storage.is_empty() {
        findings.push(make(
            &INSECURE_BROWSER_STORAGE,
            format!(
                "{} write(s) of credential-shaped keys into browser storage: {}.",
                storage.len(),
                truncate(&storage.join(", "), 200)
            ),
            vec![format!("curl -sS {url} | grep -oE '(local|session)Storage\\.setItem\\([^)]*\\)'")],
            storage.join("\n"),
        ));
    }

    let wildcard = detect_postmessage_wildcard(body);
    if !wildcard.is_empty() {
        findings.push(make(
            &POSTMESSAGE_WILDCARD,
            format!("{} postMessage call(s) target any origin.", wildcard.len()),
            vec![format!("curl -sS {url} | grep -oE 'postMessage\\([^)]*\\)'")],
            wildcard.join("\n"),
        ));
    }

    if resp.is_https() {
        let sockets = detect_plaintext_websockets(body);
        if !sockets.is_empty() {
            findings.push(make(
                &INSECURE_WEBSOCKET,
                format!(
                    "{} plaintext WebSocket endpoint(s) referenced from an HTTPS page: {}.",
                    sockets.len(),
                    truncate(&sockets.join(", "), 200)
                ),
                vec![format!("curl -sS {url} | grep -oE 'ws://[^\"'\'' ]+'")],
                sockets.join("\n"),
            ));
        }
    }

    let sinks = detect_dom_xss_sinks(body);
    if !sinks.is_empty() {
        findings.push(make(
            &DOM_XSS_SINK,
            format!(
                "URL-derived data appears alongside {} DOM injection sink(s): {}.",
                sinks.len(),
                sinks.join(", ")
            ),
            vec![format!("curl -sS {url} | grep -oE '(innerHTML|document\\.write|eval)\\s*[(=]'")],
            format!(
                "Sinks observed: {}\n\nURL sources observed: {}",
                sinks.join(", "),
                detect_url_sources(body).join(", ")
            ),
        ));
    }

    // ── Framework version ────────────────────────────────────────────────────
    if let Some(generator) = detect_generator(body) {
        findings.push(make(
            &GENERATOR_DISCLOSURE,
            format!("A generator meta tag discloses '{generator}'."),
            vec![format!("curl -sS {url} | grep -i 'name=\"generator\"'")],
            format!("<meta name=\"generator\" content=\"{generator}\">"),
        ));
    }

    findings
}

// ── Detection ────────────────────────────────────────────────────────────────

/// A credential-shaped string, with its value already reduced to a fingerprint.
#[derive(Debug, PartialEq)]
pub struct SecretHit {
    pub kind: &'static str,
    /// First and last few characters only — never the whole secret.
    pub redacted: String,
}

/// Provider credential formats, each specific enough that a match is not chance.
///
/// Deliberately no generic "looks like a long random string" rule: minified
/// JavaScript is full of long random strings, and such a rule would report a
/// webpack chunk hash on every page.
struct SecretPattern {
    kind: &'static str,
    prefix: &'static str,
    /// Characters that must follow the prefix for a match.
    body_len: usize,
    allowed: fn(char) -> bool,
}

fn is_upper_alnum(c: char) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit()
}

fn is_alnum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

const SECRET_PATTERNS: &[SecretPattern] = &[
    SecretPattern { kind: "AWS access key id", prefix: "AKIA", body_len: 16, allowed: is_upper_alnum },
    SecretPattern { kind: "AWS temporary access key id", prefix: "ASIA", body_len: 16, allowed: is_upper_alnum },
    SecretPattern { kind: "GitHub personal access token", prefix: "ghp_", body_len: 36, allowed: is_alnum },
    SecretPattern { kind: "GitHub OAuth token", prefix: "gho_", body_len: 36, allowed: is_alnum },
    SecretPattern { kind: "GitHub app token", prefix: "ghs_", body_len: 36, allowed: is_alnum },
    SecretPattern { kind: "Slack token", prefix: "xoxb-", body_len: 24, allowed: is_key_char },
    SecretPattern { kind: "Slack app token", prefix: "xapp-", body_len: 24, allowed: is_key_char },
    SecretPattern { kind: "Stripe live secret key", prefix: "sk_live_", body_len: 24, allowed: is_alnum },
    SecretPattern { kind: "Stripe live restricted key", prefix: "rk_live_", body_len: 24, allowed: is_alnum },
    SecretPattern { kind: "SendGrid API key", prefix: "SG.", body_len: 22, allowed: is_key_char },
    SecretPattern { kind: "Google API key", prefix: "AIza", body_len: 35, allowed: is_key_char },
    SecretPattern { kind: "Twilio account SID", prefix: "AC", body_len: 32, allowed: |c| c.is_ascii_hexdigit() },
    SecretPattern { kind: "npm access token", prefix: "npm_", body_len: 36, allowed: is_alnum },
];

/// Credential-shaped strings in a document, each redacted to a fingerprint.
pub fn detect_secrets(body: &str) -> Vec<SecretHit> {
    let mut hits: Vec<SecretHit> = Vec::new();

    for pattern in SECRET_PATTERNS {
        let mut cursor = 0usize;
        while let Some(offset) = body[cursor..].find(pattern.prefix) {
            let start = cursor + offset;
            let after = &body[start + pattern.prefix.len()..];
            let matched: String = after
                .chars()
                .take(pattern.body_len)
                .take_while(|c| (pattern.allowed)(*c))
                .collect();

            if matched.chars().count() == pattern.body_len {
                let full = format!("{}{}", pattern.prefix, matched);
                let hit = SecretHit { kind: pattern.kind, redacted: redact(&full) };
                if !hits.iter().any(|h| h.redacted == hit.redacted) {
                    hits.push(hit);
                }
            }

            cursor = start + pattern.prefix.len();
            if hits.len() >= 20 {
                return hits;
            }
        }
    }

    hits
}

/// Reduce a secret to a fingerprint that identifies it without disclosing it.
///
/// A report that reprints the credential it is warning about has published it a
/// second time, in a document that is emailed around and archived.
fn redact(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 10 {
        return "*".repeat(chars.len());
    }
    let head: String = chars.iter().take(6).collect();
    let tail: String = chars.iter().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    format!("{head}…{tail} ({} characters)", chars.len())
}

/// The kind of PEM private key present in a document, if any.
pub fn detect_private_key(body: &str) -> Option<&'static str> {
    const BLOCKS: &[(&str, &str)] = &[
        ("-----BEGIN RSA PRIVATE KEY-----", "RSA private key"),
        ("-----BEGIN DSA PRIVATE KEY-----", "DSA private key"),
        ("-----BEGIN EC PRIVATE KEY-----", "EC private key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH private key"),
        ("-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP private key"),
        ("-----BEGIN PRIVATE KEY-----", "PKCS#8 private key"),
        ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "encrypted PKCS#8 private key"),
    ];
    BLOCKS
        .iter()
        .find(|(marker, _)| body.contains(marker))
        .map(|(_, label)| *label)
}

/// RFC 1918 and loopback addresses appearing in a document.
///
/// Matching is on complete dotted quads with their octets range-checked, so
/// version strings like `10.2.14.3` in a changelog are the only realistic false
/// positive — and a version string that looks exactly like a private address is
/// rare enough to be worth the occasional review.
pub fn detect_private_addresses(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0usize;

    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // A quad must not begin in the middle of a longer number or identifier.
        if i > 0 && (bytes[i - 1].is_ascii_digit() || bytes[i - 1] == '.') {
            i += 1;
            continue;
        }

        let start = i;
        let mut octets: Vec<u16> = Vec::new();
        let mut j = i;
        while octets.len() < 4 {
            let digit_start = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() && j - digit_start < 3 {
                j += 1;
            }
            if j == digit_start {
                break;
            }
            let value: u16 = bytes[digit_start..j].iter().collect::<String>().parse().unwrap_or(999);
            if value > 255 {
                break;
            }
            octets.push(value);
            if octets.len() < 4 {
                if j < bytes.len() && bytes[j] == '.' {
                    j += 1;
                } else {
                    break;
                }
            }
        }

        if octets.len() == 4 && !(j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == '.')) && is_private(&octets) {
            let quad: String = bytes[start..j].iter().collect();
            if !found.contains(&quad) {
                found.push(quad);
            }
        }
        i = if j > i { j } else { i + 1 };
    }

    found
}

fn is_private(octets: &[u16]) -> bool {
    match octets {
        [10, ..] => true,
        [192, 168, ..] => true,
        [172, second, ..] if (16..=31).contains(second) => true,
        [127, ..] => true,
        // Link-local, excluding the metadata address which has its own check.
        [169, 254, ..] => false,
        _ => false,
    }
}

/// Whether client content references a cloud metadata service.
pub fn detect_metadata_reference(body: &str) -> Option<&'static str> {
    if body.contains("169.254.169.254") {
        return Some("AWS/GCP/Azure");
    }
    if body.contains("metadata.google.internal") {
        return Some("Google Cloud");
    }
    if body.contains("100.100.100.200") {
        return Some("Alibaba Cloud");
    }
    None
}

/// JSON Web Tokens in a document, reduced to their header and a fingerprint.
///
/// Matched on the structural shape — three base64url segments, the first
/// starting `eyJ`, which is `{"` encoded — rather than on a keyword, so a
/// variable merely *called* `token` does not trigger it.
///
/// The token is never reproduced in full: its payload carries the very claims
/// the finding is warning are disclosed, and a report is a document that gets
/// emailed around.
pub fn detect_jwts(body: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let bytes: Vec<char> = body.chars().collect();
    let mut i = 0usize;

    while i + 3 < bytes.len() {
        if !(bytes[i] == 'e' && bytes[i + 1] == 'y' && bytes[i + 2] == 'J') {
            i += 1;
            continue;
        }
        // A token must not start in the middle of a longer identifier.
        if i > 0 && is_b64url(bytes[i - 1]) {
            i += 1;
            continue;
        }

        let mut j = i;
        let mut segments: Vec<usize> = Vec::new();
        let mut segment_start = i;
        while j < bytes.len() && (is_b64url(bytes[j]) || bytes[j] == '.') {
            if bytes[j] == '.' {
                segments.push(j - segment_start);
                segment_start = j + 1;
            }
            j += 1;
        }
        segments.push(j - segment_start);

        // header.payload.signature, each long enough to be real.
        let looks_like_jwt = segments.len() == 3
            && segments[0] >= 10
            && segments[1] >= 10
            && segments[2] >= 8;

        if looks_like_jwt {
            let token: String = bytes[i..j].iter().collect();
            let head: String = token.chars().take(18).collect();
            let entry = format!("{head}… ({} characters, 3 segments)", token.chars().count());
            if !found.contains(&entry) {
                found.push(entry);
            }
            if found.len() >= 10 {
                return found;
            }
        }
        i = if j > i { j } else { i + 1 };
    }
    found
}

fn is_b64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Keys written into `localStorage`/`sessionStorage` that name credential material.
///
/// Only the *key* is inspected, and only when it names something sensitive.
/// Reporting every write to browser storage would fire on theme preferences and
/// dismissed banners, which is noise the reader learns to skip past.
pub fn detect_storage_of_secrets(body: &str) -> Vec<String> {
    const SENSITIVE: &[&str] = &[
        "token", "jwt", "auth", "session", "secret", "password", "passwd",
        "credential", "apikey", "api_key", "access_key", "refresh", "bearer",
    ];
    let mut found: Vec<String> = Vec::new();

    for storage in ["localstorage.setitem", "sessionstorage.setitem"] {
        let lower = body.to_lowercase();
        let mut cursor = 0usize;
        while let Some(offset) = lower[cursor..].find(storage) {
            let open = cursor + offset + storage.len();
            cursor = open;
            let Some(rest) = body.get(open..) else { break };
            let Some(end) = rest.find(')') else { break };
            let args = &rest[..end.min(160)];
            let args_lower = args.to_lowercase();

            // The key is the first argument, before the comma.
            let key = args_lower.split(',').next().unwrap_or("");
            if SENSITIVE.iter().any(|marker| key.contains(marker)) {
                let entry = format!(
                    "{}{}",
                    storage.replace(".setitem", ".setItem"),
                    truncate(args, 90)
                );
                if !found.contains(&entry) {
                    found.push(entry);
                }
            }
            if found.len() >= 15 {
                return found;
            }
        }
    }
    found
}

/// `postMessage` calls whose target origin is the `"*"` wildcard.
pub fn detect_postmessage_wildcard(body: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut cursor = 0usize;

    while let Some(offset) = body[cursor..].find("postMessage") {
        let start = cursor + offset;
        cursor = start + "postMessage".len();
        let Some(rest) = body.get(start..) else { break };
        let Some(end) = rest.find(')') else { continue };
        let call = &rest[..end + 1];

        // The wildcard is a string literal argument, not a bare asterisk: `* `
        // appears in multiplication and in comments.
        if call.contains("\"*\"") || call.contains("'*'") || call.contains("`*`") {
            let entry = truncate(call, 140);
            if !found.contains(&entry) {
                found.push(entry);
            }
        }
        if found.len() >= 10 {
            break;
        }
    }
    found
}

/// `ws://` endpoints referenced from a document.
pub fn detect_plaintext_websockets(body: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut cursor = 0usize;

    while let Some(offset) = body[cursor..].find("ws://") {
        let start = cursor + offset;
        cursor = start + 5;
        // `wss://` contains no `ws://`, but `xws://` would; require a boundary.
        if start > 0 {
            let prev = body[..start].chars().next_back().unwrap_or(' ');
            if prev.is_ascii_alphanumeric() {
                continue;
            }
        }
        let rest = &body[start..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '`' || c == '<')
            .unwrap_or(rest.len());
        let endpoint = truncate(&rest[..end], 160);
        if !found.contains(&endpoint) {
            found.push(endpoint);
        }
        if found.len() >= 10 {
            break;
        }
    }
    found
}

/// DOM sinks that parse HTML or evaluate code.
const DOM_SINKS: &[&str] = &[
    "innerHTML", "outerHTML", "document.write", "insertAdjacentHTML",
    "eval(", "Function(", "setTimeout(\"", "setInterval(\"",
];

/// Sources that read attacker-controllable data out of the URL.
const URL_SOURCES: &[&str] = &[
    "location.hash", "location.search", "location.href", "document.URL",
    "document.documentURI", "document.referrer", "window.name",
];

/// The URL-reading expressions present in a document.
pub fn detect_url_sources(body: &str) -> Vec<&'static str> {
    URL_SOURCES
        .iter()
        .filter(|source| body.contains(**source))
        .copied()
        .collect()
}

/// DOM injection sinks, reported only when a URL source is present too.
///
/// Either half on its own is ordinary: every application reads `location`, and
/// `innerHTML` with a constant is harmless. It is the combination that
/// describes the shape of DOM-based XSS — and even then this is a pattern, not
/// a proven exploit, which is why the check declares low confidence and says so
/// in its own description.
pub fn detect_dom_xss_sinks(body: &str) -> Vec<&'static str> {
    if detect_url_sources(body).is_empty() {
        return Vec::new();
    }
    DOM_SINKS
        .iter()
        .filter(|sink| body.contains(**sink))
        .copied()
        .collect()
}

/// The content of a `<meta name="generator">` tag, when it names a version.
pub fn detect_generator(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let mut cursor = 0usize;

    while let Some(offset) = lower[cursor..].find("<meta") {
        let start = cursor + offset;
        let Some(end_offset) = lower[start..].find('>') else { break };
        let tag = &body[start..=start + end_offset];
        let tag_lower = tag.to_lowercase();
        cursor = start + end_offset + 1;

        if !tag_lower.contains("name=\"generator\"") && !tag_lower.contains("name='generator'") {
            continue;
        }
        let Some(content) = read_attribute(tag, "content") else { continue };
        // A bare product name is fingerprinting the reader could do anyway; a
        // version number is what turns it into a targeting aid.
        if content.chars().any(|c| c.is_ascii_digit()) {
            return Some(truncate(content.trim(), 120));
        }
    }
    None
}

/// Read an attribute value from a tag, tolerating either quote style.
fn read_attribute(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_lowercase();
    let key = format!("{attr}=");
    let at = lower.find(&key)? + key.len();
    let rest = &tag[at..];
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let body = &rest[quote.len_utf8()..];
    let end = body.find(quote)?;
    Some(body[..end].to_string())
}

/// A window of text around the first occurrence of `needle`.
fn extract_context(body: &str, needle: &str, radius: usize) -> String {
    let Some(at) = body.find(needle) else {
        return String::new();
    };
    let start = body[..at]
        .char_indices()
        .rev()
        .nth(radius)
        .map(|(i, _)| i)
        .unwrap_or(0);
    let end = body[at..]
        .char_indices()
        .nth(radius + needle.chars().count())
        .map(|(i, _)| at + i)
        .unwrap_or(body.len());
    body[start..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Secrets ─────────────────────────────────────────────────────────────

    #[test]
    fn an_aws_key_in_a_bundle_is_detected_and_never_reprinted() {
        let key = sample("AKIA", "IOSFODNN7EXAMPLE");
        let body = format!(r#"var cfg={{key:"{key}",region:"eu-west-2"}};"#);
        let hits = detect_secrets(&body);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, "AWS access key id");
        assert!(
            !hits[0].redacted.contains("IOSFODNN7EXAMPLE"),
            "the report must not republish the secret: {}",
            hits[0].redacted
        );
        assert!(hits[0].redacted.starts_with("AKIAIO"), "but it must be identifiable");
    }

    /// Build a sample credential from its prefix and body at run time.
    ///
    /// The pieces are joined here rather than written as one literal for a
    /// reason worth not undoing: a complete `sk_live_…` string sitting in a
    /// source file is indistinguishable from a real leaked key to a scanner
    /// reading the file, and GitHub's push protection rejects the commit —
    /// which is exactly the behaviour this module exists to provide, so
    /// arguing with it would be incoherent. Splitting the literal keeps the
    /// test honest (the assembled string is what `detect_secrets` actually
    /// sees) while leaving nothing in the repository that reads as a
    /// credential.
    fn sample(prefix: &str, body: &str) -> String {
        format!("{prefix}{body}")
    }

    #[test]
    fn several_provider_formats_are_recognised() {
        let cases = [
            (sample("ghp", "_1234567890abcdefghijklmnopqrstuvwxyz"), "GitHub personal access token"),
            (sample("sk_", "live_abcdefghij1234567890ABCD"), "Stripe live secret key"),
            (sample("AIza", "SyA1234567890abcdefghijklmnopqrstuv"), "Google API key"),
            (sample("npm", "_abcdefghijklmnopqrstuvwxyz0123456789"), "npm access token"),
        ];
        for (value, expected) in cases {
            let hits = detect_secrets(&format!("const t = '{value}';"));
            assert_eq!(hits.len(), 1, "{value} was not detected");
            assert_eq!(hits[0].kind, expected);
        }
    }

    /// Minified JavaScript is one long stream of random-looking strings. A rule
    /// loose enough to catch "any long token" would fire on every page.
    #[test]
    fn ordinary_minified_javascript_is_not_reported_as_a_secret() {
        let bundle = "!function(e,t){var n='a1b2c3d4e5f6a7b8c9d0e1f2';\
                      e.webpackChunkName='main.4f8a9c2e1b7d.js';t(n)}(window,run);\
                      var hash='sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';";
        assert!(detect_secrets(bundle).is_empty(), "{:?}", detect_secrets(bundle));
    }

    #[test]
    fn a_truncated_key_is_not_a_match() {
        // Four characters short of a complete AWS key id.
        assert!(detect_secrets(&sample("AKIA", "IOSFODNN7EXA")).is_empty());
    }

    #[test]
    fn the_same_secret_twice_is_reported_once() {
        let key = sample("AKIA", "IOSFODNN7EXAMPLE");
        let body = format!("a='{key}'; b='{key}';");
        assert_eq!(detect_secrets(&body).len(), 1);
    }

    // ── Private keys ────────────────────────────────────────────────────────

    #[test]
    fn a_pem_private_key_block_is_detected_by_kind() {
        assert_eq!(
            detect_private_key("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."),
            Some("RSA private key")
        );
        assert_eq!(
            detect_private_key("-----BEGIN OPENSSH PRIVATE KEY-----"),
            Some("OpenSSH private key")
        );
        // A public key is not a finding.
        assert!(detect_private_key("-----BEGIN PUBLIC KEY-----").is_none());
        assert!(detect_private_key("-----BEGIN CERTIFICATE-----").is_none());
    }

    // ── Private addressing ──────────────────────────────────────────────────

    #[test]
    fn rfc1918_addresses_are_detected_in_body_and_headers() {
        let found = detect_private_addresses("upstream 10.0.4.17 timed out; retry via 192.168.1.5");
        assert_eq!(found, vec!["10.0.4.17".to_string(), "192.168.1.5".to_string()]);
        assert_eq!(detect_private_addresses("172.16.9.2"), vec!["172.16.9.2".to_string()]);
        assert_eq!(detect_private_addresses("127.0.0.1"), vec!["127.0.0.1".to_string()]);
    }

    #[test]
    fn public_addresses_are_not_internal_disclosure() {
        assert!(detect_private_addresses("8.8.8.8 and 172.15.0.1 and 172.32.0.1").is_empty());
    }

    /// A version number is not an address, and neither is a fragment of a
    /// longer number — both would otherwise report on ordinary pages.
    #[test]
    fn version_like_strings_do_not_produce_address_findings() {
        assert!(detect_private_addresses("build 300.10.0.1.4").is_empty());
        assert!(detect_private_addresses("v1.10.0.1234").is_empty());
        assert!(detect_private_addresses("999.999.999.999").is_empty());
    }

    /// The metadata address is link-local and has its own, more specific check;
    /// reporting it twice would inflate the finding count.
    #[test]
    fn the_metadata_address_is_left_to_its_own_check() {
        assert!(detect_private_addresses("http://169.254.169.254/latest/meta-data/").is_empty());
        assert_eq!(
            detect_metadata_reference("fetch('http://169.254.169.254/latest/meta-data/')"),
            Some("AWS/GCP/Azure")
        );
    }

    // ── Generator ───────────────────────────────────────────────────────────

    #[test]
    fn a_versioned_generator_tag_is_reported() {
        assert_eq!(
            detect_generator(r#"<meta name="generator" content="WordPress 6.1.1">"#),
            Some("WordPress 6.1.1".to_string())
        );
        assert_eq!(
            detect_generator(r#"<META NAME='generator' CONTENT='Drupal 9 (https://drupal.org)'>"#),
            Some("Drupal 9 (https://drupal.org)".to_string())
        );
    }

    /// The product name alone is visible from the page's own markup; only the
    /// version turns it into a targeting aid worth reporting.
    #[test]
    fn an_unversioned_generator_tag_is_not_reported() {
        assert!(detect_generator(r#"<meta name="generator" content="Hugo">"#).is_none());
        assert!(detect_generator(r#"<meta name="viewport" content="width=device-width">"#).is_none());
    }

    // ── JWTs ────────────────────────────────────────────────────────────────

    #[test]
    fn a_jwt_is_detected_by_shape_and_never_reprinted_in_full() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27u";
        let hits = detect_jwts(&format!(r#"<script>var t="{token}";</script>"#));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(!hits[0].contains("dBjftJeZ4CVPmB92K27u"), "the signature must not be reprinted");
        assert!(hits[0].contains("3 segments"));
    }

    /// A variable merely called `token` is not a token, and matching on the
    /// word rather than the structure would fire on every application.
    #[test]
    fn a_variable_named_token_is_not_a_jwt() {
        assert!(detect_jwts(r#"var token = getToken(); var authToken = "abc";"#).is_empty());
        assert!(detect_jwts("eyJhbGci.short.x").is_empty(), "segments must be long enough");
        assert!(detect_jwts("eyJhbGciOiJIUzI1NiJ9").is_empty(), "one segment is not a JWT");
    }

    // ── Browser storage ─────────────────────────────────────────────────────

    #[test]
    fn credential_shaped_storage_keys_are_reported() {
        let body = r#"localStorage.setItem('auth_token', t); sessionStorage.setItem("jwt", j);"#;
        let hits = detect_storage_of_secrets(body);
        assert_eq!(hits.len(), 2, "{hits:?}");
    }

    /// Reporting every write to browser storage would fire on theme
    /// preferences and dismissed banners, which the reader learns to skip.
    #[test]
    fn ordinary_preferences_in_storage_are_not_reported() {
        let body = r#"localStorage.setItem('theme', 'dark');
                      localStorage.setItem('sidebarCollapsed', '1');
                      localStorage.setItem('lastSeenRelease', v);"#;
        assert!(detect_storage_of_secrets(body).is_empty(), "{:?}", detect_storage_of_secrets(body));
    }

    // ── postMessage ─────────────────────────────────────────────────────────

    #[test]
    fn a_wildcard_target_origin_is_reported() {
        let hits = detect_postmessage_wildcard(r#"parent.postMessage(payload, "*");"#);
        assert_eq!(hits.len(), 1, "{hits:?}");
    }

    #[test]
    fn a_named_target_origin_is_correct_and_not_reported() {
        assert!(detect_postmessage_wildcard(
            r#"parent.postMessage(payload, "https://app.example.com");"#
        )
        .is_empty());
        // A bare asterisk is multiplication, not a wildcard origin.
        assert!(detect_postmessage_wildcard("const n = a * b; postMessage(n, origin);").is_empty());
    }

    // ── WebSockets ──────────────────────────────────────────────────────────

    #[test]
    fn a_plaintext_websocket_endpoint_is_extracted() {
        let hits = detect_plaintext_websockets(r#"new WebSocket("ws://api.app.test/live");"#);
        assert_eq!(hits, vec!["ws://api.app.test/live".to_string()]);
    }

    #[test]
    fn an_encrypted_websocket_is_not_a_finding() {
        assert!(detect_plaintext_websockets(r#"new WebSocket("wss://api.app.test/live");"#).is_empty());
    }

    // ── DOM XSS ─────────────────────────────────────────────────────────────

    /// Either half alone is ordinary: every application reads `location`, and
    /// `innerHTML` with a constant is harmless. Only the pair is a signal.
    #[test]
    fn a_sink_is_only_reported_alongside_a_url_source() {
        let both = r#"el.innerHTML = decodeURIComponent(location.hash.slice(1));"#;
        assert!(!detect_dom_xss_sinks(both).is_empty(), "the pair must report");

        assert!(
            detect_dom_xss_sinks(r#"el.innerHTML = "<b>static</b>";"#).is_empty(),
            "a sink with no URL source is ordinary code"
        );
        assert!(
            detect_dom_xss_sinks(r#"const q = location.search; fetch('/api?' + q);"#).is_empty(),
            "reading the URL without an HTML sink is ordinary code"
        );
    }

    #[test]
    fn the_url_sources_present_are_reported_for_the_analyst() {
        let sources = detect_url_sources("x = location.hash; y = document.referrer;");
        assert!(sources.contains(&"location.hash"));
        assert!(sources.contains(&"document.referrer"));
    }

    #[test]
    fn a_page_with_nothing_to_disclose_produces_nothing() {
        assert!(detect_secrets("<h1>Hello</h1>").is_empty());
        assert!(detect_private_key("<h1>Hello</h1>").is_none());
        assert!(detect_private_addresses("<h1>Hello</h1>").is_empty());
        assert!(detect_metadata_reference("<h1>Hello</h1>").is_none());
        assert!(detect_generator("<h1>Hello</h1>").is_none());
        assert!(detect_jwts("<h1>Hello</h1>").is_empty());
        assert!(detect_storage_of_secrets("<h1>Hello</h1>").is_empty());
        assert!(detect_postmessage_wildcard("<h1>Hello</h1>").is_empty());
        assert!(detect_plaintext_websockets("<h1>Hello</h1>").is_empty());
        assert!(detect_dom_xss_sinks("<h1>Hello</h1>").is_empty());
    }
}
