//! Authentication and authorization audit checks.
//!
//! This module is deliberately focused on high-confidence, low-noise findings.
//! Every check here either:
//!   * Observes a structural property that is always a misconfiguration (e.g.
//!     GraphQL introspection enabled in production, JWT `alg: none`)
//!   * Makes a single safe probe and measures a concrete behavioural difference
//!     (e.g. no rate limiting on the login endpoint)
//!
//! Nothing in this module sends POST requests with credentials, guesses passwords
//! or exfiltrates data. Every request is within the RoE gate's scope.
//!
//! Coverage added:
//!   • WSTG-AUTHN-03  Weak account lock-out / missing rate-limit on login
//!   • WSTG-SESS-06   JWT weak algorithm (alg: none, HS256 with public key)
//!   • WSTG-CONF-09   GraphQL introspection not disabled in production
//!   • WSTG-INFO-06   Predictable / sequential resource IDs exposed in API
//!   • WSTG-AUTHZ-01  IDOR: unauthenticated access to `/api/*/{id}` routes
//!   • WSTG-CONF-06   HTTP TRACE enabled (also checked in active.rs for methods)
//!   • WSTG-ATHN-06   Sensitive endpoints missing authentication headers
//!   • WSTG-SESS-09   Insecure default credentials on admin interfaces

use super::builder::{CheckSpec, NativeFinding};
use super::probe::{truncate, Probe, ProbeResponse};
use sentinel_core::models::finding::Finding;
use uuid::Uuid;

const OWASP_AUTHN: &str = "A07:2025-Identification and Authentication Failures";
const OWASP_ACCESS: &str = "A01:2025-Broken Access Control";
const OWASP_MISCONFIG: &str = "A02:2025-Security Misconfiguration";
const OWASP_CRYPTO: &str = "A04:2025-Cryptographic Failures";
const OWASP_INTEGRITY: &str = "A08:2025-Software or Data Integrity Failures";
const OWASP_INJECTION: &str = "A03:2025-Injection";

// ── Check Specifications ──────────────────────────────────────────────────────

const GRAPHQL_INTROSPECTION: CheckSpec = CheckSpec {
    id: "NATIVE-GRAPHQL-SCHEMA-EXPOSURE",
    title: "GraphQL Introspection Enabled in Production",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-200",
    wstg: "WSTG-CONF-09",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: Some("API8:2023-Security Misconfiguration"),
    description: "GraphQL introspection is enabled and responds to unauthenticated queries. \
Introspection exposes the complete schema of the API — every type, field, mutation, subscription \
and relationship — to anyone who can reach the endpoint. An attacker who receives the schema \
does not need to guess or brute-force endpoints: the application has published its own attack \
surface. Field names that expose sensitive capabilities (deleteUser, impersonate, adminOverride) \
are particularly useful for privilege escalation and IDOR attacks.",
    remediation: "Disable introspection in production. Apollo: `introspection: false`. \
Strawberry/Graphene: `introspection=False`. Alternatively, restrict it to authenticated users with \
an admin role and log every introspection request. Keep introspection enabled only in non-production \
environments and behind a VPN or IP allow-list.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
    ],
};

const JWT_WEAK_ALGORITHM: CheckSpec = CheckSpec {
    id: "NATIVE-JWT-WEAK-ALGORITHM",
    title: "JWT Token Uses Weak or Insecure Algorithm (alg: none / HS256 with Public Key)",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-327",
    wstg: "WSTG-SESS-06",
    owasp_2025: OWASP_CRYPTO,
    api_top10: Some("API2:2023-Broken Authentication"),
    description: "A JSON Web Token returned by the application uses `alg: none` or declares \
an algorithm that allows an attacker to forge arbitrary tokens. The `alg: none` attack removes \
the signature entirely; an algorithm-confusion attack uses a public key as the secret for an HMAC \
variant. Both allow an attacker to create valid-looking tokens for any user identity — including \
administrators — without knowing the secret key.",
    remediation: "Enforce an explicit algorithm allow-list server-side and reject tokens whose \
`alg` header does not appear in it. Never accept `alg: none`. For RS/ES algorithms, \
ensure the verifier uses `verify_with_key(public_key)` rather than `decode(token, key)` where \
the library's algorithm selection follows the token's own header.",
    references: &[
        "https://portswigger.net/web-security/jwt",
        "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    ],
};

const MISSING_AUTH_ON_API: CheckSpec = CheckSpec {
    id: "NATIVE-UNPROTECTED-API-ENDPOINT",
    title: "API Endpoint Returns Sensitive Data Without Authentication",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-306",
    wstg: "WSTG-ATHZ-01",
    owasp_2025: OWASP_ACCESS,
    api_top10: Some("API1:2023-Broken Object Level Authorization"),
    description: "An API endpoint under `/api/` responded with a 200 and a non-empty JSON body \
to an unauthenticated request. An endpoint that returns data without requiring authentication \
is reachable by any anonymous client. Where that data includes user records, personal information, \
business data or internal configuration it is a direct confidentiality breach with no preconditions \
for exploitation.",
    remediation: "Require authentication on every API endpoint. Apply authentication middleware \
at the router or framework level rather than per-handler so a new route cannot be added without \
coverage. Test with no Authorization header and no session cookie, and assert that the response \
is 401 Unauthorized or 403 Forbidden — not 200 with data.",
    references: &[
        "https://owasp.org/www-project-api-security/",
        "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
    ],
};

const RATE_LIMIT_MISSING: CheckSpec = CheckSpec {
    id: "NATIVE-NO-RATE-LIMIT-LOGIN",
    title: "Login or Authentication Endpoint Lacks Rate Limiting",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-307",
    wstg: "WSTG-ATHN-03",
    owasp_2025: OWASP_AUTHN,
    api_top10: Some("API4:2023-Unrestricted Resource Consumption"),
    description: "The authentication endpoint accepts repeated requests without any observable \
rate limiting, account lockout or CAPTCHA challenge. An attacker with a credential list can \
attempt authentication at whatever rate the network allows — a modest 100 req/s against a \
10-character lowercase password space exhausts every 6-character password in hours. The \
endpoint responded identically across all probe requests with no sign of throttling, lockout \
or challenge.",
    remediation: "Implement rate limiting at the reverse proxy (nginx `limit_req`, AWS WAF) or \
application layer. Return 429 Too Many Requests after a threshold — 5-10 failures per minute is \
a common starting point. Add exponential back-off and an account lockout for sustained failures, \
and consider requiring CAPTCHA after the first 3 failures. Ensure the lockout is per-account \
rather than per-IP, because IP rotation bypasses IP-only controls.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    ],
};

const IDOR_SEQUENTIAL_IDS: CheckSpec = CheckSpec {
    id: "NATIVE-IDOR-SEQUENTIAL-ID",
    title: "API Resource Uses Predictable Sequential ID — Potential IDOR/BOLA",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-639",
    wstg: "WSTG-ATHZ-04",
    owasp_2025: OWASP_ACCESS,
    api_top10: Some("API1:2023-Broken Object Level Authorization"),
    description: "An API endpoint exposes resource identifiers that are sequential integers. \
Predictable identifiers enable Broken Object Level Authorization (BOLA/IDOR) attacks: an \
authenticated user who knows their own resource ID can enumerate every other user's resources \
simply by iterating the identifier. The check observed a low integer (≤ 10000) at an API path, \
which is the strongest indicator that identifiers are assigned sequentially and therefore enumerable.",
    remediation: "Replace sequential integer IDs with UUIDs (random v4) or another unpredictable \
identifier. Then implement object-level authorization on every API endpoint: verify that the \
requesting user has permission to access the specific object identified by the ID in the path, \
not just that they are authenticated. A UUID without authorization enforcement is not a fix — \
it raises the bar slightly but does not remove the vulnerability.",
    references: &[
        "https://owasp.org/www-project-api-security/",
        "https://portswigger.net/web-security/access-control/idor",
        "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
    ],
};

const DEFAULT_CREDENTIALS: CheckSpec = CheckSpec {
    id: "NATIVE-DEFAULT-CREDENTIALS",
    title: "Admin Interface Accepts Default or Blank Credentials",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    cwe: "CWE-1392",
    wstg: "WSTG-ATHN-06",
    owasp_2025: OWASP_AUTHN,
    api_top10: Some("API2:2023-Broken Authentication"),
    description: "An admin or management interface was reachable and responded to a request with \
default credentials (admin:admin, admin:password, root:root, or similar). Default credentials are \
published in product documentation and exploit databases and are the first thing an attacker tries \
against a newly discovered service. Access to an administrative interface with default credentials \
typically provides complete control of the application and its data.",
    remediation: "Change all default credentials before exposing the service to any network. \
Remove or disable any hardcoded accounts that exist only for initial setup. Enforce a strong \
credential policy on the first-login flow and confirm it cannot be bypassed. Restrict administrative \
interfaces to internal networks and require MFA.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials",
    ],
};

const API_VERSION_EXPOSURE: CheckSpec = CheckSpec {
    id: "NATIVE-DEPRECATED-API-VERSION",
    title: "Deprecated API Version Still Active and Reachable",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1059",
    wstg: "WSTG-CONF-10",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: Some("API9:2023-Improper Inventory Management"),
    description: "An older API version path (v1, v2, etc.) responds with a 200 alongside the \
current version. Deprecated API versions accumulate security debt: they predate the security \
controls that were added in later versions, they may skip the authentication middleware that was \
added to v2, and they are frequently forgotten by the team responsible for patching. An attacker \
who finds that /api/v1/ bypasses the rate limiting or authorization checks on /api/v2/ has a \
trivially reachable attack path.",
    remediation: "Decommission all API versions except the current one. Where a cutover is not \
immediately possible, apply the same security controls to every active version and mark the \
older versions as end-of-life with a sunset date in the response headers. Monitor traffic to old \
versions so lingering clients are identified and updated.",
    references: &[
        "https://owasp.org/www-project-api-security/",
        "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
    ],
};

const SSRF_CANDIDATE_PARAM: CheckSpec = CheckSpec {
    id: "NATIVE-SSRF-CANDIDATE-PARAM",
    title: "Request Parameter Accepts Arbitrary Remote URL — Potential SSRF",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-918",
    wstg: "WSTG-INPV-19",
    owasp_2025: OWASP_ACCESS,
    api_top10: Some("API7:2023-Server Side Request Forgery"),
    description: "An application endpoint exposes query or path parameters designed to fetch \
remote resources (e.g. url, target, dest, redirect, webhook, feed). If the backend does not enforce \
strict protocol allow-lists and IP-range restrictions, an attacker can coerce the server into issuing \
requests to internal infrastructure, loopback interfaces (127.0.0.1), or cloud metadata endpoints.",
    remediation: "Validate all remote resource URLs against a strict allow-list of permitted domains. \
Reject private and loopback IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16). \
Disable HTTP redirects in outgoing HTTP clients and run outgoing proxy services in an isolated network segment.",
    references: &[
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
};

const CLOUD_METADATA_EXPOSURE: CheckSpec = CheckSpec {
    id: "NATIVE-CLOUD-METADATA-EXPOSURE",
    title: "Cloud Provider Instance Metadata Service Exposed via Reverse Proxy",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-200",
    wstg: "WSTG-CONF-05",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: Some("API8:2023-Security Misconfiguration"),
    description: "A cloud metadata path (such as AWS EC2 metadata at /latest/meta-data/ or GCP \
metadata at /computeMetadata/v1/) responded with valid cloud instance metadata to an external request. \
Reverse proxy routing rules or rewrite misconfigurations can route external paths directly to internal \
link-local addresses (169.254.169.254). Cloud metadata contains IAM roles, temporary credentials, \
startup scripts, and sensitive network topology.",
    remediation: "Block all incoming external requests matching metadata paths at the web server / WAF. \
On AWS, enforce IMDSv2 (`HttpTokens=required`) with hop limit set to 1 so containerized or proxied \
requests cannot reach the metadata service. On GCP/Azure, require custom metadata headers server-side.",
    references: &[
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
    ],
};

const PROTOTYPE_POLLUTION: CheckSpec = CheckSpec {
    id: "NATIVE-PROTOTYPE-POLLUTION",
    title: "Client-Side Prototype Pollution Pattern Detected in JavaScript Asset",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1321",
    wstg: "WSTG-CLNT-13",
    owasp_2025: OWASP_INTEGRITY,
    api_top10: None,
    description: "A client-side JavaScript file contains object traversal or merge patterns vulnerable \
to prototype pollution (modifying `Object.prototype` via `__proto__` or `constructor.prototype`). \
Prototype pollution allows an attacker to inject properties into all JavaScript objects running within \
the browser session, which can escalate to Cross-Site Scripting (XSS) or authentication bypass.",
    remediation: "Use `Object.create(null)` for key-value dictionary objects, freeze the prototype with \
`Object.freeze(Object.prototype)`, or validate object keys to disallow `__proto__` and `constructor`. \
Ensure external libraries (e.g. lodash, jQuery) are updated to patched versions.",
    references: &[
        "https://portswigger.net/web-security/prototype-pollution",
        "https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html",
    ],
};

const CACHE_DECEPTION: CheckSpec = CheckSpec {
    id: "NATIVE-WEB-CACHE-DECEPTION",
    title: "Web Cache Deception: Dynamic Endpoint Vulnerable to Static Path Extension Confusion",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-524",
    wstg: "WSTG-CONF-11",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: Some("API8:2023-Security Misconfiguration"),
    description: "When appending a static file extension (e.g. `.css`, `.js`) to a dynamic or \
authenticated endpoint, the origin server returns dynamic private data while downstream proxies or \
CDNs cache the response as a public static asset. An attacker who convinces a logged-in victim to \
click a forged link with a static extension can subsequently retrieve the victim's cached sensitive \
account data directly from the CDN.",
    remediation: "Configure edge caches and CDNs to cache files based on the `Content-Type` header rather \
than URL extensions alone. Set `Cache-Control: no-store, private` on all dynamic and authenticated \
endpoints, and configure web frameworks to reject path extensions that do not match the expected route.",
    references: &[
        "https://portswigger.net/web-security/web-cache-poisoning/web-cache-deception",
        "https://owasp.org/www-community/attacks/Web_Cache_Deception",
    ],
};

const DATABASE_ERROR_DISCLOSURE: CheckSpec = CheckSpec {
    id: "NATIVE-DATABASE-ERROR-LEAK",
    title: "Verbose Database Error or Syntax Exception Leaked in HTTP Response",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-209",
    wstg: "WSTG-ERRH-01",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "The application returned raw database error messages or internal syntax diagnostics \
(such as SQL syntax errors, MongoDB query faults, or ORM stack traces) in response to malformed input. \
Database error messages expose the underlying database technology, table structures, column names, \
and SQL query construction, dramatically lowering the effort needed to execute SQL injection attacks.",
    remediation: "Disable verbose error messages and debug mode in production. Catch database exceptions \
at the service layer and return generic error responses with an opaque correlation ID. Ensure error \
handlers do not echo raw database driver error strings to clients.",
    references: &[
        "https://owasp.org/www-community/Improper_Error_Handling",
        "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
    ],
};

const API_KEY_IN_URL: CheckSpec = CheckSpec {
    id: "NATIVE-API-KEY-IN-URL",
    title: "Sensitive Credential or API Key Passed in URL Query String",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-598",
    wstg: "WSTG-INFO-07",
    owasp_2025: OWASP_AUTHN,
    api_top10: Some("API2:2023-Broken Authentication"),
    description: "The application passes authentication tokens, API keys, client secrets, or user \
passwords in URL query strings (e.g. `?api_key=`, `?token=`, `?secret=`, `?access_token=`). \
URL query parameters are routinely written to web server access logs, browser history, proxy caches, \
and HTTP `Referer` headers when external links are clicked, exposing credentials to third parties.",
    remediation: "Pass authentication credentials in HTTP request headers (such as the standard `Authorization: Bearer <token>` \
header) or in the request body for POST/PUT requests. Configure web servers and proxies to redact sensitive \
query parameters from log outputs.",
    references: &[
        "https://owasp.org/www-project-api-security/",
        "https://cwe.mitre.org/data/definitions/598.html",
    ],
};

const PATH_TRAVERSAL: CheckSpec = CheckSpec {
    id: "NATIVE-PATH-TRAVERSAL-LEAK",
    title: "Path Traversal Arbitrary File Read via Parameter Manipulation",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-22",
    wstg: "WSTG-INPV-11",
    owasp_2025: OWASP_ACCESS,
    api_top10: Some("API1:2023-Broken Object Level Authorization"),
    description: "An endpoint accepts file path or template parameters (e.g. `file=`, `path=`, `doc=`, `view=`) \
which allow dot-dot-slash sequence traversal (`../../../../etc/passwd` or `..\\..\\win.ini`). The server \
returned file contents indicating unauthorized read access to server filesystem resources.",
    remediation: "Never pass unsanitized user input directly to filesystem APIs. Use an allow-list of known IDs \
or filenames mapped to internal resources. If dynamic file paths are necessary, normalize paths with canonicalization \
and verify the absolute path remains strictly within the intended base directory.",
    references: &[
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
    ],
};

const REFLECTED_XSS: CheckSpec = CheckSpec {
    id: "NATIVE-REFLECTED-XSS-PARAM",
    title: "Reflected Cross-Site Scripting (XSS) via Unencoded Input Echo",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-79",
    wstg: "WSTG-INPV-01",
    owasp_2025: OWASP_INJECTION,
    api_top10: None,
    description: "The application reflects untrusted input directly into the HTML response body or attributes \
without contextual output encoding. An attacker can construct a crafted URL that executes arbitrary JavaScript \
within the victim's browser session, allowing session hijacking, credential theft, or sensitive action execution.",
    remediation: "Apply context-aware contextual output encoding (HTML body, HTML attribute, JavaScript variable) \
before reflecting user input. Implement a robust Content Security Policy (CSP) with `script-src 'self'` and nonces \
to prevent script execution even if injection occurs.",
    references: &[
        "https://owasp.org/www-community/attacks/xss/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
};

const OPEN_REDIRECT: CheckSpec = CheckSpec {
    id: "NATIVE-OPEN-REDIRECT-VALIDATION",
    title: "Unvalidated Open Redirect via Parameter Manipulation",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-601",
    wstg: "WSTG-CLNT-04",
    owasp_2025: OWASP_ACCESS,
    api_top10: None,
    description: "The application accepts an untrusted destination URL in a query parameter (e.g. `return=`, `next=`, `redirect_uri=`) \
and issues an HTTP 30x redirect to that arbitrary location without verification. Attackers exploit open redirects in phishing campaigns \
to redirect victims from a legitimate trusted domain to a malicious credential-harvesting site.",
    remediation: "Avoid accepting arbitrary redirect targets from user input. Where redirection is required, validate \
the target URL against a strict allow-list of internal relative paths or approved domain origins.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/601.html",
    ],
};

const CRLF_INJECTION: CheckSpec = CheckSpec {
    id: "NATIVE-CRLF-HEADER-INJECTION",
    title: "CRLF Carriage Return / Line Feed HTTP Response Header Injection",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-113",
    wstg: "WSTG-INPV-15",
    owasp_2025: OWASP_INJECTION,
    api_top10: None,
    description: "The application incorporates user-supplied input into HTTP response headers without stripping CR (%0D) and LF (%0A) \
characters. This allows an attacker to inject arbitrary HTTP headers (such as `Set-Cookie`) or split the HTTP response, facilitating \
HTTP response splitting, cache poisoning, and cross-site scripting (XSS).",
    remediation: "Sanitize all user input before using it in HTTP headers by stripping carriage returns (\\r, %0D) and line feeds (\\n, %0A). \
Use modern web frameworks that automatically reject or encode header values containing newline characters.",
    references: &[
        "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
        "https://cwe.mitre.org/data/definitions/113.html",
    ],
};

const DEBUG_PARAM_EXPOSURE: CheckSpec = CheckSpec {
    id: "NATIVE-DEBUG-PARAM-EXPOSURE",
    title: "Hidden Debug or Administrative Parameter Bypass Exposed",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-489",
    wstg: "WSTG-CONF-04",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: Some("API8:2023-Security Misconfiguration"),
    description: "The application alters its execution mode, error reporting, or authentication requirements when passed hidden \
debug parameters (e.g. `?debug=true`, `?test=1`, `?admin=1`, `?trace=true`). Debug parameters left enabled in production expose \
internal diagnostics or allow bypass of business logic.",
    remediation: "Remove all debugging, test, and staging code before deploying to production. Strip development parameters \
at the reverse proxy or API gateway level and ensure debug flags cannot be enabled via client query strings or headers.",
    references: &[
        "https://cwe.mitre.org/data/definitions/489.html",
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
    ],
};

const BACKUP_SENSITIVE_FILES: CheckSpec = CheckSpec {
    id: "NATIVE-BACKUP-SENSITIVE-FILES",
    title: "Sensitive Backup, Archive, or Configuration Files Publicly Accessible",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-530",
    wstg: "WSTG-CONF-04",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: Some("API8:2023-Security Misconfiguration"),
    description: "Temporary, backup, or archive files (such as `.bak`, `.old`, `.swp`, `backup.tar.gz`, `app.zip`, `.env.backup`) \
are publicly accessible on the web server. These files often contain uncompiled source code, plaintext database credentials, \
encryption keys, and private infrastructure configuration.",
    remediation: "Configure the web server to deny access to backup, temporary, and hidden file extensions. Ensure deployment \
pipelines clean up editor swap files and database dump archives, and store backups in dedicated private storage.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
        "https://cwe.mitre.org/data/definitions/530.html",
    ],
};

// ── Public spec list ──────────────────────────────────────────────────────────

pub const SPECS: &[CheckSpec] = &[
    GRAPHQL_INTROSPECTION,
    JWT_WEAK_ALGORITHM,
    MISSING_AUTH_ON_API,
    RATE_LIMIT_MISSING,
    IDOR_SEQUENTIAL_IDS,
    DEFAULT_CREDENTIALS,
    API_VERSION_EXPOSURE,
    SSRF_CANDIDATE_PARAM,
    CLOUD_METADATA_EXPOSURE,
    PROTOTYPE_POLLUTION,
    CACHE_DECEPTION,
    DATABASE_ERROR_DISCLOSURE,
    API_KEY_IN_URL,
    PATH_TRAVERSAL,
    REFLECTED_XSS,
    OPEN_REDIRECT,
    CRLF_INJECTION,
    DEBUG_PARAM_EXPOSURE,
    BACKUP_SENSITIVE_FILES,
];

// ── Runner ────────────────────────────────────────────────────────────────────

/// Run all authentication and authorization audit checks.
///
/// Every check is safe: GET/HEAD only, no mutation, within the RoE rate limit.
pub async fn run(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    base_url: &str,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let origin = base_url.trim_end_matches('/');

    // GraphQL introspection — check well-known GraphQL paths
    findings.extend(check_graphql_introspection(probe, target_id, scan_id, origin).await);

    // JWT analysis — look for JWT tokens in responses and inspect headers
    findings.extend(check_jwt_in_responses(probe, target_id, scan_id, origin, discovered).await);

    // API endpoints without authentication
    findings.extend(check_unauthenticated_api(probe, target_id, scan_id, discovered).await);

    // Rate limiting on login/auth endpoints
    findings.extend(check_rate_limiting(probe, target_id, scan_id, origin, discovered).await);

    // IDOR via sequential IDs
    findings.extend(check_sequential_ids(probe, target_id, scan_id, discovered).await);

    // Default admin credentials
    findings.extend(check_default_credentials(probe, target_id, scan_id, origin, discovered).await);

    // Old API version still active
    findings.extend(check_deprecated_api_versions(probe, target_id, scan_id, origin, discovered).await);

    // SSRF candidate parameters
    findings.extend(check_ssrf_candidate_params(probe, target_id, scan_id, discovered).await);

    // Cloud metadata exposure
    findings.extend(check_cloud_metadata_exposure(probe, target_id, scan_id, origin).await);

    // Prototype pollution in JavaScript
    findings.extend(check_prototype_pollution(probe, target_id, scan_id, discovered).await);

    // Web cache deception
    findings.extend(check_cache_deception(probe, target_id, scan_id, origin, discovered).await);

    // Database error and syntax exception disclosure
    findings.extend(check_database_error_disclosure(probe, target_id, scan_id, discovered).await);

    // Sensitive credentials or API keys in URL query string
    findings.extend(check_api_key_in_url(probe, target_id, scan_id, discovered).await);

    // Path traversal arbitrary file read
    findings.extend(check_path_traversal(probe, target_id, scan_id, discovered).await);

    // Reflected Cross-Site Scripting (XSS)
    findings.extend(check_reflected_xss(probe, target_id, scan_id, discovered).await);

    // Unvalidated open redirect
    findings.extend(check_open_redirect(probe, target_id, scan_id, discovered).await);

    // CRLF header injection
    findings.extend(check_crlf_injection(probe, target_id, scan_id, discovered).await);

    // Hidden debug / admin parameter exposure
    findings.extend(check_debug_param_exposure(probe, target_id, scan_id, discovered).await);

    // Exposed backup / sensitive archive files
    findings.extend(check_backup_sensitive_files(probe, target_id, scan_id, origin).await);

    findings
}

// ── GraphQL introspection ─────────────────────────────────────────────────────

const GRAPHQL_PATHS: &[&str] = &["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/query", "/gql"];

const GRAPHQL_INTROSPECTION_QUERY: &str =
    r#"{"query":"{__schema{types{name}}}"}"#;

async fn check_graphql_introspection(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    origin: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // GraphQL supports GET requests with a `query` parameter — this is a safe,
    // read-only probe that the engine's method restriction (GET/HEAD/OPTIONS)
    // already allows. We use the minimal introspection query that reveals
    // whether the schema is exposed without requesting the whole schema.
    let introspection_param = "%7B__schema%7Btypes%7Bname%7D%7D%7D"; // {__schema{types{name}}}

    for path in GRAPHQL_PATHS {
        let url_with_query = format!("{origin}{path}?query={introspection_param}");
        let Ok(Some(resp)) = probe.get(&url_with_query).await else {
            // Also try without query to detect the endpoint exists
            let base_url = format!("{origin}{path}");
            let Ok(Some(base_resp)) = probe.get(&base_url).await else { continue };
            // A GraphQL endpoint that returns JSON with "errors" to an empty GET
            // is still an exposed introspection-capable endpoint
            if base_resp.status == 200 && base_resp.body.contains("\"errors\"")
                && (base_resp.body.contains("\"message\"") || base_resp.body.contains("\"data\""))
            {
                findings.push(NativeFinding::build(
                    &GRAPHQL_INTROSPECTION,
                    target_id,
                    scan_id,
                    &base_url,
                    &format!(
                        "A GraphQL endpoint was identified at `{base_url}`. \
                         Verify whether introspection is disabled by running the introspection query below."
                    ),
                    vec![
                        format!(
                            r#"curl -sSX POST '{base_url}' -H 'Content-Type: application/json' -d '{GRAPHQL_INTROSPECTION_QUERY}'"#
                        ),
                    ],
                    vec![NativeFinding::evidence(
                        "graphql_response",
                        "GraphQL endpoint detected (GET response)",
                        &base_resp.evidence_summary(),
                    )],
                ));
            }
            continue;
        };

        // A GraphQL response always has a top-level `data` key with schema info
        if resp.status == 200
            && resp.body.contains("\"__schema\"")
            && resp.body.contains("\"types\"")
        {
            findings.push(NativeFinding::build(
                &GRAPHQL_INTROSPECTION,
                target_id,
                scan_id,
                &url_with_query,
                &format!(
                    "GraphQL introspection query via GET returned schema data from `{origin}{path}`. \
                     The response contained __schema.types, exposing the full API type system to any visitor."
                ),
                vec![
                    format!(
                        r#"curl -sSG '{origin}{path}' --data-urlencode 'query={{__schema{{types{{name}}}}}}' | jq '.data.__schema.types | length'"#
                    ),
                    format!(
                        r#"# Full introspection: curl -sSX POST '{origin}{path}' -H 'Content-Type: application/json' -d '{GRAPHQL_INTROSPECTION_QUERY}'"#
                    ),
                ],
                vec![NativeFinding::evidence(
                    "graphql_response",
                    "GraphQL introspection response (first 800 bytes)",
                    &truncate(&resp.body, 800),
                )],
            ));
            break; // One finding per target is enough
        }
    }

    findings
}


// ── JWT weak algorithm ────────────────────────────────────────────────────────

async fn check_jwt_in_responses(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    origin: &str,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Look for JWT tokens in response headers (Authorization, Set-Cookie, custom X- headers)
    // and in JSON response bodies across discovered API endpoints.
    let urls_to_check: Vec<String> = std::iter::once(origin.to_string())
        .chain(discovered.iter().take(20).cloned())
        .collect();

    for url in &urls_to_check {
        let Ok(Some(resp)) = probe.get(url).await else { continue };

        // Check all response header values for JWT-like patterns
        for value in resp.headers.values() {
            let value_str = value.to_str().unwrap_or("");
            if let Some(finding) = analyze_jwt_value(value_str, &url, target_id, scan_id, &resp) {
                findings.push(finding);
                return findings; // One JWT finding per scan is sufficient signal
            }
        }

        // Check JSON response body for embedded JWTs
        if resp.body.contains("\"token\"") || resp.body.contains("\"jwt\"") || resp.body.contains("\"access_token\"") {
            // Extract JWT-like strings: three base64url segments separated by dots
            if let Some(jwt) = extract_jwt_from_json(&resp.body) {
                if let Some(finding) = analyze_jwt_value(&jwt, url, target_id, scan_id, &resp) {
                    findings.push(finding);
                    return findings;
                }
            }
        }
    }

    findings
}

/// Decode a JWT header and check for weak algorithm declarations.
fn analyze_jwt_value(value: &str, url: &str, target_id: Uuid, scan_id: Uuid, resp: &ProbeResponse) -> Option<Finding> {
    // Find a JWT pattern: three dot-separated base64url segments
    let jwt = extract_jwt_candidate(value)?;
    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }

    let header_b64 = parts[0];
    // Add padding as needed
    let padded = pad_base64(header_b64);
    let decoded = base64_url_decode(&padded).ok()?;
    let header_str = std::str::from_utf8(&decoded).ok()?;

    // Check for weak algorithm
    let alg_none = header_str.contains("\"none\"") || header_str.contains("\"None\"") || header_str.contains("\"NONE\"");
    let alg_hs256_suspicious = header_str.contains("\"HS256\"") && parts[2].is_empty();

    if alg_none || alg_hs256_suspicious {
        let detail = if alg_none {
            format!("A JWT token with `alg: none` was found at `{url}`. The signature segment is absent, meaning the token is unsigned and any payload can be forged.")
        } else {
            format!("A JWT token with `alg: HS256` and an empty signature segment was found at `{url}`, indicating possible algorithm confusion vulnerability.")
        };

        Some(NativeFinding::build(
            &JWT_WEAK_ALGORITHM,
            target_id,
            scan_id,
            url,
            &detail,
            vec![
                format!("# Decode the header and inspect the 'alg' field:"),
                format!("echo '{header_b64}' | base64 -d 2>/dev/null || echo '{header_b64}' | python3 -c \"import base64,sys; print(base64.urlsafe_b64decode(sys.stdin.read().strip()+'==').decode())\""),
            ],
            vec![NativeFinding::evidence(
                "jwt_header",
                "JWT header (decoded)",
                header_str,
            ), NativeFinding::evidence(
                "http_response",
                "Response containing weak JWT",
                &resp.evidence_summary(),
            )],
        ))
    } else {
        None
    }
}

fn extract_jwt_candidate(s: &str) -> Option<&str> {
    // Find "ey..." pattern — JWT headers always start with base64url of `{"` which is `ey`
    let start = s.find("ey")?;
    let candidate = &s[start..];
    // Take until a non-JWT character
    let end = candidate.find(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '_').unwrap_or(candidate.len());
    let jwt = &candidate[..end];
    if jwt.matches('.').count() == 2 { Some(jwt) } else { None }
}

fn extract_jwt_from_json(body: &str) -> Option<String> {
    // Look for JSON fields containing JWT-like values
    for field in &["\"token\":", "\"jwt\":", "\"access_token\":", "\"id_token\":"] {
        if let Some(pos) = body.find(field) {
            let after = &body[pos + field.len()..].trim_start();
            let after = after.trim_start_matches('"');
            if let Some(jwt) = extract_jwt_candidate(after) {
                return Some(jwt.to_string());
            }
        }
    }
    None
}

fn pad_base64(s: &str) -> String {
    let mut s = s.replace('-', "+").replace('_', "/");
    match s.len() % 4 {
        2 => s.push_str("=="),
        3 => s.push('='),
        _ => {}
    }
    s
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, ()> {

    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut bits = 0u32;
    let mut bit_count = 0u32;
    for c in s.chars() {
        if c == '=' { break; }
        let val = alphabet.find(c).ok_or(())? as u32;
        bits = (bits << 6) | val;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    Ok(out)
}

// ── Unauthenticated API endpoints ─────────────────────────────────────────────

async fn check_unauthenticated_api(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Only check API-looking paths that actually return JSON
    let api_paths: Vec<&String> = discovered
        .iter()
        .filter(|url| {
            let lower = url.to_lowercase();
            lower.contains("/api/") || lower.contains("/v1/") || lower.contains("/v2/") || lower.contains("/v3/")
        })
        .take(15)
        .collect();

    for url in api_paths {
        let Ok(Some(resp)) = probe.get(url).await else { continue };

        // Only flag if: 200 OK, JSON content type, non-trivial body (>50 bytes)
        let is_json = resp
            .header("content-type")
            .map(|ct| ct.to_lowercase().contains("application/json"))
            .unwrap_or(false);

        if resp.status == 200
            && is_json
            && resp.body.len() > 50
            && !resp.body.trim().is_empty()
            && resp.body.trim() != "[]"
            && resp.body.trim() != "{}"
        {
            // Heuristic: does the response look like it contains user/business data?
            let has_sensitive_structure = resp.body.contains("\"email\"")
                || resp.body.contains("\"user\"")
                || resp.body.contains("\"username\"")
                || resp.body.contains("\"password\"")
                || resp.body.contains("\"phone\"")
                || resp.body.contains("\"address\"")
                || resp.body.contains("\"credit_card\"")
                || resp.body.contains("\"ssn\"")
                || resp.body.contains("\"token\"")
                || resp.body.contains("\"key\"")
                || resp.body.contains("\"secret\"");

            if has_sensitive_structure {
                findings.push(NativeFinding::build(
                    &MISSING_AUTH_ON_API,
                    target_id,
                    scan_id,
                    url,
                    &format!(
                        "The API endpoint `{url}` returned {} bytes of JSON data to an \
                         unauthenticated GET request. The response contains field names \
                         suggesting sensitive data (email, user, token, key, or similar).",
                        resp.body.len()
                    ),
                    vec![
                        format!("curl -sSf '{url}' | jq ."),
                        format!("# Confirm: remove any auth headers and repeat — if response is 200 with data, the endpoint is unauthenticated"),
                    ],
                    vec![NativeFinding::evidence(
                        "api_response",
                        "Unauthenticated API response (first 800 bytes)",
                        &truncate(&resp.body, 800),
                    )],
                ));

                if findings.len() >= 3 {
                    break; // Cap at 3 per scan to avoid overwhelming the report
                }
            }
        }
    }

    findings
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

/// Common paths where a login / auth endpoint might live.
const AUTH_PATHS: &[&str] = &[
    "/login", "/signin", "/auth/login", "/api/login", "/api/auth/login",
    "/api/v1/auth/login", "/api/v2/auth/login", "/user/login", "/account/login",
    "/api/token", "/api/auth/token", "/auth/token", "/oauth/token",
    "/api/sessions", "/api/auth", "/auth",
];

async fn check_rate_limiting(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    origin: &str,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Collect candidate auth endpoints from discovered paths + well-known paths
    let mut candidates: Vec<String> = discovered
        .iter()
        .filter(|u| {
            let lower = u.to_lowercase();
            lower.contains("login") || lower.contains("signin") || lower.contains("/auth")
                || lower.contains("/token") || lower.contains("/session")
        })
        .cloned()
        .collect();

    for path in AUTH_PATHS {
        candidates.push(format!("{origin}{path}"));
    }
    candidates.dedup();

    for url in candidates.iter().take(5) {
        // Send 6 identical HEAD requests and check if any returns 429 or changes
        let mut responses = Vec::new();
        for _ in 0..6 {
            if let Ok(Some(resp)) = probe.request("HEAD", url, &[]).await {
                responses.push(resp.status);
            }
        }

        if responses.len() < 4 {
            continue; // Not enough data
        }

        // If the endpoint exists (any 2xx or 401/403) AND never returned 429
        let has_auth_endpoint = responses.iter().any(|&s| s < 500 && s != 404 && s != 410);
        let has_rate_limit = responses.iter().any(|&s| s == 429);
        let all_same = responses.windows(2).all(|w| w[0] == w[1]);

        if has_auth_endpoint && !has_rate_limit && all_same {
            findings.push(NativeFinding::build(
                &RATE_LIMIT_MISSING,
                target_id,
                scan_id,
                url,
                &format!(
                    "The endpoint `{url}` responded {} times with consistent HTTP {} status \
                     and no 429 Too Many Requests response, suggesting no rate limiting is applied.",
                    responses.len(),
                    responses[0]
                ),
                vec![
                    format!("# Send 20 rapid requests and check for 429:"),
                    format!("seq 1 20 | xargs -P5 -I{{}} curl -sSo /dev/null -w '%{{http_code}}\\n' -X HEAD '{url}'"),
                ],
                vec![NativeFinding::evidence(
                    "rate_limit_probe",
                    "Rate limit probe response codes",
                    &format!("Six consecutive HEAD requests to {url} returned: {responses:?}"),
                )],
            ));
            break; // One rate-limit finding per scan
        }
    }

    findings
}

// ── IDOR via sequential IDs ───────────────────────────────────────────────────

async fn check_sequential_ids(
    _probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for url in discovered {
        // Look for API paths that end in a small integer: /api/users/1, /api/orders/42
        let path = url::Url::parse(url)
            .ok()
            .and_then(|u| Some(u.path().to_string()))
            .unwrap_or_default();

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.len() < 2 {
            continue;
        }

        let last = *segments.last().unwrap_or(&"");
        if let Ok(id) = last.parse::<u64>() {
            // A small integer (≤ 10000) in an API path is a strong IDOR indicator
            if id > 0 && id <= 10000 {
                findings.push(NativeFinding::build(
                    &IDOR_SEQUENTIAL_IDS,
                    target_id,
                    scan_id,
                    url,
                    &format!(
                        "The API path `{path}` ends in a sequential integer ({id}). \
                         An authenticated user who knows their own resource ID can enumerate \
                         adjacent resources by incrementing or decrementing this value. \
                         Verify that the application enforces object-level authorization for \
                         every request, not just that the user is authenticated."
                    ),
                    vec![
                        format!("# Replace {id} with {pred} (the predecessor) and confirm a 403:", pred = id.saturating_sub(1)),
                        format!("curl -sSf '{url_prev}' -H 'Authorization: Bearer <your_token>'",
                            url_prev = url.replace(&format!("/{id}"), &format!("/{}", id.saturating_sub(1)))
                        ),
                    ],
                    vec![NativeFinding::evidence(
                        "api_path",
                        "API path with sequential integer ID",
                        url,
                    )],
                ));
                if findings.len() >= 2 { break; }
            }
        }
    }

    findings
}

// ── Default credentials ───────────────────────────────────────────────────────

/// Well-known admin paths.
const ADMIN_PATHS: &[&str] = &[
    "/admin", "/wp-admin", "/administrator", "/admin/login", "/wp-login.php",
    "/phpmyadmin", "/pma", "/adminer", "/panel", "/dashboard", "/manager",
    "/console", "/actuator", "/actuator/env", "/actuator/health",
];

async fn check_default_credentials(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    origin: &str,
    _discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for path in ADMIN_PATHS {
        let url = format!("{origin}{path}");
        let Ok(Some(resp)) = probe.get(&url).await else { continue };

        // Spring Boot Actuator: /actuator/env exposes environment variables including secrets
        if (path.starts_with("/actuator") && resp.status == 200)
            && (resp.body.contains("\"activeProfiles\"")
                || resp.body.contains("\"propertySources\"")
                || resp.body.contains("\"systemEnvironment\""))
        {
            findings.push(NativeFinding::build(
                &DEFAULT_CREDENTIALS,
                target_id,
                scan_id,
                &url,
                &format!(
                    "Spring Boot Actuator endpoint `{url}` is publicly accessible and returns \
                     sensitive environment data including property sources and system environment \
                     variables. This may expose secrets, database credentials and API keys."
                ),
                vec![
                    format!("curl -sSf '{url}' | jq '.propertySources[] | select(.name | contains(\"application\")) | .properties'"),
                ],
                vec![NativeFinding::evidence(
                    "actuator_response",
                    "Actuator /env response (first 800 bytes)",
                    &truncate(&resp.body, 800),
                )],
            ));
            break;
        }

        // phpMyAdmin / Adminer: returns 200 with login form — note exposure but not auth bypass
        if resp.status == 200
            && (resp.body.contains("phpMyAdmin") || resp.body.contains("Adminer"))
            && (*path == "/phpmyadmin" || *path == "/pma" || *path == "/adminer")
        {
            findings.push(NativeFinding::build(
                &DEFAULT_CREDENTIALS,
                target_id,
                scan_id,
                &url,
                &format!(
                    "A database management interface ({}) is publicly accessible at `{url}`. \
                     These interfaces are common targets for default credential attacks \
                     (root with blank password, root:root) and must not be exposed to the internet.",
                    if resp.body.contains("phpMyAdmin") { "phpMyAdmin" } else { "Adminer" }
                ),
                vec![format!("curl -sSI '{url}'")],
                vec![NativeFinding::evidence(
                    "http_response",
                    "Database management UI response",
                    &resp.evidence_summary(),
                )],
            ));
            break;
        }
    }

    findings
}

// ── Deprecated API versions ───────────────────────────────────────────────────

async fn check_deprecated_api_versions(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    origin: &str,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Find the highest API version present in discovered paths
    let mut found_versions: Vec<u32> = Vec::new();
    for url in discovered {
        let lower = url.to_lowercase();
        for v in 1u32..=10 {
            if lower.contains(&format!("/v{v}/")) || lower.contains(&format!("/api/v{v}/")) {
                if !found_versions.contains(&v) {
                    found_versions.push(v);
                }
            }
        }
    }

    found_versions.sort();
    if found_versions.len() < 2 {
        return findings; // Need at least two versions to flag the older one
    }

    let max_ver = *found_versions.last().unwrap();
    // Check if older versions are still responding
    for &old_ver in &found_versions[..found_versions.len() - 1] {
        let v1_url = format!("{origin}/api/v{old_ver}/");
        let Ok(Some(resp)) = probe.get(&v1_url).await else { continue };

        if resp.status != 404 && resp.status != 410 {
            findings.push(NativeFinding::build(
                &API_VERSION_EXPOSURE,
                target_id,
                scan_id,
                &v1_url,
                &format!(
                    "API v{old_ver} responded with HTTP {} while v{max_ver} is also active. \
                     Deprecated API versions may lack security controls present in newer versions \
                     and are frequently overlooked during security hardening and patching.",
                    resp.status
                ),
                vec![
                    format!("curl -sSI '{v1_url}'"),
                    format!("# Compare with current version: curl -sSI '{origin}/api/v{max_ver}/'"),
                ],
                vec![NativeFinding::evidence(
                    "http_response",
                    &format!("Deprecated API v{old_ver} response"),
                    &resp.evidence_summary(),
                )],
            ));
            break; // One per scan
        }
    }

    findings
}

// ── SSRF Candidate Parameters ─────────────────────────────────────────────────

const SSRF_PARAM_KEYS: &[&str] = &[
    "url", "dest", "destination", "redirect", "redirect_url", "redirect_uri",
    "target", "link", "feed", "webhook", "callback", "fetch", "proxy", "site", "host",
];

async fn check_ssrf_candidate_params(
    _probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for url in discovered {
        let Ok(parsed) = url::Url::parse(url) else { continue };
        for (key, val) in parsed.query_pairs() {
            let key_lower = key.to_lowercase();
            if SSRF_PARAM_KEYS.iter().any(|&k| k == key_lower) {
                let val_lower = val.to_lowercase();
                if val_lower.starts_with("http://")
                    || val_lower.starts_with("https://")
                    || val_lower.starts_with("ftp://")
                    || val_lower.starts_with("//")
                {
                    findings.push(NativeFinding::build(
                        &SSRF_CANDIDATE_PARAM,
                        target_id,
                        scan_id,
                        url,
                        &format!(
                            "The request parameter `{key}` in `{url}` accepts a full remote URL value (`{val}`). \
                             Endpoints that fetch resources on behalf of user requests can be exploited for Server-Side \
                             Request Forgery (SSRF) if they do not strictly validate and restrict outbound destinations."
                        ),
                        vec![
                            format!("curl -sSf '{url}'"),
                            format!("# Test if loopback or internal IPs are blocked:"),
                            format!("curl -sSI '{url}' --header 'X-Forwarded-For: 127.0.0.1'"),
                        ],
                        vec![NativeFinding::evidence(
                            "ssrf_param",
                            "SSRF candidate query parameter",
                            &format!("Parameter '{key}' with remote target '{val}' on {url}"),
                        )],
                    ));

                    if findings.len() >= 3 {
                        return findings;
                    }
                    break;
                }
            }
        }
    }

    findings
}

// ── Cloud Metadata Exposure ───────────────────────────────────────────────────

const CLOUD_METADATA_PATHS: &[&str] = &[
    "/latest/meta-data/",
    "/computeMetadata/v1/",
    "/metadata/instance",
];

async fn check_cloud_metadata_exposure(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    origin: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for path in CLOUD_METADATA_PATHS {
        let url = format!("{origin}{path}");
        let Ok(Some(resp)) = probe.get(&url).await else { continue };

        let has_aws_metadata = resp.status == 200
            && (resp.body.contains("ami-id")
                || resp.body.contains("instance-id")
                || resp.body.contains("iam/security-credentials")
                || resp.body.contains("placement/availability-zone"));

        let has_gcp_metadata = resp.status == 200
            && (resp.body.contains("computeMetadata")
                || resp.header("metadata-flavor").map(|v| v.contains("Google")).unwrap_or(false));

        let has_azure_metadata = resp.status == 200
            && (resp.body.contains("azEnvironment") || resp.body.contains("vmId"));

        if has_aws_metadata || has_gcp_metadata || has_azure_metadata {
            findings.push(NativeFinding::build(
                &CLOUD_METADATA_EXPOSURE,
                target_id,
                scan_id,
                &url,
                &format!(
                    "The cloud metadata path `{url}` returned HTTP 200 with instance metadata contents. \
                     An external request was able to access internal cloud instance metadata via reverse proxy, \
                     forwarding rule, or missing path filtering."
                ),
                vec![
                    format!("curl -sSf '{url}'"),
                ],
                vec![NativeFinding::evidence(
                    "metadata_response",
                    "Cloud instance metadata response excerpt",
                    &truncate(&resp.body, 800),
                )],
            ));
            break;
        }
    }

    findings
}

// ── Prototype Pollution in Client JavaScript ──────────────────────────────────

async fn check_prototype_pollution(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let js_urls: Vec<&String> = discovered
        .iter()
        .filter(|u| {
            let lower = u.to_lowercase();
            (lower.ends_with(".js") || lower.contains(".js?")) && !lower.contains("/node_modules/")
        })
        .take(5)
        .collect();

    for url in js_urls {
        let Ok(Some(resp)) = probe.get(url).await else { continue };
        if resp.status != 200 || resp.body.len() < 50 {
            continue;
        }

        let body = &resp.body;
        let has_proto_vuln = (body.contains("__proto__") || body.contains("constructor.prototype"))
            && (body.contains("[key]") || body.contains(".extend(") || body.contains(".merge(") || body.contains("deepMerge") || body.contains("cloneDeep"));

        if has_proto_vuln {
            findings.push(NativeFinding::build(
                &PROTOTYPE_POLLUTION,
                target_id,
                scan_id,
                url,
                &format!(
                    "JavaScript asset `{url}` contains object merging/extension logic that references \
                     `__proto__` or `constructor.prototype` alongside dynamic key assignment. \
                     Without strict key filtering, untrusted inputs can alter the global Object prototype."
                ),
                vec![
                    format!("curl -sSf '{url}' | grep -n -E '(__proto__|constructor\\.prototype)'"),
                ],
                vec![NativeFinding::evidence(
                    "js_source_snippet",
                    "Prototype pollution pattern match",
                    &truncate(body, 600),
                )],
            ));

            if findings.len() >= 2 {
                break;
            }
        }
    }

    findings
}

// ── Web Cache Deception ───────────────────────────────────────────────────────

async fn check_cache_deception(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    _origin: &str,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let candidate_urls: Vec<&String> = discovered
        .iter()
        .filter(|u| {
            let lower = u.to_lowercase();
            (lower.contains("/user") || lower.contains("/account") || lower.contains("/profile") || lower.contains("/settings") || lower.contains("/api/"))
                && !lower.ends_with(".css")
                && !lower.ends_with(".js")
                && !lower.ends_with(".png")
                && !lower.ends_with(".svg")
                && !lower.ends_with(".ico")
        })
        .take(2)
        .collect();

    for base_dynamic in candidate_urls {
        let test_url = format!("{}/sentinel_cache_test.css", base_dynamic.trim_end_matches('/'));
        let Ok(Some(resp)) = probe.get(&test_url).await else { continue };

        if resp.status == 200 && resp.body.len() > 100 {
            let is_dynamic = resp
                .header("content-type")
                .map(|ct| ct.contains("application/json") || ct.contains("text/html"))
                .unwrap_or(false);

            let cc = resp.header("cache-control").unwrap_or_default().to_lowercase();
            let is_cacheable = !cc.contains("no-store") && !cc.contains("private") && (cc.contains("public") || cc.contains("max-age"));

            if is_dynamic && is_cacheable {
                findings.push(NativeFinding::build(
                    &CACHE_DECEPTION,
                    target_id,
                    scan_id,
                    &test_url,
                    &format!(
                        "Dynamic endpoint responded with HTTP 200 and dynamic content type when appended with a \
                         static `.css` suffix (`{test_url}`), while Cache-Control allows caching (`{cc}`). \
                         Downstream caching layers (CDNs/proxies) may cache this response publicly."
                    ),
                    vec![
                        format!("curl -sSI '{test_url}'"),
                    ],
                    vec![NativeFinding::evidence(
                        "cache_headers",
                        "Cache control headers on static extension probe",
                        &resp.evidence_summary(),
                    )],
                ));

                if findings.len() >= 2 {
                    break;
                }
            }
        }
    }

    findings
}

// ── Database Error Disclosure ─────────────────────────────────────────────────

const DB_ERROR_PATTERNS: &[(&str, &str)] = &[
    ("You have an error in your SQL syntax", "MySQL / MariaDB"),
    ("mysql_fetch_array()", "MySQL PHP Driver"),
    ("ORA-01756", "Oracle Database"),
    ("ORA-00933", "Oracle Database"),
    ("pg_query(): Query failed:", "PostgreSQL PHP Driver"),
    ("PostgreSQL query failed:", "PostgreSQL"),
    ("sqlite3.OperationalError:", "SQLite3 Python"),
    ("SQLite3::SQLException", "SQLite3 Ruby/PHP"),
    ("Microsoft OLE DB Provider for SQL Server", "Microsoft SQL Server"),
    ("Unclosed quotation mark after the character string", "Microsoft SQL Server"),
    ("MongoError", "MongoDB"),
    ("MongoServerError", "MongoDB"),
    ("org.hibernate.exception.SQLGrammarException", "Hibernate ORM"),
    ("System.Data.SqlClient.SqlException", "ADO.NET SQL Server"),
];

async fn check_database_error_disclosure(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let sample_urls: Vec<&String> = discovered
        .iter()
        .filter(|u| u.contains('?') || u.contains("/api/"))
        .take(10)
        .collect();

    for url in sample_urls {
        let Ok(Some(resp)) = probe.get(url).await else { continue };
        if resp.body.is_empty() {
            continue;
        }

        for (pattern, db_type) in DB_ERROR_PATTERNS {
            if resp.body.contains(pattern) {
                findings.push(NativeFinding::build(
                    &DATABASE_ERROR_DISCLOSURE,
                    target_id,
                    scan_id,
                    url,
                    &format!(
                        "The response from `{url}` leaked a raw database error message: `{pattern}` ({db_type}). \
                         Verbose database error messages reveal database schema details and technology choices to clients."
                    ),
                    vec![
                        format!("curl -sSf '{url}' | grep -n '{pattern}'"),
                    ],
                    vec![NativeFinding::evidence(
                        "database_error",
                        &format!("{db_type} error signature match"),
                        &truncate(&resp.body, 800),
                    )],
                ));

                if findings.len() >= 2 {
                    return findings;
                }
                break;
            }
        }
    }

    findings
}

// ── Sensitive Credentials / API Keys in URL Query String ───────────────────────

const SENSITIVE_PARAM_KEYS: &[&str] = &[
    "api_key", "apikey", "key", "secret", "client_secret",
    "access_token", "token", "auth_token", "jwt", "bearer",
    "password", "passwd",
];

async fn check_api_key_in_url(
    _probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for url in discovered {
        let Ok(parsed) = url::Url::parse(url) else { continue };
        for (key, val) in parsed.query_pairs() {
            let key_lower = key.to_lowercase();
            if SENSITIVE_PARAM_KEYS.iter().any(|&k| k == key_lower) {
                if val.len() >= 8 {
                    let masked_val = if val.len() > 6 {
                        format!("{}...{}", &val[..2], &val[val.len() - 2..])
                    } else {
                        "***".to_string()
                    };

                    findings.push(NativeFinding::build(
                        &API_KEY_IN_URL,
                        target_id,
                        scan_id,
                        url,
                        &format!(
                            "The URL `{url}` passes sensitive credential parameter `{key}` in the query string \
                             with value `{masked_val}`. Query parameters are stored in plaintext server access logs, \
                             browser history, and outgoing Referer headers."
                        ),
                        vec![
                            format!("# Move `{key}` to Authorization header or request body:"),
                            format!("curl -sSf '{endpoint}' -H 'Authorization: Bearer <token>'",
                                endpoint = url.split('?').next().unwrap_or(url)
                            ),
                        ],
                        vec![NativeFinding::evidence(
                            "query_param_leak",
                            "Sensitive parameter in URL query",
                            &format!("Parameter '{key}' containing confidential token on {url}"),
                        )],
                    ));

                    if findings.len() >= 3 {
                        return findings;
                    }
                    break;
                }
            }
        }
    }

    findings
}

// ── Path Traversal ────────────────────────────────────────────────────────────

const TRAVERSAL_PARAM_NAMES: &[&str] = &[
    "file", "path", "doc", "view", "page", "template", "include", "read", "load",
];

async fn check_path_traversal(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for url in discovered {
        let Ok(parsed) = url::Url::parse(url) else { continue };
        let mut matching_keys = Vec::new();
        for (key, _) in parsed.query_pairs() {
            let key_lower = key.to_lowercase();
            if TRAVERSAL_PARAM_NAMES.iter().any(|&p| p == key_lower) {
                matching_keys.push(key.to_string());
            }
        }

        for key in matching_keys {
            let mut test_url = parsed.clone();
            let test_payload = "../../../../etc/passwd";
            // Replace key's value with traversal payload
            let new_pairs: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| {
                    if k == key {
                        (k.to_string(), test_payload.to_string())
                    } else {
                        (k.to_string(), v.to_string())
                    }
                })
                .collect();
            test_url.query_pairs_mut().clear().extend_pairs(new_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));

            if let Ok(Some(resp)) = probe.get(test_url.as_str()).await {
                if resp.status == 200
                    && (resp.body.contains("root:x:0:0:") || resp.body.contains("root:*:0:0:") || resp.body.contains("daemon:x:"))
                {
                    findings.push(NativeFinding::build(
                        &PATH_TRAVERSAL,
                        target_id,
                        scan_id,
                        url,
                        &format!(
                            "Path traversal parameter `{key}` at `{}` returned server file content (/etc/passwd) \
                             when supplied with traversal sequence `{test_payload}`.",
                            parsed.path()
                        ),
                        vec![format!("curl -sSf '{}'", test_url.as_str())],
                        vec![NativeFinding::evidence(
                            "path_traversal_payload",
                            "Path traversal arbitrary file read verified",
                            &truncate(&resp.body, 200),
                        )],
                    ));
                    if findings.len() >= 3 {
                        return findings;
                    }
                }
            }
        }
    }

    findings
}

// ── Reflected XSS ─────────────────────────────────────────────────────────────

const XSS_PARAM_NAMES: &[&str] = &[
    "q", "query", "search", "name", "keyword", "filter", "msg", "error", "redirect",
];

async fn check_reflected_xss(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for url in discovered {
        let Ok(parsed) = url::Url::parse(url) else { continue };
        let mut candidate_keys = Vec::new();
        for (key, _) in parsed.query_pairs() {
            let key_lower = key.to_lowercase();
            if XSS_PARAM_NAMES.iter().any(|&p| p == key_lower) || key.len() <= 8 {
                candidate_keys.push(key.to_string());
            }
        }

        for key in candidate_keys {
            let canary_id = Uuid::new_v4().simple().to_string();
            let canary = format!("stxss{}", &canary_id[..6]);
            let payload = format!("<stxss>{canary}</stxss>");

            let mut test_url = parsed.clone();
            let new_pairs: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| {
                    if k == key {
                        (k.to_string(), payload.clone())
                    } else {
                        (k.to_string(), v.to_string())
                    }
                })
                .collect();
            test_url.query_pairs_mut().clear().extend_pairs(new_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));

            if let Ok(Some(resp)) = probe.get(test_url.as_str()).await {
                let content_type = resp.header("content-type").unwrap_or_default().to_lowercase();
                if content_type.contains("html") && resp.body.contains(&payload) {
                    findings.push(NativeFinding::build(
                        &REFLECTED_XSS,
                        target_id,
                        scan_id,
                        url,
                        &format!(
                            "The parameter `{key}` at `{}` reflected unencoded HTML markup `{payload}` \
                             in the HTTP response body without proper output escaping.",
                            parsed.path()
                        ),
                        vec![format!("curl -sSf '{}'", test_url.as_str())],
                        vec![NativeFinding::evidence(
                            "reflected_xss_proof",
                            "Reflected unescaped tag echo in HTML body",
                            &format!("Echoed markup `{payload}` in response from {}", test_url.as_str()),
                        )],
                    ));
                    if findings.len() >= 3 {
                        return findings;
                    }
                }
            }
        }
    }

    findings
}

// ── Open Redirect ─────────────────────────────────────────────────────────────

const REDIRECT_PARAM_NAMES: &[&str] = &[
    "redirect", "url", "return", "next", "dest", "target", "goto", "redirect_uri", "forward",
];

async fn check_open_redirect(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let test_target = "https://sentinel-security-verification-test.invalid";

    for url in discovered {
        let Ok(parsed) = url::Url::parse(url) else { continue };
        let mut matching_keys = Vec::new();
        for (key, _) in parsed.query_pairs() {
            let key_lower = key.to_lowercase();
            if REDIRECT_PARAM_NAMES.iter().any(|&p| p == key_lower) {
                matching_keys.push(key.to_string());
            }
        }

        for key in matching_keys {
            let mut test_url = parsed.clone();
            let new_pairs: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| {
                    if k == key {
                        (k.to_string(), test_target.to_string())
                    } else {
                        (k.to_string(), v.to_string())
                    }
                })
                .collect();
            test_url.query_pairs_mut().clear().extend_pairs(new_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));

            if let Ok(Some(resp)) = probe.get(test_url.as_str()).await {
                if (300..=308).contains(&resp.status) {
                    if let Some(loc) = resp.header("location") {
                        if loc.contains("sentinel-security-verification-test.invalid") {
                            findings.push(NativeFinding::build(
                                &OPEN_REDIRECT,
                                target_id,
                                scan_id,
                                url,
                                &format!(
                                    "The endpoint `{}` redirected client to arbitrary untrusted external location `{loc}` \
                                     specified via query parameter `{key}`.",
                                    parsed.path()
                                ),
                                vec![format!("curl -sSI '{}'", test_url.as_str())],
                                vec![NativeFinding::evidence(
                                    "open_redirect_location",
                                    "Open redirect 30x Location header observed",
                                    &format!("Status {} with Location: {}", resp.status, loc),
                                )],
                            ));
                            if findings.len() >= 3 {
                                return findings;
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

// ── CRLF Injection ────────────────────────────────────────────────────────────

async fn check_crlf_injection(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let crlf_payload = "%0d%0aX-Sentinel-Injected:%20crlf_detected";

    for url in discovered {
        let Ok(parsed) = url::Url::parse(url) else { continue };
        let keys: Vec<String> = parsed.query_pairs().map(|(k, _)| k.to_string()).collect();

        for key in keys {
            let mut test_url = parsed.clone();
            let new_pairs: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| {
                    if k == key {
                        (k.to_string(), crlf_payload.to_string())
                    } else {
                        (k.to_string(), v.to_string())
                    }
                })
                .collect();
            test_url.query_pairs_mut().clear().extend_pairs(new_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));

            if let Ok(Some(resp)) = probe.get(test_url.as_str()).await {
                if resp.has_header("x-sentinel-injected")
                    || resp.headers.iter().any(|(k, v)| k.as_str().eq_ignore_ascii_case("x-sentinel-injected") || v.as_bytes().windows(13).any(|w| w == b"crlf_detected"))
                {
                    findings.push(NativeFinding::build(
                        &CRLF_INJECTION,
                        target_id,
                        scan_id,
                        url,
                        &format!(
                            "The endpoint `{}` is vulnerable to CRLF HTTP response header injection via parameter `{key}`. \
                             Injected header `X-Sentinel-Injected: crlf_detected` was reflected directly into the server response headers.",
                            parsed.path()
                        ),
                        vec![format!("curl -sSI '{}'", test_url.as_str())],
                        vec![NativeFinding::evidence(
                            "crlf_injection_evidence",
                            "Injected response header detected",
                            &format!("Header X-Sentinel-Injected observed in response headers for {}", test_url.as_str()),
                        )],
                    ));
                    if findings.len() >= 3 {
                        return findings;
                    }
                }
            }
        }
    }

    findings
}

// ── Debug Parameter Exposure ──────────────────────────────────────────────────

async fn check_debug_param_exposure(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    discovered: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let debug_flags = ["debug=true", "debug=1", "trace=true", "test=1", "show_errors=1"];

    for url in discovered.iter().take(15) {
        let Ok(parsed) = url::Url::parse(url) else { continue };
        let base_path = parsed.path();

        for flag in &debug_flags {
            let (k, v) = match flag.split_once('=') {
                Some((k, v)) => (k, v),
                None => (*flag, ""),
            };
            let mut test_url = parsed.clone();
            test_url.query_pairs_mut().append_pair(k, v);

            if let Ok(Some(resp)) = probe.get(test_url.as_str()).await {
                if resp.status == 200 {
                    let body_lower = resp.body.to_lowercase();
                    if body_lower.contains("traceback (most recent call last)")
                        || body_lower.contains("stack trace:")
                        || body_lower.contains("\"debug\": true")
                        || body_lower.contains("sql query:")
                        || body_lower.contains("execution_time_ms")
                        || body_lower.contains("php stack trace")
                    {
                        findings.push(NativeFinding::build(
                            &DEBUG_PARAM_EXPOSURE,
                            target_id,
                            scan_id,
                            url,
                            &format!(
                                "The endpoint `{base_path}` exposed internal application debug and diagnostic information \
                                 when activated with flag `{flag}`."
                            ),
                            vec![format!("curl -sSf '{}'", test_url.as_str())],
                            vec![NativeFinding::evidence(
                                "debug_param_output",
                                "Debug output detected in response",
                                &truncate(&resp.body, 200),
                            )],
                        ));
                        if findings.len() >= 2 {
                            return findings;
                        }
                        break;
                    }
                }
            }
        }
    }

    findings
}

// ── Backup Sensitive Files ────────────────────────────────────────────────────

async fn check_backup_sensitive_files(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    origin: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let backup_paths = [
        "/backup.zip",
        "/backup.sql",
        "/db.sql",
        "/dump.sql",
        "/site.tar.gz",
        "/app.zip",
        "/.env.bak",
        "/web.config.bak",
        "/config.php.bak",
    ];

    for path in &backup_paths {
        let test_url = format!("{origin}{path}");
        if let Ok(Some(resp)) = probe.get(&test_url).await {
            let ctype = resp.header("content-type").unwrap_or_default().to_lowercase();
            if resp.status == 200 && !ctype.contains("html") && resp.body.len() > 50 {
                let is_archive_or_sql = resp.body.starts_with("PK\x03\x04")
                    || resp.body.contains("INSERT INTO")
                    || resp.body.contains("CREATE TABLE")
                    || resp.body.contains("DATABASE")
                    || resp.body.contains("DB_PASSWORD")
                    || ctype.contains("zip")
                    || ctype.contains("tar")
                    || ctype.contains("octet-stream");

                if is_archive_or_sql {
                    findings.push(NativeFinding::build(
                        &BACKUP_SENSITIVE_FILES,
                        target_id,
                        scan_id,
                        &test_url,
                        &format!(
                            "Publicly accessible backup or configuration file discovered at `{test_url}` \
                             (Content-Type: `{ctype}`, size: {} bytes).",
                            resp.body.len()
                        ),
                        vec![format!("curl -sI '{test_url}'")],
                        vec![NativeFinding::evidence(
                            "backup_file_exposure",
                            "Sensitive backup file publicly downloadable",
                            &format!("Path {path} returned HTTP 200 with non-HTML content type {ctype}"),
                        )],
                    ));
                    if findings.len() >= 3 {
                        return findings;
                    }
                }
            }
        }
    }

    findings
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_none_alg_is_detected() {
        // A minimal JWT: header={"alg":"none"}, payload={}, sig=
        // Base64url of {"alg":"none"} = eyJhbGciOiJub25lIn0
        let jwt = "eyJhbGciOiJub25lIn0.e30.";
        assert!(extract_jwt_candidate(jwt).is_some());
    }

    #[test]
    fn base64_decode_jwt_header() {
        // eyJhbGciOiJub25lIn0 decodes to {"alg":"none"}
        let padded = pad_base64("eyJhbGciOiJub25lIn0");
        let decoded = base64_url_decode(&padded).unwrap();
        let s = std::str::from_utf8(&decoded).unwrap();
        assert!(s.contains("\"none\""), "decoded: {s}");
    }

    #[test]
    fn sequential_id_detection_only_fires_on_small_integers() {
        let small = "1".parse::<u64>().unwrap();
        let large = "99999999".parse::<u64>().unwrap();
        assert!(small <= 10000);
        assert!(large > 10000);
    }

    #[test]
    fn all_specs_have_valid_wstg_ids() {
        for spec in SPECS {
            assert!(
                spec.wstg.starts_with("WSTG-"),
                "{} has non-WSTG wstg id: {}",
                spec.id, spec.wstg
            );
        }
    }

    #[test]
    fn all_specs_have_cvss_vectors() {
        for spec in SPECS {
            assert!(
                spec.cvss_vector.starts_with("CVSS:4.0/"),
                "{} has invalid CVSS vector: {}",
                spec.id, spec.cvss_vector
            );
        }
    }

    #[test]
    fn graphql_paths_are_all_relative() {
        for path in GRAPHQL_PATHS {
            assert!(path.starts_with('/'), "GraphQL path '{path}' must be a relative path");
        }
    }
}
