//! Sensitive path, metafile and administrative interface exposure checks.
//!
//! Every probe here is a plain GET for a well-known path. Nothing is written,
//! nothing is deleted, and no payload is sent — the check is simply "is this
//! file readable by an anonymous visitor?". Each candidate is confirmed by a
//! content signature so that a catch-all 200 page cannot produce false results.

use super::builder::{CheckSpec, NativeFinding};
use super::probe::{is_readable, truncate, Probe};
use sentinel_core::models::finding::Finding;
use uuid::Uuid;

const OWASP_MISCONFIG: &str = "A02:2025-Security Misconfiguration";
const OWASP_ACCESS: &str = "A01:2025-Broken Access Control";
const OWASP_CRYPTO: &str = "A04:2025-Cryptographic Failures";

/// A well-known path worth probing, with the signature that confirms a real hit.
struct Candidate {
    path: &'static str,
    label: &'static str,
    /// Lowercase substrings; at least one must appear in the body to confirm.
    signatures: &'static [&'static str],
    spec: &'static CheckSpec,
}

const VCS_EXPOSED: CheckSpec = CheckSpec {
    id: "NATIVE-VCS-EXPOSED",
    title: "Version Control Directory Publicly Readable",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-527",
    wstg: "WSTG-CONF-04",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A version control directory is served by the web server and readable without \
authentication. The repository metadata can be downloaded and reconstructed into the application's \
complete source history, which routinely includes credentials, internal hostnames and the exact logic \
of authentication and authorization checks.",
    remediation: "Remove the version control directory from the document root — deploy build artefacts \
rather than working copies. As a compensating control, block the path at the web server or CDN \
(`location ~ /\\.git { deny all; }`). Treat every credential ever committed to that repository as \
compromised and rotate it.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
    ],
};

const ENV_EXPOSED: CheckSpec = CheckSpec {
    id: "NATIVE-ENV-EXPOSED",
    title: "Environment or Configuration File Publicly Readable",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    cwe: "CWE-538",
    wstg: "WSTG-CONF-03",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "An application configuration file is downloadable by any anonymous visitor. These \
files conventionally hold database credentials, API keys, signing secrets and third-party tokens. \
Retrieving one typically yields immediate, authenticated access to backend systems without any further \
exploitation.",
    remediation: "Move the file outside the web root immediately and deny the path at the web server. \
Rotate every credential the file contained — assume all of them are compromised. Load configuration from \
environment variables or a secrets manager rather than files inside the document root.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    ],
};

const BACKUP_EXPOSED: CheckSpec = CheckSpec {
    id: "NATIVE-BACKUP-EXPOSED",
    title: "Backup or Archive File Publicly Readable",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-530",
    wstg: "WSTG-CONF-04",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A backup or archive file is reachable in the web root. Backups commonly contain full \
source code, configuration and sometimes database dumps, giving an attacker the same insight as source \
code access — including any secrets committed inside.",
    remediation: "Delete the file from the document root and store backups outside the web server's \
served directories with restricted permissions. Add a deny rule for archive and backup extensions \
(.bak, .old, .zip, .tar.gz, .sql) at the web server.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
    ],
};

const DEBUG_ENDPOINT: CheckSpec = CheckSpec {
    id: "NATIVE-DEBUG-ENDPOINT",
    title: "Diagnostic or Management Endpoint Exposed",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N",
    cwe: "CWE-489",
    wstg: "WSTG-CONF-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: Some("API8:2023-Security Misconfiguration"),
    description: "A diagnostic, metrics or management endpoint is reachable without authentication. \
These endpoints expose runtime configuration, environment variables, heap contents or health data, and \
in several frameworks they also expose write operations that can change application state or trigger a \
shutdown.",
    remediation: "Disable diagnostic endpoints in production builds. Where they are needed for \
monitoring, bind them to an internal interface or a separate management port, require authentication, \
and expose only the specific endpoints monitoring needs (for example health, not env or heapdump).",
    references: &["https://owasp.org/www-project-secure-headers/"],
};

const ADMIN_INTERFACE: CheckSpec = CheckSpec {
    id: "NATIVE-ADMIN-INTERFACE",
    title: "Administrative Interface Reachable from the Internet",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-284",
    wstg: "WSTG-CONF-05",
    owasp_2025: OWASP_ACCESS,
    api_top10: None,
    description: "An administrative login or console is reachable from the public internet. Even when \
correctly password-protected, a publicly exposed admin surface invites credential stuffing and brute \
force, and it is the first thing an attacker looks for after fingerprinting the platform.",
    remediation: "Restrict administrative interfaces to a VPN, an allow-listed source range, or an \
authenticating reverse proxy. Where public exposure is unavoidable, enforce multi-factor authentication, \
rate limiting and lockout, and move the console off its default path.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
    ],
};

const CROSSDOMAIN_POLICY: CheckSpec = CheckSpec {
    id: "NATIVE-CROSSDOMAIN-POLICY",
    title: "Permissive Cross-Domain Policy File",
    // AT:P — exploiting a crossdomain policy requires a Flash or Silverlight
    // runtime in the victim's browser. Those are retired, so the precondition is
    // outside the attacker's control rather than absent.
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-942",
    wstg: "WSTG-CONF-08",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "A cross-domain policy file is present and grants access to all origins with a \
wildcard. Legacy rich-internet clients honouring this file would be permitted to read authenticated \
responses from this domain on behalf of any website.",
    remediation: "Delete crossdomain.xml and clientaccesspolicy.xml unless a legacy client genuinely \
requires them. If one is required, replace the wildcard with the specific origins that need access.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_RIA_Cross_Domain_Policy",
    ],
};

const METAFILE_DISCLOSURE: CheckSpec = CheckSpec {
    id: "NATIVE-METAFILE-DISCLOSURE",
    title: "Web Server Metafile Discloses Sensitive Paths",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-200",
    wstg: "WSTG-INFO-03",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "robots.txt lists paths the operator wishes to keep out of search results. The file is \
public, so every disallowed entry is effectively a signpost telling an attacker which directories are \
considered sensitive.",
    remediation: "Do not rely on robots.txt to hide anything. Keep entries generic, and protect sensitive \
areas with authentication and authorization checks. If a path must stay unindexed, use the \
`X-Robots-Tag: noindex` response header on that path instead of listing it publicly.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage",
    ],
};

const DIRECTORY_LISTING: CheckSpec = CheckSpec {
    id: "NATIVE-DIRECTORY-LISTING",
    title: "Directory Listing Enabled",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-548",
    wstg: "WSTG-CONF-04",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: None,
    description: "The web server returns an automatically generated index of directory contents. This \
reveals files that are not linked anywhere in the application — backups, notes, uploads and archives — \
removing the need for an attacker to guess filenames.",
    remediation: "Disable automatic indexing (`autoindex off` in nginx, `Options -Indexes` in Apache) \
and place an index file in every served directory.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
    ],
};

const API_DOCS_EXPOSED: CheckSpec = CheckSpec {
    id: "NATIVE-API-DOCS-EXPOSED",
    title: "API Schema or Documentation Publicly Exposed",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-1059",
    wstg: "WSTG-APIT-02",
    owasp_2025: OWASP_MISCONFIG,
    api_top10: Some("API9:2023-Improper Inventory Management"),
    description: "A machine-readable API schema or interactive documentation console is publicly \
reachable. It enumerates every endpoint, parameter and data model — including internal or deprecated \
routes that were never meant to be discoverable — giving an attacker a complete map of the attack surface.",
    remediation: "Serve API documentation only to authenticated internal users, or publish a curated \
public schema that omits internal endpoints. Confirm that deprecated versions listed in the schema are \
actually decommissioned rather than merely undocumented.",
    references: &["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
};

const GRAPHQL_INTROSPECTION: CheckSpec = CheckSpec {
    id: "NATIVE-GRAPHQL-INTROSPECTION",
    title: "GraphQL Endpoint Detected",
    cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    cwe: "CWE-284",
    wstg: "WSTG-APIT-01",
    owasp_2025: OWASP_ACCESS,
    api_top10: Some("API9:2023-Improper Inventory Management"),
    description: "A GraphQL endpoint responds at a conventional path. GraphQL endpoints warrant \
dedicated review: introspection may expose the full schema, field-level authorization is easy to miss, \
and deeply nested queries can be used to exhaust server resources.",
    remediation: "Disable introspection in production, enforce authorization at the field resolver level \
rather than only at the endpoint, and apply query depth and complexity limits.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
    ],
};

/// The probe list. Ordered roughly by severity of a hit.
/// Every check this module can raise.
///
/// Exposed so the spec audit can walk all shipped checks and confirm each
/// one carries a coherent CVSS vector, severity band and taxonomy — a
/// finding whose stated severity disagrees with its score misinforms the
/// reader of the report.
pub const SPECS: &[CheckSpec] = &[
    VCS_EXPOSED,
    ENV_EXPOSED,
    BACKUP_EXPOSED,
    DEBUG_ENDPOINT,
    ADMIN_INTERFACE,
    CROSSDOMAIN_POLICY,
    METAFILE_DISCLOSURE,
    DIRECTORY_LISTING,
    API_DOCS_EXPOSED,
    GRAPHQL_INTROSPECTION,
];

fn candidates() -> Vec<Candidate> {
    vec![
        Candidate { path: "/.git/HEAD", label: "Git repository metadata", signatures: &["ref:", "refs/heads"], spec: &VCS_EXPOSED },
        Candidate { path: "/.git/config", label: "Git repository configuration", signatures: &["[core]", "repositoryformatversion"], spec: &VCS_EXPOSED },
        Candidate { path: "/.svn/entries", label: "Subversion metadata", signatures: &["dir", "svn"], spec: &VCS_EXPOSED },
        Candidate { path: "/.hg/requires", label: "Mercurial metadata", signatures: &["revlog", "store"], spec: &VCS_EXPOSED },

        Candidate { path: "/.env", label: "Environment file", signatures: &["=", "app_", "db_", "secret", "key"], spec: &ENV_EXPOSED },
        Candidate { path: "/.env.local", label: "Local environment file", signatures: &["=", "app_", "db_", "secret"], spec: &ENV_EXPOSED },
        Candidate { path: "/.env.production", label: "Production environment file", signatures: &["=", "app_", "db_", "secret"], spec: &ENV_EXPOSED },
        Candidate { path: "/config.json", label: "Application configuration", signatures: &["password", "secret", "apikey", "api_key", "token"], spec: &ENV_EXPOSED },
        Candidate { path: "/web.config", label: "IIS configuration", signatures: &["<configuration", "system.web"], spec: &ENV_EXPOSED },
        Candidate { path: "/appsettings.json", label: ".NET application settings", signatures: &["connectionstrings", "logging", "\"allowedhosts\""], spec: &ENV_EXPOSED },
        Candidate { path: "/wp-config.php.bak", label: "WordPress configuration backup", signatures: &["db_password", "define("], spec: &ENV_EXPOSED },
        Candidate { path: "/docker-compose.yml", label: "Docker Compose definition", signatures: &["services:", "image:"], spec: &ENV_EXPOSED },

        Candidate { path: "/backup.zip", label: "Backup archive", signatures: &[], spec: &BACKUP_EXPOSED },
        Candidate { path: "/backup.sql", label: "Database dump", signatures: &["insert into", "create table", "-- mysql"], spec: &BACKUP_EXPOSED },
        Candidate { path: "/dump.sql", label: "Database dump", signatures: &["insert into", "create table"], spec: &BACKUP_EXPOSED },
        Candidate { path: "/.DS_Store", label: "macOS directory index", signatures: &[], spec: &BACKUP_EXPOSED },

        Candidate { path: "/actuator", label: "Spring Boot Actuator index", signatures: &["_links", "actuator"], spec: &DEBUG_ENDPOINT },
        Candidate { path: "/actuator/env", label: "Spring Boot environment dump", signatures: &["propertysources", "activeprofiles"], spec: &DEBUG_ENDPOINT },
        Candidate { path: "/actuator/health", label: "Spring Boot health endpoint", signatures: &["\"status\""], spec: &DEBUG_ENDPOINT },
        Candidate { path: "/server-status", label: "Apache status page", signatures: &["apache server status", "server uptime"], spec: &DEBUG_ENDPOINT },
        Candidate { path: "/phpinfo.php", label: "PHP configuration dump", signatures: &["phpinfo()", "php version"], spec: &DEBUG_ENDPOINT },
        Candidate { path: "/debug", label: "Debug console", signatures: &["debug", "traceback", "console"], spec: &DEBUG_ENDPOINT },
        Candidate { path: "/metrics", label: "Prometheus metrics", signatures: &["# help", "# type"], spec: &DEBUG_ENDPOINT },
        Candidate { path: "/.well-known/security.txt", label: "Security contact policy", signatures: &["contact:"], spec: &METAFILE_DISCLOSURE },

        Candidate { path: "/admin", label: "Admin console", signatures: &["login", "password", "sign in", "username"], spec: &ADMIN_INTERFACE },
        Candidate { path: "/administrator", label: "Admin console", signatures: &["login", "password", "sign in"], spec: &ADMIN_INTERFACE },
        Candidate { path: "/wp-admin/", label: "WordPress admin", signatures: &["wordpress", "wp-login", "log in"], spec: &ADMIN_INTERFACE },
        Candidate { path: "/phpmyadmin/", label: "phpMyAdmin console", signatures: &["phpmyadmin"], spec: &ADMIN_INTERFACE },
        Candidate { path: "/manager/html", label: "Tomcat manager", signatures: &["tomcat", "manager"], spec: &ADMIN_INTERFACE },

        Candidate { path: "/crossdomain.xml", label: "Flash cross-domain policy", signatures: &["cross-domain-policy"], spec: &CROSSDOMAIN_POLICY },
        Candidate { path: "/clientaccesspolicy.xml", label: "Silverlight access policy", signatures: &["access-policy"], spec: &CROSSDOMAIN_POLICY },

        Candidate { path: "/swagger.json", label: "OpenAPI schema", signatures: &["swagger", "openapi", "\"paths\""], spec: &API_DOCS_EXPOSED },
        Candidate { path: "/openapi.json", label: "OpenAPI schema", signatures: &["openapi", "\"paths\""], spec: &API_DOCS_EXPOSED },
        Candidate { path: "/swagger-ui.html", label: "Swagger UI console", signatures: &["swagger"], spec: &API_DOCS_EXPOSED },
        Candidate { path: "/api-docs", label: "API documentation", signatures: &["swagger", "openapi", "\"paths\""], spec: &API_DOCS_EXPOSED },

        Candidate { path: "/graphql", label: "GraphQL endpoint", signatures: &["graphql", "\"errors\"", "must provide query"], spec: &GRAPHQL_INTROSPECTION },
    ]
}

/// Probe well-known sensitive paths on the target's origin.
pub async fn run(
    probe: &Probe,
    target_id: Uuid,
    scan_id: Uuid,
    base_url: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let origin = base_url.trim_end_matches('/');

    for candidate in candidates() {
        let url = format!("{origin}{}", candidate.path);
        let Ok(Some(resp)) = probe.get(&url).await else { continue };

        if !is_readable(resp.status) {
            continue;
        }
        // A soft-404 (catch-all SPA route) returns 200 for everything, so require
        // a content signature before reporting anything.
        if !matches_signature(&resp.body, candidate.signatures) {
            continue;
        }
        // An HTML login page is expected for admin and documentation paths; for
        // a config or VCS path it means the SPA fallback served index.html
        // rather than the real file, so an HTML body is disqualifying.
        if !html_body_is_expected(candidate.spec.id) && looks_like_html_page(&resp.body) {
            continue;
        }

        let detail = format!(
            "{} is readable at {} (HTTP {}, {} bytes).",
            candidate.label,
            candidate.path,
            resp.status,
            resp.body.len()
        );
        findings.push(NativeFinding::build(
            candidate.spec,
            target_id,
            scan_id,
            &url,
            &detail,
            vec![
                format!("curl -sS -o /dev/null -w '%{{http_code}}' {url}"),
                format!("curl -sS {url} | head -c 200"),
            ],
            vec![NativeFinding::evidence(
                "http_response",
                &format!("First bytes of {}", candidate.path),
                &truncate(&resp.body, 400),
            )],
        ));
    }

    // Directory listing on the site root and common upload directories.
    for dir in ["/", "/uploads/", "/files/", "/images/", "/static/", "/assets/", "/backup/"] {
        let url = format!("{origin}{dir}");
        let Ok(Some(resp)) = probe.get(&url).await else { continue };
        if is_readable(resp.status) && is_directory_listing(&resp.body) {
            findings.push(NativeFinding::build(
                &DIRECTORY_LISTING,
                target_id,
                scan_id,
                &url,
                &format!("The server returned a generated directory index for {dir}."),
                vec![format!("curl -sS {url} | head -c 300")],
                vec![NativeFinding::evidence(
                    "http_response",
                    "Directory index",
                    &truncate(&resp.body, 400),
                )],
            ));
        }
    }

    // robots.txt disallow entries.
    let robots_url = format!("{origin}/robots.txt");
    if let Ok(Some(resp)) = probe.get(&robots_url).await {
        if is_readable(resp.status) {
            let disallowed = parse_robots_disallow(&resp.body);
            if !disallowed.is_empty() {
                findings.push(NativeFinding::build(
                    &METAFILE_DISCLOSURE,
                    target_id,
                    scan_id,
                    &robots_url,
                    &format!(
                        "robots.txt discloses {} disallowed path(s): {}.",
                        disallowed.len(),
                        truncate(&disallowed.join(", "), 300)
                    ),
                    vec![format!("curl -sS {robots_url}")],
                    vec![NativeFinding::evidence(
                        "http_response",
                        "robots.txt",
                        &truncate(&resp.body, 600),
                    )],
                ));
            }
        }
    }

    findings
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Whether an HTML response body is a legitimate result for this check, rather
/// than a single-page-app fallback standing in for a missing file.
///
/// Compared by spec id: `CheckSpec` constants are inlined at each use site, so
/// pointer identity between two `&SPEC` expressions is not guaranteed.
fn html_body_is_expected(spec_id: &str) -> bool {
    matches!(
        spec_id,
        "NATIVE-ADMIN-INTERFACE"
            | "NATIVE-API-DOCS-EXPOSED"
            | "NATIVE-GRAPHQL-INTROSPECTION"
            | "NATIVE-DEBUG-ENDPOINT"
    )
}

/// Whether a response body matches at least one confirming signature.
/// An empty signature list means the status code alone is sufficient.
pub fn matches_signature(body: &str, signatures: &[&str]) -> bool {
    if signatures.is_empty() {
        return true;
    }
    let lower = body.to_lowercase();
    signatures.iter().any(|sig| lower.contains(&sig.to_lowercase()))
}

/// Detect an SPA/catch-all HTML page standing in for a missing file.
pub fn looks_like_html_page(body: &str) -> bool {
    let head: String = body.chars().take(600).collect::<String>().to_lowercase();
    head.contains("<!doctype html") || head.contains("<html")
}

/// Recognise a server-generated directory index.
pub fn is_directory_listing(body: &str) -> bool {
    let lower = body.to_lowercase();
    (lower.contains("index of /") && lower.contains("parent directory"))
        || lower.contains("<title>index of /")
        || (lower.contains("directory listing for") && lower.contains("<ul>"))
}

/// Extract Disallow paths from a robots.txt body, ignoring bare "/" and blanks.
pub fn parse_robots_disallow(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            let lower = line.to_lowercase();
            let value = lower.strip_prefix("disallow:")?;
            let path = value.trim();
            if path.is_empty() || path == "/" {
                return None;
            }
            Some(path.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_match_requires_a_hit_when_signatures_exist() {
        assert!(matches_signature("ref: refs/heads/main", &["ref:", "refs/heads"]));
        assert!(!matches_signature("<html>not found</html>", &["ref:", "refs/heads"]));
    }

    #[test]
    fn empty_signature_list_accepts_any_body() {
        assert!(matches_signature("anything at all", &[]));
        assert!(matches_signature("", &[]));
    }

    #[test]
    fn signature_match_is_case_insensitive() {
        assert!(matches_signature("REPOSITORYFORMATVERSION = 0", &["repositoryformatversion"]));
    }

    #[test]
    fn spa_fallback_pages_are_recognised() {
        assert!(looks_like_html_page("<!DOCTYPE html><html><head>"));
        assert!(looks_like_html_page("  \n<html lang=\"en\">"));
        assert!(!looks_like_html_page("ref: refs/heads/main"));
        assert!(!looks_like_html_page("{\"status\":\"UP\"}"));
    }

    #[test]
    fn apache_directory_index_is_detected() {
        let body = "<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><a href=\"../\">Parent Directory</a>";
        assert!(is_directory_listing(body));
    }

    #[test]
    fn a_normal_page_is_not_a_directory_index() {
        assert!(!is_directory_listing("<html><body><h1>Welcome</h1></body></html>"));
    }

    #[test]
    fn robots_disallow_entries_are_extracted() {
        let body = "User-agent: *\nDisallow: /admin/\nDisallow: /internal/reports\nAllow: /public\n";
        let paths = parse_robots_disallow(body);
        assert_eq!(paths, vec!["/admin/", "/internal/reports"]);
    }

    #[test]
    fn robots_bare_slash_and_comments_are_ignored() {
        let body = "# comment\nUser-agent: *\nDisallow: /\nDisallow:\n";
        assert!(parse_robots_disallow(body).is_empty());
    }

    #[test]
    fn every_candidate_has_a_non_empty_path_and_label() {
        for c in candidates() {
            assert!(c.path.starts_with('/'), "path must be absolute: {}", c.path);
            assert!(!c.label.is_empty(), "{} has no label", c.path);
        }
    }

    #[test]
    fn candidate_paths_are_unique() {
        let list = candidates();
        let mut paths: Vec<&str> = list.iter().map(|c| c.path).collect();
        paths.sort_unstable();
        let before = paths.len();
        paths.dedup();
        assert_eq!(before, paths.len(), "duplicate candidate paths present");
    }

    #[test]
    fn critical_secrets_paths_are_covered() {
        let list = candidates();
        for required in ["/.git/HEAD", "/.env", "/actuator/env", "/swagger.json", "/graphql"] {
            assert!(
                list.iter().any(|c| c.path == required),
                "{required} must be probed"
            );
        }
    }

    #[test]
    fn html_bodies_are_expected_only_for_page_serving_checks() {
        assert!(html_body_is_expected("NATIVE-ADMIN-INTERFACE"));
        assert!(html_body_is_expected("NATIVE-API-DOCS-EXPOSED"));
        assert!(!html_body_is_expected("NATIVE-ENV-EXPOSED"));
        assert!(!html_body_is_expected("NATIVE-VCS-EXPOSED"));
    }

    #[test]
    fn html_expectation_ids_all_exist_in_the_candidate_list() {
        let list = candidates();
        for id in [
            "NATIVE-ADMIN-INTERFACE",
            "NATIVE-API-DOCS-EXPOSED",
            "NATIVE-GRAPHQL-INTROSPECTION",
            "NATIVE-DEBUG-ENDPOINT",
        ] {
            assert!(
                list.iter().any(|c| c.spec.id == id),
                "{id} is exempted from the HTML gate but no candidate uses it"
            );
        }
    }
}
