//! OWASP Web Security Testing Guide (WSTG) v4.2 checklist catalog.
//!
//! This is the authoritative test-case inventory SentinelVAPT assesses against.
//! Every item declares:
//!   • how it is covered (fully automated / partially automated / manual)
//!   • which engines contribute coverage
//!   • its OWASP Top 10:2025 and CWE mapping
//!   • a plain-language summary used in the client-facing report
//!
//! Nothing here performs I/O — it is pure reference data so both the report
//! engine and the UI can render an honest coverage matrix.

use serde::{Deserialize, Serialize};

/// How much of a WSTG test case SentinelVAPT can perform without a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageKind {
    /// The tool performs this test end to end and the result is trustworthy on its own.
    Automated,
    /// The tool performs meaningful checks but a human must confirm full coverage.
    Partial,
    /// No automated tool can honestly assert this; it requires an analyst.
    Manual,
}

impl CoverageKind {
    pub fn label(&self) -> &'static str {
        match self {
            CoverageKind::Automated => "Automated",
            CoverageKind::Partial => "Partially Automated",
            CoverageKind::Manual => "Manual Review Required",
        }
    }
}

/// Engine identifiers used across the catalog. Kept as constants so a typo
/// cannot silently break coverage attribution.
pub mod engine {
    pub const NATIVE: &str = "Sentinel Native";
    pub const ZAP: &str = "OWASP ZAP";
    pub const NUCLEI: &str = "Nuclei";
    pub const SEMGREP: &str = "Semgrep";
    pub const TRIVY: &str = "Trivy";
    pub const GITLEAKS: &str = "Gitleaks";
    pub const ANALYST: &str = "Analyst";
}

/// A single WSTG test case plus SentinelVAPT's coverage declaration.
///
/// Borrowed `&'static` fields make this a zero-allocation compile-time table,
/// so it is serialize-only; runtime results use the owned `CheckResult` type.
#[derive(Debug, Clone, Serialize)]
pub struct ChecklistItem {
    /// Full WSTG identifier, e.g. "WSTG-CONF-07".
    pub id: &'static str,
    /// Category code, e.g. "CONF".
    pub category_code: &'static str,
    /// Human-readable category name.
    pub category: &'static str,
    /// Official WSTG test name.
    pub name: &'static str,
    pub coverage: CoverageKind,
    /// Engines that contribute to this item's coverage.
    pub engines: &'static [&'static str],
    /// OWASP Top 10:2025 category this test most closely maps to.
    pub owasp_2025: &'static str,
    /// Primary CWE for findings produced by this test.
    pub cwe: &'static str,
    /// Non-technical description for the client-facing report.
    pub client_summary: &'static str,
}

/// Category display names, ordered as they appear in WSTG v4.2.
pub const CATEGORIES: &[(&str, &str)] = &[
    ("INFO", "Information Gathering"),
    ("CONF", "Configuration & Deployment Management"),
    ("IDNT", "Identity Management"),
    ("ATHN", "Authentication"),
    ("ATHZ", "Authorization"),
    ("SESS", "Session Management"),
    ("INPV", "Input Validation"),
    ("ERRH", "Error Handling"),
    ("CRYP", "Cryptography"),
    ("BUSL", "Business Logic"),
    ("CLNT", "Client-Side"),
    ("APIT", "API Testing"),
];

pub fn category_name(code: &str) -> &'static str {
    CATEGORIES
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, n)| *n)
        .unwrap_or("Other")
}

use CoverageKind::{Automated, Manual, Partial};

const E_NATIVE: &[&str] = &[engine::NATIVE];
const E_NATIVE_ZAP: &[&str] = &[engine::NATIVE, engine::ZAP];
const E_NATIVE_NUCLEI: &[&str] = &[engine::NATIVE, engine::NUCLEI];
const E_ZAP: &[&str] = &[engine::ZAP];
const E_ZAP_NUCLEI: &[&str] = &[engine::ZAP, engine::NUCLEI];
const E_ZAP_SEMGREP: &[&str] = &[engine::ZAP, engine::SEMGREP];
const E_SEMGREP: &[&str] = &[engine::SEMGREP];
const E_SEMGREP_ZAP_NUCLEI: &[&str] = &[engine::SEMGREP, engine::ZAP, engine::NUCLEI];
const E_TRIVY: &[&str] = &[engine::TRIVY];
const E_ANALYST: &[&str] = &[engine::ANALYST];
const E_NATIVE_ANALYST: &[&str] = &[engine::NATIVE, engine::ANALYST];
const E_SEMGREP_ANALYST: &[&str] = &[engine::SEMGREP, engine::ANALYST];
const E_ZAP_ANALYST: &[&str] = &[engine::ZAP, engine::ANALYST];

// OWASP Top 10:2025 category strings (verified against owasp.org/Top10/2025).
const A01: &str = "A01:2025-Broken Access Control";
const A02: &str = "A02:2025-Security Misconfiguration";
const A03: &str = "A03:2025-Software Supply Chain Failures";
const A04: &str = "A04:2025-Cryptographic Failures";
const A05: &str = "A05:2025-Injection";
const A06: &str = "A06:2025-Insecure Design";
const A07: &str = "A07:2025-Authentication Failures";
const A08: &str = "A08:2025-Software or Data Integrity Failures";
const A09: &str = "A09:2025-Security Logging and Alerting Failures";
const A10: &str = "A10:2025-Mishandling of Exceptional Conditions";

/// The full WSTG v4.2 test-case catalog with SentinelVAPT coverage declarations.
pub const WSTG_CATALOG: &[ChecklistItem] = &[
    // ── Information Gathering ────────────────────────────────────────────────
    ChecklistItem {
        id: "WSTG-INFO-01", category_code: "INFO", category: "Information Gathering",
        name: "Conduct Search Engine Discovery Reconnaissance for Information Leakage",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A02, cwe: "CWE-200",
        client_summary: "Check whether sensitive information about the application has been indexed by public search engines.",
    },
    ChecklistItem {
        id: "WSTG-INFO-02", category_code: "INFO", category: "Information Gathering",
        name: "Fingerprint Web Server",
        coverage: Automated, engines: E_NATIVE_NUCLEI, owasp_2025: A02, cwe: "CWE-200",
        client_summary: "Identify the web server software and version disclosed to any visitor.",
    },
    ChecklistItem {
        id: "WSTG-INFO-03", category_code: "INFO", category: "Information Gathering",
        name: "Review Webserver Metafiles for Information Leakage",
        coverage: Automated, engines: E_NATIVE, owasp_2025: A02, cwe: "CWE-200",
        client_summary: "Inspect robots.txt, sitemap.xml and security.txt for accidentally exposed private areas.",
    },
    ChecklistItem {
        id: "WSTG-INFO-04", category_code: "INFO", category: "Information Gathering",
        name: "Enumerate Applications on Webserver",
        coverage: Partial, engines: E_NATIVE_ZAP, owasp_2025: A02, cwe: "CWE-200",
        client_summary: "Discover additional applications or admin panels hosted on the same server.",
    },
    ChecklistItem {
        id: "WSTG-INFO-05", category_code: "INFO", category: "Information Gathering",
        name: "Review Web Page Content for Information Leakage",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A02, cwe: "CWE-200",
        client_summary: "Scan page source and comments for internal hostnames, credentials or developer notes.",
    },
    ChecklistItem {
        id: "WSTG-INFO-06", category_code: "INFO", category: "Information Gathering",
        name: "Identify Application Entry Points",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A06, cwe: "CWE-1059",
        client_summary: "Map every URL, form and API endpoint that accepts user input.",
    },
    ChecklistItem {
        id: "WSTG-INFO-07", category_code: "INFO", category: "Information Gathering",
        name: "Map Execution Paths Through Application",
        coverage: Partial, engines: E_ZAP_SEMGREP, owasp_2025: A06, cwe: "CWE-1059",
        client_summary: "Trace how requests flow through the application to find untested areas.",
    },
    ChecklistItem {
        id: "WSTG-INFO-08", category_code: "INFO", category: "Information Gathering",
        name: "Fingerprint Web Application Framework",
        coverage: Automated, engines: E_NATIVE_NUCLEI, owasp_2025: A02, cwe: "CWE-200",
        client_summary: "Determine which frameworks and libraries the application reveals to attackers.",
    },
    ChecklistItem {
        id: "WSTG-INFO-09", category_code: "INFO", category: "Information Gathering",
        name: "Fingerprint Web Application",
        coverage: Automated, engines: E_NATIVE_NUCLEI, owasp_2025: A02, cwe: "CWE-200",
        client_summary: "Identify the off-the-shelf product or CMS in use and its version.",
    },
    ChecklistItem {
        id: "WSTG-INFO-10", category_code: "INFO", category: "Information Gathering",
        name: "Map Application Architecture",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A06, cwe: "CWE-1059",
        client_summary: "Document the tiers, proxies and services behind the application.",
    },

    // ── Configuration & Deployment Management ────────────────────────────────
    ChecklistItem {
        id: "WSTG-CONF-01", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Test Network Infrastructure Configuration",
        coverage: Partial, engines: E_NATIVE_NUCLEI, owasp_2025: A02, cwe: "CWE-16",
        client_summary: "Review the hosting and network configuration for insecure defaults.",
    },
    ChecklistItem {
        id: "WSTG-CONF-02", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Test Application Platform Configuration",
        coverage: Automated, engines: E_NATIVE_NUCLEI, owasp_2025: A02, cwe: "CWE-16",
        client_summary: "Check the application platform for debug modes, sample files and unsafe defaults.",
    },
    ChecklistItem {
        id: "WSTG-CONF-03", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Test File Extensions Handling for Sensitive Information",
        coverage: Automated, engines: E_NATIVE, owasp_2025: A02, cwe: "CWE-552",
        client_summary: "Verify that configuration and source files cannot be downloaded directly.",
    },
    ChecklistItem {
        id: "WSTG-CONF-04", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Review Old Backup and Unreferenced Files for Sensitive Information",
        coverage: Automated, engines: E_NATIVE, owasp_2025: A02, cwe: "CWE-530",
        client_summary: "Look for forgotten backups, archives and version-control folders left on the server.",
    },
    ChecklistItem {
        id: "WSTG-CONF-05", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Enumerate Infrastructure and Application Admin Interfaces",
        coverage: Automated, engines: E_NATIVE_NUCLEI, owasp_2025: A01, cwe: "CWE-284",
        client_summary: "Find administrative consoles that are reachable from the public internet.",
    },
    ChecklistItem {
        id: "WSTG-CONF-06", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Test HTTP Methods",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A02, cwe: "CWE-650",
        client_summary: "Confirm that dangerous HTTP methods such as TRACE, PUT and DELETE are disabled.",
    },
    ChecklistItem {
        id: "WSTG-CONF-07", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Test HTTP Strict Transport Security",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A04, cwe: "CWE-319",
        client_summary: "Verify browsers are instructed to always use an encrypted connection.",
    },
    ChecklistItem {
        id: "WSTG-CONF-08", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Test RIA Cross Domain Policy",
        coverage: Automated, engines: E_NATIVE, owasp_2025: A01, cwe: "CWE-942",
        client_summary: "Check cross-domain policy files that could let other sites read your data.",
    },
    ChecklistItem {
        id: "WSTG-CONF-09", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Test File Permission",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A02, cwe: "CWE-732",
        client_summary: "Review server-side file permissions on application and configuration files.",
    },
    ChecklistItem {
        id: "WSTG-CONF-10", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Test for Subdomain Takeover",
        coverage: Partial, engines: E_NATIVE_NUCLEI, owasp_2025: A02, cwe: "CWE-350",
        client_summary: "Detect DNS records pointing at decommissioned services an attacker could claim.",
    },
    ChecklistItem {
        id: "WSTG-CONF-11", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Test Cloud Storage",
        coverage: Partial, engines: E_NATIVE_NUCLEI, owasp_2025: A01, cwe: "CWE-284",
        client_summary: "Check whether cloud storage buckets used by the application are publicly readable.",
    },
    ChecklistItem {
        id: "WSTG-CONF-12", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Test for Content Security Policy",
        coverage: Automated, engines: E_NATIVE, owasp_2025: A02, cwe: "CWE-1021",
        client_summary: "Evaluate the browser policy that limits damage from injected scripts.",
    },
    ChecklistItem {
        id: "WSTG-CONF-13", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Test for Path Confusion",
        coverage: Partial, engines: E_NATIVE, owasp_2025: A02, cwe: "CWE-22",
        client_summary: "Check whether unusual URL formats bypass routing or caching rules.",
    },

    // ── Identity Management ──────────────────────────────────────────────────
    ChecklistItem {
        id: "WSTG-IDNT-01", category_code: "IDNT", category: "Identity Management",
        name: "Test Role Definitions",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A01, cwe: "CWE-286",
        client_summary: "Review whether user roles grant only the access each role genuinely needs.",
    },
    ChecklistItem {
        id: "WSTG-IDNT-02", category_code: "IDNT", category: "Identity Management",
        name: "Test User Registration Process",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A07, cwe: "CWE-287",
        client_summary: "Assess whether new accounts can be created without proper verification.",
    },
    ChecklistItem {
        id: "WSTG-IDNT-03", category_code: "IDNT", category: "Identity Management",
        name: "Test Account Provisioning Process",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A01, cwe: "CWE-284",
        client_summary: "Check that only authorised staff can create or elevate accounts.",
    },
    ChecklistItem {
        id: "WSTG-IDNT-04", category_code: "IDNT", category: "Identity Management",
        name: "Testing for Account Enumeration and Guessable User Account",
        coverage: Partial, engines: E_ZAP_ANALYST, owasp_2025: A07, cwe: "CWE-204",
        client_summary: "Determine whether the login or reset flow reveals which usernames exist.",
    },
    ChecklistItem {
        id: "WSTG-IDNT-05", category_code: "IDNT", category: "Identity Management",
        name: "Testing for Weak or Unenforced Username Policy",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A07, cwe: "CWE-521",
        client_summary: "Review rules governing what usernames may be chosen.",
    },

    // ── Authentication ───────────────────────────────────────────────────────
    ChecklistItem {
        id: "WSTG-ATHN-01", category_code: "ATHN", category: "Authentication",
        name: "Testing for Credentials Transported over an Encrypted Channel",
        coverage: Automated, engines: E_NATIVE, owasp_2025: A04, cwe: "CWE-319",
        client_summary: "Confirm usernames and passwords are only ever sent over an encrypted connection.",
    },
    ChecklistItem {
        id: "WSTG-ATHN-02", category_code: "ATHN", category: "Authentication",
        name: "Testing for Default Credentials",
        coverage: Partial, engines: E_NATIVE_NUCLEI, owasp_2025: A07, cwe: "CWE-1392",
        client_summary: "Check whether any component still accepts factory-default logins.",
    },
    ChecklistItem {
        id: "WSTG-ATHN-03", category_code: "ATHN", category: "Authentication",
        name: "Testing for Weak Lock Out Mechanism",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A07, cwe: "CWE-307",
        client_summary: "Verify repeated failed logins are throttled or locked out.",
    },
    ChecklistItem {
        id: "WSTG-ATHN-04", category_code: "ATHN", category: "Authentication",
        name: "Testing for Bypassing Authentication Schema",
        coverage: Partial, engines: E_ZAP_ANALYST, owasp_2025: A07, cwe: "CWE-287",
        client_summary: "Attempt to reach protected pages without logging in.",
    },
    ChecklistItem {
        id: "WSTG-ATHN-05", category_code: "ATHN", category: "Authentication",
        name: "Testing for Vulnerable Remember Password",
        coverage: Automated, engines: E_NATIVE, owasp_2025: A07, cwe: "CWE-522",
        client_summary: "Check that 'remember me' features do not store credentials insecurely.",
    },
    ChecklistItem {
        id: "WSTG-ATHN-06", category_code: "ATHN", category: "Authentication",
        name: "Testing for Browser Cache Weaknesses",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A04, cwe: "CWE-525",
        client_summary: "Ensure sensitive pages are not left behind in the browser cache.",
    },
    ChecklistItem {
        id: "WSTG-ATHN-07", category_code: "ATHN", category: "Authentication",
        name: "Testing for Weak Password Policy",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A07, cwe: "CWE-521",
        client_summary: "Review minimum password strength requirements.",
    },
    ChecklistItem {
        id: "WSTG-ATHN-08", category_code: "ATHN", category: "Authentication",
        name: "Testing for Weak Security Question Answer",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A07, cwe: "CWE-640",
        client_summary: "Assess whether security questions can be guessed or researched.",
    },
    ChecklistItem {
        id: "WSTG-ATHN-09", category_code: "ATHN", category: "Authentication",
        name: "Testing for Weak Password Change or Reset Functionalities",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A07, cwe: "CWE-640",
        client_summary: "Test whether the password reset flow can be abused to take over an account.",
    },
    ChecklistItem {
        id: "WSTG-ATHN-10", category_code: "ATHN", category: "Authentication",
        name: "Testing for Weaker Authentication in Alternative Channel",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A07, cwe: "CWE-287",
        client_summary: "Check whether mobile or legacy entry points use weaker login rules.",
    },
    ChecklistItem {
        id: "WSTG-ATHN-11", category_code: "ATHN", category: "Authentication",
        name: "Testing Multi-Factor Authentication",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A07, cwe: "CWE-308",
        client_summary: "Review whether second-factor authentication is enforced and cannot be skipped.",
    },

    // ── Authorization ────────────────────────────────────────────────────────
    ChecklistItem {
        id: "WSTG-ATHZ-01", category_code: "ATHZ", category: "Authorization",
        name: "Testing Directory Traversal / File Include",
        coverage: Partial, engines: E_SEMGREP_ZAP_NUCLEI, owasp_2025: A01, cwe: "CWE-22",
        client_summary: "Attempt to read files outside the intended web directory.",
    },
    ChecklistItem {
        id: "WSTG-ATHZ-02", category_code: "ATHZ", category: "Authorization",
        name: "Testing for Bypassing Authorization Schema",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A01, cwe: "CWE-285",
        client_summary: "Try to access another user's data or admin functions as a normal user.",
    },
    ChecklistItem {
        id: "WSTG-ATHZ-03", category_code: "ATHZ", category: "Authorization",
        name: "Testing for Privilege Escalation",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A01, cwe: "CWE-269",
        client_summary: "Attempt to gain higher privileges than the account was granted.",
    },
    ChecklistItem {
        id: "WSTG-ATHZ-04", category_code: "ATHZ", category: "Authorization",
        name: "Testing for Insecure Direct Object References",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A01, cwe: "CWE-639",
        client_summary: "Change record identifiers in requests to see if other customers' data is returned.",
    },
    ChecklistItem {
        id: "WSTG-ATHZ-05", category_code: "ATHZ", category: "Authorization",
        name: "Testing for OAuth Weaknesses",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A01, cwe: "CWE-863",
        client_summary: "Review third-party sign-in flows for token and redirect weaknesses.",
    },

    // ── Session Management ───────────────────────────────────────────────────
    ChecklistItem {
        id: "WSTG-SESS-01", category_code: "SESS", category: "Session Management",
        name: "Testing for Session Management Schema",
        coverage: Partial, engines: E_NATIVE_ZAP, owasp_2025: A07, cwe: "CWE-384",
        client_summary: "Assess how login sessions are created, tracked and invalidated.",
    },
    ChecklistItem {
        id: "WSTG-SESS-02", category_code: "SESS", category: "Session Management",
        name: "Testing for Cookies Attributes",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A02, cwe: "CWE-1004",
        client_summary: "Verify session cookies are marked Secure, HttpOnly and SameSite.",
    },
    ChecklistItem {
        id: "WSTG-SESS-03", category_code: "SESS", category: "Session Management",
        name: "Testing for Session Fixation",
        coverage: Partial, engines: E_ZAP_ANALYST, owasp_2025: A07, cwe: "CWE-384",
        client_summary: "Check that the session identifier changes when a user logs in.",
    },
    ChecklistItem {
        id: "WSTG-SESS-04", category_code: "SESS", category: "Session Management",
        name: "Testing for Exposed Session Variables",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A04, cwe: "CWE-598",
        client_summary: "Ensure session identifiers never appear in URLs or logs.",
    },
    ChecklistItem {
        id: "WSTG-SESS-05", category_code: "SESS", category: "Session Management",
        name: "Testing for Cross Site Request Forgery",
        coverage: Partial, engines: E_NATIVE_ZAP, owasp_2025: A01, cwe: "CWE-352",
        client_summary: "Test whether another website can make actions happen on a logged-in user's behalf.",
    },
    ChecklistItem {
        id: "WSTG-SESS-06", category_code: "SESS", category: "Session Management",
        name: "Testing for Logout Functionality",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A07, cwe: "CWE-613",
        client_summary: "Confirm that logging out genuinely ends the session on the server.",
    },
    ChecklistItem {
        id: "WSTG-SESS-07", category_code: "SESS", category: "Session Management",
        name: "Testing Session Timeout",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A07, cwe: "CWE-613",
        client_summary: "Check that idle sessions expire after a reasonable period.",
    },
    ChecklistItem {
        id: "WSTG-SESS-08", category_code: "SESS", category: "Session Management",
        name: "Testing for Session Puzzling",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A06, cwe: "CWE-841",
        client_summary: "Look for session variables reused across features in unsafe ways.",
    },
    ChecklistItem {
        id: "WSTG-SESS-09", category_code: "SESS", category: "Session Management",
        name: "Testing for Session Hijacking",
        coverage: Partial, engines: E_NATIVE_ANALYST, owasp_2025: A04, cwe: "CWE-294",
        client_summary: "Assess whether a session token could be stolen and replayed by an attacker.",
    },
    ChecklistItem {
        id: "WSTG-SESS-10", category_code: "SESS", category: "Session Management",
        name: "Testing JSON Web Tokens",
        coverage: Partial, engines: E_NATIVE_ANALYST, owasp_2025: A07, cwe: "CWE-347",
        client_summary: "Inspect JWT tokens for weak signing algorithms and sensitive contents.",
    },

    // ── Input Validation ─────────────────────────────────────────────────────
    ChecklistItem {
        id: "WSTG-INPV-01", category_code: "INPV", category: "Input Validation",
        name: "Testing for Reflected Cross Site Scripting",
        coverage: Partial, engines: E_SEMGREP_ZAP_NUCLEI, owasp_2025: A05, cwe: "CWE-79",
        client_summary: "Attempt to make the site echo attacker-supplied scripts back to a victim.",
    },
    ChecklistItem {
        id: "WSTG-INPV-02", category_code: "INPV", category: "Input Validation",
        name: "Testing for Stored Cross Site Scripting",
        coverage: Partial, engines: E_ZAP_SEMGREP, owasp_2025: A05, cwe: "CWE-79",
        client_summary: "Attempt to store malicious scripts that run for other users later.",
    },
    ChecklistItem {
        id: "WSTG-INPV-03", category_code: "INPV", category: "Input Validation",
        name: "Testing for HTTP Verb Tampering",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A01, cwe: "CWE-650",
        client_summary: "Try alternative request methods to bypass access restrictions.",
    },
    ChecklistItem {
        id: "WSTG-INPV-04", category_code: "INPV", category: "Input Validation",
        name: "Testing for HTTP Parameter Pollution",
        coverage: Partial, engines: E_ZAP, owasp_2025: A05, cwe: "CWE-235",
        client_summary: "Send duplicated parameters to confuse application logic.",
    },
    ChecklistItem {
        id: "WSTG-INPV-05", category_code: "INPV", category: "Input Validation",
        name: "Testing for SQL Injection",
        coverage: Partial, engines: E_SEMGREP_ZAP_NUCLEI, owasp_2025: A05, cwe: "CWE-89",
        client_summary: "Attempt to manipulate database queries through user input.",
    },
    ChecklistItem {
        id: "WSTG-INPV-06", category_code: "INPV", category: "Input Validation",
        name: "Testing for LDAP Injection",
        coverage: Partial, engines: E_SEMGREP, owasp_2025: A05, cwe: "CWE-90",
        client_summary: "Attempt to manipulate directory-service queries through user input.",
    },
    ChecklistItem {
        id: "WSTG-INPV-07", category_code: "INPV", category: "Input Validation",
        name: "Testing for XML Injection",
        coverage: Partial, engines: E_SEMGREP_ZAP_NUCLEI, owasp_2025: A05, cwe: "CWE-91",
        client_summary: "Attempt to inject malicious XML, including external entity attacks.",
    },
    ChecklistItem {
        id: "WSTG-INPV-08", category_code: "INPV", category: "Input Validation",
        name: "Testing for SSI Injection",
        coverage: Partial, engines: E_ZAP_NUCLEI, owasp_2025: A05, cwe: "CWE-97",
        client_summary: "Attempt to inject server-side include directives.",
    },
    ChecklistItem {
        id: "WSTG-INPV-09", category_code: "INPV", category: "Input Validation",
        name: "Testing for XPath Injection",
        coverage: Partial, engines: E_SEMGREP, owasp_2025: A05, cwe: "CWE-643",
        client_summary: "Attempt to manipulate XML data queries through user input.",
    },
    ChecklistItem {
        id: "WSTG-INPV-10", category_code: "INPV", category: "Input Validation",
        name: "Testing for IMAP / SMTP Injection",
        coverage: Partial, engines: E_SEMGREP, owasp_2025: A05, cwe: "CWE-93",
        client_summary: "Attempt to inject mail-server commands through application input.",
    },
    ChecklistItem {
        id: "WSTG-INPV-11", category_code: "INPV", category: "Input Validation",
        name: "Testing for Code Injection",
        coverage: Partial, engines: E_SEMGREP_ZAP_NUCLEI, owasp_2025: A05, cwe: "CWE-94",
        client_summary: "Attempt to make the application execute attacker-supplied code.",
    },
    ChecklistItem {
        id: "WSTG-INPV-12", category_code: "INPV", category: "Input Validation",
        name: "Testing for Command Injection",
        coverage: Partial, engines: E_SEMGREP_ZAP_NUCLEI, owasp_2025: A05, cwe: "CWE-78",
        client_summary: "Attempt to run operating-system commands through the application.",
    },
    ChecklistItem {
        id: "WSTG-INPV-13", category_code: "INPV", category: "Input Validation",
        name: "Testing for Format String Injection",
        coverage: Partial, engines: E_SEMGREP, owasp_2025: A05, cwe: "CWE-134",
        client_summary: "Check for unsafe handling of format specifiers in user input.",
    },
    ChecklistItem {
        id: "WSTG-INPV-14", category_code: "INPV", category: "Input Validation",
        name: "Testing for Incubated Vulnerability",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A05, cwe: "CWE-74",
        client_summary: "Look for payloads that stay dormant until triggered by another user.",
    },
    ChecklistItem {
        id: "WSTG-INPV-15", category_code: "INPV", category: "Input Validation",
        name: "Testing for HTTP Splitting / Smuggling",
        coverage: Partial, engines: E_ZAP, owasp_2025: A05, cwe: "CWE-113",
        client_summary: "Test whether malformed requests can be smuggled past front-end proxies.",
    },
    ChecklistItem {
        id: "WSTG-INPV-16", category_code: "INPV", category: "Input Validation",
        name: "Testing for HTTP Incoming Requests",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A09, cwe: "CWE-778",
        client_summary: "Review how unexpected inbound requests are logged and handled.",
    },
    ChecklistItem {
        id: "WSTG-INPV-17", category_code: "INPV", category: "Input Validation",
        name: "Testing for Host Header Injection",
        coverage: Automated, engines: E_NATIVE, owasp_2025: A05, cwe: "CWE-644",
        client_summary: "Check whether a forged Host header can redirect users or poison caches.",
    },
    ChecklistItem {
        id: "WSTG-INPV-18", category_code: "INPV", category: "Input Validation",
        name: "Testing for Server-Side Template Injection",
        coverage: Partial, engines: E_ZAP_NUCLEI, owasp_2025: A05, cwe: "CWE-1336",
        client_summary: "Attempt to inject template expressions the server will evaluate.",
    },
    ChecklistItem {
        id: "WSTG-INPV-19", category_code: "INPV", category: "Input Validation",
        name: "Testing for Server-Side Request Forgery",
        coverage: Partial, engines: E_SEMGREP_ZAP_NUCLEI, owasp_2025: A01, cwe: "CWE-918",
        client_summary: "Attempt to make the server fetch internal resources on an attacker's behalf.",
    },
    ChecklistItem {
        id: "WSTG-INPV-20", category_code: "INPV", category: "Input Validation",
        name: "Testing for Mass Assignment",
        coverage: Partial, engines: E_SEMGREP_ANALYST, owasp_2025: A01, cwe: "CWE-915",
        client_summary: "Check whether hidden fields such as 'isAdmin' can be set by the client.",
    },

    // ── Error Handling ───────────────────────────────────────────────────────
    ChecklistItem {
        id: "WSTG-ERRH-01", category_code: "ERRH", category: "Error Handling",
        name: "Testing for Improper Error Handling",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A10, cwe: "CWE-209",
        client_summary: "Verify error pages do not reveal internal system details.",
    },
    ChecklistItem {
        id: "WSTG-ERRH-02", category_code: "ERRH", category: "Error Handling",
        name: "Testing for Stack Traces",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A10, cwe: "CWE-209",
        client_summary: "Check that programming stack traces are never shown to users.",
    },

    // ── Cryptography ─────────────────────────────────────────────────────────
    ChecklistItem {
        id: "WSTG-CRYP-01", category_code: "CRYP", category: "Cryptography",
        name: "Testing for Weak Transport Layer Security",
        coverage: Automated, engines: E_NATIVE_NUCLEI, owasp_2025: A04, cwe: "CWE-326",
        client_summary: "Verify the encrypted connection uses modern protocols and a valid certificate.",
    },
    ChecklistItem {
        id: "WSTG-CRYP-02", category_code: "CRYP", category: "Cryptography",
        name: "Testing for Padding Oracle",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A04, cwe: "CWE-209",
        client_summary: "Test whether encryption errors leak enough information to decrypt data.",
    },
    ChecklistItem {
        id: "WSTG-CRYP-03", category_code: "CRYP", category: "Cryptography",
        name: "Testing for Sensitive Information Sent via Unencrypted Channels",
        coverage: Automated, engines: E_NATIVE, owasp_2025: A04, cwe: "CWE-319",
        client_summary: "Confirm no sensitive data is transmitted without encryption.",
    },
    ChecklistItem {
        id: "WSTG-CRYP-04", category_code: "CRYP", category: "Cryptography",
        name: "Testing for Weak Encryption",
        coverage: Partial, engines: E_SEMGREP, owasp_2025: A04, cwe: "CWE-327",
        client_summary: "Look for outdated or broken encryption algorithms in the codebase.",
    },

    // ── Business Logic ───────────────────────────────────────────────────────
    ChecklistItem {
        id: "WSTG-BUSL-01", category_code: "BUSL", category: "Business Logic",
        name: "Test Business Logic Data Validation",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A06, cwe: "CWE-20",
        client_summary: "Check that business rules cannot be broken with unexpected but valid-looking data.",
    },
    ChecklistItem {
        id: "WSTG-BUSL-02", category_code: "BUSL", category: "Business Logic",
        name: "Test Ability to Forge Requests",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A06, cwe: "CWE-602",
        client_summary: "Attempt to craft requests the user interface would never allow.",
    },
    ChecklistItem {
        id: "WSTG-BUSL-03", category_code: "BUSL", category: "Business Logic",
        name: "Test Integrity Checks",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A08, cwe: "CWE-345",
        client_summary: "Verify the application detects tampering with data it trusts.",
    },
    ChecklistItem {
        id: "WSTG-BUSL-04", category_code: "BUSL", category: "Business Logic",
        name: "Test for Process Timing",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A06, cwe: "CWE-208",
        client_summary: "Check whether response timing reveals information or allows race conditions.",
    },
    ChecklistItem {
        id: "WSTG-BUSL-05", category_code: "BUSL", category: "Business Logic",
        name: "Test Number of Times a Function Can Be Used Limits",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A06, cwe: "CWE-770",
        client_summary: "Verify single-use actions such as vouchers cannot be replayed.",
    },
    ChecklistItem {
        id: "WSTG-BUSL-06", category_code: "BUSL", category: "Business Logic",
        name: "Testing for the Circumvention of Work Flows",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A06, cwe: "CWE-841",
        client_summary: "Attempt to skip required steps in a multi-stage process.",
    },
    ChecklistItem {
        id: "WSTG-BUSL-07", category_code: "BUSL", category: "Business Logic",
        name: "Test Defenses Against Application Misuse",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A09, cwe: "CWE-778",
        client_summary: "Check whether the application detects and responds to obvious abuse.",
    },
    ChecklistItem {
        id: "WSTG-BUSL-08", category_code: "BUSL", category: "Business Logic",
        name: "Test Upload of Unexpected File Types",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A06, cwe: "CWE-434",
        client_summary: "Attempt to upload file types the application should reject.",
    },
    ChecklistItem {
        id: "WSTG-BUSL-09", category_code: "BUSL", category: "Business Logic",
        name: "Test Upload of Malicious Files",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A06, cwe: "CWE-434",
        client_summary: "Attempt to upload files that could be executed by the server.",
    },
    ChecklistItem {
        id: "WSTG-BUSL-10", category_code: "BUSL", category: "Business Logic",
        name: "Test Payment Functionality",
        coverage: Manual, engines: E_ANALYST, owasp_2025: A06, cwe: "CWE-840",
        client_summary: "Review payment flows for price tampering and bypass opportunities.",
    },

    // ── Client-Side ──────────────────────────────────────────────────────────
    ChecklistItem {
        id: "WSTG-CLNT-01", category_code: "CLNT", category: "Client-Side",
        name: "Testing for DOM-Based Cross Site Scripting",
        coverage: Partial, engines: E_SEMGREP_ZAP_NUCLEI, owasp_2025: A05, cwe: "CWE-79",
        client_summary: "Look for browser-side code that unsafely handles data from the URL.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-02", category_code: "CLNT", category: "Client-Side",
        name: "Testing for JavaScript Execution",
        coverage: Partial, engines: E_SEMGREP, owasp_2025: A05, cwe: "CWE-95",
        client_summary: "Check for browser code that evaluates untrusted input as script.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-03", category_code: "CLNT", category: "Client-Side",
        name: "Testing for HTML Injection",
        coverage: Partial, engines: E_ZAP, owasp_2025: A05, cwe: "CWE-80",
        client_summary: "Attempt to inject markup that alters what users see.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-04", category_code: "CLNT", category: "Client-Side",
        name: "Testing for Client-Side URL Redirect",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A01, cwe: "CWE-601",
        client_summary: "Check whether the site can be used to redirect users to attacker websites.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-05", category_code: "CLNT", category: "Client-Side",
        name: "Testing for CSS Injection",
        coverage: Partial, engines: E_ZAP, owasp_2025: A05, cwe: "CWE-79",
        client_summary: "Attempt to inject styles that could capture data or deface the page.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-06", category_code: "CLNT", category: "Client-Side",
        name: "Testing for Client-Side Resource Manipulation",
        coverage: Partial, engines: E_SEMGREP, owasp_2025: A05, cwe: "CWE-99",
        client_summary: "Check whether attackers can control which scripts or resources the page loads.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-07", category_code: "CLNT", category: "Client-Side",
        name: "Testing Cross Origin Resource Sharing",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A02, cwe: "CWE-942",
        client_summary: "Verify other websites cannot read data from your application in a user's browser.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-08", category_code: "CLNT", category: "Client-Side",
        name: "Testing for Cross Site Flashing",
        coverage: Automated, engines: E_NATIVE, owasp_2025: A02, cwe: "CWE-942",
        client_summary: "Check for legacy Flash cross-domain policies still present on the server.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-09", category_code: "CLNT", category: "Client-Side",
        name: "Testing for Clickjacking",
        coverage: Automated, engines: E_NATIVE_ZAP, owasp_2025: A02, cwe: "CWE-1021",
        client_summary: "Verify the site cannot be hidden inside another site to trick users into clicking.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-10", category_code: "CLNT", category: "Client-Side",
        name: "Testing WebSockets",
        coverage: Partial, engines: E_NATIVE_ANALYST, owasp_2025: A01, cwe: "CWE-346",
        client_summary: "Review real-time connections for missing origin and authentication checks.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-11", category_code: "CLNT", category: "Client-Side",
        name: "Testing Web Messaging",
        coverage: Partial, engines: E_SEMGREP, owasp_2025: A05, cwe: "CWE-346",
        client_summary: "Check that cross-window messages verify their sender.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-12", category_code: "CLNT", category: "Client-Side",
        name: "Testing Browser Storage",
        coverage: Partial, engines: E_SEMGREP_ANALYST, owasp_2025: A04, cwe: "CWE-922",
        client_summary: "Check whether sensitive data is stored insecurely in the browser.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-13", category_code: "CLNT", category: "Client-Side",
        name: "Testing for Cross Site Script Inclusion",
        coverage: Partial, engines: E_ZAP_ANALYST, owasp_2025: A01, cwe: "CWE-829",
        client_summary: "Check whether other sites can include your scripts to steal data.",
    },
    ChecklistItem {
        id: "WSTG-CLNT-14", category_code: "CLNT", category: "Client-Side",
        name: "Testing for Reverse Tabnabbing",
        coverage: Automated, engines: E_NATIVE, owasp_2025: A02, cwe: "CWE-1022",
        client_summary: "Verify links opening new tabs cannot control the original page.",
    },

    // ── API Testing ──────────────────────────────────────────────────────────
    ChecklistItem {
        id: "WSTG-APIT-01", category_code: "APIT", category: "API Testing",
        name: "Testing GraphQL",
        coverage: Partial, engines: E_NATIVE_NUCLEI, owasp_2025: A01, cwe: "CWE-284",
        client_summary: "Check GraphQL endpoints for introspection exposure and query abuse.",
    },
    ChecklistItem {
        id: "WSTG-APIT-02", category_code: "APIT", category: "API Testing",
        name: "Testing for Improper Assets Management",
        coverage: Automated, engines: E_NATIVE, owasp_2025: A02, cwe: "CWE-1059",
        client_summary: "Find old or undocumented API versions still reachable in production.",
    },

    // ── Supply chain (SentinelVAPT extension beyond WSTG) ─────────────────────
    ChecklistItem {
        id: "SV-SUPPLY-01", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Known-Vulnerable Third-Party Dependencies",
        coverage: Automated, engines: E_TRIVY, owasp_2025: A03, cwe: "CWE-1395",
        client_summary: "Cross-check every third-party library against public vulnerability databases.",
    },
    ChecklistItem {
        id: "SV-SUPPLY-02", category_code: "CONF", category: "Configuration & Deployment Management",
        name: "Hardcoded Secrets and Credential Leakage",
        coverage: Automated, engines: &[engine::GITLEAKS], owasp_2025: A04, cwe: "CWE-798",
        client_summary: "Search the codebase for passwords, API keys and tokens committed by mistake.",
    },
];

/// Total number of catalog items.
pub fn total_items() -> usize {
    WSTG_CATALOG.len()
}

/// Look up a single item by its identifier.
pub fn find(id: &str) -> Option<&'static ChecklistItem> {
    WSTG_CATALOG.iter().find(|i| i.id.eq_ignore_ascii_case(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalog_ids_are_unique() {
        let mut seen = HashSet::new();
        for item in WSTG_CATALOG {
            assert!(seen.insert(item.id), "duplicate checklist id: {}", item.id);
        }
    }

    #[test]
    fn catalog_covers_all_wstg_categories() {
        for (code, _) in CATEGORIES {
            assert!(
                WSTG_CATALOG.iter().any(|i| i.category_code == *code),
                "no checklist items for category {code}"
            );
        }
    }

    #[test]
    fn every_item_declares_at_least_one_engine() {
        for item in WSTG_CATALOG {
            assert!(!item.engines.is_empty(), "{} declares no engine", item.id);
        }
    }

    #[test]
    fn manual_items_are_attributed_to_the_analyst() {
        for item in WSTG_CATALOG.iter().filter(|i| i.coverage == CoverageKind::Manual) {
            assert!(
                item.engines.contains(&engine::ANALYST),
                "{} is manual but not attributed to the analyst",
                item.id
            );
        }
    }

    #[test]
    fn category_names_are_consistent_with_codes() {
        for item in WSTG_CATALOG {
            assert_eq!(
                item.category,
                category_name(item.category_code),
                "{} category name does not match its code",
                item.id
            );
        }
    }

    #[test]
    fn owasp_mappings_use_the_2025_taxonomy() {
        for item in WSTG_CATALOG {
            assert!(
                item.owasp_2025.contains(":2025-"),
                "{} does not use an OWASP Top 10:2025 mapping",
                item.id
            );
        }
    }

    #[test]
    fn find_is_case_insensitive() {
        assert!(find("wstg-conf-07").is_some());
        assert!(find("WSTG-CONF-07").is_some());
        assert!(find("WSTG-NOPE-99").is_none());
    }

    #[test]
    fn catalog_is_substantial() {
        // Guards against accidental truncation of the catalog.
        assert!(total_items() >= 100, "catalog shrank to {} items", total_items());
    }
}
