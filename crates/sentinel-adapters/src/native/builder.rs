//! Finding construction for the native check engine.
//!
//! Each native check declares a `CheckSpec` — a compile-time description of the
//! weakness including its CVSS 4.0 vector, CWE, WSTG identifier and remediation
//! guidance for both audiences. `NativeFinding` turns a spec plus per-instance
//! evidence into a fully-populated `Finding`, so scoring, deduplication and the
//! report engine all receive consistent, taxonomy-complete data.

use sentinel_core::models::finding::{
    AITriage, CVSS4Data, Evidence, Finding, FindingStatus, Severity, FindingKind};
use sentinel_core::scoring::{Cvss4Severity, Cvss4Vector};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Compile-time description of one native check.
#[derive(Debug, Clone)]
pub struct CheckSpec {
    /// Stable internal identifier, e.g. "NATIVE-HSTS-MISSING".
    pub id: &'static str,
    pub title: &'static str,
    /// The CVSS 4.0 vector, and the single source of truth for how serious this
    /// check is.
    ///
    /// Neither a numeric score nor a severity label is stored alongside it.
    /// Both are computed from this string by [`CheckSpec::score`] and
    /// [`CheckSpec::severity`]. When they were declared by hand, 37 of the 45
    /// checks drifted away from the vector printed next to them in the report —
    /// deriving them makes that class of error unrepresentable.
    pub cvss_vector: &'static str,
    pub cwe: &'static str,
    pub wstg: &'static str,
    pub owasp_2025: &'static str,
    pub api_top10: Option<&'static str>,
    /// Technical explanation for the developer report.
    pub description: &'static str,
    /// Concrete fix instructions for the developer report.
    pub remediation: &'static str,
    /// Reference URLs.
    pub references: &'static [&'static str],
}

impl CheckSpec {
    /// The CVSS 4.0 base score, computed from [`Self::cvss_vector`].
    ///
    /// A malformed vector scores 0.0 rather than panicking; the spec audit
    /// fails the build long before a scan could reach that state.
    pub fn score(&self) -> f64 {
        Cvss4Vector::parse(self.cvss_vector)
            .map(|v| v.score())
            .unwrap_or(0.0)
    }

    /// The severity band this check's score falls into.
    pub fn severity(&self) -> Severity {
        match Cvss4Severity::of(self.score()) {
            Cvss4Severity::Critical => Severity::Critical,
            Cvss4Severity::High => Severity::High,
            Cvss4Severity::Medium => Severity::Medium,
            Cvss4Severity::Low => Severity::Low,
            Cvss4Severity::None => Severity::Info,
        }
    }
}

/// Builder that attaches per-instance detail to a `CheckSpec`.
pub struct NativeFinding;

impl NativeFinding {
    /// Construct a `Finding` from a spec.
    ///
    /// * `component` — the affected URL or endpoint.
    /// * `detail` — instance-specific sentence appended to the spec description.
    /// * `repro_steps` — copy-pasteable verification steps.
    /// * `evidences` — sanitized proof captured during the probe.
    pub fn build(
        spec: &CheckSpec,
        target_id: Uuid,
        scan_id: Uuid,
        component: &str,
        detail: &str,
        repro_steps: Vec<String>,
        evidences: Vec<Evidence>,
    ) -> Finding {
        let description = if detail.trim().is_empty() {
            spec.description.to_string()
        } else {
            format!("{}\n\nObserved: {}", spec.description, detail)
        };

        Finding {
            id: Uuid::new_v4(),
            scan_id,
            target_id,
            title: spec.title.to_string(),
            description,
            severity: spec.severity(),
            kind: FindingKind::Weakness,
            cvss4: Some(CVSS4Data {
                vector_string: spec.cvss_vector.to_string(),
                base_score: spec.score(),
                severity_label: severity_label(&spec.severity()).to_string(),
            }),
            // Native checks observe live configuration; they are not CVE-backed,
            // so EPSS/KEV do not apply and must stay absent rather than be faked.
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.0,
            // Directly observed on the running target: confirmed reachable.
            reachability_score: 1.1,
            priority_score: 0.0,
            priority_rationale: String::new(),
            cwe_id: Some(spec.cwe.to_string()),
            owasp_2025: Some(spec.owasp_2025.to_string()),
            wstg_id: Some(spec.wstg.to_string()),
            api_top10: spec.api_top10.map(str::to_string),
            affected_component: component.to_string(),
            evidences,
            repro_steps,
            remediation: match remediation_snippet(spec.id) {
                Some(snippet) => format!("{}\n\n```\n{}\n```", spec.remediation, snippet),
                None => spec.remediation.to_string(),
            },
            references: spec.references.iter().map(|r| r.to_string()).collect(),
            status: FindingStatus::Open,
            source_tools: vec!["Sentinel Native".to_string()],
            ai_triage: Some(AITriage {
                is_false_positive_confidence: fp_confidence(spec.id),
                cluster_id: Some(format!("CLUSTER_{}", spec.cwe)),
                triage_notes: Some(triage_note(spec.id).to_string()),
            }),
            created_at: chrono::Utc::now(),
        }
    }

    /// Convenience constructor for evidence blocks with a content hash.
    pub fn evidence(evidence_type: &str, title: &str, content: &str) -> Evidence {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        Evidence {
            evidence_type: evidence_type.to_string(),
            title: title.to_string(),
            content: content.to_string(),
            hash: format!("{:x}", hasher.finalize()),
        }
    }
}

/// How likely a check is to be wrong, and why — per check, not one number for
/// all of them.
///
/// Every native finding used to declare a 2% chance of being a false positive.
/// For most of the engine that is honest: a missing response header either was
/// or was not in the bytes the server returned. It is not honest for the checks
/// whose result is an *inference* from an observation — an `Allow` header
/// advertising a method that the application layer may well reject, a keyword
/// appearing in an HTML comment, a hostname reflected in a response with no
/// proof that anything downstream trusts it. Reporting those at the same
/// confidence as a directly observed header teaches the reader to distrust the
/// whole document.
///
/// The figures below are the engine's own judgement of its evidence, and they
/// drive the confidence panel in the developer report so a reviewer can start
/// with the findings most likely to need a second look.
pub fn fp_confidence(spec_id: &str) -> f64 {
    match spec_id {
        // Advertised, not proven: `Allow` lists what the server will parse, and
        // application-layer routing frequently rejects the method anyway.
        "NATIVE-DANGEROUS-METHODS" => 0.35,
        // Reflection is necessary for host-header poisoning but not sufficient;
        // whether a cache or a password-reset mail actually trusts the value is
        // not established by a single request.
        "NATIVE-HOST-HEADER-INJECTION" => 0.35,
        // Every current browser implies `noopener` for `target="_blank"`, so
        // this only matters for the long tail of older clients.
        "NATIVE-TABNABBING" => 0.35,
        // A keyword inside a comment; the surrounding text decides whether it
        // is a leak or a coincidence.
        "NATIVE-COMMENT-LEAK" => 0.30,
        // A page under /admin that renders a login form may be the intended,
        // properly protected front door.
        "NATIVE-ADMIN-INTERFACE" => 0.25,
        // Published API documentation is a deliberate choice for many products.
        "NATIVE-API-DOCS-EXPOSED" => 0.25,
        // A reachable diagnostic path is not necessarily an unauthenticated one.
        "NATIVE-DEBUG-ENDPOINT" => 0.20,
        // Session detection is a name heuristic: a long-lived cookie called
        // "user_theme" is not a session.
        "NATIVE-SESSION-LIFETIME" => 0.20,
        "NATIVE-COOKIE-SAMESITE" | "NATIVE-COOKIE-HTTPONLY" | "NATIVE-COOKIE-INSECURE" => 0.10,
        // A marker match in the body; a page can legitimately discuss an error.
        "NATIVE-STACK-TRACE" => 0.12,
        // A same-organisation CDN is often an intentional trust relationship.
        "NATIVE-SRI-MISSING" => 0.15,
        // The strongest inference in the engine: a URL source and an HTML sink
        // in the same document is the *shape* of DOM XSS, not a proof of one.
        // Whether the value is sanitised in between needs a human to read the
        // code, so this is deliberately the lowest-confidence check shipped.
        "NATIVE-DOM-XSS-SINK" => 0.55,
        // A token in the markup may be a public, non-session JWT.
        "NATIVE-JWT-IN-CONTENT" => 0.20,
        // The key name is a heuristic: `refresh_banner` is not a credential.
        "NATIVE-INSECURE-BROWSER-STORAGE" => 0.20,
        // The token is matched by field name, and a framework may inject one
        // via script or rely on a header the markup does not show.
        "NATIVE-FORM-NO-CSRF-TOKEN" => 0.30,
        // Embedding a third party unsandboxed is often a deliberate decision
        // for a payment or video widget that will not run inside one.
        "NATIVE-IFRAME-NO-SANDBOX" => 0.20,
        // The origin may be fronted by an edge that adds the control after this
        // response left it, which a direct probe cannot see.
        "NATIVE-CSP-WEAK" | "NATIVE-CACHE-CONTROL" => 0.08,
        // Everything else is read straight out of the response or the
        // certificate: it either was there or it was not.
        _ => 0.02,
    }
}

/// A copy-pasteable fix for the checks where one exists.
///
/// Most remediation advice in this engine is a paragraph, which is right for a
/// weakness whose fix depends on the application. But for a missing response
/// header the fix *is* a line of configuration, and making a developer retype
/// a directive out of a wrapped paragraph is how a Content-Security-Policy ends
/// up deployed with a typo in it.
///
/// Returned as a fenced block appended to the remediation text; the developer
/// report renders fences as code blocks and leaves the prose either side
/// intact.
fn remediation_snippet(spec_id: &str) -> Option<&'static str> {
    Some(match spec_id {
        "NATIVE-HSTS-MISSING" | "NATIVE-HSTS-WEAK" => {
            "# nginx\n\
             add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\n\n\
             # Apache\n\
             Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"\n\n\
             # Express\n\
             app.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true, preload: true }));"
        }
        "NATIVE-CSP-MISSING" | "NATIVE-CSP-WEAK" => {
            "# A nonce-based policy. Generate `$nonce` per response and put the\n\
             # same value on every inline <script nonce=\"...\">.\n\
             Content-Security-Policy:\n\
             \x20 default-src 'self';\n\
             \x20 script-src 'self' 'nonce-$nonce' 'strict-dynamic';\n\
             \x20 object-src 'none';\n\
             \x20 base-uri 'self';\n\
             \x20 frame-ancestors 'none';\n\
             \x20 form-action 'self';\n\
             \x20 require-trusted-types-for 'script'"
        }
        "NATIVE-CLICKJACKING" => {
            "# frame-ancestors supersedes X-Frame-Options where both are understood.\n\
             Content-Security-Policy: frame-ancestors 'none'\n\
             X-Frame-Options: DENY"
        }
        "NATIVE-XCTO-MISSING" => "X-Content-Type-Options: nosniff",
        "NATIVE-COOKIE-BROAD-DOMAIN" => {
            "# Drop Domain so the cookie is host-only, and let __Host- enforce it.\n\
             Set-Cookie: __Host-session=<value>; Secure; HttpOnly; SameSite=Lax; Path=/"
        }
        "NATIVE-CSP-REPORT-ONLY" => {
            "# Same policy, enforcing. Keep report-only alongside to trial a stricter one.\n\
             Content-Security-Policy: <your policy>\n\
             Content-Security-Policy-Report-Only: <a stricter policy you are still testing>"
        }
        "NATIVE-IFRAME-NO-SANDBOX" => {
            "<!-- Grant only what the embedded content needs. Never combine\n\
             \x20    allow-scripts with allow-same-origin for a third party: together\n\
             \x20    they let the frame remove its own sandbox. -->\n\
             <iframe src=\"https://widget.example.com/\" sandbox=\"allow-scripts\"></iframe>"
        }
        "NATIVE-REFERRER-POLICY" => "Referrer-Policy: strict-origin-when-cross-origin",
        "NATIVE-PERMISSIONS-POLICY" => {
            "# Deny by default; add back only what the application uses.\n\
             Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(),\n\
             \x20 magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()"
        }
        "NATIVE-COOP-MISSING" => "Cross-Origin-Opener-Policy: same-origin",
        "NATIVE-CORP-MISSING" => "Cross-Origin-Resource-Policy: same-origin",
        "NATIVE-XSS-FILTER-ENABLED" => {
            "# Disable the legacy auditor explicitly and rely on CSP instead.\n\
             X-XSS-Protection: 0"
        }
        "NATIVE-COOKIE-INSECURE" | "NATIVE-COOKIE-HTTPONLY" | "NATIVE-COOKIE-SAMESITE"
        | "NATIVE-COOKIE-PREFIX" => {
            "# __Host- is enforced by the browser: HTTPS only, Path=/, no Domain,\n\
             # so a sibling subdomain cannot overwrite the session cookie.\n\
             Set-Cookie: __Host-session=<value>; Secure; HttpOnly; SameSite=Lax; Path=/\n\n\
             // Express\n\
             res.cookie('__Host-session', value, {\n\
             \x20 secure: true, httpOnly: true, sameSite: 'lax', path: '/',\n\
             });"
        }
        "NATIVE-CACHE-CONTROL" => {
            "# On any response that carries session state or personal data.\n\
             Cache-Control: no-store\n\
             Pragma: no-cache"
        }
        "NATIVE-BANNER-DISCLOSURE" => {
            "# nginx\n\
             server_tokens off;\n\n\
             # Express\n\
             app.disable('x-powered-by');\n\n\
             # Apache\n\
             ServerTokens Prod\n\
             ServerSignature Off"
        }
        "NATIVE-DIRECTORY-LISTING" => {
            "# nginx\n\
             autoindex off;\n\n\
             # Apache\n\
             Options -Indexes"
        }
        "NATIVE-SRI-MISSING" => {
            "<!-- Generate the hash with:\n\
             \x20    openssl dgst -sha384 -binary lib.js | openssl base64 -A  -->\n\
             <script src=\"https://cdn.example.com/lib.js\"\n\
             \x20       integrity=\"sha384-<hash>\"\n\
             \x20       crossorigin=\"anonymous\"></script>"
        }
        "NATIVE-TABNABBING" => "<a href=\"https://example.com\" target=\"_blank\" rel=\"noopener noreferrer\">…</a>",
        "NATIVE-NO-HTTPS" | "NATIVE-NO-HTTPS-REDIRECT" => {
            "# nginx — redirect every plaintext request before anything else runs.\n\
             server {\n\
             \x20 listen 80;\n\
             \x20 server_name example.com;\n\
             \x20 return 301 https://$host$request_uri;\n\
             }"
        }
        "NATIVE-CORS-WILDCARD" | "NATIVE-CORS-CREDENTIALED-REFLECTION" | "NATIVE-CORS-NULL-ORIGIN" => {
            "// Reflecting the Origin header is what makes this exploitable.\n\
             // Check it against an allow-list and echo only a known value.\n\
             const ALLOWED = new Set(['https://app.example.com']);\n\
             const origin = req.get('Origin');\n\
             if (origin && ALLOWED.has(origin)) {\n\
             \x20 res.set('Access-Control-Allow-Origin', origin);\n\
             \x20 res.set('Vary', 'Origin');\n\
             \x20 res.set('Access-Control-Allow-Credentials', 'true');\n\
             }"
        }
        "NATIVE-DANGEROUS-METHODS" => {
            "# nginx — allow only the methods the application serves.\n\
             if ($request_method !~ ^(GET|HEAD|POST|PUT|PATCH|DELETE)$) {\n\
             \x20 return 405;\n\
             }\n\n\
             # Apache — TRACE is never needed and enables cross-site tracing.\n\
             TraceEnable Off"
        }
        _ => return None,
    })
}

/// The engine's own note on what its evidence does and does not establish.
fn triage_note(spec_id: &str) -> &'static str {
    match spec_id {
        "NATIVE-DANGEROUS-METHODS" => "The server advertised these methods in its OPTIONS response. \
Advertising is not the same as accepting: confirm against a real route before treating this as exploitable.",
        "NATIVE-HOST-HEADER-INJECTION" => "The submitted hostname was reflected. Impact depends on \
whether a cache, a redirect or an outbound email downstream trusts that value; that is not established here.",
        "NATIVE-TABNABBING" => "Current browsers imply rel=noopener for target=_blank, so the practical \
exposure is limited to older clients.",
        "NATIVE-COMMENT-LEAK" => "A sensitive keyword was matched inside an HTML comment. Read the \
surrounding text before acting — the word may be incidental.",
        "NATIVE-ADMIN-INTERFACE" => "A conventional administrative path responded with a page matching a \
login signature. Whether it is adequately protected is not determined by reachability alone.",
        "NATIVE-API-DOCS-EXPOSED" => "API documentation is reachable anonymously. For a public API this \
may be deliberate; for an internal one it is an inventory disclosure.",
        "NATIVE-DEBUG-ENDPOINT" => "A diagnostic endpoint responded. Confirm whether it is reachable \
without authentication from outside your network before scheduling work.",
        "NATIVE-SESSION-LIFETIME" => "The cookie was classified as session-bearing by its name. If it \
carries a preference rather than session state, this is not a finding.",
        "NATIVE-SRI-MISSING" => "The script is loaded from another origin without an integrity hash. If \
that origin is under your own control the risk is lower, but not zero.",
        "NATIVE-DOM-XSS-SINK" => "A URL-reading expression and an HTML or code sink were both found in \
this document. That is the shape of DOM-based XSS, not a demonstration of one — read the code between \
the two before treating it as exploitable.",
        "NATIVE-JWT-IN-CONTENT" => "A token matching the JWT structure was found in the page. If it is a \
public, non-session token the disclosure is limited to whatever claims it carries.",
        "NATIVE-INSECURE-BROWSER-STORAGE" => "The storage key was matched by name. Confirm the value is \
genuinely session or credential material rather than a preference that happens to be called 'token'.",
        "NATIVE-FORM-NO-CSRF-TOKEN" => "No hidden field matching a known token name was found in the \
markup. A framework that injects the token via script, or an endpoint that validates a custom header \
instead, would be protected without this check being able to see it.",
        "NATIVE-IFRAME-NO-SANDBOX" => "The frame is cross-origin and carries no sandbox attribute. \
Some third-party widgets genuinely will not run inside one; confirm before treating this as an \
oversight rather than a decision.",
        "NATIVE-CSP-WEAK" | "NATIVE-CACHE-CONTROL" => "Observed on the response from this endpoint. If a \
CDN or WAF rewrites headers at the edge, confirm the production response before acting.",
        _ => "Observed directly from the live HTTP/TLS response; not inferred.",
    }
}

pub fn severity_label(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "None",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: CheckSpec = CheckSpec {
        id: "NATIVE-TEST",
        title: "Test Check",
        cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
        cwe: "CWE-16",
        wstg: "WSTG-CONF-02",
        owasp_2025: "A02:2025-Security Misconfiguration",
        api_top10: None,
        description: "Base description.",
        remediation: "Do the fix.",
        references: &["https://example.test/ref"],
    };

    #[test]
    fn build_populates_full_taxonomy() {
        let f = NativeFinding::build(
            &SPEC,
            Uuid::new_v4(),
            Uuid::new_v4(),
            "https://app.test/",
            "header was absent",
            vec!["curl -I https://app.test/".into()],
            vec![NativeFinding::evidence("http_response", "Response", "HTTP/1.1 200 OK")],
        );

        assert_eq!(f.cwe_id.as_deref(), Some("CWE-16"));
        assert_eq!(f.wstg_id.as_deref(), Some("WSTG-CONF-02"));
        assert_eq!(f.owasp_2025.as_deref(), Some("A02:2025-Security Misconfiguration"));
        assert_eq!(f.source_tools, vec!["Sentinel Native".to_string()]);
        assert!(f.description.contains("Observed: header was absent"));
        // Computed from the vector above, not declared beside it.
        assert_eq!(f.cvss4.unwrap().base_score, 6.9);
        assert_eq!(f.references.len(), 1);
    }

    /// A directive retyped out of a wrapped paragraph is how a header ends up
    /// deployed with a typo in it.
    #[test]
    fn header_checks_carry_a_copy_pasteable_fix() {
        for id in [
            "NATIVE-HSTS-MISSING",
            "NATIVE-CSP-MISSING",
            "NATIVE-XCTO-MISSING",
            "NATIVE-COOKIE-HTTPONLY",
            "NATIVE-CORS-WILDCARD",
        ] {
            let snippet = remediation_snippet(id)
                .unwrap_or_else(|| panic!("{id} should offer a concrete fix"));
            assert!(!snippet.trim().is_empty(), "{id} has an empty snippet");
        }
    }

    /// Advice that depends on the application must stay prose — an invented
    /// snippet would be worse than none.
    #[test]
    fn application_specific_checks_offer_no_snippet() {
        assert!(remediation_snippet("NATIVE-SECRET-IN-CONTENT").is_none());
        assert!(remediation_snippet("NATIVE-STACK-TRACE").is_none());
    }

    #[test]
    fn a_snippet_is_appended_as_a_fenced_block_after_the_prose() {
        const HSTS: CheckSpec = CheckSpec {
            id: "NATIVE-XCTO-MISSING",
            title: "T",
            cvss_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
            cwe: "CWE-16",
            wstg: "WSTG-CONF-02",
            owasp_2025: "A02:2025-Security Misconfiguration",
            api_top10: None,
            description: "d",
            remediation: "Set the header.",
            references: &["https://example.test"],
        };
        let f = NativeFinding::build(&HSTS, Uuid::new_v4(), Uuid::new_v4(), "https://x.test/", "", vec![], vec![]);
        assert!(f.remediation.starts_with("Set the header."), "the prose comes first");
        assert!(f.remediation.contains("```"), "the snippet is fenced");
        assert!(f.remediation.contains("X-Content-Type-Options: nosniff"));
    }

    /// A number that is the same for every check is not a confidence estimate.
    #[test]
    fn inference_based_checks_declare_lower_confidence_than_observed_ones() {
        let observed = fp_confidence("NATIVE-HSTS-MISSING");
        let inferred = fp_confidence("NATIVE-DANGEROUS-METHODS");
        assert!(observed < 0.05, "a missing header is read straight off the wire");
        assert!(inferred > observed * 5.0, "an advertised method is a weaker claim");
        assert!(
            (0.0..=1.0).contains(&fp_confidence("NATIVE-COMMENT-LEAK")),
            "confidence must stay a probability"
        );
    }

    #[test]
    fn every_check_carries_a_note_saying_what_its_evidence_proves() {
        for id in ["NATIVE-DANGEROUS-METHODS", "NATIVE-TABNABBING", "NATIVE-HSTS-MISSING"] {
            assert!(!triage_note(id).trim().is_empty(), "{id} has no triage note");
        }
        assert_ne!(
            triage_note("NATIVE-DANGEROUS-METHODS"),
            triage_note("NATIVE-HSTS-MISSING"),
            "an inference and an observation must not read identically"
        );
    }

    #[test]
    fn native_findings_do_not_fabricate_epss_or_kev() {
        let f = NativeFinding::build(
            &SPEC, Uuid::new_v4(), Uuid::new_v4(), "https://app.test/", "", vec![], vec![],
        );
        assert!(f.epss.is_none(), "configuration findings have no EPSS score");
        assert!(!f.kev_listed, "configuration findings are not CVEs");
    }

    #[test]
    fn empty_detail_leaves_description_unchanged() {
        let f = NativeFinding::build(
            &SPEC, Uuid::new_v4(), Uuid::new_v4(), "https://app.test/", "   ", vec![], vec![],
        );
        assert_eq!(f.description, "Base description.");
    }

    #[test]
    fn evidence_hash_is_stable_and_content_addressed() {
        let a = NativeFinding::evidence("http_response", "R", "same");
        let b = NativeFinding::evidence("http_response", "R", "same");
        let c = NativeFinding::evidence("http_response", "R", "different");
        assert_eq!(a.hash, b.hash);
        assert_ne!(a.hash, c.hash);
    }
}
