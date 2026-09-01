//! End-to-end test for the native check engine against a live HTTP server.
//!
//! Starts a deliberately misconfigured server on localhost, runs the engine
//! through the authorization gate exactly as the application does, and asserts
//! that the expected weaknesses are found — and, just as importantly, that a
//! correctly configured server produces none of them.

use chrono::Utc;
use sentinel_adapters::adapter_trait::ScannerAdapter;
use sentinel_adapters::auth_gated_runner::AuthGatedDastRunner;
use sentinel_adapters::native::NativeCheckAdapter;
use sentinel_core::models::finding::{Finding, Severity};
use sentinel_core::models::target::{AuthorizationRecord, ScopeDefinition, Target};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

/// How the test server should behave.
#[derive(Clone, Copy, PartialEq)]
enum Posture {
    /// Missing every security header, leaky cookies, exposed files.
    Bad,
    /// Correct headers, locked-down cookies, nothing exposed.
    Good,
}

/// Start a minimal HTTP/1.1 server and return the address it bound to.
async fn start_server(posture: Posture) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            tokio::spawn(handle(stream, posture));
        }
    });

    addr
}

async fn handle(mut stream: TcpStream, posture: Posture) {
    let mut buf = vec![0u8; 8192];
    let Ok(n) = stream.read(&mut buf).await else { return };
    if n == 0 {
        return;
    }
    let request = String::from_utf8_lossy(&buf[..n]).to_string();
    let path = request
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let origin = header_value(&request, "origin");

    let response = match posture {
        Posture::Bad => bad_response(&path, origin.as_deref()),
        Posture::Good => good_response(&path),
    };

    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

fn header_value(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn http(status: &str, headers: &[String], body: &str) -> String {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    for h in headers {
        out.push_str(h);
        out.push_str("\r\n");
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    out.push_str(body);
    out
}

fn bad_response(path: &str, origin: Option<&str>) -> String {
    match path {
        // A readable environment file — the highest-impact exposure check.
        "/.env" => http(
            "200 OK",
            &["Content-Type: text/plain".to_string()],
            "APP_KEY=abc\nDB_PASSWORD=hunter2\nAPI_SECRET=xyz\n",
        ),
        // Readable git metadata.
        "/.git/HEAD" => http(
            "200 OK",
            &["Content-Type: text/plain".to_string()],
            "ref: refs/heads/main\n",
        ),
        // A bundle whose source map is left readable — the map is only
        // discoverable from the script that references it, so finding it proves
        // the engine followed the reference rather than guessing a path.
        "/static/app.js" => http(
            "200 OK",
            &["Content-Type: application/javascript".to_string()],
            "console.log('app');\n//# sourceMappingURL=app.js.map\n",
        ),
        "/static/app.js.map" => http(
            "200 OK",
            &["Content-Type: application/json".to_string()],
            r#"{"version":3,"file":"app.js","sources":["src/index.ts","src/secret-feature.ts"],"mappings":"AAAA"}"#,
        ),
        // An OpenAPI document naming a route nothing links to. Finding a
        // weakness there proves the engine read the specification rather than
        // only following markup.
        "/openapi.json" => http(
            "200 OK",
            &["Content-Type: application/json".to_string()],
            r#"{"openapi":"3.0.0","paths":{"/api/v2/unlinked":{"get":{}}}}"#,
        ),
        "/api/v2/unlinked" => http(
            "200 OK",
            &[
                "Content-Type: text/html".to_string(),
                // Only reachable via the specification, and it leaks.
                "Access-Control-Allow-Origin: https://sentinelvapt.invalid".to_string(),
                "Access-Control-Allow-Credentials: true".to_string(),
            ],
            r#"<!DOCTYPE html><html><body>
<pre>Traceback (most recent call last):
  File "/srv/api/v2.py", line 12, in handler
KeyError: 'tenant'</pre>
</body></html>"#,
        ),
        "/robots.txt" => http(
            "200 OK",
            &["Content-Type: text/plain".to_string()],
            "User-agent: *\nDisallow: /internal-admin/\nDisallow: /backups/\n",
        ),
        // Linked from the root, and carrying a weakness the root does not.
        // Nothing but discovery can reach it, so a finding here proves the
        // engine walked the application rather than assessing one page.
        "/reports/quarterly" => http(
            "200 OK",
            &["Content-Type: text/html".to_string()],
            r#"<!DOCTYPE html><html><body>
<h1>Quarterly</h1>
<a href="/reports/quarterly/export">Export</a>
<pre>Traceback (most recent call last):
  File "/srv/app/reports.py", line 88, in render
    total = rows[0]/ 0
ZeroDivisionError: division by zero</pre>
</body></html>"#,
        ),
        // Two links deep: only reachable from /reports/quarterly.
        "/reports/quarterly/export" => http(
            "200 OK",
            &["Content-Type: text/html".to_string()],
            r#"<!DOCTYPE html><html><body>Export</body></html>"#,
        ),
        _ => {
            let mut headers = vec![
                "Content-Type: text/html".to_string(),
                "Server: nginx/1.18.0".to_string(),
                "X-Powered-By: PHP/7.4.3".to_string(),
                // A policy that prevents nothing: reported separately from
                // having no policy at all, because the fix is different.
                "Content-Security-Policy-Report-Only: default-src 'self'".to_string(),
                // Session cookie with none of the protective attributes.
                "Set-Cookie: JSESSIONID=abc123def456; Domain=.127.0.0.1".to_string(),
            ];
            // Reflect any origin with credentials — the exploitable CORS pattern.
            if let Some(o) = origin {
                headers.push(format!("Access-Control-Allow-Origin: {o}"));
                headers.push("Access-Control-Allow-Credentials: true".to_string());
            }
            http(
                "200 OK",
                &headers,
                r#"<!DOCTYPE html><html><head><title>Vulnerable</title>
<meta name="generator" content="WordPress 6.1.1">
<script src="http://cdn.example.test/lib.js"></script>
</head><body>
<!-- TODO: remove hardcoded password admin123 before launch -->
<a href="https://external.example.test" target="_blank">External</a>
<a href="/reports/quarterly">Quarterly report</a>
<form action="/login" method="post"><input type="password" name="p" autocomplete="on"></form>
<iframe src="https://widget.other.test/w"></iframe>
<script src="/static/app.js"></script>
<script>
// AKIAIOSFODNN7EXAMPLE is AWS's own published documentation key. It is on
// GitHub's secret-scanning allowlist, which is why it can sit here as a whole
// literal while the fixtures in disclosure.rs have to be assembled at run time.
var cfg = { awsKey: "AKIAIOSFODNN7EXAMPLE", upstream: "http://10.0.4.17:8080/api" };
fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
localStorage.setItem('auth_token', cfg.t);
parent.postMessage(cfg, "*");
document.querySelector('#out').innerHTML = decodeURIComponent(location.hash.slice(1));
</script>
</body></html>"#,
            )
        }
    }
}

fn good_response(path: &str) -> String {
    if path == "/.well-known/security.txt" {
        return http(
            "200 OK",
            &["Content-Type: text/plain".to_string()],
            "Contact: mailto:security@example.test\nExpires: 2030-01-01T00:00:00.000Z\n",
        );
    }
    // Everything that is not the root is genuinely absent.
    if path != "/" {
        return http("404 Not Found", &["Content-Type: text/plain".to_string()], "not found");
    }
    http(
        "200 OK",
        &[
            "Content-Type: text/html".to_string(),
            "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; \
             base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
                .replace("             ", "")
                .to_string(),
            "X-Content-Type-Options: nosniff".to_string(),
            "X-Frame-Options: DENY".to_string(),
            "Referrer-Policy: strict-origin-when-cross-origin".to_string(),
            "Permissions-Policy: camera=(), microphone=(), geolocation=()".to_string(),
            "Cross-Origin-Opener-Policy: same-origin".to_string(),
            "Cross-Origin-Resource-Policy: same-origin".to_string(),
            // Explicitly off, which is the value the spec now recommends.
            "X-XSS-Protection: 0".to_string(),
            "Cache-Control: no-store".to_string(),
            "Set-Cookie: JSESSIONID=abc; HttpOnly; SameSite=Lax; Path=/".to_string(),
        ],
        // A well-built page that nonetheless contains every shape the
        // disclosure and content checks look for *without* the substance:
        // a bundler path, an unversioned generator, a protected _blank link and
        // a password field in its default state. None of these may report.
        r#"<!DOCTYPE html><html><head><title>Hardened</title>
<meta name="generator" content="Hugo">
</head><body>OK
<a href="https://external.example.test" target="_blank" rel="noreferrer">External</a>
<form action="/login"><input type="password" name="p"></form>
<script>var m="/static/node_modules/react/index.js.map";var v="Aurora-01";</script>
<img src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" alt="">
</body></html>"#,
    )
}

fn authorized_target(base_url: &str) -> Target {
    Target {
        id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        name: "Local test target".into(),
        target_type: "Web App".into(),
        base_url: base_url.into(),
        repo_ref: None,
        stack_description: None,
        auth_keychain_handle: None,
        authorization_record: Some(AuthorizationRecord {
            id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            scope: ScopeDefinition {
                allowed_domains: vec!["127.0.0.1".into()],
                allowed_ips_cidrs: vec![],
                out_of_scope_paths: vec![],
                // High rate limit so the test does not spend minutes sleeping.
                rate_limit_rps: 200,
                prohibited_actions: vec!["DoS".into()],
            },
            acknowledged_by: "Test Lead".into(),
            signed_at: Utc::now(),
            roe_document_hash: "test-hash".into(),
            digital_signature: "test-sig".into(),
        }),
        created_at: Utc::now(),
    }
}

async fn scan(posture: Posture) -> Vec<Finding> {
    let addr = start_server(posture).await;
    let target = authorized_target(&format!("http://{addr}"));
    // Run through the gate, exactly as the orchestrator does.
    let runner = AuthGatedDastRunner::new(NativeCheckAdapter);
    runner
        .run(&target, "{}")
        .await
        .expect("native engine run should succeed")
}

fn has(findings: &[Finding], needle: &str) -> bool {
    findings.iter().any(|f| f.title.contains(needle))
}

#[tokio::test]
async fn misconfigured_server_yields_the_expected_findings() {
    let findings = scan(Posture::Bad).await;
    assert!(!findings.is_empty(), "the engine found nothing on a deliberately broken server");

    for expected in [
        "Content-Security-Policy Header Absent",
        "Clickjacking Protection Missing",
        "X-Content-Type-Options Header Missing",
        "Referrer-Policy Not Set",
        "Session Cookie Missing HttpOnly",
        "Server Software Version Disclosed",
        "Application Served over Unencrypted HTTP",
        "CORS Policy Reflects Arbitrary Origin",
        "Environment or Configuration File Publicly Readable",
        "Version Control Directory Publicly Readable",
        "Web Server Metafile Discloses Sensitive Paths",
        "Third-Party Script Loaded without Subresource Integrity",
        "External Link Opens a New Tab without noopener",
        "Sensitive Information Disclosed in HTML Comments",
        // Cross-origin isolation and the legacy filter.
        "Cross-Origin-Opener-Policy Not Set",
        "Cross-Origin-Resource-Policy Not Set",
        // Information disclosure.
        "Credential or API Key Exposed in Client-Delivered Content",
        "Internal Hostname or Private IP Address Disclosed",
        "Cloud Instance Metadata Endpoint Referenced in Client Content",
        "Application Framework and Version Disclosed in Page Metadata",
        "Password Field Explicitly Opts Into Stored-Value Autocomplete",
        // Client-side and build-artefact classes.
        "Source Map Publicly Readable",
        "Session or Credential Material Written to Browser Storage",
        "Cross-Window Message Sent to Any Origin",
        "URL-Derived Data Reaches a DOM Injection Sink",
        "State-Changing Form Without an Anti-CSRF Token",
        "Third-Party Frame Embedded Without a Sandbox",
        "Session Cookie Scoped to the Parent Domain",
        "No Vulnerability Disclosure Contact Published",
    ] {
        assert!(
            has(&findings, expected),
            "expected a finding for: {expected} (all: {:?})",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    // The credential must be identified without being republished: a report is
    // emailed and archived, so reprinting the secret discloses it a second time.
    let secret_finding = findings
        .iter()
        .find(|f| f.title.contains("Credential or API Key"))
        .expect("the AWS key must be found");
    let rendered = format!(
        "{} {} {:?}",
        secret_finding.description,
        secret_finding.remediation,
        secret_finding.evidences.iter().map(|e| &e.content).collect::<Vec<_>>()
    );
    assert!(
        !rendered.contains("AKIAIOSFODNN7EXAMPLE"),
        "the finding reprinted the secret it is warning about"
    );

    // Mixed content is only meaningful on an HTTPS page — an http:// subresource
    // on an http:// page is not a downgrade. The test server has no TLS, so the
    // check must correctly stay silent here.
    assert!(
        !has(&findings, "Mixed Content"),
        "mixed content must not be reported for a plaintext page"
    );
}

/// Before discovery existed the engine fetched the site root and nothing else,
/// so a weakness one link away was invisible and the report said the
/// application was clean because its front page was.
#[tokio::test]
async fn a_weakness_only_reachable_by_following_a_link_is_found() {
    let findings = scan(Posture::Bad).await;

    let trace = findings
        .iter()
        .find(|f| f.title.contains("Stack Trace"))
        .unwrap_or_else(|| {
            panic!(
                "the linked page's traceback was not found — discovery did not run (all: {:?})",
                findings.iter().map(|f| &f.title).collect::<Vec<_>>()
            )
        });

    assert!(
        trace.affected_component.contains("/reports/quarterly"),
        "the finding must name the page it was actually observed on, not the root: {}",
        trace.affected_component
    );
}

/// Nothing in the markup links to this route. It exists only in the
/// application's own OpenAPI document — which the engine already fetched to
/// confirm it was readable, and until now never read.
#[tokio::test]
async fn an_endpoint_declared_only_in_the_api_specification_is_assessed() {
    let findings = scan(Posture::Bad).await;

    let from_spec: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.affected_component.contains("/api/v2/unlinked"))
        .collect();

    assert!(
        !from_spec.is_empty(),
        "the specification-declared route was never assessed (all: {:?})",
        findings.iter().map(|f| &f.affected_component).collect::<Vec<_>>()
    );
}

/// CORS is configured per route. Testing `/` and reporting on the application
/// was the wrong inference from the right observation.
#[tokio::test]
async fn cors_is_assessed_per_endpoint_rather_than_only_at_the_root() {
    let findings = scan(Posture::Bad).await;

    let cors: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.title.contains("CORS"))
        .collect();
    assert!(!cors.is_empty(), "no CORS finding at all");

    assert!(
        cors.iter().any(|f| f.affected_component.contains("/api/v2/unlinked")),
        "the permissive policy on the API route was missed; only these were checked: {:?}",
        cors.iter().map(|f| &f.affected_component).collect::<Vec<_>>()
    );
}

/// A source map has no fixed path — it is only discoverable from the script
/// that references it. Finding this one proves the engine read the bundle and
/// followed its `sourceMappingURL`, rather than guessing at a well-known path.
#[tokio::test]
async fn a_source_map_is_found_by_following_the_bundle_that_references_it() {
    let findings = scan(Posture::Bad).await;

    let map = findings
        .iter()
        .find(|f| f.title.contains("Source Map Publicly Readable"))
        .unwrap_or_else(|| {
            panic!(
                "the source map was not found (all: {:?})",
                findings.iter().map(|f| &f.title).collect::<Vec<_>>()
            )
        });

    assert!(map.affected_component.ends_with("app.js.map"), "{}", map.affected_component);
    assert!(
        map.description.contains("original source file"),
        "the finding should say how much source it exposes: {}",
        map.description
    );
}

/// A configuration issue present on every page is one decision made once. If
/// the crawl turned it into one finding per page, the severity counts would
/// describe the crawl rather than the application.
#[tokio::test]
async fn a_site_wide_misconfiguration_is_reported_once_with_its_instances() {
    let findings = scan(Posture::Bad).await;

    let csp: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.title.contains("Content-Security-Policy Header Absent"))
        .collect();

    assert_eq!(
        csp.len(),
        1,
        "a missing header across several pages must collapse to one finding, got {}",
        csp.len()
    );

    // And it must be attributed to the origin, so its identity — and therefore
    // any exception recorded against it — does not depend on crawl order.
    assert!(
        !csp[0].affected_component.contains("/reports/"),
        "a deployment-wide finding must not be pinned to whichever page was crawled first: {}",
        csp[0].affected_component
    );
}

#[tokio::test]
async fn hardened_server_yields_no_configuration_findings() {
    let findings = scan(Posture::Good).await;

    // The plaintext-HTTP finding is legitimate here: the test server has no TLS.
    // Everything else must be clean.
    for unexpected in [
        "Content-Security-Policy Header Absent",
        "Clickjacking Protection Missing",
        "X-Content-Type-Options Header Missing",
        "Referrer-Policy Not Set",
        "Permissions-Policy Header Not Set",
        "Session Cookie Missing HttpOnly",
        "Session Cookie Missing or Weak SameSite",
        "Environment or Configuration File Publicly Readable",
        "Version Control Directory Publicly Readable",
        "CORS Policy",
        "Directory Listing Enabled",
        "Server Software Version Disclosed",
        // The new checks must be as quiet on a good server as the old ones.
        "Cross-Origin-Opener-Policy Not Set",
        "Cross-Origin-Resource-Policy Not Set",
        "Legacy X-XSS-Protection Filter Enabled",
        "Credential or API Key Exposed",
        "Private Key Material Served",
        "Internal Hostname or Private IP Address Disclosed",
        "Cloud Instance Metadata Endpoint Referenced",
        "Application Framework and Version Disclosed",
        // Regression cover for the false positives that were fixed: a bundler
        // path is not a stack trace, an unversioned generator is not a version
        // disclosure, rel=noreferrer is protection, a default password field is
        // not a weakness, and `img-src data:` is not a script source.
        "Stack Trace or Debug Output",
        "External Link Opens a New Tab without noopener",
        "Password Field Explicitly Opts Into",
        "Weak Content-Security-Policy",
        "Source Map Publicly Readable",
        "JSON Web Token Embedded",
        "Session or Credential Material Written to Browser Storage",
        "Cross-Window Message Sent to Any Origin",
        "Plaintext WebSocket Referenced",
        "URL-Derived Data Reaches a DOM Injection Sink",
        "State-Changing Form Without an Anti-CSRF Token",
        "Third-Party Frame Embedded Without a Sandbox",
        "Session Cookie Scoped to the Parent Domain",
        "No Vulnerability Disclosure Contact Published",
    ] {
        assert!(
            !has(&findings, unexpected),
            "false positive on a correctly configured server: {unexpected} (all: {:?})",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}

#[tokio::test]
async fn every_finding_is_scored_and_fully_mapped() {
    let findings = scan(Posture::Bad).await;

    for f in &findings {
        assert!(f.priority_score > 0.0 || f.severity == Severity::Info,
            "'{}' has no priority score", f.title);
        assert!(!f.priority_rationale.is_empty(), "'{}' has no scoring rationale", f.title);
        assert!(f.cwe_id.is_some(), "'{}' has no CWE", f.title);
        assert!(f.wstg_id.is_some(), "'{}' has no WSTG mapping", f.title);
        assert!(f.owasp_2025.is_some(), "'{}' has no OWASP mapping", f.title);
        assert!(f.cvss4.is_some(), "'{}' has no CVSS data", f.title);
        assert!(!f.remediation.trim().is_empty(), "'{}' has no remediation", f.title);
        assert!(!f.references.is_empty(), "'{}' has no references", f.title);
        assert_eq!(f.source_tools, vec!["Sentinel Native".to_string()]);
    }
}

#[tokio::test]
async fn cookie_values_never_reach_the_evidence_store() {
    let findings = scan(Posture::Bad).await;
    for f in &findings {
        for e in &f.evidences {
            assert!(
                !e.content.contains("abc123def456"),
                "the session cookie value leaked into evidence for '{}'",
                f.title
            );
        }
    }
}

#[tokio::test]
async fn findings_feed_the_coverage_matrix() {
    use sentinel_core::checklist::{ChecklistEngine, CheckStatus};

    let findings = scan(Posture::Bad).await;
    let coverage = ChecklistEngine::assess(&["Sentinel Native".to_string()], &findings);

    // The CSP check must be marked as having found issues, not as passed.
    let csp = coverage.results.iter().find(|r| r.id == "WSTG-CONF-12").unwrap();
    assert_eq!(csp.status, CheckStatus::IssuesFound);

    // Checks needing an engine that never ran must not be claimed as passed.
    let sqli = coverage.results.iter().find(|r| r.id == "WSTG-INPV-05").unwrap();
    assert_eq!(sqli.status, CheckStatus::NotTested);
    assert!(sqli.engines_missing.contains(&"Semgrep".to_string()));

    assert!(coverage.automated_coverage_pct > 0.0);
    assert!(coverage.automated_coverage_pct < 100.0, "one engine cannot cover everything");
}

#[tokio::test]
async fn both_reports_render_from_a_real_scan() {
    use sentinel_core::checklist::ChecklistEngine;
    use sentinel_core::reporting::{ReportContext, ReportEngine};

    let findings = scan(Posture::Bad).await;
    let coverage = ChecklistEngine::assess(&["Sentinel Native".to_string()], &findings);

    let mut ctx = ReportContext::new("Acme Corp", "Local test target", "http://127.0.0.1");
    ctx.engines_executed = vec!["Sentinel Native".into()];

    let client = ReportEngine::client_report(&ctx, &findings, Some(&coverage));
    let developer = ReportEngine::developer_report(&ctx, &findings, Some(&coverage));

    // Both must be complete, self-contained, script-free documents.
    for (name, doc) in [("client", &client), ("developer", &developer)] {
        assert!(doc.starts_with("<!DOCTYPE html>"), "{name} report is malformed");
        assert!(doc.trim_end().ends_with("</html>"), "{name} report is truncated");
        assert!(!doc.contains("<script"), "{name} report contains script");
        assert!(doc.len() > 10_000, "{name} report is suspiciously short");
    }

    // Audience separation.
    assert!(!client.contains("CVSS:4.0/"), "client report leaked a CVSS vector");
    assert!(developer.contains("CVSS:4.0/"), "developer report is missing CVSS vectors");
    assert!(client.contains("Every Check We Performed"));
    assert!(developer.contains("How to fix"));

    // Neither may leak the session cookie value picked up during the scan.
    assert!(!client.contains("abc123def456"));
    assert!(!developer.contains("abc123def456"));
}

/// Writes real report samples to disk for manual inspection.
/// Enabled only when SENTINEL_SAMPLE_DIR is set, so normal runs stay hermetic.
#[tokio::test]
async fn write_report_samples_when_requested() {
    let Ok(dir) = std::env::var("SENTINEL_SAMPLE_DIR") else { return };

    use sentinel_core::checklist::ChecklistEngine;
    use sentinel_core::reporting::{ReportContext, ReportEngine};

    let findings = scan(Posture::Bad).await;
    let coverage = ChecklistEngine::assess(
        &["Sentinel Native".to_string(), "Semgrep".to_string(), "Trivy".to_string()],
        &findings,
    );

    let mut ctx = ReportContext::new("Northwind Retail Ltd", "Customer Portal", "https://portal.northwind.test");
    ctx.analyst = "Kavy Vachhani".into();
    ctx.engines_executed = vec!["Sentinel Native".into(), "Semgrep".into(), "Trivy".into()];
    ctx.allowed_domains = vec!["portal.northwind.test".into()];
    ctx.out_of_scope_paths = vec!["/admin/shutdown".into()];
    ctx.roe_hash = Some("9f2c4a1e8b7d3f6a5c0e2b8d4f1a7c3e9b6d2f8a4c1e7b3d5f9a2c6e8b4d1f7a".into());

    std::fs::write(format!("{dir}/client-report.html"),
        ReportEngine::client_report(&ctx, &findings, Some(&coverage))).unwrap();
    std::fs::write(format!("{dir}/developer-report.html"),
        ReportEngine::developer_report(&ctx, &findings, Some(&coverage))).unwrap();
    std::fs::write(format!("{dir}/developer-report.md"),
        ReportEngine::developer_markdown(&ctx, &findings)).unwrap();
    std::fs::write(format!("{dir}/findings.sarif"),
        ReportEngine::generate_sarif_json(&findings)).unwrap();

    println!("wrote {} findings to {dir}", findings.len());
}
