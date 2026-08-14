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
        "/robots.txt" => http(
            "200 OK",
            &["Content-Type: text/plain".to_string()],
            "User-agent: *\nDisallow: /internal-admin/\nDisallow: /backups/\n",
        ),
        _ => {
            let mut headers = vec![
                "Content-Type: text/html".to_string(),
                "Server: nginx/1.18.0".to_string(),
                "X-Powered-By: PHP/7.4.3".to_string(),
                // Session cookie with none of the protective attributes.
                "Set-Cookie: JSESSIONID=abc123def456".to_string(),
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
<script src="http://cdn.example.test/lib.js"></script>
</head><body>
<!-- TODO: remove hardcoded password admin123 before launch -->
<a href="https://external.example.test" target="_blank">External</a>
<form action="/login"><input type="password" name="p"></form>
</body></html>"#,
            )
        }
    }
}

fn good_response(path: &str) -> String {
    // Everything that is not the root is genuinely absent.
    if path != "/" {
        return http("404 Not Found", &["Content-Type: text/plain".to_string()], "not found");
    }
    http(
        "200 OK",
        &[
            "Content-Type: text/html".to_string(),
            "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'".to_string(),
            "X-Content-Type-Options: nosniff".to_string(),
            "X-Frame-Options: DENY".to_string(),
            "Referrer-Policy: strict-origin-when-cross-origin".to_string(),
            "Permissions-Policy: camera=(), microphone=(), geolocation=()".to_string(),
            "Cache-Control: no-store".to_string(),
            "Set-Cookie: JSESSIONID=abc; HttpOnly; SameSite=Lax; Path=/".to_string(),
        ],
        "<!DOCTYPE html><html><head><title>Hardened</title></head><body>OK</body></html>",
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
    ] {
        assert!(has(&findings, expected), "expected a finding for: {expected}");
    }

    // Mixed content is only meaningful on an HTTPS page — an http:// subresource
    // on an http:// page is not a downgrade. The test server has no TLS, so the
    // check must correctly stay silent here.
    assert!(
        !has(&findings, "Mixed Content"),
        "mixed content must not be reported for a plaintext page"
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
