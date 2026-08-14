//! Renders both deliverables from a representative finding set, so the layout,
//! the branding and the print/PDF formatting can be inspected as a real
//! document rather than asserted about in a unit test.
//!
//! Run with:  cargo run -p sentinel-core --example render_sample_reports -- <out_dir>

use chrono::{Duration, Utc};
use sentinel_core::checklist::ChecklistEngine;
use sentinel_core::models::finding::{
    AITriage, CVSS4Data, EPSSData, Evidence, Finding, FindingStatus, Severity,
};
use sentinel_core::reporting::{ReportContext, ReportEngine};
use std::path::PathBuf;
use uuid::Uuid;

/// A 2x1 PNG, enough to prove the logo pipeline embeds and renders an image.
const LOGO: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAIAAAABCAYAAAD0In+KAAAAFElEQVR4nGP8z8Dwn4GBgYEJRIAAIm0DwZbvXWEAAAAASUVORK5CYII=";

fn finding(
    title: &str,
    severity: Severity,
    cvss: f64,
    cwe: &str,
    owasp: &str,
    wstg: &str,
    component: &str,
    kev: bool,
    epss: f64,
) -> Finding {
    let label = match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "None",
    };
    Finding {
        id: Uuid::new_v4(),
        scan_id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        title: title.into(),
        description: format!(
            "{title} was observed on the assessed application. This entry exercises the \
             full report template: a multi-sentence description that wraps across lines, \
             so column widths, justification and page breaks can all be judged from the \
             rendered PDF rather than guessed at."
        ),
        severity,
        cvss4: Some(CVSS4Data {
            vector_string: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N".into(),
            base_score: cvss,
            severity_label: label.into(),
        }),
        epss: Some(EPSSData { score: epss, percentile: epss * 100.0 }),
        kev_listed: kev,
        asset_exposure_factor: 1.2,
        reachability_score: 1.1,
        priority_score: cvss,
        cwe_id: Some(cwe.into()),
        owasp_2025: Some(owasp.into()),
        wstg_id: Some(wstg.into()),
        api_top10: None,
        affected_component: component.into(),
        evidences: vec![Evidence {
            evidence_type: "http_response".into(),
            title: "Response headers".into(),
            content: "HTTP/1.1 200 OK\nServer: nginx/1.24.0\nContent-Type: text/html\n\
                      Set-Cookie: session=<redacted>; Path=/\n\
                      X-Powered-By: Express".into(),
            hash: "sha256:6f1e3d…".into(),
        }],
        repro_steps: vec![
            format!("Send GET {component} with no authentication headers."),
            "Observe the response headers listed in the evidence block.".into(),
            "Confirm the control is absent on every response, not just this route.".into(),
        ],
        remediation: "Set the header at the edge (reverse proxy or CDN) so every response \
                      carries it, then redeploy and re-run the assessment to confirm."
            .into(),
        references: vec![
            "https://owasp.org/www-project-secure-headers/".into(),
            format!("https://cwe.mitre.org/data/definitions/{}.html", cwe.trim_start_matches("CWE-")),
        ],
        status: FindingStatus::Open,
        source_tools: vec!["Sentinel Native".into()],
        ai_triage: Some(AITriage {
            is_false_positive_confidence: 0.04,
            cluster_id: None,
            triage_notes: Some("Confirmed on three separate routes.".into()),
        }),
        priority_rationale: format!(
            "CVSS4 {cvss} × EPSS {:.0}% {}× exposure 1.2 = priority {cvss}",
            epss * 100.0,
            if kev { "× KEV " } else { "" }
        ),
        created_at: Utc::now(),
    }
}

fn main() {
    let out: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&out).expect("output directory");

    let findings = vec![
        finding("SQL injection in the customer search parameter", Severity::Critical, 9.3,
                "CWE-89", "A03:2025-Injection", "WSTG-INPV-05",
                "https://dev.example.com/api/customers?q=", true, 0.94),
        finding("Session cookie missing the Secure and HttpOnly flags", Severity::High, 7.5,
                "CWE-614", "A05:2025-Security Misconfiguration", "WSTG-SESS-02",
                "https://dev.example.com/login", false, 0.21),
        finding("Reflected cross-site scripting in the error page", Severity::High, 7.1,
                "CWE-79", "A03:2025-Injection", "WSTG-INPV-01",
                "https://dev.example.com/error?msg=", false, 0.44),
        finding("Content-Security-Policy header not set", Severity::Medium, 5.3,
                "CWE-693", "A05:2025-Security Misconfiguration", "WSTG-CONF-12",
                "https://dev.example.com/", false, 0.07),
        finding("TLS 1.0 and 1.1 still accepted", Severity::Medium, 5.9,
                "CWE-327", "A02:2025-Cryptographic Failures", "WSTG-CRYP-01",
                "dev.example.com:443", false, 0.03),
        finding("Directory listing enabled on the assets path", Severity::Low, 3.7,
                "CWE-548", "A05:2025-Security Misconfiguration", "WSTG-CONF-04",
                "https://dev.example.com/assets/", false, 0.01),
        finding("Server version disclosed in response headers", Severity::Info, 0.0,
                "CWE-200", "A05:2025-Security Misconfiguration", "WSTG-INFO-02",
                "https://dev.example.com/", false, 0.00),
    ];

    let engines = vec!["Sentinel Native".to_string(), "OWASP ZAP".to_string()];
    let coverage = ChecklistEngine::assess(&engines, &findings);

    let mut ctx = ReportContext::new(
        "Industrility Ltd",
        "Customer Portal (dev)",
        "https://dev.example.com",
    );
    ctx.logo_data_uri = Some(LOGO.into());
    ctx.analyst = "K. Vachhani".to_string();
    ctx.engines_executed = engines;
    ctx.allowed_domains = vec!["dev.example.com".into()];
    ctx.out_of_scope_paths = vec!["/logout".into()];
    ctx.rate_limit_rps = 5;
    ctx.roe_hash = Some("9f2c1a77b4e05d3a8c6e1b0f4d7a2938e5c1b6a0".into());
    ctx.assessment_start = Utc::now() - Duration::days(3);
    ctx.assessment_end = Utc::now();

    let client = ReportEngine::client_report(&ctx, &findings, Some(&coverage));
    let developer = ReportEngine::developer_report(&ctx, &findings, Some(&coverage));

    std::fs::write(out.join("client-report.html"), &client).unwrap();
    std::fs::write(out.join("developer-report.html"), &developer).unwrap();

    println!("findings      : {}", findings.len());
    println!("client   bytes: {}", client.len());
    println!("developer bytes: {}", developer.len());
    println!("logo in client   : {}", client.contains(LOGO));
    println!("logo in developer: {}", developer.contains(LOGO));
    println!("wrote to {}", out.display());
}
