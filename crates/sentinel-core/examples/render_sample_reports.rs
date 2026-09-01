//! Renders both deliverables from a representative finding set, so the layout,
//! the branding and the print/PDF formatting can be inspected as a real
//! document rather than asserted about in a unit test.
//!
//! Run with:  cargo run -p sentinel-core --example render_sample_reports -- <out_dir>

use chrono::{Duration, Utc};
use sentinel_core::checklist::ChecklistEngine;
use sentinel_core::exceptions::{self, ExceptionKind};
use sentinel_core::models::finding::{
    AITriage, CVSS4Data, EPSSData, Evidence, Finding, FindingStatus, Severity, FindingKind};
use sentinel_core::reporting::{ReportContext, ReportEngine};
use std::path::PathBuf;
use uuid::Uuid;

/// A 2x1 PNG, enough to prove the logo pipeline embeds and renders an image.
const LOGO: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAIAAAABCAYAAAD0In+KAAAAFElEQVR4nGP8z8Dwn4GBgYEJRIAAIm0DwZbvXWEAAAAASUVORK5CYII=";

/// The nine fields that distinguish one sample finding from the next.
///
/// Passed as a struct rather than nine positional arguments: at that width a
/// call site is unreadable and a transposed `&str` pair compiles silently.
struct Sample<'a> {
    title: &'a str,
    severity: Severity,
    cvss: f64,
    cwe: &'a str,
    owasp: &'a str,
    wstg: &'a str,
    component: &'a str,
    kev: bool,
    epss: f64,
}

fn finding(sample: Sample<'_>) -> Finding {
    let Sample { title, severity, cvss, cwe, owasp, wstg, component, kev, epss } = sample;
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
        kind: FindingKind::default(),
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
        finding(Sample {
            title: "SQL injection in the customer search parameter",
            severity: Severity::Critical,
            cvss: 9.3,
            cwe: "CWE-89",
            owasp: "A03:2025-Injection",
            wstg: "WSTG-INPV-05",
            component: "https://dev.example.com/api/customers?q=",
            kev: true,
            epss: 0.94,
        }),
        finding(Sample {
            title: "Session cookie missing the Secure and HttpOnly flags",
            severity: Severity::High,
            cvss: 7.5,
            cwe: "CWE-614",
            owasp: "A05:2025-Security Misconfiguration",
            wstg: "WSTG-SESS-02",
            component: "https://dev.example.com/login",
            kev: false,
            epss: 0.21,
        }),
        finding(Sample {
            title: "Reflected cross-site scripting in the error page",
            severity: Severity::High,
            cvss: 7.1,
            cwe: "CWE-79",
            owasp: "A03:2025-Injection",
            wstg: "WSTG-INPV-01",
            component: "https://dev.example.com/error?msg=",
            kev: false,
            epss: 0.44,
        }),
        finding(Sample {
            title: "Content-Security-Policy header not set",
            severity: Severity::Medium,
            cvss: 5.3,
            cwe: "CWE-693",
            owasp: "A05:2025-Security Misconfiguration",
            wstg: "WSTG-CONF-12",
            component: "https://dev.example.com/",
            kev: false,
            epss: 0.07,
        }),
        finding(Sample {
            title: "TLS 1.0 and 1.1 still accepted",
            severity: Severity::Medium,
            cvss: 5.9,
            cwe: "CWE-327",
            owasp: "A02:2025-Cryptographic Failures",
            wstg: "WSTG-CRYP-01",
            component: "dev.example.com:443",
            kev: false,
            epss: 0.03,
        }),
        finding(Sample {
            title: "Directory listing enabled on the assets path",
            severity: Severity::Low,
            cvss: 3.7,
            cwe: "CWE-548",
            owasp: "A05:2025-Security Misconfiguration",
            wstg: "WSTG-CONF-04",
            component: "https://dev.example.com/assets/",
            kev: false,
            epss: 0.01,
        }),
        finding(Sample {
            title: "Server version disclosed in response headers",
            severity: Severity::Info,
            cvss: 0.0,
            cwe: "CWE-200",
            owasp: "A05:2025-Security Misconfiguration",
            wstg: "WSTG-INFO-02",
            component: "https://dev.example.com/",
            kev: false,
            epss: 0.00,
        }),
    ];

    // Two of the findings carry a decision, so the sample exercises the paths a
    // real engagement will: an accepted risk that must be disclosed in its own
    // register rather than counted as open exposure, and a dismissal that must
    // be accounted for in the assurance section without the finding itself
    // appearing anywhere.
    let mut findings = findings;
    let accepted_index = findings
        .iter()
        .position(|f| f.title.starts_with("Directory listing"))
        .expect("the sample set contains the directory-listing finding");
    findings[accepted_index].status = FindingStatus::AcceptedRisk;

    let accepted = exceptions::from_triage(
        &findings[accepted_index],
        &FindingStatus::AcceptedRisk,
        "Static build artefacts only; the directory holds no customer data. Scheduled to move \
         behind the CDN in the Q3 platform migration.",
        "R. Mehta, Head of Engineering",
        Some(Utc::now() + Duration::days(75)),
        "EXC-2026-014".into(),
    )
    .expect("an accepted risk creates an exception");

    let dismissed_source = finding(Sample {
        title: "Hardcoded credential in build fixture",
        severity: Severity::High,
        cvss: 7.8,
        cwe: "CWE-798",
        owasp: "A04:2025-Cryptographic Failures",
        wstg: "WSTG-INFO-05",
        component: "tests/fixtures/seed_users.json",
        kev: false,
        epss: 0.02,
    });
    let dismissed = exceptions::from_triage(
        &dismissed_source,
        &FindingStatus::FalsePositive,
        "Test fixture, never bundled into a release artefact. Verified against the build manifest.",
        "A. Iyer, Security Analyst",
        None,
        "EXC-2026-011".into(),
    )
    .expect("a dismissal creates an exception");
    debug_assert_eq!(dismissed.kind, ExceptionKind::FalsePositive);

    // What the scan reached. Emitted by the native engine on every run as scan
    // information rather than as a finding, so it never touches the counts —
    // the sample carries one so the coverage narrative is exercised here too.
    let mut surface = finding(Sample {
        title: "Assessment Surface — What This Scan Reached",
        severity: Severity::Info,
        cvss: 0.0,
        cwe: "CWE-1059",
        owasp: "A02:2025-Security Misconfiguration",
        wstg: "WSTG-INFO-01",
        component: "https://dev.example.com",
        kev: false,
        epss: 0.0,
    });
    surface.kind = FindingKind::ScanInformation;
    surface.description = "87 page(s) were fetched and assessed; the page limit was reached, so \
some in-scope pages were not assessed. 12 in-scope URL(s) were queued but not reached."
        .to_string();
    surface.evidences = vec![
        Evidence {
            evidence_type: "assessment_surface".into(),
            title: "Pages assessed (87)".into(),
            content: "https://dev.example.com/\nhttps://dev.example.com/account\n\
                      https://dev.example.com/reports\nhttps://dev.example.com/settings"
                .into(),
            hash: String::new(),
        },
        Evidence {
            evidence_type: "assessment_surface".into(),
            title: "In-scope URLs not reached (12)".into(),
            content: "https://dev.example.com/archive/2019\nhttps://dev.example.com/archive/2020".into(),
            hash: String::new(),
        },
        Evidence {
            evidence_type: "assessment_surface".into(),
            title: "Third-party origins referenced (3)".into(),
            content: "cdn.example.net\nanalytics.example.net\nfonts.example.net\n\n\
                      These are outside the authorised scope and were not tested. Each one is code \
                      or content the application trusts at run time, so each is a supply-chain \
                      dependency worth reviewing."
                .into(),
            hash: String::new(),
        },
    ];
    findings.push(surface);

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
    ctx.reviewed_by = Some("D. Shah, Principal Consultant".into());
    ctx.classification = "Commercial in Confidence".into();
    ctx.revision = "1.0".into();
    ctx.exceptions = vec![accepted, dismissed];

    // A re-test rather than a first assessment, so the comparison section is
    // exercised here too. Without this the samples show a document no repeat
    // engagement produces, which is the wrong thing to check layout against.
    ctx.comparison = Some(sentinel_core::reporting::delta::ScanDelta {
        previous_reference: "SV-20260715-0930".into(),
        previous_completed_at: Utc::now() - Duration::days(45),
        newly_found: vec![finding(Sample {
            title: "Reflected cross-site scripting in the error page",
            severity: Severity::High,
            cvss: 7.1,
            cwe: "CWE-79",
            owasp: "A03:2025-Injection",
            wstg: "WSTG-INPV-01",
            component: "https://dev.example.com/error?msg=",
            kev: false,
            epss: 0.44,
        })],
        resolved: vec![
            finding(Sample {
                title: "Session cookie missing the Secure and HttpOnly flags",
                severity: Severity::High,
                cvss: 7.5,
                cwe: "CWE-614",
                owasp: "A05:2025-Security Misconfiguration",
                wstg: "WSTG-SESS-02",
                component: "https://dev.example.com/login",
                kev: false,
                epss: 0.21,
            }),
            finding(Sample {
                title: "Directory listing enabled on the uploads path",
                severity: Severity::Low,
                cvss: 3.7,
                cwe: "CWE-548",
                owasp: "A05:2025-Security Misconfiguration",
                wstg: "WSTG-CONF-04",
                component: "https://dev.example.com/uploads/",
                kev: false,
                epss: 0.01,
            }),
        ],
        still_open: vec![finding(Sample {
            title: "Content-Security-Policy header not set",
            severity: Severity::Medium,
            cvss: 5.3,
            cwe: "CWE-693",
            owasp: "A05:2025-Security Misconfiguration",
            wstg: "WSTG-CONF-12",
            component: "https://dev.example.com/",
            kev: false,
            epss: 0.07,
        })],
    });

    let client = ReportEngine::client_report(&ctx, &findings, Some(&coverage));
    let developer = ReportEngine::developer_report(&ctx, &findings, Some(&coverage));

    std::fs::write(out.join("client-report.html"), &client).unwrap();
    std::fs::write(out.join("developer-report.html"), &developer).unwrap();

    println!("findings      : {}", findings.len());
    println!("exceptions    : {}", ctx.exceptions.len());
    println!("comparison    : {}", ctx.comparison.is_some());
    println!("client   bytes: {}", client.len());
    println!("developer bytes: {}", developer.len());
    println!("logo in client   : {}", client.contains(LOGO));
    println!("logo in developer: {}", developer.contains(LOGO));
    println!("wrote to {}", out.display());
}
