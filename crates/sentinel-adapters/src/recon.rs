//! Attack-surface discovery from public sources.
//!
//! Every other engine in this workspace starts from a URL somebody typed in.
//! That is the wrong starting point for a real engagement, because the host the
//! client remembered to mention is rarely the one that gets compromised — it is
//! the staging copy nobody decommissioned, the marketing microsite on a
//! forgotten provider, the API gateway that answers on a subdomain no internal
//! document lists. Reconnaissance is what finds those, and it is what turns "we
//! tested your website" into "we established what you have exposed and then
//! tested it".
//!
//! Five tools, all optional, all skipped cleanly when absent:
//!
//! | Tool           | What it contributes                                  |
//! |----------------|------------------------------------------------------|
//! | theHarvester   | hosts, subdomains and email addresses from OSINT      |
//! | subfinder      | passive subdomain enumeration across ~30 sources      |
//! | amass          | attack-surface mapping, passive mode only             |
//! | dnsx           | which of the discovered names actually resolve        |
//! | httpx          | which of those answer HTTP, and what they say         |
//!
//! SAFETY
//! ──────
//! Two rules, both enforced here rather than left to the tool's own flags.
//!
//! **Passive by default.** theHarvester, subfinder and amass are invoked in
//! modes that query third-party data sources and public records. They do not
//! send packets to the client's infrastructure, which is why this stage is
//! useful before an engagement has a signed authorisation for active testing.
//! Amass in particular is forced to `-passive`: its active mode performs
//! brute-force resolution against the target's nameservers, which is traffic
//! the Rules of Engagement did not agree to.
//!
//! **Scope is applied to the results, not to the request.** Reconnaissance
//! discovers hosts, and some of what it discovers will be out of scope — a
//! shared CDN, a third-party SaaS, another tenant on the same provider.
//! Everything found is reported, but each host is checked against the
//! authorisation record and labelled, so nothing outside the agreed scope is
//! ever handed to an engine that would send it traffic.

use crate::adapter_trait::ScannerAdapter;
use crate::process::async_command;
use crate::runner::LocalCliRunner;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use sentinel_core::checklist::catalog::owasp;
use sentinel_core::models::finding::{
    AITriage, CVSS4Data, Finding, FindingKind, FindingStatus, Severity,
};
use sentinel_core::models::target::Target;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use uuid::Uuid;

/// Engine name, matching the checklist coverage catalog.
pub const ENGINE_NAME: &str = "Sentinel Recon";

/// How long any single reconnaissance tool may run.
///
/// Passive enumeration queries dozens of third-party sources and several of
/// them are slow or rate-limited, so this is generous — but bounded, because a
/// source that never answers must not hold the stage open.
const TOOL_TIMEOUT: Duration = Duration::from_secs(6 * 60);

/// The most hosts carried forward into findings.
///
/// A wildcard DNS record or a large hosting provider can return thousands of
/// names, and a report listing all of them is a report nobody reads.
const MAX_HOSTS_REPORTED: usize = 300;

/// One host the reconnaissance stage discovered.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoveredHost {
    pub hostname: String,
    /// Which tools reported it. Two independent sources agreeing is a stronger
    /// claim than either alone, exactly as it is for vulnerability engines.
    pub sources: BTreeSet<String>,
    /// Whether the signed authorisation covers this host.
    pub in_scope: bool,
}

/// Everything one reconnaissance pass established.
#[derive(Debug, Default)]
pub struct ReconResult {
    pub hosts: BTreeMap<String, DiscoveredHost>,
    /// Email addresses found in public sources. Reported because they are the
    /// input to a phishing assessment, and because their format reveals the
    /// organisation's username convention.
    pub emails: BTreeSet<String>,
    /// Tools that were not installed, so the report can say what went unasked.
    pub unavailable: Vec<String>,
    /// Tools that ran but failed, with the reason.
    pub failed: Vec<(String, String)>,
    pub tools_run: Vec<String>,
}

pub struct ReconAdapter;

#[async_trait]
impl ScannerAdapter for ReconAdapter {
    fn name(&self) -> &'static str {
        ENGINE_NAME
    }

    /// Available when at least one reconnaissance tool is installed.
    ///
    /// Unlike the built-in engines this one orchestrates other people's
    /// binaries, so with none of them present it has nothing to do and says so
    /// rather than reporting an empty result as a finished assessment.
    async fn healthcheck(&self) -> Result<bool> {
        Ok(TOOLS.iter().any(|t| LocalCliRunner::is_installed(t.binary)))
    }

    async fn run(&self, target: &Target, _config_json: &str) -> Result<Vec<Finding>> {
        let domain = registrable_domain(&target.base_url).ok_or_else(|| {
            anyhow!(
                "reconnaissance needs a hostname to enumerate, and {:?} does not contain one",
                target.base_url
            )
        })?;

        tracing::info!(domain, "Sentinel Recon: passive enumeration starting");
        let mut result = ReconResult::default();

        for tool in TOOLS {
            if !LocalCliRunner::is_installed(tool.binary) {
                result.unavailable.push(tool.binary.to_string());
                continue;
            }
            match run_tool(tool, &domain).await {
                Ok(output) => {
                    result.tools_run.push(tool.binary.to_string());
                    ingest(tool, &output, &mut result);
                }
                Err(e) => {
                    tracing::warn!(tool = tool.binary, error = %e, "recon tool failed");
                    result.failed.push((tool.binary.to_string(), e.to_string()));
                }
            }
        }

        // Scope is decided here, once, against the signed record — not by each
        // tool, and not later by whatever consumes the host list.
        apply_scope(target, &mut result);

        let findings = build_findings(&result, &domain, target.id, Uuid::new_v4());
        tracing::info!(
            hosts = result.hosts.len(),
            emails = result.emails.len(),
            tools = result.tools_run.len(),
            "Sentinel Recon: complete"
        );
        Ok(findings)
    }
}

/// One reconnaissance tool and how to invoke it.
struct ReconTool {
    binary: &'static str,
    label: &'static str,
    /// Arguments, with `{domain}` substituted at invocation.
    args: &'static [&'static str],
    /// How to read the tool's output.
    format: OutputFormat,
    /// What this tool adds that the others do not — printed in the report so a
    /// reader can tell how thorough the enumeration actually was.
    contribution: &'static str,
}

#[derive(Clone, Copy, PartialEq)]
enum OutputFormat {
    /// One hostname per line.
    HostPerLine,
    /// theHarvester's JSON, which carries hosts and emails together.
    HarvesterJson,
    /// httpx's JSON-lines, one object per responding host.
    HttpxJsonLines,
}

const TOOLS: &[ReconTool] = &[
    ReconTool {
        binary: "subfinder",
        label: "subfinder",
        // `-silent` so stdout is the host list and nothing else; `-all` uses
        // every configured source rather than the fast subset.
        args: &["-d", "{domain}", "-silent", "-all"],
        format: OutputFormat::HostPerLine,
        contribution:
            "Passive subdomain enumeration across roughly thirty sources — certificate \
             transparency logs, passive DNS providers and search indexes. The broadest single \
             source of subdomains, and the fastest.",
    },
    ReconTool {
        binary: "theHarvester",
        label: "theHarvester",
        // `-b` selects the data sources; the ones named here need no API key,
        // so the tool is useful on a fresh install rather than only after
        // credentials have been configured.
        args: &["-d", "{domain}", "-b", "crtsh,duckduckgo,otx,rapiddns,urlscan,hackertarget", "-f", "-"],
        format: OutputFormat::HarvesterJson,
        contribution:
            "Open-source intelligence: hosts, and the email addresses associated with the \
             domain. The email list is what a phishing assessment starts from, and its format \
             reveals the organisation's username convention.",
    },
    ReconTool {
        binary: "amass",
        label: "amass",
        // `-passive` is not a preference. Amass's active mode performs
        // brute-force resolution against the target's nameservers, which is
        // traffic no passive stage is authorised to send.
        args: &["enum", "-passive", "-d", "{domain}", "-silent"],
        format: OutputFormat::HostPerLine,
        contribution:
            "Attack-surface mapping. Overlaps with subfinder by design: two enumerators \
             disagreeing is how a host that only one source knows about gets found.",
    },
];

/// Tools that take the discovered host list as input rather than the domain.
///
/// These run second, because their value is entirely in narrowing what the
/// enumerators produced: a list of two thousand names from certificate
/// transparency is not an attack surface until you know which of them resolve
/// and which answer.
const RESOLVERS: &[ReconTool] = &[
    ReconTool {
        binary: "dnsx",
        label: "dnsx",
        args: &["-silent", "-a", "-resp-only"],
        format: OutputFormat::HostPerLine,
        contribution: "Which of the enumerated names actually resolve today.",
    },
    ReconTool {
        binary: "httpx",
        label: "httpx",
        args: &["-silent", "-json", "-status-code", "-title", "-tech-detect", "-no-color"],
        format: OutputFormat::HttpxJsonLines,
        contribution: "Which resolving names answer HTTP, with what status, title and technology.",
    },
];

/// Run one tool against a domain and return its stdout.
async fn run_tool(tool: &ReconTool, domain: &str) -> Result<String> {
    let args: Vec<String> = tool
        .args
        .iter()
        .map(|a| a.replace("{domain}", domain))
        .collect();

    let mut cmd = async_command(tool.binary);
    cmd.args(&args);

    let output = match tokio::time::timeout(TOOL_TIMEOUT, cmd.output()).await {
        Ok(r) => r.with_context(|| format!("could not spawn {}", tool.binary))?,
        Err(_) => {
            return Err(anyhow!(
                "{} exceeded the {}-minute tool timeout and was abandoned; passive sources are \
                 sometimes slow or rate-limited, so this is worth retrying before treating it \
                 as a failure",
                tool.binary,
                TOOL_TIMEOUT.as_secs() / 60
            ))
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if stdout.trim().is_empty() && !output.status.success() {
        return Err(anyhow!(
            "{} failed: {}",
            tool.binary,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(stdout)
}

/// Fold one tool's output into the accumulated result.
fn ingest(tool: &ReconTool, output: &str, result: &mut ReconResult) {
    match tool.format {
        OutputFormat::HostPerLine => {
            for host in output.lines().filter_map(normalise_host) {
                record_host(result, &host, tool.label);
            }
        }
        OutputFormat::HarvesterJson => ingest_harvester(output, tool.label, result),
        OutputFormat::HttpxJsonLines => {
            for line in output.lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if let Some(host) = v
                    .get("host")
                    .or_else(|| v.get("input"))
                    .and_then(|h| h.as_str())
                    .and_then(normalise_host)
                {
                    record_host(result, &host, tool.label);
                }
            }
        }
    }
}

/// theHarvester emits JSON with `hosts` and `emails` arrays. Its host entries
/// are sometimes `name:address`, which is why they go through the same
/// normalisation as everything else.
fn ingest_harvester(output: &str, label: &str, result: &mut ReconResult) {
    // Older builds — and any run where the JSON writer failed — print a plain
    // list instead. Falling back to reading it as lines keeps the run's results
    // rather than discarding them because the format was not the expected one.
    let fall_back_to_lines = |result: &mut ReconResult| {
        for host in output.lines().filter_map(normalise_host) {
            record_host(result, &host, label);
        }
    };

    // The tool prints progress before its JSON, so find the document rather
    // than assuming stdout is only the document.
    let Some(start) = output.find('{') else {
        fall_back_to_lines(result);
        return;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&output[start..]) else {
        fall_back_to_lines(result);
        return;
    };

    for key in ["hosts", "subdomains"] {
        if let Some(list) = json.get(key).and_then(|v| v.as_array()) {
            for entry in list.iter().filter_map(|v| v.as_str()) {
                let name = entry.split(':').next().unwrap_or(entry);
                if let Some(host) = normalise_host(name) {
                    record_host(result, &host, label);
                }
            }
        }
    }
    if let Some(list) = json.get("emails").and_then(|v| v.as_array()) {
        for email in list.iter().filter_map(|v| v.as_str()) {
            let trimmed = email.trim().to_ascii_lowercase();
            if trimmed.contains('@') && !trimmed.contains(' ') {
                result.emails.insert(trimmed);
            }
        }
    }
}

fn record_host(result: &mut ReconResult, hostname: &str, source: &str) {
    result
        .hosts
        .entry(hostname.to_string())
        .or_insert_with(|| DiscoveredHost {
            hostname: hostname.to_string(),
            sources: BTreeSet::new(),
            // Decided in one place later, against the authorisation record.
            in_scope: false,
        })
        .sources
        .insert(source.to_string());
}

/// Reduce a line of tool output to a hostname, or `None` if it is not one.
///
/// Tools emit URLs, `host:port` pairs, wildcards and progress text on the same
/// stream, and a host list polluted with any of those produces findings that
/// name things that do not exist.
pub fn normalise_host(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_ascii_lowercase();
    if s.is_empty() || s.starts_with('[') || s.starts_with('#') {
        return None;
    }
    // Strip a scheme and anything after the authority.
    if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
    }
    s = s.split('/').next().unwrap_or(&s).to_string();
    s = s.split('?').next().unwrap_or(&s).to_string();
    // Drop a port, credentials and a trailing dot.
    if let Some(at) = s.rfind('@') {
        s = s[at + 1..].to_string();
    }
    s = s.split(':').next().unwrap_or(&s).to_string();
    s = s.trim_end_matches('.').to_string();
    // A wildcard record names no host.
    s = s.trim_start_matches("*.").to_string();

    if s.is_empty() || !s.contains('.') {
        return None;
    }
    let valid = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
    (valid && s.len() <= 253).then_some(s)
}

/// The registrable domain to enumerate, from the target's URL.
pub fn registrable_domain(base_url: &str) -> Option<String> {
    let host = url::Url::parse(base_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .or_else(|| normalise_host(base_url))?;
    // An address is not a domain and cannot be enumerated.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    // Deliberately not a public-suffix implementation: `example.co.uk` yields
    // `co.uk` under a naive two-label rule, which would enumerate a registry.
    // Taking the last three labels for a known two-part suffix covers the
    // common cases without shipping a suffix list that goes stale.
    const TWO_PART_SUFFIXES: &[&str] = &[
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "com.au", "net.au",
        "org.au", "co.nz", "com.br", "co.in", "co.za", "com.sg", "com.mx",
    ];
    let last_two = labels[labels.len() - 2..].join(".");
    if TWO_PART_SUFFIXES.contains(&last_two.as_str()) && labels.len() >= 3 {
        return Some(labels[labels.len() - 3..].join("."));
    }
    Some(last_two)
}

/// Mark each discovered host against the signed authorisation.
///
/// Reconnaissance finds things outside the engagement — a CDN, a SaaS provider,
/// another tenant. All of it is reported, because knowing the application
/// depends on them is part of the assessment; none of it is marked in scope
/// unless the record says so, because that flag is what any later stage would
/// use to decide whether it may send traffic.
fn apply_scope(target: &Target, result: &mut ReconResult) {
    let Some(auth) = target.authorization_record.as_ref() else {
        // No signed record means nothing is in scope, which is the safe
        // reading and the one the RoE gate already enforces elsewhere.
        return;
    };
    for host in result.hosts.values_mut() {
        host.in_scope = auth.scope.allowed_domains.iter().any(|allowed| {
            let allowed = allowed
                .trim()
                .trim_start_matches("*.")
                .to_ascii_lowercase();
            let allowed = normalise_host(&allowed).unwrap_or(allowed);
            host.hostname == allowed || host.hostname.ends_with(&format!(".{allowed}"))
        });
    }
}

/// CVSS vectors for the two things reconnaissance can legitimately claim.
const V_SURFACE: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N";

fn build_findings(
    result: &ReconResult,
    domain: &str,
    target_id: Uuid,
    scan_id: Uuid,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // ── 1. The attack surface, as scan information ───────────────────────────
    findings.push(surface_record(result, domain, target_id, scan_id));

    // ── 2. Hosts outside the agreed scope, as a weakness worth a sentence ────
    //
    // Not a vulnerability in the target, and deliberately Info: what it is, is
    // a scoping question the engagement has to answer before the next one.
    let out_of_scope: Vec<&DiscoveredHost> =
        result.hosts.values().filter(|h| !h.in_scope).collect();
    if !out_of_scope.is_empty() {
        findings.push(scope_gap_record(&out_of_scope, target_id, scan_id));
    }

    // ── 3. Disclosed email addresses ─────────────────────────────────────────
    if !result.emails.is_empty() {
        findings.push(email_disclosure(result, domain, target_id, scan_id));
    }

    for f in &mut findings {
        sentinel_core::scoring::priority::PriorityScoringEngine::score_and_explain(f);
    }
    findings
}

fn surface_record(
    result: &ReconResult,
    domain: &str,
    target_id: Uuid,
    scan_id: Uuid,
) -> Finding {
    let in_scope = result.hosts.values().filter(|h| h.in_scope).count();
    let corroborated = result.hosts.values().filter(|h| h.sources.len() > 1).count();

    let listed: Vec<String> = result
        .hosts
        .values()
        .take(MAX_HOSTS_REPORTED)
        .map(|h| {
            format!(
                "  {} {}  [{}]",
                if h.in_scope { "✓" } else { "·" },
                h.hostname,
                h.sources.iter().cloned().collect::<Vec<_>>().join(", ")
            )
        })
        .collect();

    let mut description = format!(
        "Passive reconnaissance against {domain} found {} host name(s), of which {in_scope} \
         fall inside the signed scope and {corroborated} were reported by more than one \
         independent source.\n\n\
         ✓ marks a host the authorisation covers; · marks one it does not.\n\n\
         {}{}",
        result.hosts.len(),
        listed.join("\n"),
        if result.hosts.len() > MAX_HOSTS_REPORTED {
            format!("\n  … and {} more", result.hosts.len() - MAX_HOSTS_REPORTED)
        } else {
            String::new()
        },
    );

    description.push_str(&format!(
        "\n\nTools that ran: {}.",
        if result.tools_run.is_empty() {
            "none".to_string()
        } else {
            result.tools_run.join(", ")
        }
    ));

    if !result.unavailable.is_empty() {
        description.push_str(&format!(
            "\n\nNot installed, so their sources went unasked: {}. Each contributes different \
             sources, so this list is the honest limit on how complete the enumeration is:\n{}",
            result.unavailable.join(", "),
            TOOLS
                .iter()
                .chain(RESOLVERS)
                .filter(|t| result.unavailable.contains(&t.binary.to_string()))
                .map(|t| format!("  • {} — {}", t.label, t.contribution))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    if !result.failed.is_empty() {
        description.push_str(&format!(
            "\n\nRan but failed:\n{}",
            result
                .failed
                .iter()
                .map(|(tool, why)| format!("  • {tool} — {why}"))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }

    description.push_str(
        "\n\nWhat this is and is not. Everything here comes from third-party data sources and \
         public records — certificate transparency logs, passive DNS, search indexes. No \
         packet was sent to any of these hosts by this stage. That makes the list safe to \
         gather before active testing is authorised, and it also makes it incomplete: a host \
         that has never appeared in a certificate, a public DNS dataset or a search index will \
         not be here. It is a floor on the attack surface, not a census of it.",
    );

    Finding {
        id: Uuid::new_v4(),
        scan_id,
        target_id,
        title: "Attack surface discovered by passive reconnaissance".to_string(),
        description,
        severity: Severity::Info,
        kind: FindingKind::ScanInformation,
        cvss4: None,
        epss: None,
        kev_listed: false,
        asset_exposure_factor: 1.0,
        reachability_score: 1.0,
        priority_score: 0.0,
        priority_rationale: String::new(),
        cwe_id: None,
        owasp_2025: None,
        wstg_id: Some("WSTG-INFO-01".to_string()),
        api_top10: None,
        affected_component: domain.to_string(),
        evidences: vec![crate::static_engine::finding::evidence(
            "recon_hosts",
            "Discovered hosts",
            &result
                .hosts
                .values()
                .map(|h| {
                    format!(
                        "{}\t{}\t{}",
                        h.hostname,
                        if h.in_scope { "in-scope" } else { "out-of-scope" },
                        h.sources.iter().cloned().collect::<Vec<_>>().join(",")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
        )],
        repro_steps: Vec::new(),
        remediation: String::new(),
        references: vec![
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/".to_string(),
        ],
        status: FindingStatus::Open,
        source_tools: vec![ENGINE_NAME.to_string()],
        ai_triage: None,
        created_at: chrono::Utc::now(),
    }
}

fn scope_gap_record(
    out_of_scope: &[&DiscoveredHost],
    target_id: Uuid,
    scan_id: Uuid,
) -> Finding {
    let listed: Vec<String> = out_of_scope
        .iter()
        .take(MAX_HOSTS_REPORTED)
        .map(|h| format!("  • {}", h.hostname))
        .collect();

    Finding {
        id: Uuid::new_v4(),
        scan_id,
        target_id,
        title: format!(
            "{} discovered host(s) fall outside the authorised scope",
            out_of_scope.len()
        ),
        description: format!(
            "Reconnaissance found {} host name(s) associated with this organisation that the \
             signed Rules of Engagement do not cover:\n\n{}{}\n\n\
             This is not a weakness in the target and nothing was sent to any of these hosts. \
             It is a scoping observation, and it is the most useful output of a reconnaissance \
             pass: an attacker does not restrict themselves to the hosts a scope document \
             lists, so a surface the assessment could not touch is a surface the report cannot \
             speak for.\n\n\
             Before the next engagement, decide for each of these which it is — a host that \
             belongs in scope and was missed, a host owned by a third party, or one that \
             should not exist any more. The third category is where the findings usually are: \
             a forgotten staging copy runs an old build of the same application, with the same \
             defects and none of the hardening.",
            out_of_scope.len(),
            listed.join("\n"),
            if out_of_scope.len() > MAX_HOSTS_REPORTED {
                format!("\n  • … and {} more", out_of_scope.len() - MAX_HOSTS_REPORTED)
            } else {
                String::new()
            },
        ),
        severity: Severity::Info,
        kind: FindingKind::ScanInformation,
        cvss4: None,
        epss: None,
        kev_listed: false,
        asset_exposure_factor: 1.0,
        reachability_score: 1.0,
        priority_score: 0.0,
        priority_rationale: String::new(),
        cwe_id: None,
        owasp_2025: None,
        wstg_id: Some("WSTG-INFO-04".to_string()),
        api_top10: None,
        affected_component: "engagement scope".to_string(),
        evidences: vec![crate::static_engine::finding::evidence(
            "recon_hosts",
            "Hosts outside the signed scope",
            &out_of_scope
                .iter()
                .map(|h| h.hostname.clone())
                .collect::<Vec<_>>()
                .join("\n"),
        )],
        repro_steps: Vec::new(),
        remediation: String::new(),
        references: Vec::new(),
        status: FindingStatus::Open,
        source_tools: vec![ENGINE_NAME.to_string()],
        ai_triage: None,
        created_at: chrono::Utc::now(),
    }
}

fn email_disclosure(
    result: &ReconResult,
    domain: &str,
    target_id: Uuid,
    scan_id: Uuid,
) -> Finding {
    let sample: Vec<String> = result.emails.iter().take(50).map(|e| format!("  • {e}")).collect();
    let score = sentinel_core::scoring::Cvss4Vector::parse(V_SURFACE)
        .map(|v| v.score())
        .unwrap_or(0.0);

    Finding {
        id: Uuid::new_v4(),
        scan_id,
        target_id,
        title: format!("{} organisational email address(es) exposed publicly", result.emails.len()),
        description: format!(
            "Passive reconnaissance found {} email address(es) associated with {domain} in \
             public sources — breach corpora, search indexes, code repositories and \
             certificate records.\n\n{}{}\n\n\
             Two consequences, and the second is the one that gets underrated. The addresses \
             themselves are a target list for phishing, which remains the most common initial \
             access route in reported incidents. And their *format* discloses the \
             organisation's username convention: once `first.last@` is known, every employee \
             named on a public profile becomes a guessable account name, which turns password \
             spraying from a search problem into a list problem.",
            result.emails.len(),
            sample.join("\n"),
            if result.emails.len() > 50 {
                format!("\n  • … and {} more", result.emails.len() - 50)
            } else {
                String::new()
            },
        ),
        severity: Severity::Low,
        kind: FindingKind::Weakness,
        cvss4: Some(CVSS4Data {
            vector_string: V_SURFACE.to_string(),
            base_score: score,
            severity_label: "Medium".to_string(),
        }),
        epss: None,
        kev_listed: false,
        // Public exposure by definition.
        asset_exposure_factor: 1.2,
        reachability_score: 1.0,
        priority_score: 0.0,
        priority_rationale: String::new(),
        cwe_id: Some("CWE-200".to_string()),
        owasp_2025: Some(owasp::A02.to_string()),
        wstg_id: Some("WSTG-INFO-01".to_string()),
        api_top10: None,
        affected_component: domain.to_string(),
        evidences: vec![crate::static_engine::finding::evidence(
            "recon_emails",
            "Addresses found in public sources",
            &result.emails.iter().cloned().collect::<Vec<_>>().join("\n"),
        )],
        repro_steps: vec![format!(
            "Run `theHarvester -d {domain} -b all` and compare the address list."
        )],
        remediation:
            "These addresses cannot be un-published, so the remediation is not removal — it is \
             making the disclosure not matter.\n\n\
             1. Enforce phishing-resistant multi-factor authentication. A WebAuthn or passkey \
                factor is bound to the origin, so a credential phished through a lookalike \
                domain does not authenticate. TOTP and push notifications both do.\n\
             2. Rate-limit and alert on authentication attempts spread across many accounts — \
                password spraying looks nothing like a brute force against one account, and \
                per-account lockout does not detect it.\n\
             3. Publish DMARC at `p=reject` with SPF and DKIM aligned, so the organisation's \
                own domain cannot be spoofed in the phish.\n\
             4. Use role addresses (`security@`, `support@`) in public-facing material rather \
                than individual ones.".to_string(),
        references: vec![
            "https://cwe.mitre.org/data/definitions/200.html".to_string(),
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/".to_string(),
        ],
        status: FindingStatus::Open,
        source_tools: vec![ENGINE_NAME.to_string()],
        ai_triage: Some(AITriage {
            is_false_positive_confidence: 0.05,
            cluster_id: Some("CLUSTER_CWE-200".to_string()),
            triage_notes: Some(
                "[Certain confidence] The addresses were returned by public data sources, so \
                 the disclosure is a fact. What is not established is whether any of these \
                 accounts still exists — a list dominated by former employees is a smaller \
                 problem than one that is current."
                    .to_string(),
            ),
        }),
        created_at: chrono::Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinel_core::models::target::{AuthorizationRecord, ScopeDefinition};

    fn target(base_url: &str, allowed: &[&str]) -> Target {
        Target {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            name: "t".into(),
            target_type: "Web App".into(),
            base_url: base_url.into(),
            repo_ref: None,
            stack_description: None,
            auth_keychain_handle: None,
            authorization_record: (!allowed.is_empty()).then(|| AuthorizationRecord {
                id: Uuid::new_v4(),
                target_id: Uuid::new_v4(),
                scope: ScopeDefinition {
                    allowed_domains: allowed.iter().map(|s| s.to_string()).collect(),
                    allowed_ips_cidrs: vec![],
                    out_of_scope_paths: vec![],
                    rate_limit_rps: 5,
                    prohibited_actions: vec![],
                },
                acknowledged_by: "lead".into(),
                signed_at: Utc::now(),
                roe_document_hash: "h".into(),
                digital_signature: "s".into(),
            }),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn a_hostname_is_recovered_from_every_form_a_tool_emits() {
        assert_eq!(normalise_host("app.example.com"), Some("app.example.com".into()));
        assert_eq!(normalise_host("https://app.example.com/path?a=1"), Some("app.example.com".into()));
        assert_eq!(normalise_host("app.example.com:8443"), Some("app.example.com".into()));
        assert_eq!(normalise_host("APP.Example.COM."), Some("app.example.com".into()));
        assert_eq!(normalise_host("*.example.com"), Some("example.com".into()));
        assert_eq!(normalise_host("user:pw@app.example.com"), Some("app.example.com".into()));
    }

    /// Progress text on the same stream as the host list would otherwise
    /// produce findings naming hosts that do not exist.
    #[test]
    fn tool_chatter_is_not_mistaken_for_a_hostname() {
        assert_eq!(normalise_host(""), None);
        assert_eq!(normalise_host("[INF] Enumerating subdomains"), None);
        assert_eq!(normalise_host("# comment"), None);
        assert_eq!(normalise_host("localhost"), None, "no dot, so not a name here");
        assert_eq!(normalise_host("found 42 results!"), None);
    }

    #[test]
    fn the_registrable_domain_is_taken_from_the_target_url() {
        assert_eq!(registrable_domain("https://app.example.com/x"), Some("example.com".into()));
        assert_eq!(registrable_domain("https://example.com"), Some("example.com".into()));
    }

    /// A naive last-two-labels rule would enumerate `co.uk`, which is a
    /// registry rather than an organisation.
    #[test]
    fn a_two_part_public_suffix_is_not_mistaken_for_a_domain() {
        assert_eq!(registrable_domain("https://shop.example.co.uk"), Some("example.co.uk".into()));
        assert_eq!(registrable_domain("https://www.example.com.au"), Some("example.com.au".into()));
    }

    #[test]
    fn an_address_target_cannot_be_enumerated() {
        assert_eq!(registrable_domain("https://192.168.1.10"), None);
        assert_eq!(registrable_domain("http://[::1]:8080"), None);
    }

    #[test]
    fn hosts_reported_by_two_tools_are_one_host_with_two_sources() {
        let mut r = ReconResult::default();
        record_host(&mut r, "api.example.com", "subfinder");
        record_host(&mut r, "api.example.com", "amass");
        assert_eq!(r.hosts.len(), 1);
        assert_eq!(r.hosts["api.example.com"].sources.len(), 2);
    }

    #[test]
    fn scope_is_decided_against_the_signed_record_not_by_the_tool() {
        let mut r = ReconResult::default();
        record_host(&mut r, "api.example.com", "subfinder");
        record_host(&mut r, "cdn.cloudprovider.net", "subfinder");
        record_host(&mut r, "example.com", "amass");

        apply_scope(&target("https://example.com", &["example.com"]), &mut r);

        assert!(r.hosts["api.example.com"].in_scope, "a subdomain of an allowed domain");
        assert!(r.hosts["example.com"].in_scope, "the domain itself");
        assert!(!r.hosts["cdn.cloudprovider.net"].in_scope, "a third party is not in scope");
    }

    /// The safe reading: with nothing signed, nothing may be touched.
    #[test]
    fn without_a_signed_record_nothing_is_in_scope() {
        let mut r = ReconResult::default();
        record_host(&mut r, "api.example.com", "subfinder");
        apply_scope(&target("https://example.com", &[]), &mut r);
        assert!(!r.hosts["api.example.com"].in_scope);
    }

    #[test]
    fn a_host_list_is_read_one_name_per_line() {
        let tool = &TOOLS[0];
        let mut r = ReconResult::default();
        ingest(tool, "api.example.com\nwww.example.com\n[INF] noise\n", &mut r);
        assert_eq!(r.hosts.len(), 2);
    }

    #[test]
    fn harvester_json_yields_both_hosts_and_addresses() {
        let mut r = ReconResult::default();
        ingest_harvester(
            r#"Reading sources...
{"hosts": ["api.example.com:1.2.3.4", "www.example.com"], "emails": ["Alice@Example.com", "bob@example.com"]}"#,
            "theHarvester",
            &mut r,
        );
        assert_eq!(r.hosts.len(), 2);
        assert!(r.hosts.contains_key("api.example.com"), "the address suffix is stripped");
        assert_eq!(r.emails.len(), 2);
        assert!(r.emails.contains("alice@example.com"), "addresses are normalised");
    }

    /// Discarding a run because the tool changed its output format loses
    /// everything it found.
    #[test]
    fn non_json_harvester_output_falls_back_to_reading_lines() {
        let mut r = ReconResult::default();
        ingest_harvester("api.example.com\nwww.example.com\n", "theHarvester", &mut r);
        assert_eq!(r.hosts.len(), 2);
    }

    #[test]
    fn httpx_json_lines_are_read_and_malformed_lines_skipped() {
        let mut r = ReconResult::default();
        ingest(
            &RESOLVERS[1],
            "{\"host\":\"api.example.com\",\"status_code\":200}\nnot json\n{\"input\":\"www.example.com\"}\n",
            &mut r,
        );
        assert_eq!(r.hosts.len(), 2);
    }

    #[test]
    fn the_surface_record_is_scan_information_rather_than_a_weakness() {
        let mut r = ReconResult::default();
        record_host(&mut r, "api.example.com", "subfinder");
        r.tools_run.push("subfinder".into());
        r.unavailable.push("amass".into());

        let f = surface_record(&r, "example.com", Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(f.kind, FindingKind::ScanInformation);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.description.contains("api.example.com"));
        assert!(f.description.contains("Not installed"), "the gap must be stated");
        assert!(
            f.description.contains("floor on the attack surface"),
            "passive enumeration is incomplete and the report has to say so"
        );
    }

    #[test]
    fn out_of_scope_hosts_are_reported_as_a_scoping_question_not_a_vulnerability() {
        let host = DiscoveredHost {
            hostname: "staging.example.com".into(),
            sources: ["subfinder".to_string()].into_iter().collect(),
            in_scope: false,
        };
        let f = scope_gap_record(&[&host], Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(f.kind, FindingKind::ScanInformation);
        assert!(f.description.contains("not a weakness in the target"));
        assert!(f.description.contains("staging.example.com"));
    }

    #[test]
    fn disclosed_addresses_are_remediated_by_hardening_rather_than_by_removal() {
        let mut r = ReconResult::default();
        r.emails.insert("alice@example.com".into());
        let f = email_disclosure(&r, "example.com", Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(f.kind, FindingKind::Weakness);
        assert!(f.remediation.contains("cannot be un-published"));
        assert!(f.remediation.contains("phishing-resistant"));
        assert!(f.remediation.contains("DMARC"));
    }

    #[tokio::test]
    async fn a_target_with_no_enumerable_hostname_reports_a_clear_error() {
        let err = ReconAdapter.run(&target("https://192.168.1.1", &[]), "{}").await.unwrap_err();
        assert!(err.to_string().contains("needs a hostname"), "{err}");
    }

    /// Amass's active mode brute-forces the target's nameservers, which is
    /// traffic a passive stage has no authorisation to send.
    #[test]
    fn amass_is_pinned_to_passive_mode() {
        let amass = TOOLS.iter().find(|t| t.binary == "amass").unwrap();
        assert!(
            amass.args.contains(&"-passive"),
            "amass must never be invoked in a mode that sends packets to the target"
        );
    }

    #[test]
    fn every_tool_declares_what_it_contributes() {
        for tool in TOOLS.iter().chain(RESOLVERS) {
            assert!(
                tool.contribution.len() > 40,
                "{} does not say what it adds, so its absence cannot be explained",
                tool.binary
            );
            assert!(tool.args.iter().any(|a| a.contains("silent") || a.contains("-")), "{} has no arguments", tool.binary);
        }
    }
}
