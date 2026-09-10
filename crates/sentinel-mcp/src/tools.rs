//! The tools this server exposes, and what each one is allowed to do.
//!
//! Every tool here is backed by a real engine — the same code the desktop
//! application runs — so a finding returned over MCP is identical to one in a
//! report, down to the CVSS vector and the sentence saying what its evidence
//! does not prove.
//!
//! The division that matters is between tools that read and tools that reach.
//! Reading tools take a filesystem path and are unrestricted: they inspect
//! files on a machine the caller is already running on. Reaching tools send
//! HTTP requests to somebody else's system, and every one of them goes through
//! [`require_authorization`] first.

use sentinel_adapters::adapter_trait::ScannerAdapter;
use sentinel_core::models::finding::{Finding, Severity};
use sentinel_core::models::target::{AuthorizationRecord, ScopeDefinition, Target};
use serde_json::{json, Value};
use uuid::Uuid;

/// Why a tool call did not produce a result.
#[derive(Debug)]
pub enum ToolError {
    /// No such tool.
    Unknown(String),
    /// The arguments were wrong in a way the caller can fix.
    BadArguments(String),
    /// The call would send traffic to a target with no signed authorisation.
    NotAuthorized(String),
    /// The engine ran and failed.
    Failed(String),
}

/// The tool manifest served by `tools/list`.
///
/// Descriptions are written for a model that has to choose between them
/// unaided, so each says what the tool needs, what it returns, and — for the
/// gated one — what it will refuse.
pub fn manifest() -> Vec<Value> {
    vec![
        json!({
            "name": "analyse_code",
            "description":
                "Static analysis of a source checkout across twelve languages. Follows data \
                 from request sources to dangerous sinks within each file, so a query built \
                 from a request parameter is reported and a parameterised one is not. Reads \
                 files only: nothing is executed, no dependency is resolved, no build is run. \
                 Returns findings with CVSS 4.0 scores, CWE/OWASP/WSTG mapping, and a \
                 statement of what each match does and does not establish.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repository_path": {
                        "type": "string",
                        "description": "Absolute path to a checkout on this machine."
                    },
                    "severity_at_least": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Omit for everything. Findings below this band are not returned."
                    }
                },
                "required": ["repository_path"]
            }
        }),
        json!({
            "name": "audit_dependencies",
            "description":
                "Resolves what a project actually has installed — from package-lock.json, \
                 yarn.lock, pnpm-lock.yaml, requirements.txt, Pipfile.lock, poetry.lock, \
                 Cargo.lock, go.mod/go.sum, pom.xml, build.gradle, composer.lock, \
                 Gemfile.lock, .csproj and mix.lock — and checks each version against the OSV \
                 advisory database. Distinguishes direct from transitive dependencies, because \
                 the remediation differs. Sends package names and versions to OSV.dev and \
                 nothing else; set offline to true to skip that and get the inventory alone.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repository_path": { "type": "string", "description": "Absolute path to a checkout." },
                    "offline": {
                        "type": "boolean",
                        "description": "Skip the advisory lookup. The inventory is still returned, and the report says the vulnerability check did not run."
                    }
                },
                "required": ["repository_path"]
            }
        }),
        json!({
            "name": "find_secrets",
            "description":
                "Finds credentials committed to a source tree, by provider format (AWS, GitHub, \
                 Stripe, Slack, Google, npm, private key blocks and about twenty others) and by \
                 entropy for the ones with no published format. Never returns the credential \
                 itself — every value is masked — and never tests whether it still \
                 authenticates, which would mean authenticating to a third party. Leads its \
                 remediation with rotation, because deleting the line does not close the \
                 exposure.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repository_path": { "type": "string", "description": "Absolute path to a checkout." }
                },
                "required": ["repository_path"]
            }
        }),
        json!({
            "name": "audit_infrastructure",
            "description":
                "Analyses the configuration an application is deployed from: Dockerfiles, \
                 Docker Compose, Kubernetes manifests, Terraform and CI workflows. Finds \
                 privileged containers, host namespace sharing, security groups open to the \
                 internet, public storage, wildcard IAM and RBAC, unpinned CI actions and \
                 workflow script injection. Reads files only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repository_path": { "type": "string", "description": "Absolute path to a checkout." }
                },
                "required": ["repository_path"]
            }
        }),
        json!({
            "name": "assess_target",
            "description":
                "Dynamic assessment of a live web application: security headers, TLS, cookies, \
                 CORS, HTTP methods, exposure surface, information disclosure and content \
                 analysis, across every page the crawl reaches. THIS SENDS REQUESTS TO THE \
                 TARGET. It is refused unless authorization is supplied with the domains the \
                 client has agreed to, who signed off, and a request-rate ceiling. That refusal \
                 is enforced in code and cannot be switched off. Only GET, HEAD and OPTIONS are \
                 ever issued; no payload, fuzzing or brute-force request is sent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": { "type": "string", "description": "The application's base URL." },
                    "authorization": {
                        "type": "object",
                        "description": "The signed Rules of Engagement. Without this the call is refused.",
                        "properties": {
                            "allowed_domains": {
                                "type": "array", "items": { "type": "string" },
                                "description": "Domains the client has authorised testing against."
                            },
                            "acknowledged_by": {
                                "type": "string",
                                "description": "Who authorised it. Recorded in the finding's audit trail."
                            },
                            "rate_limit_rps": {
                                "type": "integer",
                                "description": "Maximum requests per second, from the agreement. Defaults to 3."
                            },
                            "out_of_scope_paths": {
                                "type": "array", "items": { "type": "string" },
                                "description": "Paths excluded by the agreement."
                            }
                        },
                        "required": ["allowed_domains", "acknowledged_by"]
                    }
                },
                "required": ["target_url", "authorization"]
            }
        }),
        json!({
            "name": "discover_attack_surface",
            "description":
                "Passive reconnaissance: subdomains, hosts and email addresses from certificate \
                 transparency logs, passive DNS and public indexes, via subfinder, theHarvester \
                 and amass where they are installed. Sends nothing to the target — every source \
                 queried is a third party — so this needs no authorisation and is safe to run \
                 before an engagement is scoped. Results are labelled against the scope if one \
                 is supplied.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "The domain or a URL on it." },
                    "in_scope_domains": {
                        "type": "array", "items": { "type": "string" },
                        "description": "Optional. Discovered hosts are labelled in or out of scope against this list."
                    }
                },
                "required": ["domain"]
            }
        }),
        json!({
            "name": "check_authorization",
            "description":
                "Answers whether a URL falls inside a given scope, using the same gate the \
                 scanning engines use. Call this before assess_target to find out whether a \
                 host is covered, without sending anything to it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": { "type": "string" },
                    "allowed_domains": { "type": "array", "items": { "type": "string" } },
                    "out_of_scope_paths": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["target_url", "allowed_domains"]
            }
        }),
        json!({
            "name": "list_engines",
            "description":
                "Which assessment engines this installation can run, which are compiled in and \
                 always available, and which need a binary that may not be installed. Use this \
                 to find out why a scan reported nothing before concluding a target is clean.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "get_coverage_catalog",
            "description":
                "The OWASP WSTG test catalogue with this tool's coverage declaration for each \
                 case: which engines answer it, whether automatically or partially, and which \
                 cases can only be answered by a human. This is what makes a clean scan \
                 interpretable — it says what was actually looked at.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "Optional WSTG category code, e.g. INPV, ATHN, CRYP."
                    }
                }
            }
        }),
    ]
}

/// Route a tool call to its engine.
pub async fn dispatch(name: &str, args: &Value) -> Result<String, ToolError> {
    match name {
        "analyse_code" => static_scan(name, args, |t, c| {
            Box::pin(async move {
                sentinel_adapters::static_engine::sast::NativeSastAdapter.run(&t, &c).await
            })
        })
        .await,
        "audit_dependencies" => static_scan(name, args, |t, c| {
            Box::pin(async move {
                sentinel_adapters::static_engine::sca::NativeScaAdapter.run(&t, &c).await
            })
        })
        .await,
        "find_secrets" => static_scan(name, args, |t, c| {
            Box::pin(async move {
                sentinel_adapters::static_engine::secrets::NativeSecretsAdapter.run(&t, &c).await
            })
        })
        .await,
        "audit_infrastructure" => static_scan(name, args, |t, c| {
            Box::pin(async move {
                sentinel_adapters::static_engine::iac::NativeIacAdapter.run(&t, &c).await
            })
        })
        .await,
        "assess_target" => assess_target(args).await,
        "discover_attack_surface" => discover_attack_surface(args).await,
        "check_authorization" => check_authorization(args),
        "list_engines" => Ok(list_engines()),
        "get_coverage_catalog" => Ok(coverage_catalog(args)),
        other => Err(ToolError::Unknown(other.to_string())),
    }
}

type ScanFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = anyhow::Result<Vec<Finding>>> + Send>,
>;

/// Run one file-reading engine over a checkout.
async fn static_scan<F>(tool: &str, args: &Value, engine: F) -> Result<String, ToolError>
where
    F: FnOnce(Target, String) -> ScanFuture,
{
    let path = args
        .get("repository_path")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ToolError::BadArguments(format!("{tool} needs repository_path: an absolute path to a checkout."))
        })?;

    if !std::path::Path::new(path).is_dir() {
        return Err(ToolError::BadArguments(format!(
            "{path:?} is not a directory on this machine. {tool} reads a local checkout; it \
             cannot fetch a repository."
        )));
    }

    let config = json!({
        "offline": args.get("offline").and_then(Value::as_bool).unwrap_or(false),
        "crawl": { "enabled": false },
    })
    .to_string();

    // A synthetic target: these engines need only the repository path, and the
    // authorisation record stays absent because nothing here reaches a network
    // the gate governs.
    let target = Target {
        id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        name: "mcp".into(),
        target_type: "Source".into(),
        base_url: String::new(),
        repo_ref: Some(path.to_string()),
        stack_description: None,
        auth_keychain_handle: None,
        authorization_record: None,
        created_at: chrono::Utc::now(),
    };

    let findings = engine(target, config).await.map_err(|e| ToolError::Failed(e.to_string()))?;
    let floor = severity_floor(args);
    Ok(render(&findings, floor))
}

/// The dynamic engine, behind the gate.
async fn assess_target(args: &Value) -> Result<String, ToolError> {
    let url = args
        .get("target_url")
        .and_then(Value::as_str)
        .ok_or_else(|| ToolError::BadArguments("assess_target needs target_url.".into()))?;

    let record = require_authorization(args, url)?;

    let target = Target {
        id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        name: url.to_string(),
        target_type: "Web App".into(),
        base_url: url.to_string(),
        repo_ref: None,
        stack_description: None,
        auth_keychain_handle: None,
        authorization_record: Some(record),
        created_at: chrono::Utc::now(),
    };

    // Through the gated runner, not the adapter directly. Belt and braces: the
    // check above would have to be removed *and* this wrapper replaced before
    // an unauthorised request could leave the machine.
    let runner = sentinel_adapters::auth_gated_runner::AuthGatedDastRunner::new(
        sentinel_adapters::native::NativeCheckAdapter,
    );
    let config = json!({
        "crawl": { "enabled": true, "maxPages": 60, "maxDepth": 3, "budgetSeconds": 240 }
    })
    .to_string();

    let findings = runner
        .run(&target, &config)
        .await
        .map_err(|e| ToolError::Failed(e.to_string()))?;
    Ok(render(&findings, severity_floor(args)))
}

/// Extract and validate the authorisation, or refuse.
///
/// The refusal text is written for a model to read and act on: it says what is
/// missing and what would make the call succeed, rather than only that it was
/// denied.
fn require_authorization(args: &Value, url: &str) -> Result<AuthorizationRecord, ToolError> {
    const REFUSAL: &str =
        "Refused: assess_target sends HTTP requests to a live system, and no signed Rules of \
         Engagement record was supplied.\n\n\
         This is not a configuration this server can be asked to relax. Testing a system \
         without the owner's authorisation is unlawful in most jurisdictions regardless of \
         intent, and an automated caller is exactly the case the gate exists for.\n\n\
         To proceed, supply `authorization` with:\n\
         \x20 • allowed_domains — the domains the client has agreed to, from the engagement \
         document\n\
         \x20 • acknowledged_by — who authorised it; this is recorded in the audit trail\n\
         \x20 • rate_limit_rps — the agreed request ceiling (optional, defaults to 3)\n\n\
         If you are exploring rather than assessing an authorised target, the static tools — \
         analyse_code, audit_dependencies, find_secrets, audit_infrastructure — read local \
         files and need no authorisation at all. discover_attack_surface is also unrestricted: \
         it queries public records and sends nothing to the target.";

    let Some(auth) = args.get("authorization").filter(|v| v.is_object()) else {
        return Err(ToolError::NotAuthorized(REFUSAL.to_string()));
    };

    let allowed: Vec<String> = auth
        .get("allowed_domains")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
        .unwrap_or_default();
    if allowed.is_empty() {
        return Err(ToolError::NotAuthorized(format!(
            "Refused: the authorization record lists no allowed domains, so it authorises \
             nothing.\n\n{REFUSAL}"
        )));
    }

    let acknowledged_by = auth
        .get("acknowledged_by")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            ToolError::NotAuthorized(format!(
                "Refused: the authorization record does not say who authorised the testing. \
                 That name is the audit trail, and a record without one is not an \
                 authorisation.\n\n{REFUSAL}"
            ))
        })?;

    let scope = ScopeDefinition {
        allowed_domains: allowed,
        allowed_ips_cidrs: Vec::new(),
        out_of_scope_paths: auth
            .get("out_of_scope_paths")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
            .unwrap_or_default(),
        // A caller that omits the ceiling gets a conservative one rather than
        // an unbounded scan.
        rate_limit_rps: auth
            .get("rate_limit_rps")
            .and_then(Value::as_u64)
            .map(|n| n.clamp(1, 20) as u32)
            .unwrap_or(3),
        prohibited_actions: Vec::new(),
    };

    // The scope has to actually cover the URL that was asked for. A record
    // authorising `example.com` does not authorise a scan of `other.test`, and
    // accepting one that does not match would make the gate decorative.
    let record = AuthorizationRecord {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        scope,
        acknowledged_by: acknowledged_by.to_string(),
        signed_at: chrono::Utc::now(),
        roe_document_hash: "mcp-supplied".into(),
        digital_signature: "mcp-supplied".into(),
    };

    // The same gate the scanning engines use, not a second implementation of
    // the same rules — a scope check that disagrees with the one enforced
    // downstream is worse than none, because it teaches the caller the wrong
    // thing about what will be accepted.
    let probe = Target {
        id: record.target_id,
        project_id: Uuid::new_v4(),
        name: url.to_string(),
        target_type: "Web App".into(),
        base_url: url.to_string(),
        repo_ref: None,
        stack_description: None,
        auth_keychain_handle: None,
        authorization_record: Some(record.clone()),
        created_at: chrono::Utc::now(),
    };
    if let Err(e) = sentinel_core::auth::gate::AuthorizationGate::verify_active_scan_allowed(&probe, url) {
        return Err(ToolError::NotAuthorized(format!(
            "Refused: {e}\n\nScanning a host the agreement does not name is the mistake this \
             check exists to prevent. Confirm the engagement scope rather than widening the \
             record to match the URL."
        )));
    }

    Ok(record)
}

async fn discover_attack_surface(args: &Value) -> Result<String, ToolError> {
    let domain = args
        .get("domain")
        .and_then(Value::as_str)
        .ok_or_else(|| ToolError::BadArguments("discover_attack_surface needs domain.".into()))?;

    let in_scope: Vec<String> = args
        .get("in_scope_domains")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
        .unwrap_or_default();

    let base_url = if domain.contains("://") {
        domain.to_string()
    } else {
        format!("https://{domain}")
    };

    let target = Target {
        id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        name: domain.to_string(),
        target_type: "Web App".into(),
        base_url,
        repo_ref: None,
        stack_description: None,
        auth_keychain_handle: None,
        // Present only to label results in or out of scope; the recon engine
        // sends nothing to the target either way.
        authorization_record: (!in_scope.is_empty()).then(|| AuthorizationRecord {
            id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            scope: ScopeDefinition {
                allowed_domains: in_scope,
                allowed_ips_cidrs: Vec::new(),
                out_of_scope_paths: Vec::new(),
                rate_limit_rps: 1,
                prohibited_actions: Vec::new(),
            },
            acknowledged_by: "scope labelling only".into(),
            signed_at: chrono::Utc::now(),
            roe_document_hash: "n/a".into(),
            digital_signature: "n/a".into(),
        }),
        created_at: chrono::Utc::now(),
    };

    match sentinel_adapters::recon::ReconAdapter.run(&target, "{}").await {
        Ok(findings) => Ok(render(&findings, None)),
        Err(e) => Err(ToolError::Failed(format!(
            "{e}. Passive reconnaissance needs at least one of subfinder, theHarvester or \
             amass installed; without any of them there are no sources to query."
        ))),
    }
}

fn check_authorization(args: &Value) -> Result<String, ToolError> {
    let url = args
        .get("target_url")
        .and_then(Value::as_str)
        .ok_or_else(|| ToolError::BadArguments("check_authorization needs target_url.".into()))?;
    let allowed: Vec<String> = args
        .get("allowed_domains")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
        .unwrap_or_default();

    let scope = ScopeDefinition {
        allowed_domains: allowed.clone(),
        allowed_ips_cidrs: Vec::new(),
        out_of_scope_paths: args
            .get("out_of_scope_paths")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
            .unwrap_or_default(),
        rate_limit_rps: 3,
        prohibited_actions: Vec::new(),
    };

    let probe = Target {
        id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        name: url.to_string(),
        target_type: "Web App".into(),
        base_url: url.to_string(),
        repo_ref: None,
        stack_description: None,
        auth_keychain_handle: None,
        authorization_record: Some(AuthorizationRecord {
            id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            scope: scope.clone(),
            acknowledged_by: "scope check only".into(),
            signed_at: chrono::Utc::now(),
            roe_document_hash: "n/a".into(),
            digital_signature: "n/a".into(),
        }),
        created_at: chrono::Utc::now(),
    };
    let in_scope =
        sentinel_core::auth::gate::AuthorizationGate::verify_active_scan_allowed(&probe, url)
            .is_ok();
    Ok(format!(
        "{url}\n\nIn scope: {}\n\nChecked against: {:?}\nExcluded paths: {:?}\n\n{}",
        if in_scope { "yes" } else { "no" },
        allowed,
        scope.out_of_scope_paths,
        if in_scope {
            "assess_target will accept this URL with an authorization record listing these \
             domains. The record still needs acknowledged_by — a scope with nobody's name on \
             it is not an authorisation."
        } else {
            "assess_target will refuse this URL. Either the host is genuinely outside the \
             engagement, or the scope list is missing an entry the agreement does contain — \
             check the engagement document rather than adding the host to make the check pass."
        }
    ))
}

fn list_engines() -> String {
    let mut out = String::from(
        "SentinelVAPT assessment engines.\n\n\
         Built in — compiled into the binary, so these always run:\n",
    );
    for (name, what) in [
        ("Sentinel Code", "source analysis, twelve languages, intra-file dataflow"),
        ("Sentinel Dependencies", "lockfile resolution across nine ecosystems, matched against OSV"),
        ("Sentinel Secrets", "committed credentials, by provider format and by entropy"),
        ("Sentinel Infrastructure", "Dockerfiles, Compose, Kubernetes, Terraform, CI workflows"),
        ("Sentinel Native", "live checks: headers, TLS, cookies, CORS, exposure, content"),
    ] {
        out.push_str(&format!("  ✓ {name:<26} {what}\n"));
    }

    out.push_str(
        "\nOptional — each is used when its binary is on PATH, and skipped with the gap \
         recorded when it is not:\n",
    );
    for (binary, name, what) in [
        ("semgrep", "Semgrep", "source analysis against the public rule registry"),
        ("trivy", "Trivy", "dependency and container vulnerabilities, works offline"),
        ("osv-scanner", "OSV-Scanner", "a second advisory database"),
        ("gitleaks", "Gitleaks", "credentials across the git history, not just the tree"),
        ("trufflehog", "TruffleHog", "asks the provider whether a credential still authenticates"),
        ("retire", "retire.js", "vulnerable JavaScript in what the browser receives"),
        ("checkov", "Checkov", "a broader infrastructure-as-code policy set"),
        ("subfinder", "subfinder", "passive subdomain enumeration"),
        ("theHarvester", "theHarvester", "OSINT hosts and email addresses"),
        ("amass", "amass", "attack-surface mapping, passive mode"),
        ("zap.sh", "OWASP ZAP", "full dynamic scanning, including a browser-driven crawler"),
        ("nuclei", "Nuclei", "community templates for known vulnerable software"),
        ("nikto", "Nikto", "web server misconfiguration and forgotten files"),
        ("testssl.sh", "testssl.sh", "what the server will actually negotiate"),
    ] {
        let present = sentinel_adapters::runner::LocalCliRunner::is_installed(binary);
        out.push_str(&format!(
            "  {} {name:<26} {what}\n",
            if present { "✓" } else { "·" }
        ));
    }

    out.push_str(
        "\n✓ available, · not installed. An engine that is not installed does not make a \
         target clean — it makes the coverage matrix record the checks that went unanswered. \
         Read get_coverage_catalog before concluding anything from a quiet scan.\n",
    );
    out
}

fn coverage_catalog(args: &Value) -> String {
    let filter = args.get("category").and_then(Value::as_str).map(str::to_uppercase);
    let mut out = String::from("OWASP WSTG coverage declaration.\n\n");

    for item in sentinel_core::checklist::catalog::WSTG_CATALOG {
        if let Some(code) = &filter {
            if item.category_code != code {
                continue;
            }
        }
        out.push_str(&format!(
            "{:<14} {:<12} {}\n               {} — engines: {}\n",
            item.id,
            format!("{:?}", item.coverage),
            item.name,
            item.client_summary,
            item.engines.join(", "),
        ));
    }
    out.push_str(&format!("\n{}\n", sentinel_core::threat::catalogue_note()));
    out
}

/// The lowest severity a caller wants returned.
fn severity_floor(args: &Value) -> Option<Severity> {
    match args.get("severity_at_least").and_then(Value::as_str)?.to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        _ => Some(Severity::Info),
    }
}

/// Render findings as text a model can read and quote.
///
/// Not JSON. A model consuming this has to relay it to a person, and prose with
/// structure survives that better than a nested document it has to re-describe.
pub fn render(findings: &[Finding], floor: Option<Severity>) -> String {
    use sentinel_core::models::finding::FindingKind;

    let (weaknesses, information): (Vec<&Finding>, Vec<&Finding>) = findings
        .iter()
        .partition(|f| f.kind == FindingKind::Weakness);

    let mut kept: Vec<&Finding> = weaknesses
        .into_iter()
        .filter(|f| match &floor {
            // `Severity` orders Critical first, so "at least High" means the
            // variant sorts at or before High.
            Some(min) => f.severity <= *min,
            None => true,
        })
        .collect();
    kept.sort_by(|a, b| {
        b.priority_score
            .partial_cmp(&a.priority_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut out = String::new();
    if kept.is_empty() {
        out.push_str("No weaknesses were reported at or above the requested severity.\n\n");
    } else {
        out.push_str(&format!("{} weakness(es), highest priority first.\n\n", kept.len()));
        for f in &kept {
            out.push_str(&format!(
                "── {:?} · priority {:.1} · {}\n{}\n\n{}\n\n",
                f.severity,
                f.priority_score,
                f.affected_component,
                f.title,
                f.description.lines().take(8).collect::<Vec<_>>().join("\n"),
            ));
            if let Some(cvss) = &f.cvss4 {
                out.push_str(&format!("   CVSS 4.0 {:.1}  {}\n", cvss.base_score, cvss.vector_string));
            }
            if let Some(cwe) = &f.cwe_id {
                out.push_str(&format!("   {cwe}"));
                if let Some(owasp) = &f.owasp_2025 {
                    out.push_str(&format!("  ·  {owasp}"));
                }
                out.push('\n');
            }
            if let Some(triage) = f.ai_triage.as_ref().and_then(|t| t.triage_notes.as_ref()) {
                out.push_str(&format!("   {triage}\n"));
            }
            out.push_str(&format!(
                "   Fix: {}\n\n",
                f.remediation.lines().take(4).collect::<Vec<_>>().join(" ")
            ));
        }
    }

    // The coverage records are what stop "no weaknesses" being over-read, so
    // they are always included regardless of the severity filter.
    if !information.is_empty() {
        out.push_str("── What was actually examined ──\n\n");
        for f in information {
            out.push_str(&format!("{}\n{}\n\n", f.title, f.description));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::models::finding::{FindingKind, FindingStatus};

    fn finding(title: &str, severity: Severity, priority: f64) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            title: title.into(),
            description: "Description.".into(),
            severity,
            kind: FindingKind::Weakness,
            cvss4: None,
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.0,
            reachability_score: 1.0,
            priority_score: priority,
            priority_rationale: String::new(),
            cwe_id: Some("CWE-89".into()),
            owasp_2025: None,
            wstg_id: None,
            api_top10: None,
            affected_component: "src/a.js:1".into(),
            evidences: vec![],
            repro_steps: vec![],
            remediation: "Fix it.".into(),
            references: vec![],
            status: FindingStatus::Open,
            source_tools: vec!["Sentinel Code".into()],
            ai_triage: None,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn every_tool_in_the_manifest_has_a_usable_schema_and_description() {
        for tool in manifest() {
            let name = tool["name"].as_str().unwrap();
            assert!(
                tool["description"].as_str().unwrap().len() > 100,
                "{name} does not tell a model when to choose it"
            );
            assert_eq!(tool["inputSchema"]["type"], "object", "{name}");
            // A required field the schema does not define is a call that always
            // fails validation.
            if let Some(required) = tool["inputSchema"]["required"].as_array() {
                for field in required {
                    let field = field.as_str().unwrap();
                    assert!(
                        tool["inputSchema"]["properties"].get(field).is_some(),
                        "{name} requires {field} but does not define it"
                    );
                }
            }
        }
    }

    #[test]
    fn the_dynamic_tool_declares_that_it_sends_traffic() {
        let assess = manifest()
            .into_iter()
            .find(|t| t["name"] == "assess_target")
            .unwrap();
        let description = assess["description"].as_str().unwrap();
        assert!(description.contains("SENDS REQUESTS TO THE TARGET"));
        assert!(description.contains("refused"));
        assert!(assess["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "authorization"));
    }

    #[tokio::test]
    async fn an_unknown_tool_is_reported_as_unknown() {
        assert!(matches!(
            dispatch("nope", &json!({})).await,
            Err(ToolError::Unknown(_))
        ));
    }

    #[tokio::test]
    async fn a_static_tool_without_a_path_says_which_argument_is_missing() {
        let err = dispatch("analyse_code", &json!({})).await.unwrap_err();
        match err {
            ToolError::BadArguments(m) => assert!(m.contains("repository_path"), "{m}"),
            other => panic!("expected bad arguments, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_path_that_is_not_a_directory_is_reported_clearly() {
        let err = dispatch("analyse_code", &json!({ "repository_path": "/nope/nothing" }))
            .await
            .unwrap_err();
        match err {
            ToolError::BadArguments(m) => assert!(m.contains("not a directory"), "{m}"),
            other => panic!("got {other:?}"),
        }
    }

    // ── The gate ────────────────────────────────────────────────────────────

    #[test]
    fn a_call_with_no_authorization_is_refused_with_an_explanation() {
        let err = require_authorization(&json!({}), "https://example.com").unwrap_err();
        match err {
            ToolError::NotAuthorized(m) => {
                assert!(m.contains("Rules of Engagement"));
                assert!(m.contains("allowed_domains"), "the refusal says how to comply");
                assert!(m.contains("analyse_code"), "and points at what is available instead");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn an_authorization_naming_nobody_is_not_an_authorization() {
        let err = require_authorization(
            &json!({ "authorization": { "allowed_domains": ["example.com"] } }),
            "https://example.com",
        )
        .unwrap_err();
        match err {
            ToolError::NotAuthorized(m) => assert!(m.contains("who authorised"), "{m}"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn an_empty_domain_list_authorises_nothing() {
        let err = require_authorization(
            &json!({ "authorization": { "allowed_domains": [], "acknowledged_by": "lead" } }),
            "https://example.com",
        )
        .unwrap_err();
        assert!(matches!(err, ToolError::NotAuthorized(_)));
    }

    /// Supplying *an* authorisation is not the same as supplying one that
    /// covers the URL being asked about.
    #[test]
    fn a_record_that_does_not_cover_the_url_is_refused() {
        let err = require_authorization(
            &json!({
                "authorization": { "allowed_domains": ["example.com"], "acknowledged_by": "lead" }
            }),
            "https://someone-elses-bank.test",
        )
        .unwrap_err();
        match err {
            ToolError::NotAuthorized(m) => {
                assert!(m.contains("not covered by the signed scope"), "{m}");
                assert!(m.contains("rather than widening the record"));
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn a_valid_record_is_accepted_and_carries_the_name_that_authorised_it() {
        let record = require_authorization(
            &json!({
                "authorization": {
                    "allowed_domains": ["example.com"],
                    "acknowledged_by": "Security Lead",
                    "rate_limit_rps": 7
                }
            }),
            "https://app.example.com/login",
        )
        .unwrap();
        assert_eq!(record.acknowledged_by, "Security Lead");
        assert_eq!(record.scope.rate_limit_rps, 7);
    }

    /// An unbounded rate is traffic the agreement did not authorise.
    #[test]
    fn the_request_rate_is_clamped_and_defaults_conservatively() {
        let base = |rate: Value| {
            json!({
                "authorization": {
                    "allowed_domains": ["example.com"],
                    "acknowledged_by": "lead",
                    "rate_limit_rps": rate
                }
            })
        };
        let of = |v: Value| require_authorization(&v, "https://example.com").unwrap().scope.rate_limit_rps;
        assert_eq!(of(base(json!(9999))), 20, "clamped");
        assert_eq!(of(base(json!(0))), 1, "never zero");

        let no_rate = json!({
            "authorization": { "allowed_domains": ["example.com"], "acknowledged_by": "lead" }
        });
        assert_eq!(of(no_rate), 3, "a conservative default, not unbounded");
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    #[test]
    fn findings_are_rendered_highest_priority_first() {
        let out = render(
            &[
                finding("low one", Severity::Low, 2.0),
                finding("critical one", Severity::Critical, 9.5),
            ],
            None,
        );
        let critical = out.find("critical one").unwrap();
        let low = out.find("low one").unwrap();
        assert!(critical < low, "the highest priority must come first");
    }

    #[test]
    fn the_severity_floor_excludes_what_is_below_it() {
        let findings = [
            finding("critical", Severity::Critical, 9.0),
            finding("medium", Severity::Medium, 5.0),
            finding("info", Severity::Info, 1.0),
        ];
        let out = render(&findings, Some(Severity::High));
        assert!(out.contains("critical"));
        assert!(!out.contains("medium"));
    }

    /// The coverage record is what stops "nothing found" being over-read, so it
    /// survives the severity filter.
    #[test]
    fn scan_information_is_always_included_however_the_filter_is_set() {
        let mut coverage = finding("Static analysis coverage", Severity::Info, 0.0);
        coverage.kind = FindingKind::ScanInformation;
        coverage.description = "Read 41 files.".into();

        let out = render(&[coverage], Some(Severity::Critical));
        assert!(out.contains("What was actually examined"));
        assert!(out.contains("Read 41 files"));
    }

    #[test]
    fn an_empty_result_says_so_rather_than_returning_nothing() {
        let out = render(&[], Some(Severity::High));
        assert!(out.contains("No weaknesses were reported"));
    }

    #[test]
    fn check_authorization_explains_both_answers() {
        let yes = check_authorization(&json!({
            "target_url": "https://app.example.com",
            "allowed_domains": ["example.com"]
        }))
        .unwrap();
        assert!(yes.contains("In scope: yes"));
        assert!(yes.contains("acknowledged_by"));

        let no = check_authorization(&json!({
            "target_url": "https://other.test",
            "allowed_domains": ["example.com"]
        }))
        .unwrap();
        assert!(no.contains("In scope: no"));
        assert!(no.contains("rather than adding the host to make the check pass"));
    }

    #[test]
    fn the_engine_list_distinguishes_built_in_from_optional_and_says_why_it_matters() {
        let out = list_engines();
        assert!(out.contains("Sentinel Code"));
        assert!(out.contains("Built in"));
        assert!(out.contains("Optional"));
        assert!(
            out.contains("does not make a target clean"),
            "a missing engine must not be read as a clean result"
        );
    }

    #[test]
    fn the_coverage_catalog_can_be_filtered_by_category() {
        let all = coverage_catalog(&json!({}));
        let injection = coverage_catalog(&json!({ "category": "INPV" }));
        assert!(injection.len() < all.len());
        assert!(injection.contains("WSTG-INPV-05"));
        assert!(!injection.contains("WSTG-ATHN-01"));
        assert!(all.contains("cisa.gov"), "the KEV qualification travels with the catalogue");
    }
}
