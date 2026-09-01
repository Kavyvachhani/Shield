//! Same-origin discovery, so the passive checks see the whole application.
//!
//! Until this existed the native engine fetched exactly one document — the site
//! root — and ran every header, content and disclosure check against it. That
//! answers "is the front page configured correctly", which is not the question
//! an assessment is asking. A Content-Security-Policy set on `/` and absent on
//! `/admin`, a stack trace on one API route, a key compiled into one lazily
//! loaded bundle: none of it was reachable, and the report said the application
//! was clean because the one page it looked at was.
//!
//! SAFETY
//! ──────
//! Discovery inherits every guarantee the rest of the engine makes, because it
//! goes through the same [`Probe`]:
//!
//! * `GET` only — `Probe` refuses anything outside GET/HEAD/OPTIONS.
//! * Every URL is checked against the signed scope before a socket opens, so a
//!   link to another host is recorded and never fetched.
//! * Requests are rate limited to the RoE ceiling; crawling makes a scan longer,
//!   never faster or noisier per second.
//! * Nothing is submitted. Forms are read for their `action` attribute and
//!   never posted, and query strings found in links are followed as-is rather
//!   than mutated.
//!
//! The crawl is bounded on four axes — pages, depth, wall clock and per-page
//! links — because an application with a calendar widget or a faceted search
//! has an unbounded URL space, and a scanner that walks into one never
//! finishes.

use super::endpoints::{self, Endpoint};
use super::probe::{is_readable, Probe, ProbeResponse};
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};
use url::Url;

/// Bounds on a crawl. Defaults are deliberately modest: a first assessment
/// should finish, and an analyst who wants more can raise them.
#[derive(Debug, Clone, Copy)]
pub struct CrawlLimits {
    /// Maximum documents fetched, including the root.
    pub max_pages: usize,
    /// How many links deep to follow from the root. 0 crawls nothing.
    pub max_depth: usize,
    /// Wall-clock ceiling for the whole discovery phase.
    pub budget: Duration,
    /// Maximum links taken from any single page, so one sitemap-like index
    /// cannot fill the queue on its own.
    pub max_links_per_page: usize,
}

impl Default for CrawlLimits {
    fn default() -> Self {
        Self {
            max_pages: 120,
            max_depth: 3,
            budget: Duration::from_secs(300),
            max_links_per_page: 60,
        }
    }
}

/// What discovery found.
pub struct Crawl {
    /// Documents fetched, in the order they were visited. The root is first.
    pub pages: Vec<ProbeResponse>,
    /// In-scope URLs that were queued but not fetched, because a limit was hit.
    /// Reported so a clean result cannot be mistaken for a complete one.
    pub not_visited: Vec<String>,
    /// Endpoints found in the application's own published descriptions rather
    /// than by following links — the API specification, robots.txt, the
    /// sitemap, and paths referenced from JavaScript.
    pub declared: Vec<Endpoint>,
    /// Distinct off-origin hosts the application links to. Not fetched — they
    /// are outside the authorised scope — but worth telling the analyst about,
    /// since third-party origins are where supply-chain risk enters.
    pub external_hosts: Vec<String>,
    /// Why the crawl stopped.
    pub stopped_because: StopReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Everything reachable within the limits was visited.
    Exhausted,
    PageLimit,
    DepthLimit,
    TimeBudget,
}

impl StopReason {
    /// Phrasing for the coverage note in a report.
    pub fn describe(&self) -> &'static str {
        match self {
            StopReason::Exhausted => "every in-scope page reachable by link was assessed",
            StopReason::PageLimit => "the page limit was reached, so some in-scope pages were not assessed",
            StopReason::DepthLimit => "the depth limit was reached, so pages further from the entry point were not assessed",
            StopReason::TimeBudget => "the discovery time budget was reached, so some in-scope pages were not assessed",
        }
    }
}

/// Walk the application from `root`, breadth-first, within `limits`.
///
/// Breadth-first rather than depth-first on purpose: with a page budget, the
/// pages you most want are the ones nearest the entry point — navigation,
/// login, account, admin — not one arbitrary branch followed to its end.
pub async fn discover(
    probe: &Probe,
    root: ProbeResponse,
    limits: CrawlLimits,
) -> Crawl {
    let started = Instant::now();
    let mut pages: Vec<ProbeResponse> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut external: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    let mut not_visited: Vec<String> = Vec::new();
    let mut stopped = StopReason::Exhausted;

    let Ok(origin) = Url::parse(&root.final_url) else {
        return Crawl {
            pages: vec![root],
            not_visited,
            declared: Vec::new(),
            external_hosts: Vec::new(),
            stopped_because: StopReason::Exhausted,
        };
    };
    let origin_host = origin.host_str().unwrap_or_default().to_ascii_lowercase();

    seen.insert(canonical(&root.final_url));
    for link in links_from(&root, &origin, limits.max_links_per_page, &mut external, &origin_host) {
        if seen.insert(canonical(&link)) {
            queue.push_back((link, 1));
        }
    }
    pages.push(root);

    // Ask the application what it exposes before guessing from its markup.
    //
    // A single-page application has no links to follow: its routes live in a
    // bundle and its data comes from fetch calls. Its API specification, on the
    // other hand, is an authoritative list written by the people who built it,
    // and robots.txt is a list of what the operator did not want found. Both
    // are fetched here and queued at depth 1, so a declared endpoint is
    // assessed even when nothing links to it.
    let declared = declared_endpoints(probe, &origin).await;
    for endpoint in &declared {
        if seen.insert(canonical(&endpoint.url)) {
            queue.push_back((endpoint.url.clone(), 1));
        }
    }

    while let Some((url, depth)) = queue.pop_front() {
        if pages.len() >= limits.max_pages {
            stopped = StopReason::PageLimit;
            not_visited.push(url);
            not_visited.extend(queue.into_iter().map(|(u, _)| u));
            break;
        }
        if started.elapsed() >= limits.budget {
            stopped = StopReason::TimeBudget;
            not_visited.push(url);
            not_visited.extend(queue.into_iter().map(|(u, _)| u));
            break;
        }
        if depth > limits.max_depth {
            stopped = StopReason::DepthLimit;
            not_visited.push(url);
            continue;
        }

        // `Ok(None)` is an out-of-scope URL or an unreachable host; neither is
        // fatal, and neither should stop the walk.
        let Ok(Some(page)) = probe.get(&url).await else { continue };
        if !is_readable(page.status) {
            continue;
        }

        if depth < limits.max_depth {
            for link in links_from(&page, &origin, limits.max_links_per_page, &mut external, &origin_host) {
                if seen.insert(canonical(&link)) {
                    queue.push_back((link, depth + 1));
                }
            }
            // A bundle's string literals are the only route list a
            // single-page application has.
            for endpoint in script_endpoints(&page, &origin) {
                if seen.insert(canonical(&endpoint.url)) {
                    queue.push_back((endpoint.url, depth + 1));
                }
            }
        }
        pages.push(page);
    }

    not_visited.truncate(200);
    let mut external_hosts: Vec<String> = external.into_iter().collect();
    external_hosts.sort();

    Crawl { pages, not_visited, declared, external_hosts, stopped_because: stopped }
}

/// Fetch the application's own descriptions of what it exposes.
///
/// Each is a single `GET` for a well-known path, and each is a document the
/// application publishes deliberately. Nothing is guessed.
async fn declared_endpoints(probe: &Probe, origin: &Url) -> Vec<Endpoint> {
    let base = origin.clone();
    let root = origin.as_str().trim_end_matches('/').to_string();
    let mut found: Vec<Endpoint> = Vec::new();

    // The API specification: the authoritative surface, written by the people
    // who built the service.
    for path in ["/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs"] {
        let Ok(Some(resp)) = probe.get(&format!("{root}{path}")).await else { continue };
        if !is_readable(resp.status) {
            continue;
        }
        let parsed = endpoints::from_openapi(&resp.body, &base);
        if !parsed.is_empty() {
            found.extend(parsed);
            break; // One specification is the specification.
        }
    }

    // robots.txt: a public list of what the operator did not want indexed.
    if let Ok(Some(resp)) = probe.get(&format!("{root}/robots.txt")).await {
        if is_readable(resp.status) {
            found.extend(endpoints::from_robots(&resp.body, &base));
        }
    }

    // sitemap.xml: pages that may have no inbound link at all.
    if let Ok(Some(resp)) = probe.get(&format!("{root}/sitemap.xml")).await {
        if is_readable(resp.status) {
            found.extend(endpoints::from_sitemap(&resp.body));
        }
    }

    endpoints::same_origin(found, &base)
}

/// Endpoints referenced from a script the crawl fetched.
fn script_endpoints(page: &ProbeResponse, origin: &Url) -> Vec<Endpoint> {
    let content_type = page.header("content-type").unwrap_or_default().to_lowercase();
    let is_script = content_type.contains("javascript") || content_type.contains("ecmascript");
    // Inline scripts live in HTML, so both are worth reading.
    if !is_script && !content_type.contains("text/html") {
        return Vec::new();
    }
    let base = Url::parse(&page.final_url).unwrap_or_else(|_| origin.clone());
    endpoints::same_origin(endpoints::from_javascript(&page.body, &base), origin)
}

/// Same-origin, fetchable links from one document.
///
/// Off-origin destinations are recorded in `external` and never returned: the
/// probe would refuse them anyway, but filtering here keeps the queue honest
/// and lets the report name the third-party origins the application depends on.
fn links_from(
    page: &ProbeResponse,
    origin: &Url,
    cap: usize,
    external: &mut HashSet<String>,
    origin_host: &str,
) -> Vec<String> {
    if !is_html(page) {
        return Vec::new();
    }
    let base = Url::parse(&page.final_url).unwrap_or_else(|_| origin.clone());
    let mut out = Vec::new();

    for raw in raw_references(&page.body) {
        let Ok(resolved) = base.join(&raw) else { continue };
        if !matches!(resolved.scheme(), "http" | "https") {
            continue;
        }
        let host = resolved.host_str().unwrap_or_default().to_ascii_lowercase();
        if host != origin_host {
            if !host.is_empty() {
                external.insert(host);
            }
            continue;
        }
        if is_uninteresting(&resolved) {
            continue;
        }
        out.push(resolved.to_string());
        if out.len() >= cap {
            break;
        }
    }
    out
}

/// Attribute values worth resolving: navigation, forms and same-origin scripts.
///
/// `action` is included because an endpoint that only appears as a form target
/// is exactly the kind of route that never gets assessed otherwise — it is read
/// and fetched with GET, never posted to.
fn raw_references(body: &str) -> Vec<String> {
    const ATTRS: &[&str] = &["href=", "src=", "action=", "data-href=", "data-url="];
    let mut found = Vec::new();
    let lower = body.to_lowercase();

    for attr in ATTRS {
        let mut cursor = 0usize;
        while let Some(offset) = lower[cursor..].find(attr) {
            let at = cursor + offset + attr.len();
            cursor = at;
            let rest = &body[at.min(body.len())..];
            let Some(quote) = rest.chars().next() else { break };
            if quote != '"' && quote != '\'' {
                continue;
            }
            let value_start = quote.len_utf8();
            let Some(end) = rest[value_start..].find(quote) else { continue };
            let value = rest[value_start..value_start + end].trim();
            if value.is_empty() || value.starts_with('#') {
                continue;
            }
            found.push(value.to_string());
            if found.len() >= 400 {
                return found;
            }
        }
    }
    found
}

/// Assets that cannot carry the weaknesses these checks look for.
///
/// Images and fonts have no headers worth a second finding and no body worth
/// reading, and fetching them burns the page budget on nothing. Scripts and
/// stylesheets are *not* excluded — a bundle is where a leaked credential
/// actually lives.
fn is_uninteresting(url: &Url) -> bool {
    const SKIP: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico", ".bmp",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".mp4", ".webm", ".mp3", ".wav", ".ogg", ".avi", ".mov",
        ".zip", ".gz", ".tar", ".7z", ".rar", ".dmg", ".exe", ".msi",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ];
    let path = url.path().to_ascii_lowercase();
    SKIP.iter().any(|ext| path.ends_with(ext))
}

/// The form of a URL used for the visited set.
///
/// The fragment is dropped — `/page` and `/page#section` are one document, and
/// treating them as two wastes the page budget on duplicates. The query string
/// is kept, because `?id=1` and `?id=2` really can be different pages.
fn canonical(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut u) => {
            u.set_fragment(None);
            u.to_string().trim_end_matches('/').to_ascii_lowercase()
        }
        Err(_) => url.trim_end_matches('/').to_ascii_lowercase(),
    }
}

fn is_html(page: &ProbeResponse) -> bool {
    page.header("content-type")
        .map(|ct| ct.to_lowercase().contains("text/html"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    fn page(url: &str, body: &str, content_type: &str) -> ProbeResponse {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_str(content_type).unwrap());
        ProbeResponse {
            url: url.to_string(),
            final_url: url.to_string(),
            status: 200,
            headers,
            body: body.to_string(),
            body_truncated: false,
            elapsed_ms: 1,
        }
    }

    fn extract(body: &str) -> (Vec<String>, Vec<String>) {
        let origin = Url::parse("https://app.test/").unwrap();
        let p = page("https://app.test/", body, "text/html");
        let mut external = HashSet::new();
        let links = links_from(&p, &origin, 60, &mut external, "app.test");
        let mut ext: Vec<String> = external.into_iter().collect();
        ext.sort();
        (links, ext)
    }

    #[test]
    fn relative_and_absolute_same_origin_links_are_followed() {
        let (links, _) = extract(
            r#"<a href="/about">a</a><a href="contact">b</a><a href="https://app.test/pricing">c</a>"#,
        );
        assert!(links.contains(&"https://app.test/about".to_string()), "{links:?}");
        assert!(links.contains(&"https://app.test/contact".to_string()), "{links:?}");
        assert!(links.contains(&"https://app.test/pricing".to_string()), "{links:?}");
    }

    /// A form target is often the only reference to an endpoint anywhere in the
    /// markup, and it is exactly the sort of route that goes unassessed.
    #[test]
    fn form_actions_are_discovered_but_never_submitted() {
        let (links, _) = extract(r#"<form action="/api/login" method="post"></form>"#);
        assert_eq!(links, vec!["https://app.test/api/login".to_string()]);
        // The crawler only ever calls `probe.get`; `Probe` itself refuses
        // anything outside GET/HEAD/OPTIONS, which is asserted in probe.rs.
    }

    #[test]
    fn off_origin_links_are_recorded_and_not_queued() {
        let (links, external) = extract(
            r#"<a href="https://evil.test/x">x</a><script src="https://cdn.test/a.js"></script>"#,
        );
        assert!(links.is_empty(), "off-origin URLs must never be queued: {links:?}");
        assert_eq!(external, vec!["cdn.test".to_string(), "evil.test".to_string()]);
    }

    /// A bundle is where a leaked credential actually lives, so scripts and
    /// stylesheets must stay in the queue even though images do not.
    #[test]
    fn scripts_are_crawled_and_binary_assets_are_not() {
        let (links, _) = extract(
            r#"<script src="/static/app.js"></script>
               <link rel="stylesheet" href="/static/app.css">
               <img src="/img/logo.png">
               <a href="/manual.pdf">manual</a>"#,
        );
        assert!(links.iter().any(|l| l.ends_with("app.js")), "{links:?}");
        assert!(links.iter().any(|l| l.ends_with("app.css")), "{links:?}");
        assert!(!links.iter().any(|l| l.ends_with(".png")), "{links:?}");
        assert!(!links.iter().any(|l| l.ends_with(".pdf")), "{links:?}");
    }

    #[test]
    fn non_http_schemes_are_ignored() {
        let (links, external) = extract(
            r#"<a href="mailto:x@app.test">m</a><a href="tel:+1">t</a><a href="javascript:void(0)">j</a>"#,
        );
        assert!(links.is_empty());
        assert!(external.is_empty(), "a mailto host is not a third-party origin");
    }

    #[test]
    fn a_bare_fragment_is_not_a_page() {
        let (links, _) = extract(r##"<a href="#main">skip</a>"##);
        assert!(links.is_empty());
    }

    /// Fragments would otherwise multiply one document into as many entries as
    /// it has anchors, and exhaust the page budget on itself.
    #[test]
    fn the_same_document_under_different_fragments_is_one_page() {
        assert_eq!(canonical("https://app.test/docs#intro"), canonical("https://app.test/docs#api"));
        // A query string is a different page, though.
        assert_ne!(canonical("https://app.test/p?id=1"), canonical("https://app.test/p?id=2"));
    }

    #[test]
    fn links_are_only_taken_from_html() {
        let origin = Url::parse("https://app.test/").unwrap();
        let json = page("https://app.test/api", r#"{"href":"/secret"}"#, "application/json");
        let mut external = HashSet::new();
        assert!(links_from(&json, &origin, 60, &mut external, "app.test").is_empty());
    }

    #[test]
    fn one_page_cannot_fill_the_queue_on_its_own() {
        let body: String = (0..500)
            .map(|i| format!(r#"<a href="/p{i}">{i}</a>"#))
            .collect();
        let origin = Url::parse("https://app.test/").unwrap();
        let p = page("https://app.test/", &body, "text/html");
        let mut external = HashSet::new();
        assert_eq!(links_from(&p, &origin, 60, &mut external, "app.test").len(), 60);
    }

    #[test]
    fn single_quoted_attributes_are_handled() {
        let (links, _) = extract(r#"<a href='/single'>x</a>"#);
        assert_eq!(links, vec!["https://app.test/single".to_string()]);
    }

    #[test]
    fn every_stop_reason_explains_itself_for_the_report() {
        for reason in [
            StopReason::Exhausted,
            StopReason::PageLimit,
            StopReason::DepthLimit,
            StopReason::TimeBudget,
        ] {
            assert!(!reason.describe().is_empty());
        }
        assert!(StopReason::PageLimit.describe().contains("not assessed"));
    }
}
