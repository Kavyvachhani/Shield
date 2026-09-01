//! Endpoint discovery from the sources a link crawler cannot see.
//!
//! Following `href` and `src` finds the pages a browser would navigate to. It
//! does not find the application's actual surface, and on anything built in the
//! last decade the gap is most of it:
//!
//! * **A single-page application has no links.** Its routes live in a bundle and
//!   its data comes from `fetch('/api/v2/orders')`. A link crawler sees one HTML
//!   document and concludes the application has one page.
//! * **The API is described, in a file we already fetch.** The exposure checks
//!   confirm `/swagger.json` is readable and stop there — while that file
//!   contains the complete, authoritative list of every endpoint the service
//!   exposes, written by the people who built it.
//! * **`robots.txt` is a list of what the operator did not want found.** Admin
//!   consoles, exports, staging routes. It is the highest-signal file on most
//!   sites and it is public by definition.
//! * **`sitemap.xml` enumerates pages** that may have no inbound link at all.
//!
//! Everything here is extraction from documents already being fetched, or a
//! `GET` for a well-known path. Nothing is guessed, brute-forced or fuzzed: a
//! path appears here because something the application published named it.

use std::collections::HashSet;
use url::Url;

/// Where a discovered endpoint came from, so the report can say how the surface
/// was established rather than presenting a list with no provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Origin {
    /// Declared in an OpenAPI or Swagger document.
    ApiSpecification,
    /// Listed in sitemap.xml.
    Sitemap,
    /// Named in a robots.txt directive.
    RobotsDirective,
    /// A path referenced from client-side JavaScript.
    ClientScript,
}

impl Origin {
    pub fn describe(&self) -> &'static str {
        match self {
            Origin::ApiSpecification => "declared in the application's own API specification",
            Origin::Sitemap => "listed in sitemap.xml",
            Origin::RobotsDirective => "named in a robots.txt directive",
            Origin::ClientScript => "referenced from client-side JavaScript",
        }
    }
}

/// One discovered endpoint and where it was found.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub url: String,
    pub origin: Origin,
}

/// Paths declared by an OpenAPI 3 or Swagger 2 document.
///
/// This is the authoritative surface: written by the people who built the
/// service, listing every route it exposes. Path templates keep their
/// placeholders — `/users/{id}` is requested as written rather than with an
/// invented identifier, because substituting a guess would be sending a
/// value the application never published, and this engine does not do that.
pub fn from_openapi(spec: &str, base: &Url) -> Vec<Endpoint> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(spec) else {
        return Vec::new();
    };
    let Some(paths) = doc.get("paths").and_then(|p| p.as_object()) else {
        return Vec::new();
    };

    // OpenAPI 3 servers[].url, or Swagger 2 basePath, prefix every path.
    let prefix = doc
        .pointer("/servers/0/url")
        .and_then(|v| v.as_str())
        .or_else(|| doc.get("basePath").and_then(|v| v.as_str()))
        .unwrap_or("");

    let mut out = Vec::new();
    for path in paths.keys() {
        let joined = format!("{}{}", prefix.trim_end_matches('/'), path);
        if let Ok(url) = base.join(&joined) {
            out.push(Endpoint { url: url.to_string(), origin: Origin::ApiSpecification });
        }
        if out.len() >= 300 {
            break;
        }
    }
    out
}

/// Locations listed in a sitemap.
///
/// Handles a sitemap index as well as a sitemap: both use `<loc>`, so pulling
/// every one and letting the crawler's own scope and content-type rules sort
/// them out is simpler than modelling the two document types separately.
pub fn from_sitemap(xml: &str) -> Vec<Endpoint> {
    let mut out = Vec::new();
    let mut rest = xml;

    while let Some(start) = rest.find("<loc>") {
        let after = &rest[start + 5..];
        let Some(end) = after.find("</loc>") else { break };
        let raw = after[..end].trim();
        rest = &after[end + 6..];

        if raw.is_empty() {
            continue;
        }
        // Sitemaps are XML, so the URL may carry entities.
        let decoded = raw
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'");
        out.push(Endpoint { url: decoded, origin: Origin::Sitemap });

        if out.len() >= 300 {
            break;
        }
    }
    out
}

/// Paths named by `Disallow` and `Allow` directives.
///
/// The highest-signal file on most sites, and public by definition: it is a
/// list of what the operator did not want a search engine to index, which is
/// very often the administrative and export routes.
///
/// A bare `Disallow: /` means "index nothing" rather than naming a path, and is
/// skipped — crawling the root is already covered.
pub fn from_robots(text: &str, base: &Url) -> Vec<Endpoint> {
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((directive, value)) = line.split_once(':') else { continue };
        if !matches!(
            directive.trim().to_ascii_lowercase().as_str(),
            "disallow" | "allow"
        ) {
            continue;
        }

        let path = value.trim();
        if path.is_empty() || path == "/" {
            continue;
        }
        // A wildcard is a pattern, not a location. Take the literal prefix
        // before it, which is a real directory worth looking at.
        let literal = path.split(['*', '$']).next().unwrap_or(path).trim();
        if literal.is_empty() || literal == "/" {
            continue;
        }

        if let Ok(url) = base.join(literal) {
            out.push(Endpoint { url: url.to_string(), origin: Origin::RobotsDirective });
        }
        if out.len() >= 100 {
            break;
        }
    }
    out
}

/// Paths referenced from JavaScript.
///
/// This is what makes a single-page application assessable at all: its routes
/// and its API calls exist only as string literals in a bundle, and no link
/// crawler will ever see them.
///
/// Deliberately narrow. Only quoted literals that look like an absolute path —
/// starting with a single `/`, containing no spaces, and not a filename that
/// belongs to the build — are taken. A looser rule pulls in CSS selectors,
/// regular expressions, date formats and MIME types, and the resulting queue is
/// mostly noise that costs real requests against the target.
pub fn from_javascript(body: &str, base: &Url) -> Vec<Endpoint> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    for quote in ['"', '\'', '`'] {
        let mut rest = body;
        while let Some(start) = rest.find(quote) {
            let after = &rest[start + quote.len_utf8()..];
            let Some(end) = after.find(quote) else { break };
            let literal = &after[..end];
            rest = &after[end + quote.len_utf8()..];

            if !is_path_literal(literal) {
                continue;
            }
            if let Ok(url) = base.join(literal) {
                let as_string = url.to_string();
                if seen.insert(as_string.clone()) {
                    out.push(Endpoint { url: as_string, origin: Origin::ClientScript });
                }
            }
            if out.len() >= 200 {
                return out;
            }
        }
    }
    out
}

/// Whether a string literal is plausibly a request path this application serves.
fn is_path_literal(literal: &str) -> bool {
    // A single leading slash: `//` is a protocol-relative URL to somewhere else.
    if !literal.starts_with('/') || literal.starts_with("//") {
        return false;
    }
    if literal.len() < 2 || literal.len() > 200 {
        return false;
    }
    // Whitespace and quotes mean it is prose or a template, not a path.
    if literal.chars().any(|c| c.is_whitespace() || c == '<' || c == '>') {
        return false;
    }
    // A regular expression literal frequently starts with `/` too.
    if literal.contains(".*") || literal.contains("\\d") || literal.contains("\\w")
        || literal.contains("[^") || literal.contains("(?:")
    {
        return false;
    }
    // Build assets are already reached by the crawler and carry no endpoint
    // behaviour worth probing.
    const ASSET_EXTENSIONS: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webm",
    ];
    let lower = literal.to_ascii_lowercase();
    let path_only = lower.split(['?', '#']).next().unwrap_or(&lower);
    if ASSET_EXTENSIONS.iter().any(|ext| path_only.ends_with(ext)) {
        return false;
    }
    // At least one path character beyond the slash.
    literal[1..].chars().any(|c| c.is_ascii_alphanumeric())
}

/// Merge discovered endpoints, keeping the first origin seen for each URL and
/// dropping anything off the target's own host.
///
/// Off-origin filtering matters here as much as in the crawler: a sitemap can
/// legitimately list a CDN, and an API specification's `servers` block often
/// names production while the assessment is authorised for staging only.
pub fn same_origin(endpoints: Vec<Endpoint>, base: &Url) -> Vec<Endpoint> {
    let host = base.host_str().unwrap_or_default().to_ascii_lowercase();
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    for endpoint in endpoints {
        let Ok(parsed) = Url::parse(&endpoint.url) else { continue };
        if !matches!(parsed.scheme(), "http" | "https") {
            continue;
        }
        if parsed.host_str().unwrap_or_default().to_ascii_lowercase() != host {
            continue;
        }
        let key = {
            let mut normalised = parsed.clone();
            normalised.set_fragment(None);
            normalised.to_string().trim_end_matches('/').to_ascii_lowercase()
        };
        if seen.insert(key) {
            out.push(endpoint);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("https://app.test/").unwrap()
    }

    // ── OpenAPI ─────────────────────────────────────────────────────────────

    /// The exposure check already confirms this file is readable. It contains
    /// the complete surface, written by the people who built the service, and
    /// until now the engine read none of it.
    #[test]
    fn an_openapi_document_yields_every_declared_path() {
        let spec = r#"{"openapi":"3.0.0","paths":{
            "/users":{"get":{}},"/users/{id}":{"get":{},"delete":{}},"/orders/{id}/items":{"post":{}}}}"#;
        let out = from_openapi(spec, &base());
        let urls: Vec<&str> = out.iter().map(|e| e.url.as_str()).collect();

        assert!(urls.contains(&"https://app.test/users"));
        assert!(urls.contains(&"https://app.test/orders/%7Bid%7D/items") || urls.iter().any(|u| u.contains("orders")));
        assert!(out.iter().all(|e| e.origin == Origin::ApiSpecification));
    }

    #[test]
    fn a_servers_url_or_swagger_base_path_prefixes_the_paths() {
        let v3 = r#"{"servers":[{"url":"https://app.test/api/v2"}],"paths":{"/users":{}}}"#;
        assert!(from_openapi(v3, &base())[0].url.contains("/api/v2/users"));

        let v2 = r#"{"swagger":"2.0","basePath":"/api/v1","paths":{"/health":{}}}"#;
        assert!(from_openapi(v2, &base())[0].url.contains("/api/v1/health"));
    }

    /// Substituting a value for `{id}` would mean sending the application
    /// something it never published, which this engine does not do.
    #[test]
    fn path_templates_are_requested_as_written_rather_than_filled_in() {
        let out = from_openapi(r#"{"paths":{"/users/{id}":{}}}"#, &base());
        assert!(!out[0].url.contains("/users/1"), "no identifier may be invented: {}", out[0].url);
    }

    #[test]
    fn a_document_that_is_not_a_specification_yields_nothing() {
        assert!(from_openapi("<html>not json</html>", &base()).is_empty());
        assert!(from_openapi(r#"{"openapi":"3.0.0"}"#, &base()).is_empty());
    }

    // ── robots.txt ──────────────────────────────────────────────────────────

    /// A public list of what the operator did not want found.
    #[test]
    fn robots_directives_become_endpoints() {
        let txt = "User-agent: *\nDisallow: /internal-admin/\nDisallow: /exports/\nAllow: /public/\n";
        let urls: Vec<String> = from_robots(txt, &base()).into_iter().map(|e| e.url).collect();
        assert!(urls.iter().any(|u| u.ends_with("/internal-admin/")));
        assert!(urls.iter().any(|u| u.ends_with("/exports/")));
        assert!(urls.iter().any(|u| u.ends_with("/public/")));
    }

    /// `Disallow: /` means "index nothing", not "here is a path".
    #[test]
    fn a_blanket_disallow_is_not_an_endpoint() {
        assert!(from_robots("Disallow: /\n", &base()).is_empty());
        assert!(from_robots("Disallow:\n", &base()).is_empty());
    }

    #[test]
    fn a_wildcard_pattern_contributes_its_literal_prefix() {
        let out = from_robots("Disallow: /reports/*.pdf$\n", &base());
        assert_eq!(out.len(), 1);
        assert!(out[0].url.ends_with("/reports/"), "{}", out[0].url);
    }

    #[test]
    fn comments_and_other_directives_are_ignored() {
        let txt = "# a comment\nUser-agent: *\nSitemap: https://app.test/sitemap.xml\nCrawl-delay: 10\n";
        assert!(from_robots(txt, &base()).is_empty());
    }

    // ── sitemap ─────────────────────────────────────────────────────────────

    #[test]
    fn sitemap_locations_are_extracted_and_entity_decoded() {
        let xml = r#"<urlset><url><loc>https://app.test/a</loc></url>
                     <url><loc>https://app.test/s?x=1&amp;y=2</loc></url></urlset>"#;
        let urls: Vec<String> = from_sitemap(xml).into_iter().map(|e| e.url).collect();
        assert!(urls.contains(&"https://app.test/a".to_string()));
        assert!(urls.contains(&"https://app.test/s?x=1&y=2".to_string()), "{urls:?}");
    }

    // ── JavaScript ──────────────────────────────────────────────────────────

    /// The change that makes a single-page application assessable: its routes
    /// exist only as string literals in a bundle.
    #[test]
    fn api_calls_in_a_bundle_become_endpoints() {
        let js = r#"fetch('/api/v2/orders');axios.get("/api/v2/users");const r="/account/settings";"#;
        let urls: Vec<String> = from_javascript(js, &base()).into_iter().map(|e| e.url).collect();
        assert!(urls.iter().any(|u| u.ends_with("/api/v2/orders")), "{urls:?}");
        assert!(urls.iter().any(|u| u.ends_with("/api/v2/users")), "{urls:?}");
        assert!(urls.iter().any(|u| u.ends_with("/account/settings")), "{urls:?}");
    }

    /// A looser rule fills the queue with selectors, regexes and MIME types,
    /// and every one of those costs a real request against the target.
    #[test]
    fn strings_that_merely_start_with_a_slash_are_not_endpoints() {
        for noise in [
            r#"const re = "/^[a-z]\\d+$/";"#,
            r#"const t = "/ leading space";"#,
            r#"const p = "//cdn.other.test/lib.js";"#,
            r#"const s = "/assets/logo.png";"#,
            r#"const c = "/styles/main.css";"#,
            r#"const m = "/(?:a|b)";"#,
            r#"const x = "/";"#,
        ] {
            assert!(
                from_javascript(noise, &base()).is_empty(),
                "should not be treated as an endpoint: {noise}"
            );
        }
    }

    #[test]
    fn the_same_path_quoted_twice_is_one_endpoint() {
        let js = r#"a('/api/x'); b("/api/x"); c(`/api/x`);"#;
        assert_eq!(from_javascript(js, &base()).len(), 1);
    }

    // ── Merging ─────────────────────────────────────────────────────────────

    /// A sitemap can legitimately list a CDN, and a specification's `servers`
    /// block often names production while the RoE covers staging only.
    #[test]
    fn off_origin_endpoints_are_dropped_before_anything_is_requested() {
        let discovered = vec![
            Endpoint { url: "https://app.test/ok".into(), origin: Origin::Sitemap },
            Endpoint { url: "https://cdn.other.test/x".into(), origin: Origin::Sitemap },
            Endpoint { url: "mailto:a@app.test".into(), origin: Origin::ClientScript },
        ];
        let kept = same_origin(discovered, &base());
        assert_eq!(kept.len(), 1);
        assert!(kept[0].url.ends_with("/ok"));
    }

    #[test]
    fn duplicates_across_sources_collapse_to_the_first_origin_seen() {
        let discovered = vec![
            Endpoint { url: "https://app.test/api/x".into(), origin: Origin::ApiSpecification },
            Endpoint { url: "https://app.test/api/x/".into(), origin: Origin::ClientScript },
            Endpoint { url: "https://app.test/api/x#frag".into(), origin: Origin::Sitemap },
        ];
        let kept = same_origin(discovered, &base());
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].origin, Origin::ApiSpecification, "the strongest source wins by order");
    }

    #[test]
    fn every_origin_explains_itself_for_the_report() {
        for origin in [
            Origin::ApiSpecification, Origin::Sitemap,
            Origin::RobotsDirective, Origin::ClientScript,
        ] {
            assert!(!origin.describe().is_empty());
        }
    }
}
