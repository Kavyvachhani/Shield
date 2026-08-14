//! HTML escaping for report rendering.
//!
//! Report content is not trusted input. Finding titles, affected URLs, response
//! headers and page extracts all originate from the assessed target, which is by
//! definition potentially hostile. Interpolating them into HTML unescaped would
//! both corrupt the report and let a target inject script into a document the
//! client is about to open — so every interpolation goes through this module.

/// Escape text for an HTML text node or a double-quoted attribute value.
pub fn html(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Escape text and convert newlines to `<br>` for multi-line prose.
pub fn html_multiline(input: &str) -> String {
    html(input).replace('\n', "<br>")
}

/// Escape a value destined for a `url(...)` or `href` attribute.
///
/// Rejects any scheme capable of executing script; the caller receives `#` for
/// anything that is not a plain http(s), mailto or relative URL.
pub fn href(input: &str) -> String {
    let trimmed = input.trim();
    let lower = trimmed.to_lowercase();
    let scheme_is_safe = lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("mailto:")
        || lower.starts_with('/')
        || lower.starts_with('#');
    if !scheme_is_safe {
        return "#".to_string();
    }
    html(trimmed)
}

/// Escape a `data:` image URI for use as a logo `src`.
///
/// Only base64 image payloads are accepted; anything else yields `None` so the
/// report simply renders without a logo rather than embedding active content.
pub fn image_data_uri(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let lower = trimmed.to_lowercase();
    let allowed = [
        "data:image/png;base64,",
        "data:image/jpeg;base64,",
        "data:image/jpg;base64,",
        "data:image/gif;base64,",
        "data:image/webp;base64,",
    ];
    if !allowed.iter().any(|prefix| lower.starts_with(prefix)) {
        return None;
    }
    // SVG is deliberately excluded: it can carry script.
    let payload = trimmed.split_once(',')?.1;
    if payload.is_empty()
        || !payload
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return None;
    }
    Some(html(trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_tags_are_neutralised() {
        let escaped = html("<script>alert(1)</script>");
        assert!(!escaped.contains("<script>"));
        assert_eq!(escaped, "&lt;script&gt;alert(1)&lt;/script&gt;");
    }

    #[test]
    fn attribute_breakouts_are_neutralised() {
        let escaped = html(r#"" onload="alert(1)"#);
        assert!(!escaped.contains('"'));
        assert!(escaped.contains("&quot;"));
    }

    #[test]
    fn single_quotes_are_escaped_for_single_quoted_attributes() {
        assert_eq!(html("it's"), "it&#x27;s");
    }

    #[test]
    fn ampersands_are_escaped_first_and_only_once() {
        assert_eq!(html("a&b"), "a&amp;b");
        assert_eq!(html("&lt;"), "&amp;lt;");
    }

    #[test]
    fn ordinary_text_is_unchanged() {
        assert_eq!(html("Plain finding title 123"), "Plain finding title 123");
    }

    #[test]
    fn unicode_is_preserved() {
        assert_eq!(html("日本語 — café"), "日本語 — café");
    }

    #[test]
    fn multiline_becomes_line_breaks() {
        assert_eq!(html_multiline("a\nb"), "a<br>b");
        assert_eq!(html_multiline("<b>\n</b>"), "&lt;b&gt;<br>&lt;/b&gt;");
    }

    #[test]
    fn safe_schemes_survive_href_escaping() {
        assert_eq!(href("https://owasp.org/x"), "https://owasp.org/x");
        assert_eq!(href("/local/path"), "/local/path");
        assert_eq!(href("#anchor"), "#anchor");
    }

    #[test]
    fn javascript_urls_are_rejected() {
        assert_eq!(href("javascript:alert(1)"), "#");
        assert_eq!(href("JavaScript:alert(1)"), "#");
        assert_eq!(href("  javascript:alert(1)  "), "#");
        assert_eq!(href("data:text/html,<script>"), "#");
        assert_eq!(href("vbscript:msgbox"), "#");
    }

    #[test]
    fn href_still_escapes_quotes_in_safe_urls() {
        assert!(!href("https://x.test/\" onmouseover=\"alert(1)").contains('"'));
    }

    #[test]
    fn valid_png_data_uri_is_accepted() {
        let uri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==";
        assert_eq!(image_data_uri(uri).as_deref(), Some(uri));
    }

    #[test]
    fn svg_data_uri_is_rejected_because_it_can_carry_script() {
        assert!(image_data_uri("data:image/svg+xml;base64,PHN2Zz4=").is_none());
    }

    #[test]
    fn non_data_logo_paths_are_rejected() {
        assert!(image_data_uri("https://evil.test/logo.png").is_none());
        assert!(image_data_uri("/local/logo.png").is_none());
    }

    #[test]
    fn malformed_base64_payloads_are_rejected() {
        assert!(image_data_uri("data:image/png;base64,<script>").is_none());
        assert!(image_data_uri("data:image/png;base64,").is_none());
    }
}
