//! Inline SVG chart rendering for reports.
//!
//! Charts are emitted as literal SVG markup with no JavaScript and no external
//! resources, so a report file remains a single self-contained document that
//! renders identically in a browser, in an email client, and when printed to PDF.

use crate::models::finding::Severity;

/// Severity palette shared by every chart, the finding tables and the UI, so a
/// colour always means the same thing wherever it appears.
pub fn severity_color(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "#b91c1c",
        Severity::High => "#ea580c",
        Severity::Medium => "#ca8a04",
        Severity::Low => "#0284c7",
        Severity::Info => "#64748b",
    }
}

pub fn severity_name(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Informational",
    }
}

/// One slice or bar.
#[derive(Debug, Clone)]
pub struct Slice {
    pub label: String,
    pub value: usize,
    pub color: String,
}

impl Slice {
    pub fn new(label: &str, value: usize, color: &str) -> Self {
        Self { label: label.to_string(), value, color: color.to_string() }
    }
}

/// Render a donut chart with a centred total.
///
/// Returns an empty-state donut when every value is zero, so the report never
/// contains a broken or invisible graphic.
pub fn donut(slices: &[Slice], center_label: &str) -> String {
    let total: usize = slices.iter().map(|s| s.value).sum();
    let (cx, cy, r, stroke) = (90.0_f64, 90.0_f64, 66.0_f64, 26.0_f64);
    let circumference = 2.0 * std::f64::consts::PI * r;

    let mut segments = String::new();

    if total == 0 {
        segments.push_str(&format!(
            r##"<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#e2e8f0" stroke-width="{stroke}"/>"##
        ));
    } else {
        let mut offset = 0.0_f64;
        for slice in slices.iter().filter(|s| s.value > 0) {
            let fraction = slice.value as f64 / total as f64;
            let length = fraction * circumference;
            segments.push_str(&format!(
                r##"<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="{stroke}" stroke-dasharray="{length:.3} {rest:.3}" stroke-dashoffset="{dashoffset:.3}" transform="rotate(-90 {cx} {cy})"><title>{label}: {value}</title></circle>"##,
                color = slice.color,
                length = length,
                rest = circumference - length,
                dashoffset = -offset,
                label = crate::reporting::escape::html(&slice.label),
                value = slice.value,
            ));
            offset += length;
        }
    }

    format!(
        r##"<svg viewBox="0 0 180 180" width="180" height="180" role="img" aria-label="{aria}" xmlns="http://www.w3.org/2000/svg">
  {segments}
  <text x="{cx}" y="{ty}" text-anchor="middle" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="34" font-weight="700" fill="#0f172a">{total}</text>
  <text x="{cx}" y="{ly}" text-anchor="middle" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="11" letter-spacing="0.5" fill="#64748b">{center}</text>
</svg>"##,
        aria = crate::reporting::escape::html(&format!("{center_label}: {total}")),
        ty = cy + 6.0,
        ly = cy + 24.0,
        center = crate::reporting::escape::html(center_label),
    )
}

/// Render a horizontal bar chart. Bars are scaled against the largest value.
pub fn horizontal_bars(slices: &[Slice], width: f64) -> String {
    if slices.is_empty() {
        return String::new();
    }
    let max = slices.iter().map(|s| s.value).max().unwrap_or(0).max(1);
    let row_height = 26.0_f64;
    let label_width = 108.0_f64;
    let value_width = 44.0_f64;
    let track = (width - label_width - value_width).max(40.0);
    let height = row_height * slices.len() as f64;

    let mut rows = String::new();
    for (i, slice) in slices.iter().enumerate() {
        let y = i as f64 * row_height;
        let bar_len = (slice.value as f64 / max as f64) * track;
        rows.push_str(&format!(
            r##"<text x="0" y="{ty:.1}" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="12" fill="#334155">{label}</text>
  <rect x="{lx}" y="{by:.1}" width="{track:.1}" height="12" rx="6" fill="#f1f5f9"/>
  <rect x="{lx}" y="{by:.1}" width="{bar:.1}" height="12" rx="6" fill="{color}"><title>{label}: {value}</title></rect>
  <text x="{vx}" y="{ty:.1}" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="12" font-weight="600" fill="#0f172a">{value}</text>
"##,
            ty = y + 15.0,
            by = y + 5.0,
            lx = label_width,
            vx = label_width + track + 10.0,
            bar = bar_len,
            color = slice.color,
            label = crate::reporting::escape::html(&slice.label),
            value = slice.value,
        ));
    }

    format!(
        r##"<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" aria-label="Bar chart" xmlns="http://www.w3.org/2000/svg">
  {rows}
</svg>"##
    )
}

/// Render a segmented coverage bar: passed / issues / not tested / manual.
pub fn stacked_bar(slices: &[Slice], width: f64, height: f64) -> String {
    let total: usize = slices.iter().map(|s| s.value).sum();
    if total == 0 {
        return format!(
            r##"<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" xmlns="http://www.w3.org/2000/svg"><rect x="0" y="0" width="{width}" height="{height}" rx="{r}" fill="#e2e8f0"/></svg>"##,
            r = height / 2.0
        );
    }

    let mut x = 0.0_f64;
    let mut segments = String::new();
    for slice in slices.iter().filter(|s| s.value > 0) {
        let w = (slice.value as f64 / total as f64) * width;
        segments.push_str(&format!(
            r##"<rect x="{x:.2}" y="0" width="{w:.2}" height="{height}" fill="{color}"><title>{label}: {value}</title></rect>"##,
            color = slice.color,
            label = crate::reporting::escape::html(&slice.label),
            value = slice.value,
        ));
        x += w;
    }

    format!(
        r##"<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" aria-label="Coverage breakdown" xmlns="http://www.w3.org/2000/svg">
  <clipPath id="coverage-clip"><rect x="0" y="0" width="{width}" height="{height}" rx="{r}"/></clipPath>
  <g clip-path="url(#coverage-clip)">{segments}</g>
</svg>"##,
        r = height / 2.0
    )
}

/// Render a 0–100 gauge used for the overall security posture score.
pub fn posture_gauge(score: f64, band_label: &str, band_color: &str) -> String {
    let score = score.clamp(0.0, 100.0);
    let (cx, cy, r) = (100.0_f64, 100.0_f64, 76.0_f64);
    // Semicircular gauge: 180° of arc mapped onto 0–100.
    let circumference = std::f64::consts::PI * r;
    let filled = (score / 100.0) * circumference;

    format!(
        r##"<svg viewBox="0 0 200 124" width="200" height="124" role="img" aria-label="{aria}" xmlns="http://www.w3.org/2000/svg">
  <path d="M {x0} {cy} A {r} {r} 0 0 1 {x1} {cy}" fill="none" stroke="#e2e8f0" stroke-width="18" stroke-linecap="round"/>
  <path d="M {x0} {cy} A {r} {r} 0 0 1 {x1} {cy}" fill="none" stroke="{band_color}" stroke-width="18" stroke-linecap="round" stroke-dasharray="{filled:.3} {rest:.3}"/>
  <text x="{cx}" y="{sy}" text-anchor="middle" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="36" font-weight="700" fill="#0f172a">{score:.0}</text>
  <text x="{cx}" y="{by}" text-anchor="middle" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="12" font-weight="600" fill="{band_color}">{band}</text>
</svg>"##,
        x0 = cx - r,
        x1 = cx + r,
        rest = circumference - filled,
        sy = cy - 10.0,
        by = cy + 12.0,
        band = crate::reporting::escape::html(band_label),
        aria = crate::reporting::escape::html(&format!("Security posture score {score:.0} out of 100, rated {band_label}")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slices() -> Vec<Slice> {
        vec![
            Slice::new("Critical", 2, "#b91c1c"),
            Slice::new("High", 5, "#ea580c"),
            Slice::new("Medium", 8, "#ca8a04"),
        ]
    }

    #[test]
    fn donut_renders_a_segment_per_non_zero_slice() {
        let svg = donut(&slices(), "FINDINGS");
        assert_eq!(svg.matches("<circle").count(), 3);
        assert!(svg.contains(">15<"), "total should be rendered in the centre");
    }

    #[test]
    fn donut_skips_zero_valued_slices() {
        let with_zero = vec![Slice::new("Critical", 0, "#b91c1c"), Slice::new("High", 3, "#ea580c")];
        let svg = donut(&with_zero, "FINDINGS");
        assert_eq!(svg.matches("<circle").count(), 1);
    }

    #[test]
    fn donut_with_no_findings_renders_an_empty_ring_not_a_broken_chart() {
        let svg = donut(&[Slice::new("Critical", 0, "#b91c1c")], "FINDINGS");
        assert!(svg.contains("#e2e8f0"), "empty state should draw a grey ring");
        assert!(svg.contains(">0<"));
    }

    #[test]
    fn donut_segments_never_exceed_the_circumference() {
        let svg = donut(&slices(), "FINDINGS");
        // Every dasharray remainder must be non-negative; a negative value would
        // mean a slice overflowed the ring.
        for chunk in svg.split("stroke-dasharray=\"").skip(1) {
            let arr = chunk.split('"').next().unwrap();
            let rest: f64 = arr.split_whitespace().nth(1).unwrap().parse().unwrap();
            assert!(rest >= -0.001, "segment overflowed the ring: {arr}");
        }
    }

    #[test]
    fn chart_labels_are_html_escaped() {
        let evil = vec![Slice::new("<script>alert(1)</script>", 3, "#000")];
        let svg = donut(&evil, "FINDINGS");
        assert!(!svg.contains("<script>"));
        assert!(svg.contains("&lt;script&gt;"));
    }

    #[test]
    fn bar_chart_label_escaping_applies_too() {
        let evil = vec![Slice::new("\"><script>x</script>", 1, "#000")];
        let svg = horizontal_bars(&evil, 400.0);
        assert!(!svg.contains("<script>"));
    }

    #[test]
    fn horizontal_bars_render_one_row_per_slice() {
        let svg = horizontal_bars(&slices(), 400.0);
        assert_eq!(svg.matches("<title>").count(), 3);
    }

    #[test]
    fn horizontal_bars_of_nothing_renders_nothing() {
        assert!(horizontal_bars(&[], 400.0).is_empty());
    }

    #[test]
    fn stacked_bar_segments_sum_to_the_full_width() {
        let svg = stacked_bar(&slices(), 600.0, 14.0);
        // Sum only the coloured segments, identified by their x/width pair,
        // ignoring the outer <svg> and the clip-path rect.
        let widths: f64 = svg
            .match_indices("<rect x=\"")
            .filter_map(|(i, _)| {
                let tag = &svg[i..];
                // Segment rects wrap a <title>, so they close with '>' not '/>'.
                let end = tag.find('>')?;
                let tag = &tag[..end];
                // The clip rect starts at x="0" with the full width; segments carry a fill.
                if !tag.contains("fill=\"#") {
                    return None;
                }
                let w = tag.split("width=\"").nth(1)?.split('"').next()?;
                w.parse::<f64>().ok()
            })
            .sum();
        assert!((widths - 600.0).abs() < 1.0, "segments summed to {widths}, expected 600");
    }

    #[test]
    fn stacked_bar_with_no_data_renders_a_grey_track() {
        let svg = stacked_bar(&[], 600.0, 14.0);
        assert!(svg.contains("#e2e8f0"));
    }

    #[test]
    fn posture_gauge_clamps_out_of_range_scores() {
        assert!(posture_gauge(150.0, "Strong", "#16a34a").contains(">100<"));
        assert!(posture_gauge(-20.0, "Critical", "#b91c1c").contains(">0<"));
    }

    #[test]
    fn posture_gauge_includes_an_accessible_label() {
        let svg = posture_gauge(72.0, "Moderate", "#ca8a04");
        assert!(svg.contains("aria-label="));
        assert!(svg.contains("Moderate"));
    }

    #[test]
    fn every_severity_has_a_distinct_colour() {
        let all = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info];
        let mut colors: Vec<&str> = all.iter().map(severity_color).collect();
        colors.sort_unstable();
        let before = colors.len();
        colors.dedup();
        assert_eq!(before, colors.len(), "severity colours must be distinguishable");
    }

    #[test]
    fn charts_contain_no_script_or_external_references() {
        let svg = format!(
            "{}{}{}",
            donut(&slices(), "FINDINGS"),
            horizontal_bars(&slices(), 400.0),
            posture_gauge(50.0, "Moderate", "#ca8a04")
        );
        assert!(!svg.contains("<script"));
        assert!(!svg.to_lowercase().contains("onload"));
        // The SVG xmlns is a namespace identifier, not a fetch. What must be
        // absent is anything that would load a remote resource.
        assert!(!svg.contains("<image"));
        assert!(!svg.contains("xlink:href"));
        assert!(!svg.contains("url(http"));
        assert!(!svg.contains("@import"));
    }
}
