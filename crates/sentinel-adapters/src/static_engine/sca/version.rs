//! Deciding whether an installed version falls inside a vulnerable range.
//!
//! Every advisory database expresses "which versions are affected" as a set of
//! half-open intervals: introduced at one version, fixed at another. Answering
//! that question is the whole job of a dependency scanner, and getting it wrong
//! in either direction is expensive — a false negative ships a known-exploited
//! CVE, and a false positive sends a team to upgrade something that was never
//! affected.
//!
//! The hard part is that "version" means something different in every
//! ecosystem. `1.0.0-rc1` precedes `1.0.0` in semver; `1.0.0rc1` does the same
//! in Python but is spelled differently; Maven has qualifiers with their own
//! order; Go prefixes everything with `v`. Rather than implement each
//! specification, this uses one comparison that is *correct for the common
//! shape all of them share* — dot-separated numeric components, optionally
//! followed by a pre-release suffix that sorts before the release — and
//! deliberately declines to answer when it meets something it cannot order.
//!
//! Declining is the important part. A comparison that guesses produces a
//! confident wrong answer; one that returns [`Ordering::Equal`] for two
//! versions it cannot rank would silently mark them as matching. So
//! [`compare`] returns an `Option`, and a range that cannot be evaluated does
//! not match rather than matching by default.

use std::cmp::Ordering;

/// A version split into the parts that can be ordered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Numeric components, e.g. `1.2.3` → `[1, 2, 3]`.
    numeric: Vec<u64>,
    /// Pre-release identifiers, e.g. `-rc.1` → `["rc", "1"]`. Empty for a
    /// release, which sorts *after* any pre-release of the same numbers.
    pre: Vec<String>,
}

impl Version {
    /// Parse a version string, or `None` if nothing numeric can be found.
    ///
    /// Tolerant of the decorations ecosystems add — a leading `v`, an epoch
    /// prefix, build metadata after `+` — because those carry no ordering
    /// information and rejecting them would refuse to scan real lockfiles.
    pub fn parse(raw: &str) -> Option<Version> {
        let mut s = raw.trim();
        if s.is_empty() {
            return None;
        }
        // Leading `v` (Go, and common elsewhere).
        s = s.strip_prefix('v').or_else(|| s.strip_prefix('V')).unwrap_or(s);
        // Debian/RPM-style epoch: `1:2.3.4`. The epoch dominates ordering, but
        // it is not used by any ecosystem this scanner reads, so dropping it is
        // safe here and would not be in a distro scanner.
        if let Some((epoch, rest)) = s.split_once(':') {
            if epoch.chars().all(|c| c.is_ascii_digit()) {
                s = rest;
            }
        }
        // Build metadata is explicitly ignored by semver when ordering.
        if let Some((before, _)) = s.split_once('+') {
            s = before;
        }
        // Go pseudo-versions and module suffixes: `1.2.3-0.20210101120000-abcdef`
        // still parses, with the timestamp as a pre-release identifier.

        let (core, pre_raw) = split_prerelease(s);
        let numeric: Vec<u64> = core
            .split(['.', '_'])
            .take_while(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
            .filter_map(|part| part.parse().ok())
            .collect();
        if numeric.is_empty() {
            return None;
        }
        let pre = pre_raw
            .map(|p| {
                p.split(['.', '-'])
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        Some(Version { numeric, pre })
    }

    /// Whether this is a pre-release, which every ecosystem orders before the
    /// corresponding release.
    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

/// Split a version into its numeric core and its pre-release suffix.
///
/// Handles both spellings: `1.0.0-rc1` (semver, Maven, Go) and `1.0.0rc1`
/// (Python PEP 440), plus `1.0.0.beta` used by a few Java projects.
fn split_prerelease(s: &str) -> (&str, Option<&str>) {
    if let Some((core, pre)) = s.split_once('-') {
        return (core, Some(pre));
    }
    // PEP 440 glues the marker straight onto the number.
    for marker in ["rc", "a", "b", "alpha", "beta", "dev", "post", "pre"] {
        if let Some(idx) = find_marker(s, marker) {
            return (&s[..idx], Some(&s[idx..]));
        }
    }
    // A trailing dotted word: `1.0.0.Final`, `1.0.0.RELEASE`.
    if let Some(idx) = s.rfind('.') {
        let tail = &s[idx + 1..];
        if !tail.is_empty() && tail.chars().any(|c| c.is_ascii_alphabetic()) {
            return (&s[..idx], Some(tail));
        }
    }
    (s, None)
}

/// The index at which a PEP 440 pre-release marker begins, if any.
///
/// The marker must follow a digit, so the `b` in `1.0b2` is found but the `a`
/// inside a hex build identifier is not.
fn find_marker(s: &str, marker: &str) -> Option<usize> {
    let lower = s.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find(marker) {
        let idx = from + pos;
        let preceded_by_digit = idx > 0 && lower.as_bytes()[idx - 1].is_ascii_digit();
        if preceded_by_digit {
            return Some(idx);
        }
        from = idx + 1;
        if from >= lower.len() {
            break;
        }
    }
    None
}

/// Order two version strings, or `None` when either cannot be parsed.
///
/// `None` means "this scanner does not know", and every caller must treat it as
/// "no match" rather than as any particular ordering.
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    Some(compare_parsed(&Version::parse(a)?, &Version::parse(b)?))
}

fn compare_parsed(a: &Version, b: &Version) -> Ordering {
    // Missing trailing components are zero: 1.2 == 1.2.0 everywhere.
    let len = a.numeric.len().max(b.numeric.len());
    for i in 0..len {
        let x = a.numeric.get(i).copied().unwrap_or(0);
        let y = b.numeric.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    // Same numbers: a release outranks any pre-release of it.
    match (a.pre.is_empty(), b.pre.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => compare_prerelease(&a.pre, &b.pre),
    }
}

/// Compare pre-release identifier lists, semver's rules.
///
/// Numeric identifiers compare numerically and rank below alphanumeric ones; a
/// longer list of otherwise-equal identifiers ranks higher.
fn compare_prerelease(a: &[String], b: &[String]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        let nx = x.parse::<u64>().ok();
        let ny = y.parse::<u64>().ok();
        let ord = match (nx, ny) {
            (Some(i), Some(j)) => i.cmp(&j),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => rank_word(x).cmp(&rank_word(y)).then_with(|| x.cmp(y)),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

/// Where a named pre-release stage sits relative to the others.
///
/// Alphabetical order gets this wrong — "beta" sorts before "rc" by luck, but
/// "alpha" before "beta" only by accident and "dev" lands in the wrong place
/// entirely.
fn rank_word(word: &str) -> u8 {
    match word {
        "dev" => 0,
        "alpha" | "a" => 1,
        "beta" | "b" => 2,
        "pre" | "preview" => 3,
        "rc" | "cr" => 4,
        "snapshot" => 5,
        "final" | "release" | "ga" => 7,
        _ => 6,
    }
}

/// One affected interval from an advisory: affected from `introduced`
/// (inclusive) until `fixed` (exclusive).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Range {
    /// The first affected version. `None` means "from the beginning".
    pub introduced: Option<String>,
    /// The version that fixes it. `None` means "no fix published".
    pub fixed: Option<String>,
    /// The last affected version, inclusive — used by advisories that publish a
    /// ceiling rather than a fix.
    pub last_affected: Option<String>,
}

impl Range {
    /// Whether `version` falls inside this range.
    ///
    /// Returns false whenever the comparison cannot be made. A dependency
    /// scanner that reports a CVE it cannot actually place trains its users to
    /// ignore it.
    pub fn contains(&self, version: &str) -> bool {
        let Some(v) = Version::parse(version) else {
            return false;
        };

        if let Some(introduced) = self.introduced.as_deref() {
            // "0" is how OSV spells "since the beginning".
            if introduced != "0" {
                let Some(lower) = Version::parse(introduced) else {
                    return false;
                };
                if compare_parsed(&v, &lower) == Ordering::Less {
                    return false;
                }
            }
        }
        if let Some(fixed) = self.fixed.as_deref() {
            let Some(upper) = Version::parse(fixed) else {
                return false;
            };
            if compare_parsed(&v, &upper) != Ordering::Less {
                return false;
            }
        }
        if let Some(last) = self.last_affected.as_deref() {
            let Some(upper) = Version::parse(last) else {
                return false;
            };
            if compare_parsed(&v, &upper) == Ordering::Greater {
                return false;
            }
        }
        // A range with no bounds at all affects everything, which is what an
        // advisory means when it publishes one.
        true
    }

    /// A human-readable form for the finding text.
    pub fn describe(&self) -> String {
        match (self.introduced.as_deref(), self.fixed.as_deref(), self.last_affected.as_deref()) {
            (Some(i), Some(f), _) if i != "0" => format!(">= {i}, < {f}"),
            (_, Some(f), _) => format!("< {f}"),
            (Some(i), None, Some(l)) if i != "0" => format!(">= {i}, <= {l}"),
            (_, None, Some(l)) => format!("<= {l}"),
            (Some(i), None, None) if i != "0" => format!(">= {i}, no fix published"),
            _ => "all published versions".to_string(),
        }
    }
}

/// The lowest fixed version across a set of ranges — what to upgrade to.
pub fn lowest_fix(ranges: &[Range], installed: &str) -> Option<String> {
    ranges
        .iter()
        .filter_map(|r| r.fixed.as_deref())
        .filter(|f| compare(f, installed) == Some(Ordering::Greater))
        .min_by(|a, b| compare(a, b).unwrap_or(Ordering::Equal))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lt(a: &str, b: &str) {
        assert_eq!(compare(a, b), Some(Ordering::Less), "{a} should be < {b}");
        assert_eq!(compare(b, a), Some(Ordering::Greater), "{b} should be > {a}");
    }

    fn eq(a: &str, b: &str) {
        assert_eq!(compare(a, b), Some(Ordering::Equal), "{a} should equal {b}");
    }

    #[test]
    fn numeric_components_order_numerically_not_lexically() {
        lt("1.2.3", "1.2.10");
        lt("1.9.0", "1.10.0");
        lt("2.0.0", "10.0.0");
    }

    #[test]
    fn missing_trailing_components_are_zero() {
        eq("1.2", "1.2.0");
        eq("1", "1.0.0");
        lt("1.2", "1.2.1");
    }

    /// The rule every ecosystem shares, and the one a naive string comparison
    /// gets backwards.
    #[test]
    fn a_prerelease_sorts_below_its_release() {
        lt("1.0.0-rc1", "1.0.0");
        lt("1.0.0-alpha", "1.0.0-beta");
        lt("1.0.0-beta", "1.0.0-rc1");
        lt("2.0.0-rc.2", "2.0.0");
    }

    #[test]
    fn python_style_prereleases_parse_without_a_separator() {
        lt("1.0.0rc1", "1.0.0");
        lt("2.0b1", "2.0");
        lt("1.0a1", "1.0b1");
    }

    #[test]
    fn go_and_maven_decorations_do_not_change_the_order() {
        eq("v1.2.3", "1.2.3");
        lt("v1.2.3", "v1.2.4");
        lt("1.0.0.Final", "1.0.0");
        eq("1.2.3+build.99", "1.2.3");
    }

    #[test]
    fn numeric_prerelease_identifiers_compare_numerically() {
        lt("1.0.0-rc.2", "1.0.0-rc.10");
    }

    /// The scanner must not invent an ordering it cannot justify.
    #[test]
    fn an_unparseable_version_yields_no_answer_rather_than_a_guess() {
        assert_eq!(compare("latest", "1.0.0"), None);
        assert_eq!(compare("*", "1.0.0"), None);
        assert_eq!(compare("", "1.0.0"), None);
        assert_eq!(compare("file:../local", "1.0.0"), None);
    }

    #[test]
    fn a_half_open_range_includes_its_lower_bound_and_excludes_the_fix() {
        let r = Range {
            introduced: Some("1.2.0".into()),
            fixed: Some("1.4.2".into()),
            last_affected: None,
        };
        assert!(r.contains("1.2.0"), "introduced is inclusive");
        assert!(r.contains("1.3.9"));
        assert!(r.contains("1.4.1"));
        assert!(!r.contains("1.4.2"), "the fixed version is not affected");
        assert!(!r.contains("1.1.9"));
        assert!(!r.contains("2.0.0"));
        assert_eq!(r.describe(), ">= 1.2.0, < 1.4.2");
    }

    #[test]
    fn zero_means_from_the_beginning() {
        let r = Range { introduced: Some("0".into()), fixed: Some("1.0.0".into()), last_affected: None };
        assert!(r.contains("0.0.1"));
        assert!(r.contains("0.9.9"));
        assert!(!r.contains("1.0.0"));
        assert_eq!(r.describe(), "< 1.0.0");
    }

    #[test]
    fn a_last_affected_ceiling_is_inclusive() {
        let r = Range { introduced: None, fixed: None, last_affected: Some("2.3.4".into()) };
        assert!(r.contains("2.3.4"), "last_affected is inclusive");
        assert!(!r.contains("2.3.5"));
        assert_eq!(r.describe(), "<= 2.3.4");
    }

    #[test]
    fn an_advisory_with_no_fix_still_reports_its_lower_bound() {
        let r = Range { introduced: Some("3.0.0".into()), fixed: None, last_affected: None };
        assert!(r.contains("3.0.0"));
        assert!(r.contains("99.0.0"));
        assert!(!r.contains("2.9.9"));
        assert!(r.describe().contains("no fix published"));
    }

    /// A version the scanner cannot parse must not be reported as vulnerable.
    #[test]
    fn an_unparseable_installed_version_never_matches() {
        let r = Range { introduced: Some("0".into()), fixed: Some("9.9.9".into()), last_affected: None };
        assert!(!r.contains("latest"));
        assert!(!r.contains("workspace:*"));
        assert!(!r.contains(""));
    }

    #[test]
    fn a_prerelease_inside_the_window_is_affected() {
        let r = Range { introduced: Some("1.0.0".into()), fixed: Some("1.2.0".into()), last_affected: None };
        assert!(r.contains("1.1.0-rc1"));
        // 1.2.0-rc1 sorts *below* 1.2.0, so it is inside the half-open window
        // and genuinely still affected — the fix is in 1.2.0, not in its
        // release candidate. Reporting otherwise would clear a version that
        // does not contain the patch.
        assert!(r.contains("1.2.0-rc1"));
        assert!(!r.contains("1.2.0"));
    }

    #[test]
    fn the_upgrade_target_is_the_lowest_fix_above_what_is_installed() {
        let ranges = vec![
            Range { introduced: Some("0".into()), fixed: Some("1.4.2".into()), last_affected: None },
            Range { introduced: Some("2.0.0".into()), fixed: Some("2.1.0".into()), last_affected: None },
        ];
        assert_eq!(lowest_fix(&ranges, "1.2.0").as_deref(), Some("1.4.2"));
        assert_eq!(lowest_fix(&ranges, "2.0.5").as_deref(), Some("2.1.0"));
        assert_eq!(lowest_fix(&ranges, "9.0.0"), None, "nothing to upgrade to");
    }

    #[test]
    fn prerelease_detection_is_available_to_callers() {
        assert!(Version::parse("1.0.0-rc1").unwrap().is_prerelease());
        assert!(!Version::parse("1.0.0").unwrap().is_prerelease());
    }
}
