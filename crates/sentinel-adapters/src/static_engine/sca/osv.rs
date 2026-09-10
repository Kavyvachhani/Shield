//! Asking OSV.dev whether the versions in a lockfile are known-vulnerable.
//!
//! OSV is the aggregation point for the ecosystem advisory databases — GitHub
//! Security Advisories, PyPA, RustSec, Go's vulndb, and the rest — normalised
//! into one schema with machine-readable affected ranges. That last part is
//! what makes it usable here: an advisory that says "affected: >= 1.2.0,
//! < 1.4.2" can be evaluated against an installed version, whereas one that
//! says "affected: earlier versions" cannot.
//!
//! WHAT LEAVES THE MACHINE
//! ──────────────────────
//! Package names and versions. Nothing else — not the repository path, not the
//! target, not the engagement, not any identifier that could tie the query to a
//! client. The names are already public, and they are sent because there is no
//! way to answer "is this version vulnerable" without them. A scan that must
//! not make the request at all can set [`OsvClient::offline`], and the report
//! then records the gap rather than implying the dependencies were clean.

use super::manifest::{Ecosystem, Package};
use super::version::Range;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

const OSV_API: &str = "https://api.osv.dev";

/// Packages per batch query. OSV accepts up to 1000; a smaller batch keeps any
/// single failure from losing the whole inventory.
const BATCH_SIZE: usize = 100;

/// The most advisories whose full detail is fetched.
///
/// A large monorepo can match several hundred, and each is a separate request.
/// Past this the scan reports the identifiers it has without the prose, which
/// is still actionable, rather than spending ten minutes on the tail.
const MAX_DETAIL_FETCHES: usize = 250;

/// The most packages queried in one scan.
const MAX_PACKAGES: usize = 4000;

/// One advisory, reduced to what a finding needs.
#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    /// CVE and GHSA identifiers for the same issue.
    pub aliases: Vec<String>,
    pub summary: String,
    pub details: String,
    /// The CVSS vector the advisory published, if it published one.
    pub cvss_vector: Option<String>,
    /// The severity word the source database assigned, when there is no vector.
    pub database_severity: Option<String>,
    pub cwe_ids: Vec<String>,
    pub references: Vec<String>,
    /// Affected ranges for the package that matched.
    pub ranges: Vec<Range>,
    /// Explicitly enumerated affected versions, where the advisory lists them
    /// instead of a range.
    pub versions: Vec<String>,
    pub withdrawn: bool,
}

impl Advisory {
    /// The CVE identifier, preferred over the GHSA in a report because it is
    /// the one EPSS and KEV are keyed by.
    pub fn cve(&self) -> Option<&str> {
        std::iter::once(self.id.as_str())
            .chain(self.aliases.iter().map(String::as_str))
            .find(|id| id.starts_with("CVE-"))
    }

    /// Whether this advisory applies to `version`.
    ///
    /// An advisory that enumerates versions is matched exactly; one that
    /// publishes ranges is evaluated. An advisory that does neither does not
    /// match — it has told us nothing we can act on.
    pub fn affects(&self, version: &str) -> bool {
        if self.withdrawn {
            return false;
        }
        if self.versions.iter().any(|v| v == version) {
            return true;
        }
        self.ranges.iter().any(|r| r.contains(version))
    }
}

/// Why an advisory lookup could not be performed.
#[derive(Debug, Clone)]
pub struct LookupGap {
    pub reason: String,
}

/// The result of a lookup: what was found, and what could not be looked up.
pub struct LookupResult {
    /// Advisories per package key, as produced by [`Package::key`].
    pub advisories: HashMap<(Ecosystem, String, String), Vec<Advisory>>,
    /// Set when the database could not be reached, so the report can say the
    /// dependency assessment did not happen rather than that it found nothing.
    pub gap: Option<LookupGap>,
    /// How many packages were actually submitted.
    pub queried: usize,
}

pub struct OsvClient {
    client: reqwest::Client,
    /// When true, no request is made and every lookup reports a gap.
    pub offline: bool,
}

impl OsvClient {
    pub fn new(offline: bool, timeout: Duration) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("SentinelVAPT/dependency-audit")
            .build()?;
        Ok(Self { client, offline })
    }

    /// Look up every package, batching queries and fetching detail for the
    /// advisories that matched.
    pub async fn lookup(&self, packages: &[Package]) -> LookupResult {
        let mut result = LookupResult {
            advisories: HashMap::new(),
            gap: None,
            queried: 0,
        };
        if self.offline {
            result.gap = Some(LookupGap {
                reason: "The dependency audit was configured to run offline, so no advisory \
                         database was consulted. The package inventory below is complete, but \
                         nothing in it has been checked against a published vulnerability."
                    .to_string(),
            });
            return result;
        }
        if packages.is_empty() {
            return result;
        }

        let submitted: Vec<&Package> = packages.iter().take(MAX_PACKAGES).collect();
        result.queried = submitted.len();

        // ── 1. Batch query: which packages have advisories at all ────────────
        let mut ids_per_package: Vec<(usize, Vec<String>)> = Vec::new();
        let mut failures = 0usize;

        for chunk in submitted.chunks(BATCH_SIZE) {
            match self.query_batch(chunk).await {
                Ok(per_query) => {
                    let base = ids_per_package.len();
                    for (offset, ids) in per_query.into_iter().enumerate() {
                        if !ids.is_empty() {
                            ids_per_package.push((base + offset, ids));
                        }
                    }
                }
                Err(e) => {
                    failures += 1;
                    tracing::warn!(error = %e, "OSV batch query failed");
                }
            }
        }

        if failures > 0 && ids_per_package.is_empty() {
            result.gap = Some(LookupGap {
                reason: format!(
                    "The advisory database at {OSV_API} could not be reached, so no dependency \
                     was checked against a published vulnerability. The package inventory is \
                     complete and correct; the vulnerability assessment did not run. Re-run \
                     the scan with network access, or install Trivy or OSV-Scanner for an \
                     offline database."
                ),
            });
            return result;
        }

        // ── 2. Fetch each distinct advisory once ─────────────────────────────
        let mut wanted: Vec<String> = ids_per_package
            .iter()
            .flat_map(|(_, ids)| ids.iter().cloned())
            .collect();
        wanted.sort();
        wanted.dedup();
        let truncated = wanted.len() > MAX_DETAIL_FETCHES;
        wanted.truncate(MAX_DETAIL_FETCHES);

        let mut details: BTreeMap<String, RawVuln> = BTreeMap::new();
        for id in &wanted {
            match self.fetch_vuln(id).await {
                Ok(v) => {
                    details.insert(id.clone(), v);
                }
                Err(e) => tracing::warn!(id, error = %e, "advisory detail fetch failed"),
            }
        }

        if truncated {
            result.gap = Some(LookupGap {
                reason: format!(
                    "More than {MAX_DETAIL_FETCHES} distinct advisories matched this \
                     dependency tree. The detail of the first {MAX_DETAIL_FETCHES} was \
                     retrieved; the remainder are known to exist but were not described. \
                     A tree in this state is best addressed by upgrading the framework \
                     that pins it rather than package by package."
                ),
            });
        }

        // ── 3. Attach advisories to the packages they actually affect ────────
        for (index, ids) in ids_per_package {
            let Some(pkg) = submitted.get(index) else { continue };
            let mut matched = Vec::new();
            for id in ids {
                let Some(raw) = details.get(&id) else { continue };
                let advisory = raw.to_advisory(pkg);
                // OSV's batch endpoint is deliberately generous; the range check
                // is what makes the result precise, and skipping it would report
                // advisories for versions that were never affected.
                if advisory.affects(&pkg.version) {
                    matched.push(advisory);
                }
            }
            if !matched.is_empty() {
                result.advisories.insert(pkg.key(), matched);
            }
        }

        result
    }

    async fn query_batch(&self, packages: &[&Package]) -> anyhow::Result<Vec<Vec<String>>> {
        let queries: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                serde_json::json!({
                    "version": p.version,
                    "package": { "name": p.name, "ecosystem": p.ecosystem.osv_name() }
                })
            })
            .collect();

        let response = self
            .client
            .post(format!("{OSV_API}/v1/querybatch"))
            .json(&serde_json::json!({ "queries": queries }))
            .send()
            .await?
            .error_for_status()?
            .json::<BatchResponse>()
            .await?;

        Ok(response
            .results
            .into_iter()
            .map(|r| r.vulns.into_iter().map(|v| v.id).collect())
            .collect())
    }

    async fn fetch_vuln(&self, id: &str) -> anyhow::Result<RawVuln> {
        Ok(self
            .client
            .get(format!("{OSV_API}/v1/vulns/{id}"))
            .send()
            .await?
            .error_for_status()?
            .json::<RawVuln>()
            .await?)
    }
}

// ── Wire types ───────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Deserialize, Default)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<VulnRef>,
}

#[derive(Deserialize)]
struct VulnRef {
    id: String,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct RawVuln {
    #[serde(default)]
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    severity: Vec<RawSeverity>,
    #[serde(default)]
    affected: Vec<RawAffected>,
    #[serde(default)]
    references: Vec<RawReference>,
    #[serde(default)]
    database_specific: serde_json::Value,
}

#[derive(Deserialize, Debug, Clone)]
struct RawSeverity {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    score: String,
}

#[derive(Deserialize, Debug, Clone, Default)]
struct RawAffected {
    #[serde(default)]
    package: RawPackage,
    #[serde(default)]
    ranges: Vec<RawRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
struct RawPackage {
    #[serde(default)]
    name: String,
    #[serde(default)]
    ecosystem: String,
}

#[derive(Deserialize, Debug, Clone, Default)]
struct RawRange {
    #[serde(default)]
    events: Vec<RawEvent>,
}

#[derive(Deserialize, Debug, Clone, Default)]
struct RawEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    last_affected: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
struct RawReference {
    #[serde(default)]
    url: String,
}

impl RawVuln {
    /// Reduce the wire form to the advisory for one specific package.
    ///
    /// An OSV record covers every package it affects, across ecosystems. Taking
    /// the ranges from the wrong `affected` entry is how a scanner reports that
    /// npm `foo@1.0` is vulnerable because PyPI `foo@1.0` was.
    pub fn to_advisory(&self, pkg: &Package) -> Advisory {
        let mine: Vec<&RawAffected> = self
            .affected
            .iter()
            .filter(|a| {
                a.package.ecosystem.eq_ignore_ascii_case(pkg.ecosystem.osv_name())
                    && a.package.name.eq_ignore_ascii_case(&pkg.name)
            })
            .collect();

        let ranges = mine
            .iter()
            .flat_map(|a| a.ranges.iter())
            .map(|r| {
                let mut out = Range::default();
                for event in &r.events {
                    if let Some(v) = &event.introduced {
                        out.introduced = Some(v.clone());
                    }
                    if let Some(v) = &event.fixed {
                        out.fixed = Some(v.clone());
                    }
                    if let Some(v) = &event.last_affected {
                        out.last_affected = Some(v.clone());
                    }
                }
                out
            })
            .collect();

        let versions = mine.iter().flat_map(|a| a.versions.iter().cloned()).collect();

        // Prefer a CVSS 4.0 vector where the advisory published one; the rest
        // of the pipeline scores v4 natively.
        let cvss_vector = self
            .severity
            .iter()
            .find(|s| s.kind.eq_ignore_ascii_case("CVSS_V4"))
            .or_else(|| self.severity.iter().find(|s| s.kind.starts_with("CVSS")))
            .map(|s| s.score.clone())
            .filter(|s| s.starts_with("CVSS:"));

        let database_severity = self
            .database_specific
            .get("severity")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let cwe_ids = self
            .database_specific
            .get("cwe_ids")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
            .unwrap_or_default();

        Advisory {
            id: self.id.clone(),
            aliases: self.aliases.clone(),
            summary: self.summary.clone(),
            details: self.details.clone(),
            cvss_vector,
            database_severity,
            cwe_ids,
            references: self.references.iter().map(|r| r.url.clone()).collect(),
            ranges,
            versions,
            withdrawn: self.withdrawn.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, version: &str) -> Package {
        Package {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
            manifest: "package-lock.json".into(),
            direct: true,
        }
    }

    fn raw(json: &str) -> RawVuln {
        serde_json::from_str(json).expect("fixture parses")
    }

    #[test]
    fn ranges_are_taken_from_the_entry_for_this_package_only() {
        let v = raw(r#"{
          "id": "GHSA-xxxx",
          "affected": [
            { "package": { "name": "other", "ecosystem": "npm" },
              "ranges": [{ "events": [{ "introduced": "0" }, { "fixed": "99.0.0" }] }] },
            { "package": { "name": "lodash", "ecosystem": "npm" },
              "ranges": [{ "events": [{ "introduced": "0" }, { "fixed": "4.17.21" }] }] }
          ]
        }"#);
        let advisory = v.to_advisory(&pkg("lodash", "4.17.20"));
        assert_eq!(advisory.ranges.len(), 1);
        assert!(advisory.affects("4.17.20"));
        assert!(!advisory.affects("4.17.21"), "the fixed version is not affected");
    }

    /// The same package name in two ecosystems is two different packages.
    #[test]
    fn an_advisory_for_another_ecosystem_does_not_match() {
        let v = raw(r#"{
          "id": "GHSA-y",
          "affected": [
            { "package": { "name": "requests", "ecosystem": "PyPI" },
              "ranges": [{ "events": [{ "introduced": "0" }, { "fixed": "2.31.0" }] }] }
          ]
        }"#);
        let advisory = v.to_advisory(&pkg("requests", "2.20.0"));
        assert!(advisory.ranges.is_empty());
        assert!(!advisory.affects("2.20.0"));
    }

    #[test]
    fn an_enumerated_version_list_is_matched_exactly() {
        let v = raw(r#"{
          "id": "GHSA-z",
          "affected": [
            { "package": { "name": "lodash", "ecosystem": "npm" },
              "versions": ["4.17.19", "4.17.20"] }
          ]
        }"#);
        let advisory = v.to_advisory(&pkg("lodash", "4.17.20"));
        assert!(advisory.affects("4.17.20"));
        assert!(!advisory.affects("4.17.18"));
    }

    #[test]
    fn a_withdrawn_advisory_never_matches() {
        let v = raw(r#"{
          "id": "GHSA-w",
          "withdrawn": "2024-01-01T00:00:00Z",
          "affected": [
            { "package": { "name": "lodash", "ecosystem": "npm" },
              "ranges": [{ "events": [{ "introduced": "0" }] }] }
          ]
        }"#);
        assert!(!v.to_advisory(&pkg("lodash", "1.0.0")).affects("1.0.0"));
    }

    #[test]
    fn a_cvss_v4_vector_is_preferred_over_v3() {
        let v = raw(r#"{
          "id": "GHSA-a",
          "severity": [
            { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
            { "type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }
          ]
        }"#);
        let a = v.to_advisory(&pkg("x", "1.0.0"));
        assert!(a.cvss_vector.as_deref().unwrap().starts_with("CVSS:4.0/"));
    }

    #[test]
    fn a_v3_vector_is_used_when_that_is_all_the_advisory_published() {
        let v = raw(r#"{
          "id": "GHSA-b",
          "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }]
        }"#);
        assert!(v.to_advisory(&pkg("x", "1.0.0")).cvss_vector.is_some());
    }

    #[test]
    fn the_cve_alias_is_preferred_as_the_reportable_identifier() {
        let v = raw(r#"{ "id": "GHSA-abcd", "aliases": ["CVE-2021-23337"] }"#);
        let a = v.to_advisory(&pkg("x", "1.0.0"));
        assert_eq!(a.cve(), Some("CVE-2021-23337"));
    }

    #[test]
    fn an_advisory_with_no_cve_reports_none_rather_than_inventing_one() {
        let v = raw(r#"{ "id": "GHSA-abcd", "aliases": ["GHSA-other"] }"#);
        assert_eq!(v.to_advisory(&pkg("x", "1.0.0")).cve(), None);
    }

    #[test]
    fn database_severity_and_cwes_are_read_from_the_source_database_block() {
        let v = raw(r#"{
          "id": "GHSA-c",
          "database_specific": { "severity": "HIGH", "cwe_ids": ["CWE-1321"] }
        }"#);
        let a = v.to_advisory(&pkg("x", "1.0.0"));
        assert_eq!(a.database_severity.as_deref(), Some("HIGH"));
        assert_eq!(a.cwe_ids, vec!["CWE-1321".to_string()]);
    }

    /// Offline must produce a stated gap, never a clean result — the two mean
    /// entirely different things to whoever reads the report.
    #[tokio::test]
    async fn an_offline_client_reports_a_gap_rather_than_no_vulnerabilities() {
        let client = OsvClient::new(true, Duration::from_secs(5)).unwrap();
        let result = client.lookup(&[pkg("lodash", "4.17.20")]).await;
        assert!(result.advisories.is_empty());
        let gap = result.gap.expect("offline must be disclosed");
        assert!(gap.reason.contains("offline"));
        assert!(gap.reason.contains("has been checked") || gap.reason.contains("nothing in it"));
    }

    #[tokio::test]
    async fn an_empty_inventory_needs_no_request_and_reports_no_gap() {
        let client = OsvClient::new(false, Duration::from_secs(5)).unwrap();
        let result = client.lookup(&[]).await;
        assert!(result.gap.is_none());
        assert_eq!(result.queried, 0);
    }

    #[test]
    fn a_missing_field_anywhere_in_the_wire_format_parses_to_a_default() {
        let v = raw(r#"{ "id": "GHSA-minimal" }"#);
        let a = v.to_advisory(&pkg("x", "1.0.0"));
        assert_eq!(a.id, "GHSA-minimal");
        assert!(a.ranges.is_empty());
        assert!(!a.withdrawn);
    }
}
