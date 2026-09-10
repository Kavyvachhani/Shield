//! Which vulnerabilities are being exploited, as opposed to which exist.
//!
//! CVSS answers "how bad would this be if someone used it". It does not answer
//! "is anyone using it", and the gap between those two questions is where most
//! remediation effort is wasted. A 9.8 with no public exploit and no observed
//! activity is a lower priority than a 7.5 that ransomware crews have been
//! using for two years, and a report that ranks them the other way round sends
//! a team to fix the wrong thing first.
//!
//! Two signals fill that gap, and this module supplies the one that can be
//! answered offline:
//!
//! * **CISA KEV** — a catalogue of vulnerabilities with confirmed, observed
//!   exploitation in the wild. Membership is a binary fact, it changes slowly,
//!   and it is public, so a useful subset can ship inside the application and
//!   be correct without a network call.
//! * **EPSS** — a daily-updated probability that a CVE will be exploited in the
//!   next thirty days. It is a moving number, so a copy bundled with a release
//!   is stale the week after. It is fetched live where the scan has network
//!   access, and left absent otherwise, because a stale probability presented
//!   as current is worse than no probability at all.
//!
//! The bundled KEV list is explicitly a *subset*, and [`catalogue_note`] says
//! so in words a report can print. A scanner that implies it holds the whole
//! catalogue, and then answers "not exploited" for something CISA added last
//! month, has made a claim it cannot support.

use serde::Deserialize;
use std::collections::HashSet;
use std::sync::OnceLock;

/// The bundled catalogue, compiled into the binary.
const SNAPSHOT: &str = include_str!("../data/epss_kev_snapshot.json");

#[derive(Debug, Deserialize)]
struct Snapshot {
    metadata: Metadata,
    #[serde(default)]
    kev_cves: Vec<String>,
    /// The original field name, kept so an older snapshot file still loads.
    #[serde(default)]
    kev_sample_cves: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct Metadata {
    #[serde(default)]
    version: String,
    #[serde(default)]
    last_updated: String,
    #[serde(default)]
    kev_record_count: u64,
}

struct Catalogue {
    kev: HashSet<String>,
    metadata: Metadata,
}

fn catalogue() -> &'static Catalogue {
    static CACHE: OnceLock<Catalogue> = OnceLock::new();
    CACHE.get_or_init(|| {
        // A malformed bundled file is a build problem, not a runtime one, and
        // the tests below fail long before a release could carry one. At
        // runtime an empty catalogue is the safe degradation: it answers "not
        // known to be exploited", which understates urgency rather than
        // inventing it.
        let parsed: Snapshot = serde_json::from_str(SNAPSHOT).unwrap_or(Snapshot {
            metadata: Metadata {
                version: "unavailable".into(),
                last_updated: "unknown".into(),
                kev_record_count: 0,
            },
            kev_cves: Vec::new(),
            kev_sample_cves: Vec::new(),
        });

        let kev = parsed
            .kev_cves
            .iter()
            .chain(parsed.kev_sample_cves.iter())
            .map(|s| s.trim().to_ascii_uppercase())
            .filter(|s| s.starts_with("CVE-"))
            .collect();

        Catalogue { kev, metadata: parsed.metadata }
    })
}

/// Whether this CVE is in the bundled known-exploited catalogue.
///
/// `false` means "not in the subset that ships with this build", which is a
/// weaker statement than "not exploited". [`catalogue_note`] is what a report
/// should print alongside any conclusion drawn from this.
pub fn is_known_exploited(cve: &str) -> bool {
    let id = cve.trim().to_ascii_uppercase();
    if !id.starts_with("CVE-") {
        return false;
    }
    catalogue().kev.contains(&id)
}

/// How many entries the bundled catalogue holds.
pub fn catalogue_size() -> usize {
    catalogue().kev.len()
}

/// The sentence a report prints so its reader knows what the KEV column means.
pub fn catalogue_note() -> String {
    let m = &catalogue().metadata;
    format!(
        "Known-exploited status is checked against a catalogue of {} entries bundled with \
         this build (snapshot {}, dated {}), drawn from the CISA Known Exploited \
         Vulnerabilities list. It is a subset, not the full catalogue: a finding not marked \
         as exploited may still have been added to the CISA list since this build. Confirm \
         against https://www.cisa.gov/known-exploited-vulnerabilities-catalog before treating \
         the absence of the marker as assurance.",
        catalogue_size(),
        if m.version.is_empty() { "unversioned" } else { &m.version },
        if m.last_updated.is_empty() { "unknown" } else { &m.last_updated },
    )
}

/// The declared record count from the snapshot's own metadata.
///
/// Differs from [`catalogue_size`] when the bundle ships a subset, which is the
/// normal case; the difference is exactly what [`catalogue_note`] discloses.
pub fn declared_upstream_size() -> u64 {
    catalogue().metadata.kev_record_count
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A malformed bundled catalogue would silently disable exploitation
    /// ranking for every scan this build ever runs.
    #[test]
    fn the_bundled_catalogue_parses() {
        let parsed: Snapshot = serde_json::from_str(SNAPSHOT).expect("bundled snapshot is valid");
        assert!(
            !parsed.kev_cves.is_empty() || !parsed.kev_sample_cves.is_empty(),
            "the bundled catalogue is empty, so no finding will ever be marked exploited"
        );
    }

    #[test]
    fn a_catalogued_cve_is_recognised_however_it_is_cased() {
        // Log4Shell: on the CISA catalogue since December 2021.
        assert!(is_known_exploited("CVE-2021-44228"));
        assert!(is_known_exploited("cve-2021-44228"));
        assert!(is_known_exploited("  CVE-2021-44228  "));
    }

    #[test]
    fn a_cve_outside_the_catalogue_is_not_claimed_as_exploited() {
        assert!(!is_known_exploited("CVE-1999-0001"));
    }

    /// A GHSA identifier is not a CVE and must not be looked up as one.
    #[test]
    fn a_non_cve_identifier_is_rejected_rather_than_matched() {
        assert!(!is_known_exploited("GHSA-jf85-cpcp-j695"));
        assert!(!is_known_exploited(""));
        assert!(!is_known_exploited("not an id"));
    }

    /// The note is what stops "no marker" being read as "not exploited".
    #[test]
    fn the_catalogue_note_discloses_that_the_bundle_is_a_subset() {
        let note = catalogue_note();
        assert!(note.contains("subset"), "{note}");
        assert!(note.contains("cisa.gov"), "the reader needs somewhere to confirm");
        assert!(note.contains(&catalogue_size().to_string()));
    }

    #[test]
    fn the_catalogue_is_not_trivially_small() {
        assert!(
            catalogue_size() >= 5,
            "a catalogue this small provides no useful ranking signal"
        );
    }
}
