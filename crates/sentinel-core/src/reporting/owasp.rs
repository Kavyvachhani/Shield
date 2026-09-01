//! OWASP Top 10:2025 rollup.
//!
//! Every finding already carries the risk category it belongs to, but until now
//! nothing added them up. That mattered for two different readers.
//!
//! A client's security programme is usually tracked against the Top 10, so a
//! report that lists twenty findings without saying which categories they fall
//! into cannot be reconciled with anything they already measure. And a
//! developer looking at twenty separate tickets cannot see that fourteen of
//! them are one root cause — a missing set of response headers — which is the
//! difference between fourteen pieces of work and one.
//!
//! The rollup reports **every** category, including the ones with no findings.
//! A category with nothing against it is a result, and omitting it would make
//! the table a list of failures rather than a picture of coverage.

use crate::models::finding::{Finding, Severity};
use serde::{Deserialize, Serialize};

/// One OWASP Top 10:2025 category.
pub struct Top10Category {
    /// The `A01`…`A10` code, matching the prefix on a finding's `owasp_2025`.
    pub code: &'static str,
    pub name: &'static str,
    /// What this category means to someone who does not write code.
    pub client_meaning: &'static str,
    /// What a developer should look at when findings land here.
    pub developer_focus: &'static str,
}

/// The catalogue, in canonical order.
pub const TOP_10: &[Top10Category] = &[
    Top10Category {
        code: "A01",
        name: "Broken Access Control",
        client_meaning: "Whether a user can reach data or functions that belong to someone else, or that belong to an administrator.",
        developer_focus: "Authorisation decided on the server for every request, keyed on the session rather than on a value the client supplied. Object identifiers in URLs are the usual entry point.",
    },
    Top10Category {
        code: "A02",
        name: "Security Misconfiguration",
        client_meaning: "Whether the platform is deployed with the protections it supports actually switched on, and without development artefacts left reachable.",
        developer_focus: "Response headers, cookie attributes, cross-origin policy and file exposure. Most of this is set once at the edge or in middleware and fixes every route at once.",
    },
    Top10Category {
        code: "A03",
        name: "Software Supply Chain Failures",
        client_meaning: "Whether the third-party code the application depends on is current, and whether what it loads at run time can be tampered with.",
        developer_focus: "Dependency versions against published advisories, integrity attributes on externally hosted scripts, and lockfile discipline in CI.",
    },
    Top10Category {
        code: "A04",
        name: "Cryptographic Failures",
        client_meaning: "Whether sensitive data is properly encrypted in transit and at rest, and whether the encryption in use is still considered sound.",
        developer_focus: "TLS configuration and certificate validity, secret handling, and anything sensitive that reaches the client or a log.",
    },
    Top10Category {
        code: "A05",
        name: "Injection",
        client_meaning: "Whether data supplied by a user can be made to run as code — the class behind database compromise and browser-side account takeover.",
        developer_focus: "Parameterised queries, contextual output encoding, and a Content-Security-Policy strong enough to matter if encoding is missed.",
    },
    Top10Category {
        code: "A06",
        name: "Insecure Design",
        client_meaning: "Whether the application's own rules can be abused — steps skipped, limits bypassed, values a user should not control.",
        developer_focus: "Threat-model the workflow, not the endpoint. Automated testing cannot answer this; it needs an analyst who knows the intended behaviour.",
    },
    Top10Category {
        code: "A07",
        name: "Authentication Failures",
        client_meaning: "Whether the login process resists guessing, replay and account enumeration.",
        developer_focus: "Session issuance and invalidation, credential transport, rate limiting on authentication, and uniform responses that do not reveal whether an account exists.",
    },
    Top10Category {
        code: "A08",
        name: "Software or Data Integrity Failures",
        client_meaning: "Whether code and data can be modified in transit or by an upstream party without anyone noticing.",
        developer_focus: "Subresource integrity, signed artefacts, and never deserialising data from an untrusted source into live objects.",
    },
    Top10Category {
        code: "A09",
        name: "Security Logging and Alerting Failures",
        client_meaning: "Whether an attack in progress would be recorded and noticed. This is what determines how long a breach lasts.",
        developer_focus: "Authentication and authorisation events logged with enough context to reconstruct a session, shipped somewhere an attacker on the host cannot edit.",
    },
    Top10Category {
        code: "A10",
        name: "Mishandling of Exceptional Conditions",
        client_meaning: "Whether failures are handled without leaking internal detail or leaving the system in an unsafe state.",
        developer_focus: "Error responses that say nothing about the stack, and a fail-closed default when a dependency is unavailable.",
    },
];

/// Findings tallied against one category.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryRollup {
    pub code: String,
    pub name: String,
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    /// Titles of the findings in this category, deduplicated, highest risk first.
    pub examples: Vec<String>,
}

impl CategoryRollup {
    /// Findings that need action — everything above informational.
    pub fn actionable(&self) -> usize {
        self.critical + self.high + self.medium + self.low
    }

    /// The colour a report should use for this row's status.
    pub fn status_color(&self) -> &'static str {
        if self.critical > 0 {
            "#b91c1c"
        } else if self.high > 0 {
            "#ea580c"
        } else if self.medium > 0 {
            "#ca8a04"
        } else if self.actionable() > 0 {
            "#0284c7"
        } else {
            "#16a34a"
        }
    }

    /// One-word verdict for the row.
    pub fn status_label(&self) -> &'static str {
        if self.critical > 0 {
            "Critical"
        } else if self.high > 0 {
            "High"
        } else if self.medium > 0 {
            "Medium"
        } else if self.actionable() > 0 {
            "Low"
        } else {
            "None found"
        }
    }
}

/// Tally `findings` across all ten categories, in canonical order.
///
/// A finding whose `owasp_2025` is absent or unrecognised is counted nowhere
/// rather than being forced into a category it may not belong to — a
/// misattributed finding is worse than an uncounted one, because it sends the
/// reader to the wrong remediation.
pub fn rollup(findings: &[Finding]) -> Vec<CategoryRollup> {
    TOP_10
        .iter()
        .map(|category| {
            let matching: Vec<&Finding> = findings
                .iter()
                .filter(|f| belongs_to(f, category.code))
                .collect();

            let mut examples: Vec<String> = Vec::new();
            // `sort_by_priority` has already ordered the input, so taking titles
            // in order gives highest-risk-first without a second sort.
            for f in &matching {
                if !examples.contains(&f.title) {
                    examples.push(f.title.clone());
                }
            }
            examples.truncate(6);

            CategoryRollup {
                code: category.code.to_string(),
                name: category.name.to_string(),
                total: matching.len(),
                critical: count(&matching, Severity::Critical),
                high: count(&matching, Severity::High),
                medium: count(&matching, Severity::Medium),
                low: count(&matching, Severity::Low),
                info: count(&matching, Severity::Info),
                examples,
            }
        })
        .collect()
}

/// Whether a finding's declared category carries this code.
///
/// Matched on the `A0n` prefix rather than the whole string, so a finding
/// written as `A02:2025-Security Misconfiguration` and one written as
/// `A02:2021-Security Misconfiguration` — an older engine's spelling — both
/// land in the same row instead of one of them vanishing.
fn belongs_to(finding: &Finding, code: &str) -> bool {
    finding
        .owasp_2025
        .as_deref()
        .map(|declared| declared.trim().to_ascii_uppercase().starts_with(code))
        .unwrap_or(false)
}

fn count(findings: &[&Finding], severity: Severity) -> usize {
    findings.iter().filter(|f| f.severity == severity).count()
}

/// The category description for a code, for report prose.
pub fn category(code: &str) -> Option<&'static Top10Category> {
    TOP_10.iter().find(|c| c.code == code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::tests::finding;

    fn categorised(title: &str, severity: Severity, score: f64, owasp: &str) -> Finding {
        let mut f = finding(title, severity, score);
        f.owasp_2025 = Some(owasp.to_string());
        f
    }

    #[test]
    fn all_ten_categories_are_reported_including_the_empty_ones() {
        let rows = rollup(&[]);
        assert_eq!(rows.len(), 10);
        assert_eq!(rows[0].code, "A01");
        assert_eq!(rows[9].code, "A10");
        assert!(rows.iter().all(|r| r.total == 0));
        assert_eq!(rows[0].status_label(), "None found");
        assert_eq!(rows[0].status_color(), "#16a34a");
    }

    #[test]
    fn findings_are_tallied_into_their_declared_category() {
        let findings = vec![
            categorised("Missing CSP", Severity::Medium, 5.3, "A02:2025-Security Misconfiguration"),
            categorised("Missing HSTS", Severity::Medium, 5.0, "A02:2025-Security Misconfiguration"),
            categorised("SQLi", Severity::Critical, 9.4, "A05:2025-Injection"),
        ];
        let rows = rollup(&findings);

        let misconfig = rows.iter().find(|r| r.code == "A02").unwrap();
        assert_eq!(misconfig.total, 2);
        assert_eq!(misconfig.medium, 2);
        assert_eq!(misconfig.status_label(), "Medium");

        let injection = rows.iter().find(|r| r.code == "A05").unwrap();
        assert_eq!(injection.critical, 1);
        assert_eq!(injection.status_label(), "Critical");
        assert_eq!(injection.status_color(), "#b91c1c");
    }

    /// A finding written against an older Top 10 edition must still land in its
    /// row rather than disappearing from the rollup entirely.
    #[test]
    fn a_category_from_an_earlier_edition_still_counts() {
        let findings = vec![categorised("Old", Severity::High, 7.0, "A02:2021-Security Misconfiguration")];
        let rows = rollup(&findings);
        assert_eq!(rows.iter().find(|r| r.code == "A02").unwrap().total, 1);
    }

    /// Guessing a category sends the reader to the wrong remediation, which is
    /// worse than admitting the finding was not categorised.
    #[test]
    fn an_uncategorised_finding_is_not_forced_into_a_row() {
        let mut f = finding("Mystery", Severity::High, 7.0);
        f.owasp_2025 = None;
        let rows = rollup(&[f]);
        assert!(rows.iter().all(|r| r.total == 0));
    }

    #[test]
    fn examples_are_deduplicated_and_bounded() {
        let findings: Vec<Finding> = (0..20)
            .map(|i| {
                categorised(
                    if i % 2 == 0 { "Missing CSP" } else { "Missing HSTS" },
                    Severity::Low,
                    3.0,
                    "A02:2025-Security Misconfiguration",
                )
            })
            .collect();
        let rows = rollup(&findings);
        let misconfig = rows.iter().find(|r| r.code == "A02").unwrap();
        assert_eq!(misconfig.total, 20);
        assert_eq!(misconfig.examples.len(), 2, "identical titles collapse: {:?}", misconfig.examples);
    }

    #[test]
    fn informational_findings_do_not_make_a_category_actionable() {
        let findings = vec![categorised("Banner", Severity::Info, 0.0, "A02:2025-Security Misconfiguration")];
        let rows = rollup(&findings);
        let misconfig = rows.iter().find(|r| r.code == "A02").unwrap();
        assert_eq!(misconfig.total, 1);
        assert_eq!(misconfig.actionable(), 0);
        assert_eq!(misconfig.status_label(), "None found");
    }

    #[test]
    fn every_category_carries_prose_for_both_audiences() {
        for c in TOP_10 {
            assert!(!c.client_meaning.trim().is_empty(), "{} has no client prose", c.code);
            assert!(!c.developer_focus.trim().is_empty(), "{} has no developer prose", c.code);
            assert!(category(c.code).is_some());
        }
        assert!(category("A99").is_none());
    }
}
