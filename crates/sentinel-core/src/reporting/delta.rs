//! Comparison against the previous assessment.
//!
//! A standalone report answers "what is wrong today". The question actually
//! asked after a remediation cycle is "did the work land, and did anything get
//! worse" — and a document that cannot answer it forces the reader to diff two
//! PDFs by hand, which is how a regression goes unnoticed for a quarter.
//!
//! Three groups, and the middle one is the reason this exists:
//!
//! * **Newly found** — present now, absent last time. Either a regression or
//!   something the previous assessment could not reach.
//! * **Resolved** — present last time, absent now. This is the only evidence
//!   anywhere in the deliverable that remediation worked, and it is why marking
//!   a finding `Remediated` by hand deliberately does *not* suppress the
//!   re-test: a fix has to be observed, not asserted.
//! * **Still open** — present in both. The number that matters at a steering
//!   meeting, because it is the work that was scheduled and did not happen.
//!
//! Matching is on the same fingerprint the exception register uses, so a
//! weakness is "the same weakness" across scans by exactly the rule the rest of
//! the engine already applies — not by finding id, which changes every run.

use crate::exceptions::fingerprint;
use crate::models::finding::{Finding, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// What changed between two assessments of the same target.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanDelta {
    /// The reference of the assessment being compared against.
    pub previous_reference: String,
    pub previous_completed_at: DateTime<Utc>,
    /// Present now, absent last time.
    pub newly_found: Vec<Finding>,
    /// Present last time, absent now — carried from the previous scan, since
    /// there is no current record of something that no longer exists.
    pub resolved: Vec<Finding>,
    /// Present in both, as recorded now.
    pub still_open: Vec<Finding>,
}

impl ScanDelta {
    /// Compare two assessments of the same target.
    ///
    /// `previous` and `current` should both be the reportable sets — false
    /// positives already excluded — or a dismissal between the two runs reads
    /// as remediation, which would be the report claiming credit for work
    /// nobody did.
    pub fn compute(
        previous: &[Finding],
        current: &[Finding],
        previous_reference: impl Into<String>,
        previous_completed_at: DateTime<Utc>,
    ) -> Self {
        let previous_keys: HashSet<String> = previous.iter().map(fingerprint).collect();
        let current_keys: HashSet<String> = current.iter().map(fingerprint).collect();

        let (still_open, newly_found): (Vec<Finding>, Vec<Finding>) = current
            .iter()
            .cloned()
            .partition(|f| previous_keys.contains(&fingerprint(f)));

        let resolved: Vec<Finding> = previous
            .iter()
            .filter(|f| !current_keys.contains(&fingerprint(f)))
            .cloned()
            .collect();

        Self {
            previous_reference: previous_reference.into(),
            previous_completed_at,
            newly_found,
            resolved,
            still_open,
        }
    }

    /// Whether anything changed at all.
    pub fn is_unchanged(&self) -> bool {
        self.newly_found.is_empty() && self.resolved.is_empty()
    }

    /// Resolved findings that actually mattered — informational ones closing is
    /// not remediation progress worth reporting to a steering meeting.
    pub fn resolved_actionable(&self) -> usize {
        self.resolved.iter().filter(|f| f.severity != Severity::Info).count()
    }

    pub fn new_actionable(&self) -> usize {
        self.newly_found.iter().filter(|f| f.severity != Severity::Info).count()
    }

    /// Still-open findings at or above High, which is the figure that decides
    /// whether a remediation cycle is judged successful.
    pub fn still_open_high_impact(&self) -> usize {
        self.still_open
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .count()
    }

    /// A one-sentence verdict for the top of the section.
    ///
    /// Deliberately refuses to congratulate on volume alone: closing nine low
    /// findings while introducing one critical is not progress, and a report
    /// that reads it as progress is misleading the person who authorised the
    /// work.
    pub fn verdict(&self) -> String {
        let introduced_high = self
            .newly_found
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .count();

        if introduced_high > 0 {
            return format!(
                "{introduced_high} high-impact finding{} {} appeared since the previous \
                 assessment. Whatever else closed, that is the result that matters here: either \
                 a change introduced it, or the previous assessment could not reach it.",
                if introduced_high == 1 { "" } else { "s" },
                if introduced_high == 1 { "has" } else { "have" },
            );
        }
        if self.is_unchanged() {
            return "Nothing has changed since the previous assessment: no finding was closed, \
                    and none appeared. If remediation was expected in this period, it has not \
                    reached the assessed environment."
                .to_string();
        }
        if self.newly_found.is_empty() {
            return format!(
                "{} finding{} closed since the previous assessment and nothing new appeared. \
                 {} remain{} open.",
                self.resolved.len(),
                if self.resolved.len() == 1 { " was" } else { "s were" },
                self.still_open.len(),
                if self.still_open.len() == 1 { "s" } else { "" },
            );
        }
        format!(
            "{} finding{} closed and {} appeared since the previous assessment, leaving {} open.",
            self.resolved.len(),
            if self.resolved.len() == 1 { " was" } else { "s were" },
            self.newly_found.len(),
            self.still_open.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::tests::finding;
    use chrono::Duration;

    /// Two scans of the *same* target share its id, and the fingerprint
    /// includes it — deliberately, so an exception can never cross targets.
    /// A fixture that generated a fresh id per finding would make every
    /// weakness look new, which is what the first version of this test did.
    fn target() -> uuid::Uuid {
        uuid::Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap()
    }

    fn at(component: &str, title: &str, severity: Severity) -> Finding {
        let mut f = finding(title, severity, 5.0);
        f.target_id = target();
        f.affected_component = component.to_string();
        f
    }

    fn delta(previous: &[Finding], current: &[Finding]) -> ScanDelta {
        ScanDelta::compute(previous, current, "SV-PREV", Utc::now() - Duration::days(30))
    }

    /// The three groups, on the rule the exception register already uses.
    #[test]
    fn findings_are_split_into_new_resolved_and_still_open() {
        let previous = vec![
            at("https://app.test/a", "Missing CSP", Severity::Medium),
            at("https://app.test/b", "Directory listing", Severity::Low),
        ];
        let current = vec![
            at("https://app.test/a", "Missing CSP", Severity::Medium),
            at("https://app.test/c", "Leaked key", Severity::Critical),
        ];

        let d = delta(&previous, &current);
        assert_eq!(d.still_open.len(), 1);
        assert_eq!(d.still_open[0].title, "Missing CSP");
        assert_eq!(d.resolved.len(), 1);
        assert_eq!(d.resolved[0].title, "Directory listing");
        assert_eq!(d.newly_found.len(), 1);
        assert_eq!(d.newly_found[0].title, "Leaked key");
    }

    /// Findings are re-created with new ids on every scan, so matching on id
    /// would report every finding as both resolved and new.
    #[test]
    fn a_weakness_is_matched_across_scans_by_identity_not_by_id() {
        let before = at("https://app.test/a", "Missing CSP", Severity::Medium);
        let after = at("https://app.test/a", "Missing CSP", Severity::Medium);
        assert_ne!(before.id, after.id);

        let d = delta(&[before], &[after]);
        assert_eq!(d.still_open.len(), 1);
        assert!(d.newly_found.is_empty());
        assert!(d.resolved.is_empty());
    }

    /// Closing nine low findings while introducing one critical is not
    /// progress, and a verdict that reads it as progress misleads the person
    /// who authorised the work.
    #[test]
    fn the_verdict_leads_with_a_new_high_impact_finding_however_much_closed() {
        let previous: Vec<Finding> = (0..9)
            .map(|i| at(&format!("https://app.test/{i}"), "Old", Severity::Low))
            .collect();
        let current = vec![at("https://app.test/new", "Leaked key", Severity::Critical)];

        let verdict = delta(&previous, &current).verdict();
        assert!(verdict.contains("1 high-impact finding"), "{verdict}");
        assert!(verdict.contains("that is the result that matters"), "{verdict}");
    }

    #[test]
    fn a_clean_remediation_cycle_is_reported_as_one() {
        let previous = vec![at("https://app.test/a", "Missing CSP", Severity::Medium)];
        let d = delta(&previous, &[]);
        assert_eq!(d.resolved.len(), 1);
        assert!(d.verdict().contains("nothing new appeared"), "{}", d.verdict());
    }

    /// Silence is a finding of its own: if remediation was expected and nothing
    /// moved, the report should say so rather than reading as a clean bill.
    #[test]
    fn no_change_at_all_is_stated_rather_than_glossed() {
        let same = vec![at("https://app.test/a", "Missing CSP", Severity::Medium)];
        let d = delta(&same, &same);
        assert!(d.is_unchanged());
        assert!(d.verdict().contains("Nothing has changed"), "{}", d.verdict());
        assert!(d.verdict().contains("has not reached the assessed environment"));
    }

    /// A steering meeting is not interested in an informational item closing.
    #[test]
    fn informational_findings_do_not_count_as_remediation_progress() {
        let previous = vec![
            at("https://app.test/a", "Banner", Severity::Info),
            at("https://app.test/b", "Missing CSP", Severity::Medium),
        ];
        let d = delta(&previous, &[]);
        assert_eq!(d.resolved.len(), 2);
        assert_eq!(d.resolved_actionable(), 1);
    }

    #[test]
    fn the_high_impact_backlog_is_counted_separately() {
        let shared = vec![
            at("https://app.test/a", "RCE", Severity::Critical),
            at("https://app.test/b", "XSS", Severity::High),
            at("https://app.test/c", "Banner", Severity::Info),
        ];
        let d = delta(&shared, &shared);
        assert_eq!(d.still_open.len(), 3);
        assert_eq!(d.still_open_high_impact(), 2);
    }

    /// A comparison is only meaningful within one target: the fingerprint
    /// includes the target id, so findings from a different engagement cannot
    /// be mistaken for remediation here.
    #[test]
    fn findings_from_another_target_never_match() {
        let mut theirs = at("https://app.test/a", "Missing CSP", Severity::Medium);
        theirs.target_id = uuid::Uuid::parse_str("99999999-8888-7777-6666-555555555555").unwrap();
        let ours = at("https://app.test/a", "Missing CSP", Severity::Medium);

        let d = delta(&[theirs], &[ours]);
        assert!(d.still_open.is_empty(), "a different target is not the same weakness");
        assert_eq!(d.newly_found.len(), 1);
        assert_eq!(d.resolved.len(), 1);
    }

    #[test]
    fn a_first_assessment_has_nothing_to_compare_and_everything_is_new() {
        let current = vec![at("https://app.test/a", "Missing CSP", Severity::Medium)];
        let d = delta(&[], &current);
        assert_eq!(d.newly_found.len(), 1);
        assert!(d.resolved.is_empty());
        assert!(d.still_open.is_empty());
        assert!(!d.is_unchanged());
    }

    #[test]
    fn new_actionable_excludes_informational_arrivals() {
        let current = vec![
            at("https://app.test/a", "Banner", Severity::Info),
            at("https://app.test/b", "XSS", Severity::High),
        ];
        let d = delta(&[], &current);
        assert_eq!(d.new_actionable(), 1);
    }
}
