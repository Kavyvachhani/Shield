//! The exception register: analyst decisions that outlive the scan that raised them.
//!
//! A triage decision used to live on one `Finding`, and a `Finding` lives and
//! dies with its scan run. Re-scanning the same target produced brand new
//! findings with brand new ids, so every dismissal the analyst had already made
//! came back as an open issue in the next report. On a re-test that meant
//! re-triaging the same false positives every single time, and a client report
//! that never converged.
//!
//! An exception is therefore recorded against the *target* and keyed by a
//! [`fingerprint`] that is stable across scans, not against a finding id. The
//! register is applied to a fresh scan's results before anything is reported,
//! so a decision made once stays made.
//!
//! Two kinds, with deliberately different consequences:
//!
//! * [`ExceptionKind::FalsePositive`] — the engine was wrong. The finding is
//!   not a finding, so it is excluded from every deliverable outright.
//! * [`ExceptionKind::AcceptedRisk`] — the finding is real and the business has
//!   chosen to carry it. It is removed from the open-findings counts and the
//!   posture score, and printed instead in the report's accepted-risk register
//!   with its justification, its owner and its review date. Accepted exposure
//!   is disclosed, never deleted.
//!
//! An accepted risk may carry an expiry. Past it the exception stops applying
//! and the finding returns to the open list, which is what stops "accepted"
//! quietly becoming "forgotten".

use crate::models::finding::{Finding, FindingStatus, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Why a finding is excepted, and how a report must treat it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionKind {
    /// The engine was wrong; this is not a real weakness.
    FalsePositive,
    /// Real, and knowingly carried by the business.
    AcceptedRisk,
}

impl ExceptionKind {
    pub fn label(&self) -> &'static str {
        match self {
            ExceptionKind::FalsePositive => "False Positive",
            ExceptionKind::AcceptedRisk => "Accepted Risk",
        }
    }

    /// The triage status a finding takes when this exception is applied.
    pub fn status(&self) -> FindingStatus {
        match self {
            ExceptionKind::FalsePositive => FindingStatus::FalsePositive,
            ExceptionKind::AcceptedRisk => FindingStatus::AcceptedRisk,
        }
    }

    /// The status label an exception is created from, if any.
    pub fn from_status(status: &FindingStatus) -> Option<Self> {
        match status {
            FindingStatus::FalsePositive => Some(ExceptionKind::FalsePositive),
            FindingStatus::AcceptedRisk => Some(ExceptionKind::AcceptedRisk),
            _ => None,
        }
    }
}

/// One recorded exception.
///
/// Everything an auditor needs to challenge the decision is on the record:
/// what was excepted, why, who signed it off, when, and when it lapses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExceptionRecord {
    pub id: String,
    /// The target the decision was made against. Exceptions never cross targets.
    pub target_id: String,
    /// Stable identity of the weakness, from [`fingerprint`].
    pub fingerprint: String,
    pub kind: ExceptionKind,
    /// Title of the finding when the decision was taken, for the register.
    pub title: String,
    pub affected_component: String,
    /// Severity at the time of acceptance, so the register shows what was carried.
    pub severity: Severity,
    /// Why. Required — an exception with no rationale is not auditable.
    pub justification: String,
    /// Who approved it.
    pub raised_by: String,
    pub created_at: DateTime<Utc>,
    /// When the acceptance lapses. `None` means it stands until revoked.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

impl ExceptionRecord {
    /// Whether this exception still applies at `now`.
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            Some(expiry) => now < expiry,
            None => true,
        }
    }

    /// Days until expiry; negative once lapsed, `None` when open-ended.
    pub fn days_until_expiry(&self, now: DateTime<Utc>) -> Option<i64> {
        self.expires_at.map(|e| (e - now).num_days())
    }

    /// One-line audit trail entry to attach to a finding this exception covers.
    pub fn triage_note(&self) -> String {
        let expiry = match self.expires_at {
            Some(e) => format!(" (review by {})", e.format("%Y-%m-%d")),
            None => String::new(),
        };
        format!(
            "[{}] {} → {}{}: {} — carried forward automatically from exception {} \
             recorded on {}.",
            Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
            self.raised_by,
            self.kind.label(),
            expiry,
            self.justification,
            self.id,
            self.created_at.format("%Y-%m-%d"),
        )
    }
}

/// The stable identity of a weakness, independent of which scan found it.
///
/// Built from the target, the taxonomy (CWE + WSTG) and the normalised
/// location and title. Deliberately *not* built from the finding id, the scan
/// id, the timestamp, the evidence or the observed detail — all of those change
/// on a re-scan, which is precisely what broke carrying decisions forward.
///
/// The unit of exception is therefore "this check, on this location". Two
/// findings that a report would show as the same row on the same endpoint share
/// a fingerprint and are excepted together, which is how an analyst reasons
/// about it: you accept "no HttpOnly on /login", not "finding 3f2a…".
pub fn fingerprint(finding: &Finding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!(
        "SVX1:{}:{}:{}:{}:{}",
        finding.target_id,
        finding.cwe_id.as_deref().unwrap_or("NO-CWE").to_uppercase(),
        finding.wstg_id.as_deref().unwrap_or("NO-WSTG").to_uppercase(),
        normalise_component(&finding.affected_component),
        normalise_title(&finding.title),
    ));
    format!("{:x}", hasher.finalize())
}

/// Reduce a location to the part that is stable between scans.
///
/// Query strings and fragments carry per-run values (cache busters, probe
/// parameters, session ids), so they are dropped; a trailing slash is not a
/// different endpoint; and a `file.rs:412` source location keeps the file but
/// drops the line, because inserting one line above a weakness must not make
/// the analyst re-triage it.
pub fn normalise_component(component: &str) -> String {
    let without_fragment = component.split('#').next().unwrap_or(component);
    let without_query = without_fragment.split('?').next().unwrap_or(without_fragment);
    let trimmed = without_query.trim();

    // Source locations: strip a trailing `:line` or `:line:col`.
    let base = strip_line_numbers(trimmed);

    let lowered = base.to_lowercase();
    let no_trailing_slash = lowered.trim_end_matches('/');
    if no_trailing_slash.is_empty() {
        lowered
    } else {
        no_trailing_slash.to_string()
    }
}

/// Remove `:12` / `:12:5` suffixes without touching a `host:port` authority.
///
/// The two look identical on their own — `database.rs:412` and `app.test:443`
/// are both "dotted name, colon, digits". What separates them is that a source
/// location has a path in front of it and an authority does not, so a trailing
/// digit segment is only dropped when what precedes it contains a path
/// separator. `https://app.test:8443/x.js:12` keeps its port and loses its line.
fn strip_line_numbers(value: &str) -> String {
    let mut parts: Vec<&str> = value.split(':').collect();

    while parts.len() > 1 {
        let is_digits = parts
            .last()
            .is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
        if !is_digits {
            break;
        }
        let base = parts[..parts.len() - 1].join(":");
        // The authority of a URL is `scheme://host`, whose only slashes are the
        // scheme's own — a port there must survive.
        let path_after_authority = match base.split_once("://") {
            Some((_, rest)) => rest,
            None => base.as_str(),
        };
        if !path_after_authority.contains('/') && !path_after_authority.contains('\\') {
            break;
        }
        parts.pop();
    }

    parts.join(":")
}

/// Collapse a title to a comparable form: case- and whitespace-insensitive.
pub fn normalise_title(title: &str) -> String {
    title.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

/// What happened when a register was applied to a set of findings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// Findings suppressed as false positives.
    pub false_positives: usize,
    /// Findings moved into the accepted-risk register.
    pub accepted_risks: usize,
    /// Exceptions whose expiry has passed, so their findings stayed open.
    pub lapsed: usize,
}

impl ApplyOutcome {
    pub fn total_applied(&self) -> usize {
        self.false_positives + self.accepted_risks
    }
}

/// An indexed set of exceptions, ready to apply to a fresh scan's findings.
#[derive(Debug, Clone, Default)]
pub struct ExceptionRegister {
    by_fingerprint: HashMap<String, ExceptionRecord>,
}

impl ExceptionRegister {
    /// Index the records that belong to `target_id`.
    ///
    /// Where two records share a fingerprint the most recent wins, so
    /// re-deciding a weakness replaces the earlier judgement rather than
    /// leaving two contradictory ones in play.
    pub fn for_target<'a>(
        records: impl IntoIterator<Item = &'a ExceptionRecord>,
        target_id: &str,
    ) -> Self {
        let mut by_fingerprint: HashMap<String, ExceptionRecord> = HashMap::new();
        for record in records {
            if record.target_id != target_id {
                continue;
            }
            match by_fingerprint.get(&record.fingerprint) {
                Some(existing) if existing.created_at >= record.created_at => {}
                _ => {
                    by_fingerprint.insert(record.fingerprint.clone(), record.clone());
                }
            }
        }
        Self { by_fingerprint }
    }

    /// Index every supplied record regardless of target.
    pub fn from_records<'a>(records: impl IntoIterator<Item = &'a ExceptionRecord>) -> Self {
        let mut by_fingerprint: HashMap<String, ExceptionRecord> = HashMap::new();
        for record in records {
            match by_fingerprint.get(&record.fingerprint) {
                Some(existing) if existing.created_at >= record.created_at => {}
                _ => {
                    by_fingerprint.insert(record.fingerprint.clone(), record.clone());
                }
            }
        }
        Self { by_fingerprint }
    }

    pub fn is_empty(&self) -> bool {
        self.by_fingerprint.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_fingerprint.len()
    }

    /// The exception covering `finding`, if one is recorded and still in force.
    pub fn covering(&self, finding: &Finding, now: DateTime<Utc>) -> Option<&ExceptionRecord> {
        self.by_fingerprint
            .get(&fingerprint(finding))
            .filter(|record| record.is_active_at(now))
    }

    /// Apply the register to a fresh scan's findings, in place.
    ///
    /// Returns what was applied so the scan console can tell the analyst that
    /// their earlier decisions were honoured rather than silently re-raised.
    ///
    /// A finding the analyst has already triaged by hand in *this* scan is left
    /// alone: an explicit decision on the record in front of them outranks a
    /// carried-forward one.
    pub fn apply(&self, findings: &mut [Finding], now: DateTime<Utc>) -> ApplyOutcome {
        let mut outcome = ApplyOutcome::default();
        if self.by_fingerprint.is_empty() {
            return outcome;
        }

        for finding in findings.iter_mut() {
            if finding.status != FindingStatus::Open {
                continue;
            }
            let Some(record) = self.by_fingerprint.get(&fingerprint(finding)) else {
                continue;
            };
            if !record.is_active_at(now) {
                outcome.lapsed += 1;
                continue;
            }
            finding.status = record.kind.status();
            match record.kind {
                ExceptionKind::FalsePositive => outcome.false_positives += 1,
                ExceptionKind::AcceptedRisk => outcome.accepted_risks += 1,
            }
        }

        outcome
    }

    /// Every record in the register, newest decision first.
    pub fn records(&self) -> Vec<&ExceptionRecord> {
        let mut all: Vec<&ExceptionRecord> = self.by_fingerprint.values().collect();
        all.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.title.cmp(&b.title)));
        all
    }
}

/// Build an exception record from a finding the analyst has just triaged.
///
/// Returns `None` for statuses that are not exceptions — `Remediated` is a fix,
/// not a decision to carry a weakness, and must not suppress the next scan's
/// result: the whole point of re-testing is to confirm the fix landed.
pub fn from_triage(
    finding: &Finding,
    status: &FindingStatus,
    justification: &str,
    raised_by: &str,
    expires_at: Option<DateTime<Utc>>,
    id: String,
) -> Option<ExceptionRecord> {
    let kind = ExceptionKind::from_status(status)?;
    Some(ExceptionRecord {
        id,
        target_id: finding.target_id.to_string(),
        fingerprint: fingerprint(finding),
        kind,
        title: finding.title.clone(),
        affected_component: finding.affected_component.clone(),
        severity: finding.severity.clone(),
        justification: justification.trim().to_string(),
        raised_by: raised_by.trim().to_string(),
        created_at: Utc::now(),
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{CVSS4Data, Finding};
    use chrono::Duration;
    use uuid::Uuid;

    fn finding(target: Uuid, title: &str, component: &str) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            target_id: target,
            title: title.into(),
            description: "Observed on this run.".into(),
            severity: Severity::Medium,
            cvss4: Some(CVSS4Data {
                vector_string: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N".into(),
                base_score: 5.3,
                severity_label: "Medium".into(),
            }),
            epss: None,
            kev_listed: false,
            asset_exposure_factor: 1.0,
            reachability_score: 1.0,
            priority_score: 5.3,
            cwe_id: Some("CWE-693".into()),
            owasp_2025: Some("A05:2025-Security Misconfiguration".into()),
            wstg_id: Some("WSTG-CONF-12".into()),
            api_top10: None,
            affected_component: component.into(),
            evidences: vec![],
            repro_steps: vec![],
            remediation: "Set the header.".into(),
            references: vec!["https://owasp.org".into()],
            status: FindingStatus::Open,
            source_tools: vec!["Sentinel Native".into()],
            ai_triage: None,
            priority_rationale: String::new(),
            created_at: Utc::now(),
        }
    }

    fn exception(f: &Finding, kind: ExceptionKind, expires: Option<DateTime<Utc>>) -> ExceptionRecord {
        ExceptionRecord {
            id: "EXC-1".into(),
            target_id: f.target_id.to_string(),
            fingerprint: fingerprint(f),
            kind,
            title: f.title.clone(),
            affected_component: f.affected_component.clone(),
            severity: f.severity.clone(),
            justification: "Compensating control at the CDN.".into(),
            raised_by: "CISO".into(),
            created_at: Utc::now(),
            expires_at: expires,
        }
    }

    /// The bug this whole module exists to fix: a decision taken on one scan
    /// must still hold on the next one, where every id has changed.
    #[test]
    fn a_decision_survives_a_rescan_that_changes_every_id() {
        let target = Uuid::new_v4();
        let first = finding(target, "Content-Security-Policy header not set", "https://app.test/");
        let record = exception(&first, ExceptionKind::FalsePositive, None);

        // The next scan: new finding id, new scan id, same weakness.
        let mut second = vec![finding(target, "Content-Security-Policy header not set", "https://app.test/")];
        assert_ne!(first.id, second[0].id);

        let register = ExceptionRegister::for_target([&record], &target.to_string());
        let outcome = register.apply(&mut second, Utc::now());

        assert_eq!(outcome.false_positives, 1);
        assert_eq!(second[0].status, FindingStatus::FalsePositive);
    }

    #[test]
    fn an_accepted_risk_is_marked_accepted_not_dismissed() {
        let target = Uuid::new_v4();
        let f = finding(target, "Directory listing enabled", "https://app.test/assets/");
        let record = exception(&f, ExceptionKind::AcceptedRisk, None);
        let mut findings = vec![finding(target, "Directory listing enabled", "https://app.test/assets/")];

        let outcome = ExceptionRegister::from_records([&record]).apply(&mut findings, Utc::now());

        assert_eq!(outcome.accepted_risks, 1);
        assert_eq!(outcome.false_positives, 0);
        assert_eq!(findings[0].status, FindingStatus::AcceptedRisk);
    }

    /// An acceptance with a review date must not become permanent by neglect.
    #[test]
    fn a_lapsed_acceptance_lets_the_finding_come_back() {
        let target = Uuid::new_v4();
        let f = finding(target, "TLS 1.0 accepted", "app.test:443");
        let record = exception(&f, ExceptionKind::AcceptedRisk, Some(Utc::now() - Duration::days(1)));
        let mut findings = vec![finding(target, "TLS 1.0 accepted", "app.test:443")];

        let outcome = ExceptionRegister::from_records([&record]).apply(&mut findings, Utc::now());

        assert_eq!(outcome.lapsed, 1);
        assert_eq!(outcome.total_applied(), 0);
        assert_eq!(findings[0].status, FindingStatus::Open, "a lapsed exception must stop suppressing");
    }

    #[test]
    fn an_unexpired_acceptance_still_applies() {
        let target = Uuid::new_v4();
        let f = finding(target, "TLS 1.0 accepted", "app.test:443");
        let record = exception(&f, ExceptionKind::AcceptedRisk, Some(Utc::now() + Duration::days(30)));
        let mut findings = vec![finding(target, "TLS 1.0 accepted", "app.test:443")];

        ExceptionRegister::from_records([&record]).apply(&mut findings, Utc::now());
        assert_eq!(findings[0].status, FindingStatus::AcceptedRisk);
    }

    #[test]
    fn exceptions_never_cross_targets() {
        let mine = Uuid::new_v4();
        let theirs = Uuid::new_v4();
        let f = finding(mine, "Directory listing enabled", "https://app.test/assets/");
        let record = exception(&f, ExceptionKind::FalsePositive, None);

        let mut other_target = vec![finding(theirs, "Directory listing enabled", "https://app.test/assets/")];
        let register = ExceptionRegister::for_target([&record], &theirs.to_string());
        assert!(register.is_empty(), "the record belongs to another target");
        assert_eq!(register.apply(&mut other_target, Utc::now()).total_applied(), 0);
    }

    #[test]
    fn a_different_weakness_on_the_same_page_is_untouched() {
        let target = Uuid::new_v4();
        let f = finding(target, "Content-Security-Policy header not set", "https://app.test/");
        let record = exception(&f, ExceptionKind::FalsePositive, None);

        let mut findings = vec![finding(target, "Directory listing enabled", "https://app.test/")];
        let outcome = ExceptionRegister::from_records([&record]).apply(&mut findings, Utc::now());
        assert_eq!(outcome.total_applied(), 0);
        assert_eq!(findings[0].status, FindingStatus::Open);
    }

    /// A per-run query parameter must not defeat the match, or every probe-based
    /// finding would need re-triaging on every scan.
    #[test]
    fn query_strings_and_trailing_slashes_do_not_change_identity() {
        let target = Uuid::new_v4();
        let a = finding(target, "Open redirect", "https://app.test/go/?next=https://probe.test/");
        let b = finding(target, "Open redirect", "https://app.test/go?next=https://other.test/");
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    /// Inserting a line above a weakness must not silently un-triage it.
    #[test]
    fn a_shifted_source_line_keeps_its_identity() {
        let target = Uuid::new_v4();
        let a = finding(target, "Hardcoded secret", "src/config/database.rs:412");
        let b = finding(target, "Hardcoded secret", "src/config/database.rs:419:8");
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn a_host_port_authority_is_not_mistaken_for_a_line_number() {
        assert_eq!(normalise_component("https://app.test:8443/"), "https://app.test:8443");
        assert_eq!(normalise_component("app.test:443"), "app.test:443");
        // A port and a line number in the same value: keep one, drop the other.
        assert_eq!(
            normalise_component("https://app.test:8443/static/app.js:120"),
            "https://app.test:8443/static/app.js"
        );
    }

    #[test]
    fn a_windows_source_path_loses_its_line_number_too() {
        assert_eq!(
            normalise_component("C:\\src\\config\\database.rs:412"),
            "c:\\src\\config\\database.rs"
        );
    }

    #[test]
    fn a_different_file_is_a_different_weakness() {
        let target = Uuid::new_v4();
        let a = finding(target, "Hardcoded secret", "src/config/database.rs:412");
        let b = finding(target, "Hardcoded secret", "src/config/cache.rs:412");
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    /// The analyst is looking at this scan's record; that beats an old decision.
    #[test]
    fn a_decision_already_taken_on_this_scan_is_not_overwritten() {
        let target = Uuid::new_v4();
        let f = finding(target, "Directory listing enabled", "https://app.test/assets/");
        let record = exception(&f, ExceptionKind::FalsePositive, None);

        let mut findings = vec![finding(target, "Directory listing enabled", "https://app.test/assets/")];
        findings[0].status = FindingStatus::Remediated;

        ExceptionRegister::from_records([&record]).apply(&mut findings, Utc::now());
        assert_eq!(findings[0].status, FindingStatus::Remediated);
    }

    #[test]
    fn re_deciding_a_weakness_replaces_the_earlier_judgement() {
        let target = Uuid::new_v4();
        let f = finding(target, "Directory listing enabled", "https://app.test/assets/");
        let mut old = exception(&f, ExceptionKind::FalsePositive, None);
        old.created_at = Utc::now() - Duration::days(30);
        old.id = "EXC-OLD".into();
        let new = exception(&f, ExceptionKind::AcceptedRisk, None);

        for order in [vec![&old, &new], vec![&new, &old]] {
            let register = ExceptionRegister::from_records(order);
            assert_eq!(register.len(), 1);
            assert_eq!(register.records()[0].kind, ExceptionKind::AcceptedRisk);
        }
    }

    /// Re-testing exists to confirm a fix. Suppressing the check that would
    /// prove it would make the next report a lie.
    #[test]
    fn remediation_does_not_create_an_exception() {
        let target = Uuid::new_v4();
        let f = finding(target, "Directory listing enabled", "https://app.test/assets/");
        assert!(from_triage(&f, &FindingStatus::Remediated, "fixed in 2.1", "dev", None, "x".into()).is_none());
        assert!(from_triage(&f, &FindingStatus::Open, "looking", "dev", None, "x".into()).is_none());
        assert!(from_triage(&f, &FindingStatus::InProgress, "on it", "dev", None, "x".into()).is_none());
        assert!(from_triage(&f, &FindingStatus::AcceptedRisk, "risk owned", "ciso", None, "x".into()).is_some());
        assert!(from_triage(&f, &FindingStatus::FalsePositive, "not real", "analyst", None, "x".into()).is_some());
    }

    #[test]
    fn a_record_built_from_triage_captures_the_audit_trail() {
        let target = Uuid::new_v4();
        let f = finding(target, "Directory listing enabled", "https://app.test/assets/");
        let record = from_triage(
            &f,
            &FindingStatus::AcceptedRisk,
            "  Static asset index, no sensitive files.  ",
            " M. Patel ",
            None,
            "EXC-9".into(),
        )
        .unwrap();

        assert_eq!(record.justification, "Static asset index, no sensitive files.");
        assert_eq!(record.raised_by, "M. Patel");
        assert_eq!(record.fingerprint, fingerprint(&f));
        assert_eq!(record.target_id, target.to_string());
        assert!(record.triage_note().contains("carried forward automatically"));
    }

    #[test]
    fn the_triage_note_names_the_review_date_when_there_is_one() {
        let target = Uuid::new_v4();
        let f = finding(target, "Directory listing enabled", "https://app.test/assets/");
        let record = exception(&f, ExceptionKind::AcceptedRisk, Some(Utc::now() + Duration::days(90)));
        assert!(record.triage_note().contains("review by"));
        assert_eq!(record.days_until_expiry(Utc::now()), Some(89));
    }

    #[test]
    fn titles_compare_case_and_whitespace_insensitively() {
        assert_eq!(normalise_title("  Missing   HSTS Header "), "missing hsts header");
    }
}
