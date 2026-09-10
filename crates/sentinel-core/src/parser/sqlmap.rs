//! sqlmap output.
//!
//! sqlmap is the tool that answers the one question a SQL-injection finding
//! from any other engine cannot: is it actually exploitable, and how. A static
//! rule sees a query built from a request value; a DAST scanner sees a response
//! that changed when a quote was added. sqlmap confirms the injection by
//! fingerprinting the backend, enumerating the injection technique, and — where
//! permitted — proving it end to end. That confirmation is what turns a
//! "potential SQLi" a client can argue with into a demonstrated one they cannot.
//!
//! This parser reads sqlmap's console output rather than its session database,
//! because the console is the one format stable across versions. sqlmap prints
//! its confirmed injection points in a fixed block:
//!
//! ```text
//! sqlmap identified the following injection point(s) with a total of ...
//! ---
//! Parameter: id (GET)
//!     Type: boolean-based blind
//!     Title: AND boolean-based blind - WHERE or HAVING clause
//!     Payload: id=1 AND 3011=3011
//!
//!     Type: UNION query
//!     Title: Generic UNION query (NULL) - 3 columns
//!     Payload: id=1 UNION ALL SELECT NULL,NULL,...
//! ---
//! ```
//!
//! One finding is raised per injected parameter, not per technique: five
//! techniques against `id` is one vulnerability with five confirmations, and
//! reporting it as five would inflate the count of a report that lives or dies
//! on the reader trusting it. The techniques and payloads are attached as
//! evidence.

use super::external::ExternalFinding;
use crate::models::finding::{Finding, Severity};
use anyhow::Result;
use uuid::Uuid;

pub struct SqlmapParser;

/// One confirmed injection point, as sqlmap describes it.
struct InjectionPoint {
    parameter: String,
    place: String,
    techniques: Vec<String>,
    payloads: Vec<String>,
}

impl SqlmapParser {
    /// Parse the console output of an `sqlmap --batch` run.
    pub fn parse(output: &str, target_url: &str, target_id: Uuid, scan_id: Uuid) -> Result<Vec<Finding>> {
        let dbms = Self::backend_dbms(output);
        let points = Self::injection_points(output);

        let findings = points
            .into_iter()
            .map(|p| Self::finding(&p, target_url, dbms.as_deref()).into_finding(target_id, scan_id))
            .collect();
        Ok(findings)
    }

    /// The "back-end DBMS: MySQL >= 5.0" line, when sqlmap fingerprinted one.
    fn backend_dbms(output: &str) -> Option<String> {
        output
            .lines()
            .find_map(|l| l.split("back-end DBMS:").nth(1))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Every "Parameter:" block inside the injection-point section.
    ///
    /// The section is bounded, so a "Parameter:" appearing elsewhere in the log
    /// (a crawl line, a warning) is not mistaken for a confirmed injection.
    fn injection_points(output: &str) -> Vec<InjectionPoint> {
        let Some(start) = output.find("identified the following injection point") else {
            return Vec::new();
        };
        // The block runs to the DBMS fingerprint line or the end of output.
        let rest = &output[start..];
        let block_end = rest.find("\nback-end DBMS:").unwrap_or(rest.len());
        let block = &rest[..block_end];

        let mut points: Vec<InjectionPoint> = Vec::new();
        for raw in block.split("Parameter:").skip(1) {
            // "id (GET)" -> parameter "id", place "GET".
            let header = raw.lines().next().unwrap_or("").trim();
            let (parameter, place) = match (header.find('('), header.find(')')) {
                (Some(o), Some(c)) if c > o => (
                    header[..o].trim().to_string(),
                    header[o + 1..c].trim().to_string(),
                ),
                _ => (header.to_string(), "unknown".to_string()),
            };
            if parameter.is_empty() {
                continue;
            }

            let techniques = raw
                .lines()
                .filter_map(|l| l.trim().strip_prefix("Title:"))
                .map(|t| t.trim().to_string())
                .collect();
            let payloads = raw
                .lines()
                .filter_map(|l| l.trim().strip_prefix("Payload:"))
                .map(|t| t.trim().to_string())
                .collect();

            points.push(InjectionPoint { parameter, place, techniques, payloads });
        }
        points
    }

    fn finding(point: &InjectionPoint, target_url: &str, dbms: Option<&str>) -> ExternalFinding {
        let dbms_phrase = dbms
            .map(|d| format!(" against {d}"))
            .unwrap_or_default();

        let technique_list = if point.techniques.is_empty() {
            "one or more injection techniques".to_string()
        } else {
            point.techniques.join("; ")
        };

        let mut ef = ExternalFinding::new(
            format!(
                "SQL injection confirmed in the {} parameter '{}'",
                point.place, point.parameter
            ),
            // A confirmed, exploitable injection is the real thing, not a lead.
            Severity::Critical,
            format!("{target_url} (parameter '{}', {})", point.parameter, point.place),
            "sqlmap",
        )
        .description(format!(
            "sqlmap confirmed that the '{}' parameter ({}) is injectable{dbms_phrase}. Unlike a \
             pattern match, this is a demonstrated flaw: sqlmap altered the query the application \
             sent to its database and observed the result change as predicted, using {technique_list}. \
             An attacker with the same access can read any data the database account can reach, and \
             depending on the account's rights, modify it or reach the host underneath. The presence \
             of a working UNION or stacked-query technique in particular means data can be extracted \
             directly rather than inferred a bit at a time.",
            point.parameter, point.place,
        ))
        .remediation(
            "Fix the query, not the input. Use a parameterised query (a prepared statement with \
             bound parameters) so the database receives the statement and the values separately \
             and can never parse one as the other. Escaping and input filtering are not \
             substitutes — sqlmap's technique list is, in effect, a list of the filters that have \
             already been bypassed.\n\n\
             Where the injectable value is an identifier rather than a datum — a table or column \
             name, a sort direction — a bound parameter will not apply; map the input through a \
             fixed allow-list of permitted identifiers instead. After fixing, re-run sqlmap against \
             the same parameter to confirm the injection is gone."
        )
        .taxonomy("CWE-89", "A05:2025-Injection", Some("WSTG-INPV-05"))
        .references(vec![
            "https://cwe.mitre.org/data/definitions/89.html".to_string(),
            "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                .to_string(),
        ])
        .repro(vec![
            format!(
                "Send a request to {target_url} where the '{}' parameter carries a SQL payload \
                 rather than a plain value.",
                point.parameter
            ),
            "sqlmap automates this; the exact payloads it used are in the evidence below."
                .to_string(),
            "Observe that the response reflects the injected condition — the query executed with \
             attacker-controlled logic."
                .to_string(),
        ])
        // sqlmap confirms exploitation rather than matching a signature, so the
        // false-positive rate is very low and reachability is full.
        .confidence(
            0.02,
            "sqlmap confirmed this by exploiting it, not by matching a pattern. Treat it as a \
             true positive unless the target is a deliberately vulnerable test application.",
        )
        .reachability(1.0);

        if !point.techniques.is_empty() {
            ef = ef.evidence(
                "sqlmap_techniques",
                "Confirmed injection techniques",
                &point.techniques.join("\n"),
            );
        }
        if !point.payloads.is_empty() {
            ef = ef.evidence(
                "sqlmap_payloads",
                "Payloads that confirmed the injection",
                &point.payloads.join("\n"),
            );
        }
        ef
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 247 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3011=3011

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT NULL,CONCAT(0x71,0x76),NULL-- -
---
[INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
";

    fn parse(s: &str) -> Vec<Finding> {
        SqlmapParser::parse(s, "https://shop.example.net/item", Uuid::new_v4(), Uuid::new_v4()).unwrap()
    }

    #[test]
    fn a_confirmed_injection_becomes_one_critical_finding() {
        let f = parse(SAMPLE);
        assert_eq!(f.len(), 1, "one parameter, one finding — not one per technique");
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].cwe_id.as_deref(), Some("CWE-89"));
        assert!(f[0].title.contains("'id'"));
    }

    #[test]
    fn the_backend_and_every_technique_are_kept_as_evidence() {
        let f = parse(SAMPLE);
        let ev: String = f[0].evidences.iter().map(|e| e.content.clone()).collect::<Vec<_>>().join("\n");
        assert!(ev.contains("boolean-based blind"), "technique kept");
        assert!(ev.contains("UNION query"), "second technique kept");
        assert!(ev.contains("UNION ALL SELECT"), "payload kept");
        assert!(f[0].description.contains("MySQL"), "the fingerprinted DBMS is named");
    }

    #[test]
    fn output_with_no_injection_yields_nothing() {
        let clean = "all tested parameters do not appear to be injectable.";
        assert!(parse(clean).is_empty());
    }

    #[test]
    fn a_parameter_named_outside_the_injection_block_is_not_a_finding() {
        // "Parameter:" can appear in sqlmap's chatter; only the block counts.
        let noise = "\
[INFO] testing if GET parameter 'id' is dynamic
[WARNING] GET parameter 'ref' does not seem to be injectable
all tested parameters do not appear to be injectable.";
        assert!(parse(noise).is_empty());
    }

    #[test]
    fn two_injectable_parameters_are_two_findings() {
        let two = "\
sqlmap identified the following injection point(s) with a total of 40 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
    Payload: id=1 AND 1=1
Parameter: cat (GET)
    Type: error-based
    Title: MySQL error-based
    Payload: cat=1 AND GTID_SUBSET(...)
---
back-end DBMS: MySQL >= 5.0";
        let f = parse(two);
        assert_eq!(f.len(), 2);
        assert!(f.iter().any(|x| x.title.contains("'id'")));
        assert!(f.iter().any(|x| x.title.contains("'cat'")));
    }
}
