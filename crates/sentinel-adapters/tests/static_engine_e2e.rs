//! End-to-end test for the static engines against a realistic source tree.
//!
//! The unit corpus proves each rule fires on a line written to provoke it. That
//! is necessary and not sufficient: it says nothing about whether the engine
//! finds the same weakness inside a file that also contains imports, comments,
//! helpers and correct code, nor whether the walker reaches the file at all.
//! Between a rule matching a string and a finding reaching a report sit the
//! directory walk, the skip rules, the language detection, the comment state
//! machine, the taint table and the per-rule caps — each of which can silently
//! drop a real defect.
//!
//! So this writes an application to disk, in the shape applications are
//! actually written, and runs the adapter the desktop app runs. The vulnerable
//! tree must produce the findings; the remediated tree — same application, same
//! files, same structure, defects fixed — must produce none of them. The second
//! half is what stops the engine from passing by reporting everything.

use sentinel_adapters::adapter_trait::ScannerAdapter;
use sentinel_adapters::static_engine::sast::NativeSastAdapter;
use sentinel_core::models::finding::Finding;
use sentinel_core::models::target::Target;
use std::path::Path;
use uuid::Uuid;

/// A scratch directory that removes itself.
///
/// Deliberately not `tempfile`: this crate is cross-compiled to Windows for the
/// desktop bundle, and a test-only dependency is still a dependency the release
/// build has to resolve. The needs here are one unique directory and cleanup on
/// drop, which is a dozen lines.
struct ScratchRepo(std::path::PathBuf);

impl ScratchRepo {
    fn new(label: &str) -> Self {
        // The address of a local allocation plus the label is unique enough to
        // keep concurrent tests in this binary from sharing a tree.
        let unique = format!("sentinel-{label}-{:p}-{:?}", &label, std::thread::current().id());
        let path = std::env::temp_dir().join(unique.replace(['(', ')', ' '], ""));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch repo");
        ScratchRepo(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn target_for(repo: &Path) -> Target {
    Target {
        id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        name: "acme-shop".into(),
        target_type: "Web App".into(),
        base_url: "https://shop.example.net".into(),
        repo_ref: Some(repo.to_string_lossy().into_owned()),
        stack_description: Some("Node + Python".into()),
        auth_keychain_handle: None,
        authorization_record: None,
        created_at: chrono::Utc::now(),
    }
}

fn write(root: &Path, relative: &str, body: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().expect("a parent directory")).expect("create dirs");
    std::fs::write(path, body).expect("write source file");
}

async fn scan(root: &Path) -> Vec<Finding> {
    NativeSastAdapter
        .run(&target_for(root), "{}")
        .await
        .expect("the code engine runs over a readable checkout")
}

fn found(findings: &[Finding], cwe: &str) -> bool {
    findings.iter().any(|f| f.cwe_id.as_deref() == Some(cwe))
}

/// The order-handling service, written the way it goes wrong.
fn write_vulnerable_app(root: &Path) {
    write(root, "package.json", r#"{ "name": "acme-shop", "version": "1.0.0" }"#);

    write(root, "src/routes/orders.js", r#"
const express = require('express');
const router = express.Router();
const db = require('../db');

// Look up an order for the signed-in customer.
router.get('/orders/:id', async (req, res) => {
  // The id comes straight off the route and into the statement.
  const rows = await db.query('SELECT * FROM orders WHERE id = ' + req.params.id);
  if (!rows.length) {
    return res.status(404).json({ error: 'not found' });
  }
  return res.json(rows[0]);
});

router.post('/orders', async (req, res) => {
  try {
    const order = await db.insert('orders', req.body);
    res.json(order);
  } catch (err) {
    res.send(err.stack);
  }
});

module.exports = router;
"#);

    write(root, "src/routes/admin.js", r#"
const express = require('express');
const router = express.Router();
const { exec } = require('child_process');

const ADMIN_IPS = ['10.0.0.4', '10.0.0.5'];

router.post('/admin/purge-cache', (req, res) => {
  if (ADMIN_IPS.includes(req.headers['x-forwarded-for'])) {
    exec('redis-cli FLUSHDB ' + req.body.namespace, (e, out) => res.send(out));
    return;
  }
  res.status(403).end();
});

module.exports = router;
"#);

    write(root, "src/lib/session.js", r#"
const crypto = require('crypto');
const session = require('express-session');

const SESSION_SECRET = 'k39fjs82hdnc61mz';

function configure(app) {
  app.use(session({
    secret: SESSION_SECRET,
    cookie: { httpOnly: false, secure: false },
  }));
}

function resetLink(req, token) {
  return 'https://' + req.headers['host'] + '/account/reset?token=' + token;
}

function newToken() {
  return Math.random().toString(36).slice(2);
}

module.exports = { configure, resetLink, newToken, crypto };
"#);

    write(root, "services/accounts.py", r#"
import hashlib
import subprocess

from flask import request


def store_password(user, password):
    """Persist the customer's password."""
    user.password_hash = hashlib.sha256(password.encode()).hexdigest()
    user.save()


def run_report(name):
    subprocess.run("generate-report " + name, shell=True)


def require_admin(current_user):
    assert current_user.is_admin


def load_profile(path):
    try:
        with open(path) as handle:
            return handle.read()
    except Exception:
        pass
"#);
}

/// The same application with each defect corrected. Nothing is deleted — the
/// endpoints, the helpers and the control flow all remain — so a finding here
/// is the engine reporting correct code.
fn write_remediated_app(root: &Path) {
    write(root, "package.json", r#"{ "name": "acme-shop", "version": "1.0.0" }"#);

    write(root, "src/routes/orders.js", r#"
const express = require('express');
const router = express.Router();
const db = require('../db');

router.get('/orders/:id', async (req, res) => {
  const rows = await db.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
  if (!rows.length) {
    return res.status(404).json({ error: 'not found' });
  }
  return res.json(rows[0]);
});

router.post('/orders', async (req, res) => {
  try {
    const order = await db.insert('orders', { sku: req.body.sku, qty: req.body.qty });
    res.json(order);
  } catch (err) {
    req.log.error(err);
    res.status(500).json({ error: 'order could not be created' });
  }
});

module.exports = router;
"#);

    write(root, "src/routes/admin.js", r#"
const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');

router.post('/admin/purge-cache', requireAdminRole, (req, res) => {
  const namespace = NAMESPACES[req.body.namespace];
  if (!namespace) {
    return res.status(400).end();
  }
  execFile('redis-cli', ['FLUSHDB', namespace], (e, out) => res.send(out));
});

module.exports = router;
"#);

    write(root, "src/lib/session.js", r#"
const crypto = require('crypto');
const session = require('express-session');

function configure(app) {
  app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: { httpOnly: true, secure: true },
  }));
}

function resetLink(req, token) {
  return process.env.PUBLIC_BASE_URL + '/account/reset?token=' + token;
}

function newToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { configure, resetLink, newToken };
"#);

    write(root, "services/accounts.py", r#"
import subprocess

import bcrypt
from flask import request

from .errors import PermissionDenied


def store_password(user, password):
    """Persist the customer's password."""
    user.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
    user.save()


def run_report(name):
    subprocess.run(["generate-report", name], shell=False)


def require_admin(current_user):
    if not current_user.is_admin:
        raise PermissionDenied("admin role required")


def load_profile(path):
    try:
        with open(path) as handle:
            return handle.read()
    except OSError as exc:
        logger.warning("profile unreadable: %s", exc)
        return None
"#);
}

/// Every weakness planted in the tree, by the CWE a report would group it under.
const PLANTED: &[(&str, &str)] = &[
    ("CWE-89", "SQL built from a route parameter"),
    ("CWE-78", "shell command built from a request body value"),
    ("CWE-348", "admin check on a forwarding header"),
    ("CWE-798", "session signing key committed to source"),
    ("CWE-644", "reset link built from the Host header"),
    ("CWE-916", "password stored with a fast hash"),
    ("CWE-617", "authorisation enforced with assert"),
    ("CWE-338", "token generated from a non-cryptographic RNG"),
    ("CWE-209", "stack trace returned to the client"),
];

#[tokio::test]
async fn a_realistic_vulnerable_application_yields_the_planted_findings() {
    let dir = ScratchRepo::new("vulnerable");
    write_vulnerable_app(dir.path());

    let findings = scan(dir.path()).await;

    let missed: Vec<&str> = PLANTED
        .iter()
        .filter(|(cwe, _)| !found(&findings, cwe))
        .map(|(_, what)| *what)
        .collect();
    let cwes: Vec<&str> = findings.iter().filter_map(|f| f.cwe_id.as_deref()).collect();
    assert!(
        missed.is_empty(),
        "the engine missed {} planted weakness(es): {:?}\n  it reported: {:?}",
        missed.len(),
        missed,
        cwes
    );
}

/// The half that makes the test above mean something.
#[tokio::test]
async fn the_remediated_application_produces_none_of_them() {
    let dir = ScratchRepo::new("remediated");
    write_remediated_app(dir.path());

    let findings = scan(dir.path()).await;

    let spurious: Vec<String> = PLANTED
        .iter()
        .filter(|(cwe, _)| found(&findings, cwe))
        .map(|(cwe, what)| {
            let titles: Vec<&str> = findings
                .iter()
                .filter(|f| f.cwe_id.as_deref() == Some(*cwe))
                .map(|f| f.title.as_str())
                .collect();
            format!("{cwe} ({what}) — reported as {titles:?}")
        })
        .collect();
    assert!(
        spurious.is_empty(),
        "the engine reported {} weakness(es) in code where each was corrected:\n  {}",
        spurious.len(),
        spurious.join("\n  ")
    );
}

/// A scan that finds nothing and a scan that was never able to read anything
/// look identical in a report unless the engine says what it covered.
#[tokio::test]
async fn every_scan_states_what_it_read() {
    let dir = ScratchRepo::new("remediated");
    write_remediated_app(dir.path());

    let findings = scan(dir.path()).await;
    let coverage = findings
        .iter()
        .find(|f| f.title.contains("coverage"))
        .expect("the engine records what it analysed");
    assert!(
        coverage.description.contains('5') || coverage.description.contains("file"),
        "the coverage record does not say how much was read: {}",
        coverage.description
    );
}

/// A repository path that does not exist is an engagement setup mistake, and
/// has to fail loudly rather than produce an empty, reassuring report.
#[tokio::test]
async fn a_missing_checkout_is_an_error_rather_than_a_clean_result() {
    let mut target = target_for(Path::new("/nonexistent/acme-shop"));
    target.repo_ref = Some("/nonexistent/acme-shop".into());
    assert!(NativeSastAdapter.run(&target, "{}").await.is_err());
}
