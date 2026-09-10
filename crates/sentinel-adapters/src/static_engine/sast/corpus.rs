//! Proof that every rule in the catalog actually fires.
//!
//! A rule is a regex, a mode and a paragraph of prose. Nothing about writing
//! one guarantees it ever matches: a pattern can be subtly wrong, an `unless`
//! clause can be broad enough to suppress every real hit, and a `Tainted` rule
//! can be unreachable because no language profile recognises the source it
//! depends on. All three failures are silent. The catalog still lists the rule,
//! the coverage matrix still counts its OWASP category as answered, and the
//! report still tells a client that the codebase was checked for it — while the
//! engine has never once been able to raise it.
//!
//! That is the failure this module exists to make impossible. Every rule needs
//! a sample it is expected to catch, and the exhaustiveness test below fails
//! the build when a rule is added without one, so a new rule cannot ship
//! without evidence that it works.
//!
//! The negative corpus matters just as much. A rule that fires on the safe form
//! of the same construct is worse than no rule: it teaches an analyst to skim
//! past the category, and on a real engagement it buries the one true finding
//! under forty parameterised queries.

use super::*;
use crate::static_engine::codebase::{Provenance, WalkStop};
use std::path::PathBuf;

/// One sample and the rule it is expected to provoke.
struct Case {
    rule: &'static str,
    /// Chosen for its extension, which is what selects the language profile.
    /// Never contains "test" — the engine classifies those as test code and
    /// skips them, which would make a case pass by scanning nothing.
    file: &'static str,
    code: &'static str,
}

/// Vulnerable samples. Each is the shape the rule was written to catch.
///
/// The `Tainted` rules take their source inline rather than through a local
/// variable. Both forms work, but the inline form isolates what is under test:
/// a failure here is the rule's pattern, not the flow analysis.
const VULNERABLE: &[Case] = &[
    // ── Injection ────────────────────────────────────────────────────────────
    Case { rule: "SENTINEL-SQLI", file: "src/users.js",
        code: "db.query('SELECT * FROM users WHERE id = ' + req.query.id);" },
    Case { rule: "SENTINEL-SQLI-ORM-RAW", file: "src/report.js",
        code: "sequelize.query('SELECT * FROM t WHERE n = ' + req.query.name);" },
    Case { rule: "SENTINEL-CMDI", file: "src/ops.js",
        code: "exec('rm -rf ' + req.body.path);" },
    Case { rule: "SENTINEL-SHELL-TRUE", file: "src/run.py",
        code: "subprocess.run(command, shell=True)" },
    Case { rule: "SENTINEL-CODE-EVAL", file: "src/calc.js",
        code: "const result = eval(expression);" },
    Case { rule: "SENTINEL-NOSQLI", file: "src/find.js",
        code: "db.collection('users').findOne(req.body.filter);" },
    Case { rule: "SENTINEL-LDAPI", file: "src/dir.js",
        code: "ldap.search('(uid=' + req.query.user + ')');" },
    Case { rule: "SENTINEL-SSTI", file: "src/view.py",
        code: "render_template_string('Hello ' + request.args.get('name'))" },
    Case { rule: "SENTINEL-XPATH", file: "src/lookup.js",
        code: "doc.evaluate('//user[@id=\"' + req.query.id + '\"]');" },
    Case { rule: "SENTINEL-LOG-INJECTION", file: "src/audit.js",
        code: "logger.info('login for ' + req.query.user);" },

    // ── Cross-site scripting ────────────────────────────────────────────────
    Case { rule: "SENTINEL-XSS-DOM-SINK", file: "src/render.js",
        code: "el.innerHTML = req.query.name;" },
    Case { rule: "SENTINEL-XSS-FRAMEWORK-BYPASS", file: "src/Post.jsx",
        code: "<div dangerouslySetInnerHTML={{ __html: body }} />" },
    Case { rule: "SENTINEL-XSS-AUTOESCAPE-OFF", file: "src/tmpl.py",
        code: "env = Environment(loader=loader, autoescape=False)" },

    // ── Deserialization and parsing ─────────────────────────────────────────
    Case { rule: "SENTINEL-INSECURE-DESERIALIZATION", file: "src/cache.py",
        code: "session = pickle.loads(blob)" },
    Case { rule: "SENTINEL-XXE", file: "src/Parse.java",
        code: "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();" },

    // ── File and network access ─────────────────────────────────────────────
    Case { rule: "SENTINEL-PATH-TRAVERSAL", file: "src/files.js",
        code: "fs.readFile(req.query.file, cb);" },
    Case { rule: "SENTINEL-ZIP-SLIP", file: "src/unpack.py",
        code: "zipfile.ZipFile(archive).extractall(destination)" },
    Case { rule: "SENTINEL-SSRF", file: "src/proxy.js",
        code: "fetch(req.query.url);" },

    // ── Cryptography ────────────────────────────────────────────────────────
    Case { rule: "SENTINEL-WEAK-HASH", file: "src/sign.js",
        code: "const d = crypto.createHash('md5').update(body).digest('hex');" },
    Case { rule: "SENTINEL-WEAK-CIPHER", file: "src/Crypt.java",
        code: "Cipher c = Cipher.getInstance(\"DES\");" },
    Case { rule: "SENTINEL-WEAK-RANDOM", file: "src/token.js",
        code: "const value = Math.random().toString(36);" },
    Case { rule: "SENTINEL-STATIC-IV", file: "src/aes.js",
        code: "const iv = 'A1B2C3D4E5F60718';" },
    Case { rule: "SENTINEL-SMALL-KEY", file: "src/keys.js",
        code: "crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });" },
    Case { rule: "SENTINEL-TLS-VERIFY-DISABLED", file: "src/http.js",
        code: "const agent = new https.Agent({ rejectUnauthorized: false });" },
    Case { rule: "SENTINEL-PLAINTEXT-TRANSPORT", file: "src/api.js",
        code: "const endpoint = \"http://payments.acme-shop.net/charge\";" },
    Case { rule: "SENTINEL-JWT-UNVERIFIED", file: "src/auth.js",
        code: "const claims = jwt.decode(bearer);" },

    // ── Web configuration ───────────────────────────────────────────────────
    Case { rule: "SENTINEL-CORS-WILDCARD-CREDENTIALS", file: "src/cors.js",
        code: "app.use(cors({ origin: '*', credentials: true }));" },
    Case { rule: "SENTINEL-CSRF-DISABLED", file: "src/views.py",
        code: "@csrf_exempt" },
    Case { rule: "SENTINEL-COOKIE-INSECURE", file: "src/session.js",
        code: "app.use(session({ cookie: { httpOnly: false } }));" },
    Case { rule: "SENTINEL-OPEN-REDIRECT", file: "src/login.js",
        code: "res.redirect(req.query.next);" },
    Case { rule: "SENTINEL-MASS-ASSIGNMENT", file: "src/signup.js",
        code: "User.create(req.body);" },
    Case { rule: "SENTINEL-DEBUG-ENABLED", file: "src/app.py",
        code: "app.run(host='127.0.0.1', debug=True)" },
    Case { rule: "SENTINEL-BIND-ALL-INTERFACES", file: "src/serve.py",
        code: "server.bind(('0.0.0.0', 8080))" },

    // ── Language and platform specifics ─────────────────────────────────────
    Case { rule: "SENTINEL-PROTOTYPE-POLLUTION", file: "src/opts.js",
        code: "merge(defaults, req.body);" },
    Case { rule: "SENTINEL-REDOS", file: "src/validate.js",
        code: "const re = /^(a+)+$/;" },
    Case { rule: "SENTINEL-INSECURE-TEMP-FILE", file: "src/scratch.py",
        code: "handle = open('/tmp/upload.dat', 'wb')" },
    Case { rule: "SENTINEL-UNSAFE-REFLECTION", file: "src/dispatch.py",
        code: "handler = getattr(module, request.args.get('action'))" },
    Case { rule: "SENTINEL-ELECTRON-NODE-INTEGRATION", file: "src/window.js",
        code: "new BrowserWindow({ webPreferences: { nodeIntegration: true } });" },
    Case { rule: "SENTINEL-GRAPHQL-INTROSPECTION", file: "src/gql.js",
        code: "const server = new ApolloServer({ schema, introspection: true });" },
    Case { rule: "SENTINEL-TIMING-UNSAFE-COMPARE", file: "src/verify.js",
        code: "if (signature === expected) { return true; }" },
    Case { rule: "SENTINEL-BUFFER-UNSAFE", file: "src/parse.c",
        code: "strcpy(destination, source);" },
    Case { rule: "SENTINEL-HARDCODED-DB-CONNECTION", file: "src/db.js",
        code: "const dsn = 'postgres://svcadmin:h7Kp2qRz@db.acme-shop.net/orders';" },
    Case { rule: "SENTINEL-DISABLED-CERT-PINNING", file: "src/Web.java",
        code: "webView.getSettings().setJavaScriptEnabled(true);" },
    Case { rule: "SENTINEL-PERMISSIVE-FILE-MODE", file: "src/perms.py",
        code: "os.chmod(path, 0o777)" },
    Case { rule: "SENTINEL-MISSING-AUTH-CHECK", file: "src/routes.js",
        code: "app.post('/admin/delete-user', async (req, res) => {" },
    Case { rule: "SENTINEL-EXCEPTION-SWALLOWED", file: "src/worker.py",
        code: "try:\n    flush()\nexcept Exception:\n    pass" },
    Case { rule: "SENTINEL-STACK-TRACE-TO-CLIENT", file: "src/error.js",
        code: "res.send(err.stack);" },

    // ── Trust boundaries, credentials and secrets ───────────────────────────
    Case { rule: "SENTINEL-HEADER-INJECTION", file: "src/trace.js",
        code: "res.setHeader('X-Trace-Id', 'req-' + req.query.trace);" },
    Case { rule: "SENTINEL-TRUSTED-PROXY-HEADER", file: "src/gate.js",
        code: "if (ADMIN_IPS.includes(req.headers['x-forwarded-for'])) { grant(); }" },
    Case { rule: "SENTINEL-HOST-HEADER-TRUST", file: "src/mail.js",
        code: "const link = 'https://' + req.headers['host'] + '/reset/' + token;" },
    Case { rule: "SENTINEL-FAST-HASH-PASSWORD", file: "src/accounts.py",
        code: "stored = hashlib.sha256(password.encode()).hexdigest()" },
    Case { rule: "SENTINEL-HARDCODED-FRAMEWORK-SECRET", file: "src/settings.py",
        code: "SECRET_KEY = 'x7f2k9qm4vz1bnp8'" },
    Case { rule: "SENTINEL-ASSERT-FOR-SECURITY", file: "src/admin.py",
        code: "    assert current_user.is_admin" },
];

/// Safe counterparts. The construct is present in a form that is not a defect,
/// and the rule must stay quiet — either because taint analysis clears it, an
/// `unless` clause recognises the safe idiom, or the pattern is precise enough
/// not to match in the first place.
const SAFE: &[Case] = &[
    Case { rule: "SENTINEL-SQLI", file: "src/users.js",
        code: "db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);" },
    Case { rule: "SENTINEL-CMDI", file: "src/ops.js",
        code: "execFile('rm', ['-rf', req.body.path]);" },
    Case { rule: "SENTINEL-SHELL-TRUE", file: "src/run.py",
        code: "subprocess.run(command, shell=False)" },
    Case { rule: "SENTINEL-PATH-TRAVERSAL", file: "src/files.js",
        code: "fs.readFile(path.basename(req.query.file), cb);" },
    Case { rule: "SENTINEL-SSRF", file: "src/proxy.js",
        code: "fetch('https://api.acme-shop.net/status');" },
    Case { rule: "SENTINEL-INSECURE-DESERIALIZATION", file: "src/cache.py",
        code: "config = yaml.safe_load(blob)" },
    Case { rule: "SENTINEL-WEAK-RANDOM", file: "src/token.js",
        code: "const value = crypto.randomBytes(32).toString('hex');" },
    Case { rule: "SENTINEL-XSS-DOM-SINK", file: "src/render.js",
        code: "el.textContent = req.query.name;" },
    Case { rule: "SENTINEL-TIMING-UNSAFE-COMPARE", file: "src/verify.js",
        code: "if (crypto.timingSafeEqual(signature, expected)) { return true; }" },
    Case { rule: "SENTINEL-BUFFER-UNSAFE", file: "src/parse.c",
        code: "strncpy(destination, source, sizeof(destination) - 1);" },
    Case { rule: "SENTINEL-MISSING-AUTH-CHECK", file: "src/routes.js",
        code: "app.post('/admin/delete-user', requireAuth, async (req, res) => {" },
    Case { rule: "SENTINEL-STACK-TRACE-TO-CLIENT", file: "src/error.js",
        code: "if (process.env.NODE_ENV !== 'production') { res.send(err.stack); }" },
    Case { rule: "SENTINEL-ZIP-SLIP", file: "src/unpack.py",
        code: "zipfile.ZipFile(archive).extractall(destination, filter='data')" },
    Case { rule: "SENTINEL-DEBUG-ENABLED", file: "src/app.py",
        code: "app.run(debug=os.environ.get('DEBUG') == '1')" },
    Case { rule: "SENTINEL-HEADER-INJECTION", file: "src/trace.js",
        code: "res.setHeader('Content-Type', 'application/json');" },
    Case { rule: "SENTINEL-TRUSTED-PROXY-HEADER", file: "src/gate.js",
        code: "logger.info('client ip', req.headers['x-forwarded-for']);" },
    Case { rule: "SENTINEL-FAST-HASH-PASSWORD", file: "src/accounts.py",
        code: "stored = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))" },
    Case { rule: "SENTINEL-HARDCODED-FRAMEWORK-SECRET", file: "src/settings.py",
        code: "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']" },
    Case { rule: "SENTINEL-ASSERT-FOR-SECURITY", file: "src/admin.py",
        code: "    if not current_user.is_admin:\n        raise PermissionDenied()" },
    Case { rule: "SENTINEL-HOST-HEADER-TRUST", file: "src/mail.js",
        code: "const link = process.env.PUBLIC_BASE_URL + '/reset/' + token;" },
    // PHP's `include` is a file-read sink; JavaScript's `.includes()` is a
    // substring test that happens to start with the same seven letters. The
    // path-traversal rule matched the second as though it were the first.
    Case { rule: "SENTINEL-PATH-TRAVERSAL", file: "src/gate.js",
        code: "if (ADMIN_IPS.includes(req.headers['x-forwarded-for'])) { grant(); }" },
];

fn scan_one(case: &Case) -> Vec<Finding> {
    let extension = case.file.rsplit('.').next().unwrap_or("").to_string();
    let file = SourceFile {
        path: PathBuf::from(format!("/repo/{}", case.file)),
        relative: case.file.to_string(),
        extension,
        provenance: Provenance::Authored,
        size_bytes: case.code.len() as u64,
        content: case.code.to_string(),
    };
    let codebase = Codebase {
        root: PathBuf::from("/repo"),
        files: vec![file],
        skipped: Vec::new(),
        stopped_because: WalkStop::Exhausted,
    };
    analyze(&codebase, uuid::Uuid::new_v4(), uuid::Uuid::new_v4())
}

/// The title a rule raises its findings under, which is how a finding is
/// traced back to the rule that produced it.
fn title_of(rule_id: &str) -> &'static str {
    rules::all()
        .iter()
        .find(|r| r.spec.id == rule_id)
        .unwrap_or_else(|| panic!("the corpus names {rule_id}, which is not a rule in the catalog"))
        .spec
        .title
}

fn fired(findings: &[Finding], rule_id: &str) -> bool {
    let title = title_of(rule_id);
    findings.iter().any(|f| f.title == title)
}

#[test]
fn every_rule_in_the_catalog_has_a_vulnerable_sample() {
    let covered: std::collections::HashSet<&str> = VULNERABLE.iter().map(|c| c.rule).collect();
    let missing: Vec<&str> = rules::all()
        .iter()
        .map(|r| r.spec.id)
        .filter(|id| !covered.contains(id))
        .collect();
    assert!(
        missing.is_empty(),
        "{missing:?} ship in the catalog with nothing proving they ever fire. \
         Add a sample to VULNERABLE in this file."
    );
}

#[test]
fn every_rule_fires_on_its_vulnerable_sample() {
    let mut silent = Vec::new();
    for case in VULNERABLE {
        let findings = scan_one(case);
        if !fired(&findings, case.rule) {
            let raised: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
            silent.push(format!(
                "{} did not fire on {}\n      sample:  {}\n      raised:  {:?}",
                case.rule, case.file, case.code.replace('\n', " ⏎ "), raised
            ));
        }
    }
    assert!(
        silent.is_empty(),
        "{} rule(s) never matched the weakness they exist to find:\n  {}",
        silent.len(),
        silent.join("\n  ")
    );
}

#[test]
fn no_rule_fires_on_the_safe_form_of_its_own_construct() {
    let mut noisy = Vec::new();
    for case in SAFE {
        let findings = scan_one(case);
        if fired(&findings, case.rule) {
            noisy.push(format!(
                "{} fired on safe code\n      sample:  {}",
                case.rule,
                case.code.replace('\n', " ⏎ ")
            ));
        }
    }
    assert!(
        noisy.is_empty(),
        "{} rule(s) report the correct form of the construct as a defect:\n  {}",
        noisy.len(),
        noisy.join("\n  ")
    );
}

/// The forms that the line-oriented engine could not express.
///
/// Each of these is the idiomatic way the weakness is actually written — the
/// two-line Python handler far more common than `except E: pass`, and the Ruby
/// `rescue`/`end` pair which requires a newline by definition and so could
/// never have matched a single line. Before whole-file matching existed the
/// rule reported none of them while still counting as coverage.
#[test]
fn an_empty_handler_is_found_in_the_forms_that_span_lines() {
    for (name, file, code) in [
        ("python two-line", "src/w.py", "try:\n    flush()\nexcept Exception:\n    pass"),
        ("python one-line", "src/w.py", "try:\n    flush()\nexcept Exception: pass"),
        ("java braces apart", "src/W.java", "try {\n    flush();\n} catch (IOException e) {\n}"),
        ("java braces together", "src/W.java", "try { flush(); } catch (IOException e) {}"),
        ("ruby rescue/end", "src/w.rb", "begin\n  flush\nrescue => e\nend"),
        ("csharp bare catch", "src/W.cs", "try { Flush(); } catch { }"),
    ] {
        let findings = scan_one(&Case { rule: "SENTINEL-EXCEPTION-SWALLOWED", file, code });
        assert!(
            fired(&findings, "SENTINEL-EXCEPTION-SWALLOWED"),
            "the {name} form of an empty handler was not reported"
        );
    }
}

/// A handler that does something is not swallowed, and saying it is would make
/// the rule useless on any codebase that handles errors properly.
#[test]
fn a_handler_that_does_something_is_left_alone() {
    for (name, file, code) in [
        ("python logs", "src/w.py", "try:\n    flush()\nexcept Exception as e:\n    log.error(e)"),
        ("python re-raises", "src/w.py", "try:\n    flush()\nexcept Exception:\n    raise"),
        ("java logs", "src/W.java", "try {\n    flush();\n} catch (IOException e) {\n    log.warn(e);\n}"),
        ("ruby handles", "src/w.rb", "begin\n  flush\nrescue => e\n  report(e)\nend"),
    ] {
        let findings = scan_one(&Case { rule: "SENTINEL-EXCEPTION-SWALLOWED", file, code });
        assert!(
            !fired(&findings, "SENTINEL-EXCEPTION-SWALLOWED"),
            "the {name} case was reported as a swallowed exception"
        );
    }
}

/// A whole-file pattern runs against the entire text, so an unbounded quantifier
/// does not merely over-report — it can match from the top of a file to the
/// bottom and produce a single finding whose evidence is the file. Keeping the
/// patterns anchored is what makes the facility safe to add rules to.
#[test]
fn whole_file_patterns_stay_bounded() {
    for rule in rules::all().iter().filter(|r| r.multiline) {
        assert!(
            !rule.pattern.contains("(?s)"),
            "{} enables dot-matches-newline over a whole file",
            rule.spec.id
        );
        assert!(
            !rule.pattern.contains(".*") && !rule.pattern.contains(".+"),
            "{} uses an unbounded wildcard in a whole-file pattern",
            rule.spec.id
        );
    }
}

/// The line number is derived from a byte offset rather than a loop counter,
/// which is the one thing about whole-file matching that can silently go wrong:
/// an off-by-one sends the analyst to the wrong line of a real file.
#[test]
fn a_whole_file_match_reports_the_line_the_construct_is_on() {
    let code = "def a():\n    pass\n\n\ndef b():\n    try:\n        flush()\n    except Exception:\n        pass\n";
    let findings = scan_one(&Case { rule: "SENTINEL-EXCEPTION-SWALLOWED", file: "src/w.py", code });
    let title = title_of("SENTINEL-EXCEPTION-SWALLOWED");
    let f = findings.iter().find(|f| f.title == title).expect("the handler is reported");
    assert!(
        f.repro_steps.iter().any(|s| s.contains("line 8")),
        "expected the `except` on line 8, got: {:?}",
        f.repro_steps.first()
    );
}

/// Severity reaches the report from the CVSS vector alone. A sample that lands
/// as Info would be filtered out of most report profiles before anybody read
/// it, which is indistinguishable from the rule not firing.
#[test]
fn findings_from_the_corpus_carry_a_severity_worth_reporting() {
    for case in VULNERABLE {
        let findings = scan_one(case);
        let title = title_of(case.rule);
        for f in findings.iter().filter(|f| f.title == title) {
            assert!(
                f.cvss4.as_ref().is_some_and(|c| c.base_score > 0.0),
                "{} produced a finding with no usable score",
                case.rule
            );
            assert!(f.cwe_id.is_some(), "{} produced a finding with no CWE", case.rule);
        }
    }
}
