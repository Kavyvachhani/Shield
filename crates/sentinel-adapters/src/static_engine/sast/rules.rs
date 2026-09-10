//! The code engine's rule catalog.
//!
//! Each rule is a sink — a construct that is dangerous when it is handed data
//! somebody else controls — plus the metadata a report needs to explain it.
//! What decides whether a rule *fires* is not the pattern alone but what
//! [`taint`](super::taint) can say about the data reaching it, which is why
//! most of these are written to match the call rather than to match the call
//! and guess about its argument.
//!
//! Three properties every rule in here has to hold, because a static engine
//! that gets any of them wrong is worse than not shipping one:
//!
//! 1. **Severity is computed from the vector.** Never declared beside it.
//! 2. **The confidence is the tainted case.** A rule declares how sure it is
//!    when the engine traced attacker-controlled data into the sink. When it
//!    could not, the engine downgrades the finding to `Tentative` itself — the
//!    rule does not get to claim certainty the dataflow did not support.
//! 3. **The triage note says what the match does not prove.** A reviewer
//!    deciding which of forty findings to open first is the person this field
//!    is written for.

use super::lang::Language;
use sentinel_core::checklist::catalog::owasp;
use crate::static_engine::finding::{CodeSpec, Confidence};

/// When a rule is allowed to raise a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The construct is the weakness whatever is passed to it — a disabled
    /// certificate check does not become safe because its argument is a
    /// constant.
    Always,
    /// Dangerous only with data from outside. Suppressed entirely when the
    /// argument is a literal or is sanitised at the call.
    Tainted,
}

/// One rule.
pub struct SastRule {
    pub spec: CodeSpec,
    /// Languages this rule applies to. A rule that matched everywhere would
    /// fire on Go for a PHP function that happens to share a name.
    pub languages: &'static [Language],
    /// The sink. If it has a capture group named `arg`, that text is what gets
    /// handed to the taint classifier; otherwise the whole line is, which is
    /// strictly more conservative.
    pub pattern: &'static str,
    pub mode: Mode,
    /// Any of these on the same line and the rule stays quiet. This is where
    /// framework-specific safe forms go.
    pub unless: &'static [&'static str],
    /// Whether the rule is worth running over test code. Almost never: a test
    /// that builds a SQL string from a fixture is a test, and reporting it
    /// buries the one in the request handler.
    pub scan_tests: bool,
}

// ── CVSS 4.0 vectors, calibrated once and reused ─────────────────────────────
//
// Named by what they describe rather than by their score, so a rule reads as a
// judgement about impact instead of a number somebody picked. The scores in the
// comments are what the calculator returns; `vectors_score_as_documented`
// below fails the build if that ever stops being true.

/// Full compromise of confidentiality, integrity and availability. 9.3.
const V_RCE: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
/// Read and modify everything the process can, no availability impact. 9.3.
const V_INJECTION: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N";
/// Total loss of confidentiality. 8.7.
const V_DISCLOSURE: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N";
/// Total loss of integrity. 8.7.
const V_INTEGRITY: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N";
/// Service made unavailable. 8.7.
const V_DOS: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N";
/// High impact but needs the victim to act — the stored-XSS shape. 8.5.
const V_XSS: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N";
/// High impact behind a condition the attacker does not control. 8.2.
const V_CONDITIONAL: &str = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N";
/// High confidentiality impact, but the attacker must already hold an account. 7.1.
const V_AUTHENTICATED: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N";
/// Partial disclosure. 6.9.
const V_PARTIAL_INFO: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N";
/// Partial integrity loss. 6.9.
const V_PARTIAL_INTEGRITY: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N";
/// Limited impact, and only along a path the attacker cannot force. 6.3.
const V_LIMITED: &str = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N";
/// Limited impact requiring the victim to interact. 5.3.
const V_LIMITED_UI: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N";
/// Limited impact, local access, some privilege already held. 4.8.
const V_LOCAL: &str = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N";
/// Hygiene: real, small, and only under conditions that rarely hold. 2.3.
const V_HYGIENE: &str = "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N";

// Language groups, so a rule lists an idea rather than a list.
const WEB_LANGS: &[Language] = &[
    Language::JavaScript, Language::TypeScript, Language::Python, Language::Java,
    Language::Kotlin, Language::Php, Language::Go, Language::Ruby, Language::CSharp,
];
const JS: &[Language] = &[Language::JavaScript, Language::TypeScript];
const JS_MARKUP: &[Language] = &[Language::JavaScript, Language::TypeScript, Language::Markup];
const JVM: &[Language] = &[Language::Java, Language::Kotlin];
const NATIVE_LANGS: &[Language] = &[Language::C];

/// Every rule the code engine ships.
pub fn all() -> &'static [SastRule] {
    RULES
}

const RULES: &[SastRule] = &[

// ══ Injection ═══════════════════════════════════════════════════════════════

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-SQLI",
        title: "SQL query assembled from untrusted input",
        cvss_vector: V_INJECTION,
        cwe: "CWE-89",
        wstg: "WSTG-INPV-05",
        owasp_2025: owasp::A05,
        api_top10: Some("API8:2023-Security Misconfiguration"),
        description:
            "A SQL statement is built by joining strings together, and at least one of the \
             pieces is a value the application did not produce itself. Anyone who controls \
             that value controls the shape of the query, not merely its contents: they can \
             end the intended statement, add their own, and read or change any data the \
             database account can reach. This is not mitigated by input validation, by an \
             allow-list of characters, or by escaping — all three have well-known bypasses \
             for every major database, which is why the fix is structural rather than \
             defensive.",
        remediation:
            "Use a parameterised query so the database receives the statement and the values \
             separately and can never confuse one for the other.\n\n\
             ```\n\
             // Node (pg)\n\
             db.query('SELECT * FROM users WHERE id = $1', [id]);\n\n\
             # Python (psycopg / sqlite3)\n\
             cur.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n\n\
             // Java\n\
             PreparedStatement ps = c.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n\
             ps.setLong(1, id);\n\n\
             // PHP (PDO)\n\
             $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n\
             $stmt->execute(['id' => $id]);\n\
             ```\n\n\
             Where the variable part is an identifier rather than a value — a table name, a \
             sort column — a parameter will not work. Map the input through a fixed allow-list \
             of permitted identifiers instead of interpolating it.",
        references: &[
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A query call receives a string that the engine traced back to request data. \
             Confirm the driver is not parameterising behind the scenes, and check whether an \
             ORM layer escapes the value before it reaches this call.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)\b(?:execute|executeQuery|executeUpdate|query|rawQuery|exec_sql|prepare)\s*\((?P<arg>[^)]*(?:\+|\$\{|%s|\|\||\.format\(|f["'])[^)]*)\)"#,
    mode: Mode::Tainted,
    unless: &["?", "$1", ":id", "prepareStatement", "@param"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-SQLI-ORM-RAW",
        title: "ORM escape hatch used with an interpolated string",
        cvss_vector: V_INJECTION,
        cwe: "CWE-89",
        wstg: "WSTG-INPV-05",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "The application uses its ORM's raw-SQL escape hatch and builds the statement by \
             interpolation. The ORM's parameterisation — the reason it is safe everywhere \
             else in the codebase — does not apply on this path. These calls are the most \
             common source of SQL injection in an otherwise ORM-based application precisely \
             because the surrounding code looks safe.",
        remediation:
            "Every ORM's raw interface accepts bind parameters; use them.\n\n\
             ```\n\
             # Django\n\
             Model.objects.raw('SELECT * FROM t WHERE id = %s', [id])\n\n\
             # SQLAlchemy\n\
             session.execute(text('SELECT * FROM t WHERE id = :id'), {'id': id})\n\n\
             // Sequelize\n\
             sequelize.query('SELECT * FROM t WHERE id = :id',\n\
             \x20 { replacements: { id }, type: QueryTypes.SELECT });\n\n\
             # Rails\n\
             Model.where('id = ?', id)\n\
             ```",
        references: &[
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://docs.djangoproject.com/en/stable/topics/db/sql/#passing-parameters-into-raw",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A raw-SQL interface was called with a built string. Even when the surrounding \
             application uses an ORM throughout, this call bypasses it.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)\b(?:\.raw|raw_query|rawQuery|\.whereRaw|\.havingRaw|\.orderByRaw|sequelize\.query|session\.execute|db\.exec|Model\.objects\.raw|find_by_sql)\s*\((?P<arg>[^)]*(?:\+|\$\{|%s|#\{|\.format\(|f["'])[^)]*)\)"#,
    mode: Mode::Tainted,
    unless: &["replacements", "params=", ":id", "bindparams"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-CMDI",
        title: "Operating-system command built from untrusted input",
        cvss_vector: V_RCE,
        cwe: "CWE-78",
        wstg: "WSTG-INPV-12",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "A shell command is assembled from a value the application did not produce. \
             Because it goes to a shell rather than directly to the kernel, the injected \
             text is not merely an extra argument — `;`, `|`, `&&`, backticks and `$( )` all \
             start a new command running as the application's user. This is the shortest \
             path from a web request to arbitrary code execution on the host, and it is \
             usually the finding that ends an assessment early.",
        remediation:
            "Do not build a command line. Pass the program and its arguments as separate \
             values so no shell is involved and nothing in the data can be read as syntax.\n\n\
             ```\n\
             // Node — no shell at all\n\
             const { execFile } = require('node:child_process');\n\
             execFile('convert', [inputPath, outputPath], cb);\n\n\
             # Python\n\
             subprocess.run(['convert', input_path, output_path], shell=False, check=True)\n\n\
             // Go\n\
             exec.Command(\"convert\", inputPath, outputPath)\n\n\
             // Java\n\
             new ProcessBuilder(\"convert\", inputPath, outputPath).start();\n\
             ```\n\n\
             Where a shell genuinely is required, quote every interpolated value with the \
             platform's own quoting function — `shlex.quote`, `escapeshellarg`, \
             `Shellwords.escape` — and validate the value against an allow-list first. \
             Better still, replace the shell-out with a library call.",
        references: &[
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A subprocess or shell call receives a built string. Confirm the value cannot be \
             influenced by a request; if it can, treat this as remote code execution rather \
             than as an injection to be escaped.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)\b(?:exec|execSync|spawnSync|system|popen|shell_exec|passthru|proc_open|os\.system|subprocess\.(?:call|run|Popen|check_output)|Runtime\.getRuntime\(\)\.exec|exec\.Command|Process\.Start|IO\.popen|Kernel\.system|`)\s*\(?(?P<arg>[^)\n]*)"#,
    mode: Mode::Tainted,
    unless: &["execFile", "shell=False", "shell:false", "ProcessBuilder"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-SHELL-TRUE",
        title: "Subprocess spawned through a shell",
        cvss_vector: V_CONDITIONAL,
        cwe: "CWE-78",
        wstg: "WSTG-INPV-12",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "A subprocess is launched with the shell enabled. This is what turns a command \
             argument into a command line: shell metacharacters in any interpolated value \
             become syntax, and a value that today comes from configuration becomes an \
             injection the moment somebody wires it to a request. The flag is almost never \
             needed — it is usually there for a pipe or a glob that has a library equivalent.",
        remediation:
            "Turn the shell off and pass an argument list.\n\n\
             ```\n\
             # Python\n\
             subprocess.run(['ls', '-la', directory], shell=False)\n\n\
             // Node\n\
             execFile('ls', ['-la', directory]);\n\
             ```\n\n\
             If the reason for the shell is a pipeline, build it with two processes and a \
             pipe rather than a string. If it is a glob, expand it with `glob`/`fs.readdir` \
             in the application.",
        references: &[
            "https://docs.python.org/3/library/subprocess.html#security-considerations",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "The shell flag is set on this call. It is a weakness in waiting rather than \
             necessarily an exploitable one today: rate it on whether any argument can reach \
             it from outside the application.",
    },
    languages: &[Language::Python, Language::JavaScript, Language::TypeScript, Language::Ruby],
    pattern: r"(?i)\b(?:shell\s*=\s*True|shell\s*:\s*true)\b",
    mode: Mode::Always,
    unless: &[],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-CODE-EVAL",
        title: "Source code evaluated at runtime",
        cvss_vector: V_RCE,
        cwe: "CWE-95",
        wstg: "WSTG-INPV-11",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "The application compiles and runs a string as program code. If any part of that \
             string can be influenced from outside, the attacker is not injecting into a \
             query or a command — they are writing application code that runs with the \
             application's full privileges, inside its process, with access to every \
             credential and connection it holds.",
        remediation:
            "Remove the dynamic evaluation. Almost every use has a direct replacement:\n\n\
             * parsing data → `JSON.parse`, `json.loads`, `yaml.safe_load`\n\
             * looking up a function by name → a hash map from permitted names to functions\n\
             * arithmetic from a user → a small expression parser with a fixed grammar\n\
             * templating → the framework's template engine with escaping on\n\n\
             If evaluation is genuinely required, run it in a real sandbox with no host \
             bindings — not `vm.runInNewContext`, which does not contain an attacker.",
        references: &[
            "https://cwe.mitre.org/data/definitions/95.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A runtime evaluation construct was found. If its input is a constant this is a \
             maintainability problem; if any of it comes from a request it is remote code \
             execution.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)(?:\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*["'`]|\bsetInterval\s*\(\s*["'`]|\bexec\s*\(\s*compile|\bassert\s*\(\s*["']|\bcreate_function\s*\(|\bReflectionFunction\s*\(|\bScriptEngine|\bGroovyShell|\binstance_eval|\bclass_eval|\bBinding\.eval)"#,
    mode: Mode::Always,
    unless: &["eval(\"require\")", "// eslint", "eval_type"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-NOSQLI",
        title: "NoSQL query built from an unvalidated object",
        cvss_vector: V_INJECTION,
        cwe: "CWE-943",
        wstg: "WSTG-INPV-05",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "A document-database query is built from a value taken straight out of a request \
             body or query string. Because these values arrive already parsed into objects, \
             an attacker does not need to break out of a string — they submit \
             `{\"$ne\": null}` or `{\"$gt\": \"\"}` where a scalar was expected and the query \
             matches every document. Against a login handler that is an authentication \
             bypass with no password guessing at all.",
        remediation:
            "Coerce every value to the type the query expects before it reaches the driver, \
             and reject anything that arrives as an object where a scalar belongs.\n\n\
             ```\n\
             // Explicit coercion\n\
             const email = String(req.body.email);\n\
             const user = await User.findOne({ email });\n\n\
             // Or a schema validator that rejects the wrong shape outright\n\
             const { email, password } = loginSchema.parse(req.body);\n\
             ```\n\n\
             Enabling the driver's own sanitiser (`mongo-sanitize`, Mongoose's \
             `sanitizeFilter`) covers the operator-injection case as defence in depth, but \
             validating the shape at the boundary is what actually fixes it.",
        references: &[
            "https://cwe.mitre.org/data/definitions/943.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A request value reaches a document-database query. The question to settle is \
             whether the value is coerced to a scalar first — if it can still arrive as an \
             object, operator injection applies.",
    },
    languages: JS,
    pattern: r"(?i)\b(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate)\s*\(\s*(?P<arg>\{[^}]*\}|[A-Za-z_$][A-Za-z0-9_$.]*)",
    mode: Mode::Tainted,
    unless: &["String(", "Number(", "ObjectId(", "sanitize", "toString()"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-LDAPI",
        title: "LDAP filter built by concatenation",
        cvss_vector: V_DISCLOSURE,
        cwe: "CWE-90",
        wstg: "WSTG-INPV-06",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "An LDAP search filter is assembled from a value the application did not produce. \
             The filter grammar treats `*`, `(`, `)`, `&` and `|` as syntax, so an attacker \
             who supplies `*` where a username was expected turns an equality test into a \
             wildcard and enumerates the whole directory — or, against an authentication \
             bind, matches an account without knowing its password.",
        remediation:
            "Escape every interpolated value with the LDAP filter encoder your platform \
             provides — `javax.naming.ldap` filter escaping, .NET's `LdapFilterEncode`, \
             `ldap3.utils.conv.escape_filter_chars` in Python — and validate the value \
             against an allow-list before that. Where the library supports parameterised \
             filters, use them instead.",
        references: &[
            "https://cwe.mitre.org/data/definitions/90.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "An LDAP filter is built by concatenation. Confirm whether the directory is \
             reachable with the credentials this code binds as, which sets how much the \
             wildcard actually exposes.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)(?:search|bind|LdapQuery|DirectorySearcher|ldap_search|search_s)\s*\((?P<arg>[^)]*\(\s*(?:cn|uid|sAMAccountName|mail|objectClass)\s*=[^)]*)"#,
    mode: Mode::Tainted,
    unless: &["escape_filter_chars", "LdapFilterEncode", "escapeLDAP"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-SSTI",
        title: "Template rendered from an untrusted string",
        cvss_vector: V_RCE,
        cwe: "CWE-1336",
        wstg: "WSTG-INPV-18",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "A template is compiled from a string rather than loaded from a file, and the \
             string is built at runtime. Template languages are programming languages: in \
             Jinja2, Twig, Freemarker, Velocity and Handlebars alike, an attacker who \
             controls template *source* rather than template *data* can reach the object \
             graph of the host language and from there the runtime itself. Server-side \
             template injection is normally a direct route to code execution, not an \
             escaping problem.",
        remediation:
            "Load templates from files that ship with the application and pass user data in \
             as context, never as part of the template text.\n\n\
             ```\n\
             # Wrong — the user's value becomes template source\n\
             render_template_string('Hello ' + name)\n\n\
             # Right — the user's value is data the template renders\n\
             render_template('hello.html', name=name)\n\
             ```\n\n\
             Where users genuinely need to supply templates, use a sandboxed environment \
             with a strict allow-list of attributes, and treat escaping it as an expected \
             attack rather than an edge case.",
        references: &[
            "https://cwe.mitre.org/data/definitions/1336.html",
            "https://portswigger.net/research/server-side-template-injection",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A template is being compiled from a runtime string. Establish whether any part \
             of that string originates outside the application before rating it — the \
             difference is between a style issue and remote code execution.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)\b(?:render_template_string|Template\s*\(|from_string|compile\s*\(|createTemplate|new\s+Template|Handlebars\.compile|_\.template|Twig_Template|StringTemplateLoader)\s*\((?P<arg>[^)]*)",
    mode: Mode::Tainted,
    unless: &["render_template(", "loadTemplate", "FileTemplateLoader"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-XPATH",
        title: "XPath expression built by concatenation",
        cvss_vector: V_DISCLOSURE,
        cwe: "CWE-643",
        wstg: "WSTG-INPV-09",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "An XPath expression is assembled from a value the application did not produce. \
             As with SQL, the injected text is read as syntax: `' or '1'='1` turns a lookup \
             into a match-everything expression, exposing the whole document rather than the \
             node that was asked for.",
        remediation:
            "Use a variable-resolving XPath API — `XPathExpression` with an \
             `XPathVariableResolver` in Java, `lxml`'s `xpath(expr, name=value)` in Python, \
             `SelectSingleNode` with `XsltArgumentList` in .NET — so the value is bound \
             rather than interpolated. Where that is not possible, escape quotes and validate \
             against an allow-list.",
        references: &[
            "https://cwe.mitre.org/data/definitions/643.html",
            "https://owasp.org/www-community/attacks/XPATH_Injection",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "An XPath expression is being built by string joining. What it exposes depends \
             on what the document holds — check that before rating it.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)\b(?:xpath|selectNodes|selectSingleNode|SelectSingleNode|evaluate|compile)\s*\((?P<arg>[^)]*["'](?:/|//)[^)]*(?:\+|\$\{|%s|\.format\()[^)]*)"#,
    mode: Mode::Tainted,
    unless: &["XPathVariableResolver", "setVariable"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-LOG-INJECTION",
        title: "Untrusted value written to a log without encoding",
        cvss_vector: V_PARTIAL_INTEGRITY,
        cwe: "CWE-117",
        wstg: "WSTG-INPV-01",
        owasp_2025: owasp::A09,
        api_top10: None,
        description:
            "A value from a request is written into a log line unencoded. Newlines in that \
             value become new log entries, so an attacker can forge records — including \
             records that appear to come from other users or from the system itself — and \
             break the log's usefulness as evidence. Where logs are shipped to a dashboard \
             that renders them as HTML, the same value becomes stored XSS against whoever \
             reads the log.",
        remediation:
            "Strip or encode CR and LF before logging any external value, and prefer \
             structured logging, which writes the value as a field rather than as part of \
             the message text.\n\n\
             ```\n\
             logger.info('login failed', { user: username, ip: req.ip });\n\
             ```\n\n\
             Structured records survive a newline in a field without producing a second \
             entry.",
        references: &[
            "https://cwe.mitre.org/data/definitions/117.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
        ],
        confidence: Confidence::Tentative,
        triage_note:
            "A request value reaches a log call. Many logging frameworks encode newlines by \
             default and structured loggers sidestep the problem entirely — check which is \
             in use before treating this as actionable.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)\b(?:log|logger|logging|console)\.(?:info|warn|error|debug|log|trace)\s*\((?P<arg>[^)]*(?:\+|\$\{|%s|#\{|\.format\(|f["'])[^)]*)\)"#,
    mode: Mode::Tainted,
    unless: &["encode", "sanitize", "replace(/[\\r\\n]/"],
    scan_tests: false,
},

// ══ Cross-site scripting ════════════════════════════════════════════════════

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-XSS-DOM-SINK",
        title: "Untrusted value written to an HTML sink",
        cvss_vector: V_XSS,
        cwe: "CWE-79",
        wstg: "WSTG-CLNT-01",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "A value the application did not produce is assigned to a sink that parses HTML. \
             `innerHTML`, `outerHTML`, `document.write` and `insertAdjacentHTML` all build a \
             DOM from the string they are given, so markup in the value becomes real \
             elements — and an attribute such as `onerror` on an `<img>` becomes script \
             running in the victim's session, with their cookies and their privileges.",
        remediation:
            "Set text rather than markup wherever the value is text: `textContent`, \
             `innerText`, or `createTextNode` never parse what they are given.\n\n\
             ```\n\
             el.textContent = userValue;             // safe by construction\n\
             ```\n\n\
             Where markup genuinely must be rendered, sanitise it immediately before the \
             assignment with a maintained library — DOMPurify is the reference choice — and \
             deploy a Content-Security-Policy with `require-trusted-types-for 'script'`, \
             which turns this class of assignment into a runtime error rather than a \
             vulnerability.",
        references: &[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
            "https://web.dev/articles/trusted-types",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A URL- or request-derived value reaches an HTML-parsing sink. Read what happens \
             between the two: a sanitiser call the engine does not recognise would make this \
             safe, and its absence makes it exploitable.",
    },
    languages: JS_MARKUP,
    pattern: r"(?i)(?:\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(|\$\([^)]*\)\.(?:html|append|prepend|after|before|replaceWith)\s*\()(?P<arg>[^;\n]*)",
    mode: Mode::Tainted,
    unless: &["DOMPurify", "sanitize", "textContent", "escapeHtml"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-XSS-FRAMEWORK-BYPASS",
        title: "Framework HTML escaping deliberately bypassed",
        cvss_vector: V_XSS,
        cwe: "CWE-79",
        wstg: "WSTG-CLNT-01",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "The code uses the one construct its framework provides for rendering unescaped \
             HTML — React's `dangerouslySetInnerHTML`, Vue's `v-html`, Angular's \
             `bypassSecurityTrustHtml`, Django's `mark_safe`, Rails's `html_safe`, Go's \
             `template.HTML`. These exist for content the application itself authored. \
             Every one of them turns off the escaping that makes the rest of the templating \
             safe, so a value that reaches one of them unsanitised is cross-site scripting \
             with the framework's protection explicitly disabled.",
        remediation:
            "Render the value as text and let the framework escape it. Where markup is \
             genuinely required — rendering stored rich text, for instance — sanitise on the \
             way *in* with a strict allow-list of tags and attributes, store the sanitised \
             form, and sanitise again at render time; a sanitiser applied only once, at only \
             one end, has been bypassed by every mutation-XSS technique published in the last \
             decade.",
        references: &[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "An escaping bypass is in use. If the value is a constant or is sanitised \
             immediately before, this is intentional and safe; the finding is about \
             confirming which of the two it is.",
    },
    languages: &[
        Language::JavaScript, Language::TypeScript, Language::Python,
        Language::Ruby, Language::Go, Language::Java, Language::Php, Language::Markup,
    ],
    pattern: r"(?i)(?:dangerouslySetInnerHTML|\bv-html\b|bypassSecurityTrust(?:Html|Script|Url|ResourceUrl)|\bmark_safe\s*\(|\|\s*safe\b|\bhtml_safe\b|\braw\s+@|template\.HTML\s*\(|\{\{\{|\bautoescape\s+off\b|\bHtml\.Raw\s*\()(?P<arg>[^;\n]*)",
    mode: Mode::Always,
    unless: &["DOMPurify.sanitize", "sanitizeHtml("],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-XSS-AUTOESCAPE-OFF",
        title: "Template auto-escaping disabled globally",
        cvss_vector: V_XSS,
        cwe: "CWE-79",
        wstg: "WSTG-CLNT-01",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "The template engine is configured with automatic escaping switched off. This is \
             not a local decision about one value: from this point every variable rendered by \
             every template is emitted raw, so any of them carrying user data is cross-site \
             scripting. A codebase in this state cannot be made safe by reviewing the \
             templates, because a template written correctly a year from now will still be \
             unescaped.",
        remediation:
            "Turn auto-escaping back on and mark the specific values that must stay raw:\n\n\
             ```\n\
             # Jinja2\n\
             Environment(loader=..., autoescape=select_autoescape(['html', 'xml']))\n\
             ```\n\n\
             The handful of places that break are exactly the places that were relying on \
             the unsafe default, so fixing them is the point rather than a cost.",
        references: &[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://jinja.palletsprojects.com/en/stable/api/#autoescaping",
        ],
        confidence: Confidence::Certain,
        triage_note:
            "Auto-escaping is explicitly off in the engine's configuration. This is a \
             configuration fact rather than an inference; what needs judging is how many \
             templates it exposes.",
    },
    languages: &[Language::Python, Language::JavaScript, Language::TypeScript, Language::Java, Language::Go],
    pattern: r"(?i)autoescape\s*[=:]\s*(?:False|false|0|None)\b|escape\s*:\s*false",
    mode: Mode::Always,
    unless: &[],
    scan_tests: false,
},

// ══ Deserialization ═════════════════════════════════════════════════════════

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-INSECURE-DESERIALIZATION",
        title: "Untrusted data passed to an unsafe deserialiser",
        cvss_vector: V_RCE,
        cwe: "CWE-502",
        wstg: "WSTG-INPV-11",
        owasp_2025: owasp::A08,
        api_top10: None,
        description:
            "The application reconstructs objects from a serialised byte stream using a \
             deserialiser that can instantiate arbitrary types and invoke their methods \
             while doing so. Python's `pickle`, PHP's `unserialize`, Java's \
             `ObjectInputStream`, .NET's `BinaryFormatter` and PyYAML's unsafe `load` all \
             work this way. An attacker who controls the stream does not need a bug in the \
             application: they assemble a chain out of classes already on the classpath and \
             get code execution during deserialisation, before a single line of the \
             application's own logic runs.",
        remediation:
            "Use a data format that describes data rather than objects, and construct your \
             own types from it after validation.\n\n\
             ```\n\
             # Python\n\
             data = json.loads(payload)          # not pickle.loads\n\
             cfg  = yaml.safe_load(text)         # not yaml.load\n\n\
             // Java — JSON with polymorphic typing disabled\n\
             // .NET — System.Text.Json, never BinaryFormatter (removed in .NET 9)\n\
             ```\n\n\
             Where a binary object format cannot be avoided, sign the payload and verify the \
             signature before deserialising, and constrain the deserialiser to an explicit \
             allow-list of permitted types.",
        references: &[
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "An unsafe deserialiser is in use. If the stream never leaves the process this is \
             low risk; the moment it crosses a trust boundary — a cookie, a cache, a queue, \
             an upload — it is a code-execution path.",
    },
    languages: WEB_LANGS,
    // No look-ahead: the `regex` crate omits it deliberately, because the
    // linear-time guarantee is what makes it safe to run over a repository
    // somebody else wrote. "yaml.load that is not yaml.safe_load" is therefore
    // expressed with `unless` below, which is the same decision made where a
    // reviewer can see it.
    pattern: r"(?i)\b(?:pickle\.loads?|cPickle\.loads?|marshal\.loads?|yaml\.load\s*\(|unserialize\s*\(|ObjectInputStream|readObject\s*\(|BinaryFormatter|LosFormatter|NetDataContractSerializer|TypeNameHandling\s*\.\s*(?:All|Objects|Auto)|Marshal\.load|node-serialize|serialize\.unserialize)\s*",
    mode: Mode::Always,
    unless: &["safe_load", "SafeLoader", "yaml.safe_load", "safe_dump", "CSafeLoader"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-XXE",
        title: "XML parser accepts external entities",
        cvss_vector: V_DISCLOSURE,
        cwe: "CWE-611",
        wstg: "WSTG-INPV-07",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "An XML parser is constructed without disabling external entity resolution. A \
             document that declares `<!ENTITY xxe SYSTEM \"file:///etc/passwd\">` makes the \
             parser read that file and place its contents in the output, so any endpoint \
             accepting XML becomes an arbitrary file read. The same mechanism reaches \
             internal HTTP endpoints, which turns it into server-side request forgery \
             against services that trust the application's network position.",
        remediation:
            "Disable DTD processing on every parser the application constructs. This is one \
             or two lines and has no cost for documents that do not use entities.\n\n\
             ```\n\
             // Java\n\
             var f = DocumentBuilderFactory.newInstance();\n\
             f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n\
             f.setXIncludeAware(false);\n\
             f.setExpandEntityReferences(false);\n\n\
             # Python\n\
             from defusedxml.ElementTree import parse   # replaces xml.etree\n\n\
             // .NET\n\
             new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };\n\n\
             // PHP\n\
             libxml_set_external_entity_loader(null);\n\
             ```",
        references: &[
            "https://cwe.mitre.org/data/definitions/611.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "An XML parser is created without the entity-disabling calls. Some runtimes have \
             defaulted to safe since a recent version — confirm the runtime in production \
             before rating, since the same source is exploitable on one and not the other.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)\b(?:DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLInputFactory\.newInstance|XmlTextReader|XmlDocument\s*\(\s*\)|xml\.etree\.ElementTree\.(?:parse|fromstring)|lxml\.etree\.(?:parse|fromstring)|simplexml_load_(?:string|file)|DOMDocument\s*\(|libxml_disable_entity_loader\s*\(\s*false)",
    mode: Mode::Always,
    unless: &["defusedxml", "disallow-doctype-decl", "DtdProcessing.Prohibit", "resolve_entities=False", "XMLParser(resolve_entities=False)"],
    scan_tests: false,
},

// ══ Path and file handling ══════════════════════════════════════════════════

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-PATH-TRAVERSAL",
        title: "Filesystem path built from untrusted input",
        cvss_vector: V_DISCLOSURE,
        cwe: "CWE-22",
        wstg: "WSTG-ATHZ-01",
        owasp_2025: owasp::A01,
        api_top10: Some("API1:2023-Broken Object Level Authorization"),
        description:
            "A file path is assembled from a value the application did not produce. `../` \
             sequences in that value walk out of the intended directory, so a handler meant \
             to serve one folder serves the whole filesystem the process can read — \
             configuration files, private keys, the application's own source. On a write \
             path the same weakness overwrites files instead, which frequently escalates \
             to code execution by replacing something the application later loads.",
        remediation:
            "Never trust a path. Resolve it and verify the result is inside the directory \
             you meant, after resolution rather than before:\n\n\
             ```\n\
             const root = path.resolve('/srv/uploads');\n\
             const full = path.resolve(root, userPath);\n\
             if (!full.startsWith(root + path.sep)) throw new Error('outside root');\n\n\
             # Python\n\
             root = Path('/srv/uploads').resolve()\n\
             full = (root / user_path).resolve()\n\
             if root not in full.parents: raise ValueError('outside root')\n\
             ```\n\n\
             Better still, do not accept paths at all: give each file an opaque identifier \
             and look the real path up in a table. An identifier cannot contain `../`.",
        references: &[
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A request value reaches a filesystem call. What decides exploitability is \
             whether a containment check follows the path resolution — a check performed \
             before resolving does not count, because `..` is resolved afterwards.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)\b(?:open|readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|sendFile|File\.(?:read|write|open|new)|FileInputStream|FileOutputStream|Paths\.get|os\.path\.join|fopen|file_get_contents|file_put_contents|readfile|include|require_once|ioutil\.ReadFile|os\.(?:Open|ReadFile)|File\.(?:ReadAllText|WriteAllText|OpenRead))\s*\(?(?P<arg>[^)\n]*)"#,
    mode: Mode::Tainted,
    unless: &["path.basename", "os.path.basename", "filepath.Base", "secure_filename", "Path.GetFileName", "File.basename", "__dirname", "resolve(root"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-ZIP-SLIP",
        title: "Archive entry extracted without a containment check",
        cvss_vector: V_INTEGRITY,
        cwe: "CWE-22",
        wstg: "WSTG-BUSL-09",
        owasp_2025: owasp::A01,
        api_top10: None,
        description:
            "An archive is unpacked using each entry's own name as the destination path. \
             Archive formats place no constraint on that name, so an entry called \
             `../../../../etc/cron.d/x` is written wherever the process can write. This is \
             the Zip Slip pattern: it turns \"upload an archive\" into arbitrary file write, \
             and from there usually into code execution by dropping a file somewhere the \
             system loads from.",
        remediation:
            "Resolve each entry against the extraction root and reject anything that lands \
             outside it, before opening the output file.\n\n\
             ```\n\
             const dest = path.resolve(root, entry.fileName);\n\
             if (!dest.startsWith(root + path.sep)) throw new Error('unsafe entry');\n\
             ```\n\n\
             Also reject absolute entry names and symlink entries, and cap both the entry \
             count and the decompressed size — the same input that carries a traversal \
             usually also carries a decompression bomb.",
        references: &[
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://security.snyk.io/research/zip-slip-vulnerability",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "An extraction loop writes to a path derived from the entry name. Look for a \
             `startsWith`/`commonPath` containment check in the same loop; if it is absent \
             this is an arbitrary file write.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)(?:\bZipEntry\b|\bTarEntry\b|zipfile\.ZipFile|tarfile\.open|extractall|\.extract\s*\(|getNextEntry|entry\.(?:getName|fileName|name))",
    mode: Mode::Always,
    unless: &["startsWith(", "commonPath", "is_within", "resolve(root", "safe_extract", "filter='data'", "filter=\"data\""],
    scan_tests: false,
},

// ══ Server-side request forgery ═════════════════════════════════════════════

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-SSRF",
        title: "Outbound request to an attacker-influenced URL",
        cvss_vector: V_DISCLOSURE,
        cwe: "CWE-918",
        wstg: "WSTG-INPV-19",
        owasp_2025: owasp::A01,
        api_top10: Some("API7:2023-Server Side Request Forgery"),
        description:
            "The application makes an HTTP request to a URL that a caller can influence. The \
             request comes from inside the network perimeter, so it reaches things the caller \
             cannot: internal admin panels, databases with no authentication because they are \
             \"not exposed\", and cloud instance metadata at 169.254.169.254, which hands out \
             the credentials attached to the workload. SSRF is the standard first step in a \
             cloud compromise for exactly that reason.",
        remediation:
            "Validate the destination, not the input string. Parse the URL, require an \
             expected scheme and an allow-listed host, resolve the host to an address, and \
             reject loopback, link-local, and RFC 1918 ranges — then connect to the address \
             you resolved, so DNS cannot answer differently the second time.\n\n\
             ```\n\
             const url = new URL(candidate);\n\
             if (url.protocol !== 'https:') throw new Error('scheme');\n\
             if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error('host');\n\
             const { address } = await dns.promises.lookup(url.hostname);\n\
             if (isPrivate(address)) throw new Error('internal address');\n\
             ```\n\n\
             Disable redirect-following, or re-run the check on every hop: a redirect to \
             `http://169.254.169.254/` defeats a check applied only to the first URL. Where \
             the platform offers it, put the egress behind a proxy with its own allow-list \
             and require IMDSv2 so metadata cannot be read with a bare GET.",
        references: &[
            "https://cwe.mitre.org/data/definitions/918.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A request value reaches an outbound HTTP call. Establish what the application's \
             network position actually reaches — the severity of an SSRF is entirely a \
             property of where the request lands, not of the code that makes it.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)\b(?:fetch|axios(?:\.(?:get|post|put|delete|request))?|got|superagent|request|http\.(?:get|request)|https\.(?:get|request)|urllib\.request\.urlopen|requests\.(?:get|post|put|delete|head|request)|HttpClient|WebClient|RestTemplate|file_get_contents|curl_setopt|http\.Get|http\.Post|Net::HTTP)\s*\(?(?P<arg>[^)\n]*)",
    mode: Mode::Tainted,
    unless: &["ALLOWED_HOSTS", "allowlist", "allowList", "isPrivate(", "127.0.0.1", "localhost"],
    scan_tests: false,
},

// ══ Cryptography ════════════════════════════════════════════════════════════

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-WEAK-HASH",
        title: "Broken hash function used where collision resistance matters",
        cvss_vector: V_LIMITED,
        cwe: "CWE-327",
        wstg: "WSTG-CRYP-04",
        owasp_2025: owasp::A04,
        api_top10: None,
        description:
            "MD5 or SHA-1 is used. Both are broken for collision resistance — chosen-prefix \
             collisions against SHA-1 have been demonstrated at practical cost — so any use \
             that depends on two different inputs not producing the same digest is unsound: \
             signatures, integrity checks, deduplication of security-relevant content, \
             certificate handling. Neither is acceptable for password storage either, though \
             for a different reason: both are far too fast.",
        remediation:
            "For integrity and signatures, use SHA-256 or SHA-3. For passwords, use a \
             memory-hard password hash with a per-password salt — Argon2id, scrypt or \
             bcrypt — never a general-purpose digest, however many times it is iterated.\n\n\
             ```\n\
             // Node\n\
             const hash = crypto.createHash('sha256').update(data).digest('hex');\n\
             const pw   = await argon2.hash(password);   // for credentials\n\
             ```\n\n\
             Where MD5 is used as a non-security checksum — a cache key, an ETag — it is not \
             a vulnerability, but naming it as such in a comment saves the next reviewer the \
             same investigation.",
        references: &[
            "https://cwe.mitre.org/data/definitions/327.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
        ],
        confidence: Confidence::Tentative,
        triage_note:
            "A broken digest is in use. Whether it matters depends entirely on what it is \
             used for — a cache key is fine, a signature is not — so read the surrounding \
             call before rating this.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)(?:createHash\s*\(\s*["'](?:md5|sha1)["']|hashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']|MD5\.Create\s*\(|SHA1\.Create\s*\(|md5\s*\(\s*\$|Digest::MD5|crypto/md5|crypto/sha1)"#,
    mode: Mode::Always,
    unless: &["etag", "cache", "checksum", "non-crypto", "nonSecurity"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-WEAK-CIPHER",
        title: "Broken or misused symmetric cipher",
        cvss_vector: V_DISCLOSURE,
        cwe: "CWE-327",
        wstg: "WSTG-CRYP-04",
        owasp_2025: owasp::A04,
        api_top10: None,
        description:
            "The code selects a cipher or mode that does not provide the protection its use \
             implies. DES and 3DES have inadequate block and key sizes; RC4 has practical \
             biases; ECB mode encrypts identical plaintext blocks to identical ciphertext \
             blocks, so structure in the data survives encryption and can be read straight \
             off the ciphertext. CBC without a separate authentication step is malleable: an \
             attacker who cannot read the plaintext can still change it.",
        remediation:
            "Use authenticated encryption, which gives confidentiality and integrity in one \
             construction and has no mode to choose wrongly.\n\n\
             ```\n\
             // AES-256-GCM: unique 96-bit nonce per message, never reused with one key\n\
             const iv = crypto.randomBytes(12);\n\
             const c  = crypto.createCipheriv('aes-256-gcm', key, iv);\n\
             const ct = Buffer.concat([c.update(pt), c.final()]);\n\
             const tag = c.getAuthTag();   // store alongside; verify on decrypt\n\
             ```\n\n\
             XChaCha20-Poly1305 is an equally good choice and is more forgiving of nonce \
             handling. Prefer a high-level library — libsodium, Tink — over assembling \
             primitives.",
        references: &[
            "https://cwe.mitre.org/data/definitions/327.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A weak cipher or an unauthenticated mode was selected explicitly. What decides \
             the impact is what is being protected — read the surrounding function to see \
             whether this is session data, stored credentials, or a legacy interop path.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)(?:["'](?:des|des-ede3|rc4|rc2|blowfish)[-_a-z0-9]*["']|AES/ECB|/ECB/|Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC2|RC4|AES/ECB)|MODE_ECB|DESCryptoServiceProvider|RC2CryptoServiceProvider|TripleDES|createCipheriv\s*\(\s*["'][^"']*ecb)"#,
    mode: Mode::Always,
    unless: &[],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-WEAK-RANDOM",
        title: "Non-cryptographic random used for a security value",
        cvss_vector: V_AUTHENTICATED,
        cwe: "CWE-338",
        wstg: "WSTG-CRYP-02",
        owasp_2025: owasp::A04,
        api_top10: None,
        description:
            "A general-purpose pseudo-random generator produces a value used for security — \
             a token, a session identifier, a password-reset code, a nonce. These generators \
             are built for speed and statistical quality, not unpredictability: their internal \
             state is recoverable from a modest number of outputs, after which every past and \
             future value is computable. An attacker who can request a few tokens can then \
             predict somebody else's.",
        remediation:
            "Use the platform's cryptographic generator, which is a one-word change:\n\n\
             ```\n\
             crypto.randomBytes(32).toString('base64url');     // Node\n\
             secrets.token_urlsafe(32)                          # Python\n\
             new SecureRandom().nextBytes(buf);                // Java\n\
             RandomNumberGenerator.Fill(buf);                  // .NET\n\
             rand.Read(buf)                                    // Go (crypto/rand)\n\
             ```\n\n\
             128 bits of entropy is the floor for anything that acts as a bearer credential.",
        references: &[
            "https://cwe.mitre.org/data/definitions/338.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A weak generator produces a value on a line that also names a token, key, \
             session or password. If the value is a jitter delay or a UI id this is noise; \
             if it is a credential it is predictable.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)(?:Math\.random\s*\(\)|\brandom\.(?:random|randint|choice|randrange|sample)\s*\(|new\s+Random\s*\(|mt_rand\s*\(|\brand\s*\(\)|math/rand|Random\.Next|SecureRandom\.hex|srand\s*\()",
    mode: Mode::Always,
    unless: &["secrets.", "SecureRandom", "crypto.randomBytes", "crypto/rand", "RandomNumberGenerator"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-STATIC-IV",
        title: "Fixed initialisation vector or nonce",
        cvss_vector: V_DISCLOSURE,
        cwe: "CWE-329",
        wstg: "WSTG-CRYP-04",
        owasp_2025: owasp::A04,
        api_top10: None,
        description:
            "An initialisation vector or nonce is a constant. Every mode that takes one \
             requires it to be unique per message under a given key, and most require it to \
             be unpredictable as well. Repeating it in CBC leaks whether two messages start \
             the same; repeating it in a counter mode such as GCM or CTR is catastrophic — \
             the keystream repeats, XORing two ciphertexts cancels it out, and for GCM \
             specifically nonce reuse also leaks the authentication key, so an attacker can \
             forge messages rather than merely read them.",
        remediation:
            "Generate a fresh IV from a cryptographic source for every single encryption and \
             transmit it alongside the ciphertext — it is not secret, only unique.\n\n\
             ```\n\
             const iv = crypto.randomBytes(12);          // per message, never reused\n\
             const out = Buffer.concat([iv, ciphertext, tag]);\n\
             ```",
        references: &[
            "https://cwe.mitre.org/data/definitions/329.html",
            "https://csrc.nist.gov/pubs/sp/800/38/d/final",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "The IV argument is a literal or a module-level constant. Confirm it is not \
             overwritten before use; if it is genuinely fixed, the mode determines whether \
             this is a leak or a total break.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)\b(?:iv|IV|nonce|initializationVector|initialization_vector)\s*[=:]\s*(?:["'][A-Za-z0-9+/=_-]{8,}["']|(?:Buffer\.from|bytes|new\s+byte\[\]|b)\s*\(?\s*["'][^"']{8,}["'])"#,
    mode: Mode::Always,
    unless: &["randomBytes", "urandom", "SecureRandom", "rand.Read", "RandomNumberGenerator"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-SMALL-KEY",
        title: "Asymmetric key generated below the current minimum size",
        cvss_vector: V_LIMITED,
        cwe: "CWE-326",
        wstg: "WSTG-CRYP-04",
        owasp_2025: owasp::A04,
        api_top10: None,
        description:
            "An RSA or DSA key is generated at 1024 bits or smaller. Keys of that size are \
             below every current recommendation — NIST withdrew approval in 2013 — and are \
             considered factorable by a well-resourced attacker. A key generated at this size \
             today will be in use for years.",
        remediation:
            "Generate RSA at 3072 bits or above, or move to an elliptic-curve key, which \
             gives equivalent strength in a fraction of the size and cost:\n\n\
             ```\n\
             crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });\n\
             crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });\n\
             ```",
        references: &[
            "https://cwe.mitre.org/data/definitions/326.html",
            "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final",
        ],
        confidence: Confidence::Certain,
        triage_note:
            "The key size is a literal in the generation call. This is read directly from the \
             source rather than inferred; the only question is whether the key is still in use.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)(?:modulusLength\s*:\s*(?:512|768|1024)\b|key_size\s*=\s*(?:512|768|1024)\b|initialize\s*\(\s*(?:512|768|1024)\s*\)|RSA\.Create\s*\(\s*(?:512|768|1024)\s*\)|GenerateKey\s*\([^,]*,\s*(?:512|768|1024)\s*\)|rsa\.generate_private_key\([^)]*key_size\s*=\s*(?:512|768|1024))",
    mode: Mode::Always,
    unless: &[],
    scan_tests: false,
},

// ══ Transport security ══════════════════════════════════════════════════════

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-TLS-VERIFY-DISABLED",
        title: "TLS certificate verification switched off",
        cvss_vector: V_DISCLOSURE,
        cwe: "CWE-295",
        wstg: "WSTG-CRYP-01",
        owasp_2025: owasp::A04,
        api_top10: None,
        description:
            "The code disables certificate validation on an outbound TLS connection. The \
             connection is still encrypted, which is what makes this so easy to miss, but it \
             is encrypted to whoever answered — any party on the network path can present \
             their own certificate, terminate the session and read and modify everything, \
             including the credentials the application sends to authenticate. Encryption \
             without authentication of the peer provides no protection against an active \
             attacker.",
        remediation:
            "Remove the flag. If it is there because an internal service uses a private CA, \
             add that CA to the trust store for this client rather than trusting everything:\n\n\
             ```\n\
             // Node\n\
             new https.Agent({ ca: fs.readFileSync('internal-ca.pem') });\n\n\
             # Python\n\
             requests.get(url, verify='/etc/ssl/internal-ca.pem')\n\n\
             // Go\n\
             &tls.Config{ RootCAs: pool }   // never InsecureSkipVerify: true\n\
             ```\n\n\
             If it is there because a certificate expired, fix the certificate. A verification \
             bypass added during an incident is the single most common way this reaches \
             production permanently.",
        references: &[
            "https://cwe.mitre.org/data/definitions/295.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
        ],
        confidence: Confidence::Certain,
        triage_note:
            "Verification is explicitly disabled in this source line. There is no reading of \
             this that is safe on an untrusted network; the only judgement is whether the \
             path in question is on one.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\x22]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|CURLOPT_SSL_VERIFYHOST\s*,\s*0|ServerCertificateValidationCallback\s*[+=]+\s*(?:delegate|\()|setHostnameVerifier\s*\(\s*(?:ALLOW_ALL|NoopHostnameVerifier|\(.*\)\s*->\s*true)|TrustAllCerts|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|verify_mode\s*=\s*(?:OpenSSL::)?SSL::VERIFY_NONE|CERT_NONE)",
    mode: Mode::Always,
    unless: &[],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-PLAINTEXT-TRANSPORT",
        title: "Credential or API call sent over plain HTTP",
        cvss_vector: V_PARTIAL_INFO,
        cwe: "CWE-319",
        wstg: "WSTG-CRYP-03",
        owasp_2025: owasp::A04,
        api_top10: None,
        description:
            "A URL on this line uses `http://` and the surrounding code sends authentication \
             material or calls an API. Anything on that connection — tokens, session cookies, \
             the response body — is readable by every device on the path and modifiable by \
             any of them.",
        remediation:
            "Change the scheme to `https://` and confirm the endpoint presents a valid \
             certificate. Where the destination is a service that genuinely does not support \
             TLS, put it behind a TLS-terminating proxy rather than leaving the application \
             speaking plaintext across a network.",
        references: &[
            "https://cwe.mitre.org/data/definitions/319.html",
        ],
        confidence: Confidence::Tentative,
        triage_note:
            "A plaintext URL appears alongside credential-shaped code. Localhost and \
             in-cluster addresses are frequently fine; a public hostname is not.",
    },
    languages: WEB_LANGS,
    // The exclusions live in `unless` rather than in a look-ahead: loopback,
    // in-cluster and namespace URLs are all legitimate plaintext, and listing
    // them where a reader can see them beats hiding them inside the pattern.
    pattern: r#"(?i)["']http://[a-z0-9][a-z0-9.-]{2,}"#,
    mode: Mode::Always,
    unless: &[
        "localhost", "127.0.0.1", "0.0.0.0", "[::1]", ".local", ".internal",
        ".svc", "www.w3.org", "schemas.", "xmlns", "DOCTYPE", "schemaLocation",
        "example.com", "example.org", "//127.", "purl.org", "docbook.org",
    ],
    scan_tests: false,
},

// ══ Authentication, sessions and access control ═════════════════════════════

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-JWT-UNVERIFIED",
        title: "JSON Web Token decoded without verifying its signature",
        cvss_vector: V_RCE,
        cwe: "CWE-347",
        wstg: "WSTG-ATHN-10",
        owasp_2025: owasp::A07,
        api_top10: Some("API2:2023-Broken Authentication"),
        description:
            "A JWT is decoded without its signature being checked — either by calling a \
             decode-only function, by passing `verify: false`, or by permitting the `none` \
             algorithm. A JWT's payload is base64, not encryption: anyone can read it and \
             anyone can write one. Without signature verification the claims inside it are \
             attacker-supplied input, so changing `\"role\":\"user\"` to `\"role\":\"admin\"` \
             and re-encoding is a complete authentication and authorisation bypass requiring \
             no credentials at all.",
        remediation:
            "Verify with an explicit algorithm allow-list, and never let the token's own \
             header choose it:\n\n\
             ```\n\
             jwt.verify(token, publicKey, {\n\
             \x20 algorithms: ['RS256'],       // fixed here, not read from the token\n\
             \x20 issuer: 'https://issuer.example.com',\n\
             \x20 audience: 'api://this-service',\n\
             });\n\
             ```\n\n\
             Pinning the algorithm is what closes the related `alg: none` and \
             RS256→HS256 confusion attacks, where the public key is used as an HMAC secret. \
             Check `iss`, `aud` and `exp` as well: a validly signed token issued for a \
             different service is still the wrong token.",
        references: &[
            "https://cwe.mitre.org/data/definitions/347.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        ],
        confidence: Confidence::Certain,
        triage_note:
            "The decode call skips verification. Occasionally this is deliberate — reading a \
             claim for logging before verifying elsewhere — so confirm a real `verify` call \
             governs the request path before rating it critical.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)(?:jwt\.decode\s*\(|jose\.decode\s*\(|verify\s*:\s*false|verify\s*=\s*False|algorithms\s*[=:]\s*\[?\s*["']none["']|decode\s*\([^)]*\{\s*complete\s*:\s*true\s*\}|parser\(\)\.parseClaimsJwt|\.setSigningKey\s*\(\s*null|verify_signature["']?\s*:\s*False)"#,
    mode: Mode::Always,
    // `jwt.decode` with verification on is the correct call, so the safe forms
    // are excluded here rather than by a look-ahead the engine cannot express.
    unless: &["jwt.verify", "verify=True", "requireSignature", "verify_signature\": True", "options={\"verify_signature\": True}"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-CORS-WILDCARD-CREDENTIALS",
        title: "CORS policy reflects the origin and allows credentials",
        cvss_vector: V_DISCLOSURE,
        cwe: "CWE-942",
        wstg: "WSTG-CONF-07",
        owasp_2025: owasp::A02,
        api_top10: Some("API8:2023-Security Misconfiguration"),
        description:
            "The cross-origin policy is configured to echo whatever origin asked, or to \
             allow any origin, while also allowing credentials. That combination removes the \
             same-origin policy for this application: a page on any site the victim visits \
             can call these endpoints with the victim's session cookie attached and read the \
             responses. Everything the user can see, an arbitrary third-party page can now \
             read on their behalf.",
        remediation:
            "Match the request's `Origin` against a fixed allow-list and echo only a value \
             that matched. Send `Vary: Origin` so caches do not serve one origin's response \
             to another.\n\n\
             ```\n\
             const ALLOWED = new Set(['https://app.example.com']);\n\
             app.use(cors({\n\
             \x20 origin: (o, cb) => cb(null, !o || ALLOWED.has(o)),\n\
             \x20 credentials: true,\n\
             }));\n\
             ```\n\n\
             `Access-Control-Allow-Origin: *` and `credentials: true` are rejected together \
             by browsers, which is why reflection is the form that actually ships — and the \
             form that is exploitable.",
        references: &[
            "https://cwe.mitre.org/data/definitions/942.html",
            "https://portswigger.net/web-security/cors",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "The configuration reflects origins or wildcards them with credentials enabled. \
             If the endpoints behind it carry no session and no personal data, the impact is \
             limited to whatever they do return.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)(?:origin\s*:\s*true|origin\s*:\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[,:]\s*(?:req|request)\.(?:headers|get)|setHeader\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*(?:req|origin)|AllowAnyOrigin\s*\(\s*\)|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|allow_origins\s*=\s*\[\s*["']\*["'])"#,
    mode: Mode::Always,
    unless: &["ALLOWED", "allowlist", "allowList"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-CSRF-DISABLED",
        title: "Cross-site request forgery protection disabled",
        cvss_vector: V_INTEGRITY,
        cwe: "CWE-352",
        wstg: "WSTG-SESS-05",
        owasp_2025: owasp::A01,
        api_top10: None,
        description:
            "CSRF protection is switched off — globally in the framework's configuration, or \
             per-handler with an exemption decorator. Without it, any page the victim visits \
             can make their browser issue a state-changing request to this application with \
             their session cookie attached. The attacker never sees the response and does not \
             need to: the effect is the change itself, made under the victim's identity.",
        remediation:
            "Re-enable the framework's protection. Where a route is exempted because it is \
             an API called by a script rather than a form, the correct fix is usually to \
             authenticate it with a bearer token rather than a cookie — a token is not \
             attached automatically by the browser, so CSRF does not apply to it at all.\n\n\
             Set `SameSite=Lax` (or `Strict`) on the session cookie regardless. It is not a \
             substitute for a token, but it removes the cross-site request from most of the \
             ways it is delivered.",
        references: &[
            "https://cwe.mitre.org/data/definitions/352.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A CSRF exemption is in the source. Whether it is a real weakness depends on \
             whether the exempted route changes state and whether it authenticates by cookie.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)(?:@csrf_exempt|csrf\s*:\s*false|WTF_CSRF_ENABLED\s*=\s*False|skip_before_action\s*:\s*verify_authenticity_token|protect_from_forgery\s+with:\s*:null_session|\.csrf\(\)\.disable\(\)|IgnoreAntiforgeryToken|@CrossOrigin\s*\(\s*origins\s*=\s*[\x22']\*)",
    mode: Mode::Always,
    unless: &[],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-COOKIE-INSECURE",
        title: "Session cookie set without its protective attributes",
        cvss_vector: V_AUTHENTICATED,
        cwe: "CWE-614",
        wstg: "WSTG-SESS-02",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "A cookie is configured with `httpOnly`, `secure` or `sameSite` explicitly \
             disabled, or a session cookie is created without them. Without `httpOnly` the \
             value is readable by any script on the page, so a single XSS becomes full \
             session theft. Without `secure` the browser sends it over plain HTTP, exposing \
             it to the network. Without `sameSite` it is attached to cross-site requests, \
             which is what makes CSRF possible in the first place.",
        remediation:
            "Set all three, and prefer the `__Host-` prefix, which the browser itself \
             enforces:\n\n\
             ```\n\
             res.cookie('__Host-session', value, {\n\
             \x20 httpOnly: true, secure: true, sameSite: 'lax', path: '/',\n\
             });\n\
             ```\n\n\
             `__Host-` requires HTTPS, `Path=/` and no `Domain`, which additionally stops a \
             compromised sibling subdomain from overwriting the session cookie.",
        references: &[
            "https://cwe.mitre.org/data/definitions/614.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "An attribute is explicitly false on this cookie. Check whether the cookie \
             carries session state — a preference cookie without `httpOnly` is a deliberate \
             and reasonable choice.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)(?:httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*['\x22]?none['\x22]?|SESSION_COOKIE_HTTPONLY\s*=\s*False|SESSION_COOKIE_SECURE\s*=\s*False|setHttpOnly\s*\(\s*false\s*\)|setSecure\s*\(\s*false\s*\)|HttpOnly\s*=\s*false|RequireHttps\s*=\s*false|session\.cookie_httponly\s*=\s*0)",
    mode: Mode::Always,
    unless: &[],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-OPEN-REDIRECT",
        title: "Redirect destination taken from the request",
        cvss_vector: V_LIMITED_UI,
        cwe: "CWE-601",
        wstg: "WSTG-CLNT-04",
        owasp_2025: owasp::A01,
        api_top10: None,
        description:
            "The application redirects to a URL supplied in the request. The link that \
             starts the journey is on the application's own domain, with its own \
             certificate, so it survives inspection by a cautious user and by mail filters \
             that check the visible hostname — and lands the victim on the attacker's page. \
             Where the redirect happens after login, it also leaks whatever the application \
             appends to it: an authorisation code, a token, a session identifier.",
        remediation:
            "Do not redirect to a supplied URL. Accept a key and look the destination up:\n\n\
             ```\n\
             const DESTINATIONS = { dashboard: '/dashboard', billing: '/billing' };\n\
             res.redirect(DESTINATIONS[req.query.to] ?? '/');\n\
             ```\n\n\
             Where an arbitrary return path is genuinely needed, accept only a path — reject \
             anything containing a scheme, a host, a backslash, or a leading `//`, all of \
             which browsers resolve as absolute.",
        references: &[
            "https://cwe.mitre.org/data/definitions/601.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A request value reaches a redirect. If the code restricts it to a relative path, \
             this is safe — check for that restriction before rating.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)\b(?:res\.redirect|response\.redirect|redirect|sendRedirect|Redirect|header\s*\(\s*['\x22]Location:|http\.Redirect|redirect_to)\s*\(?(?P<arg>[^)\n]*)",
    mode: Mode::Tainted,
    unless: &["DESTINATIONS", "startsWith('/')", "allowlist", "url_for("],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-MASS-ASSIGNMENT",
        title: "Request body bound directly to a persisted model",
        cvss_vector: V_INTEGRITY,
        cwe: "CWE-915",
        wstg: "WSTG-INPV-20",
        owasp_2025: owasp::A01,
        api_top10: Some("API3:2023-Broken Object Property Level Authorization"),
        description:
            "A whole request body is handed to a model constructor or update call. Whatever \
             fields the model has, the caller can now set — including the ones the interface \
             never exposes. `isAdmin`, `role`, `accountBalance`, `emailVerified` and \
             `organizationId` are all set the same way as `displayName`, and the endpoint \
             becomes a privilege-escalation primitive without any bug in its own logic.",
        remediation:
            "Choose the fields explicitly rather than excluding the dangerous ones — a \
             deny-list has to be updated every time the model gains a field, and it will not \
             be.\n\n\
             ```\n\
             const { displayName, bio } = req.body;      // exactly what may change\n\
             await User.update({ displayName, bio }, { where: { id: req.user.id } });\n\
             ```\n\n\
             A schema validator (zod, Joi, pydantic, a DTO) that strips unknown keys gives \
             the same guarantee for a whole API at once.",
        references: &[
            "https://cwe.mitre.org/data/definitions/915.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A whole request body reaches a persistence call. If a schema strips unknown keys \
             upstream, or the model has no sensitive fields, this is not exploitable — both \
             are worth checking before raising it.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)\b(?:new\s+\w+|\w+\.(?:create|update|save|insert|bulkCreate|findOneAndUpdate)|\w+\.objects\.(?:create|update)|BeanUtils\.copyProperties)\s*\(\s*(?P<arg>(?:req|request)\.body|(?:req|request)\.params|\*\*request\.(?:json|form)|params\[[^\]]*\](?:\.permit!)?)",
    mode: Mode::Always,
    unless: &["permit(", "pick(", "select(", "only:", "fields="],
    scan_tests: false,
},

// ══ Configuration and operational ═══════════════════════════════════════════

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-DEBUG-ENABLED",
        title: "Debug mode enabled in application configuration",
        cvss_vector: V_PARTIAL_INFO,
        cwe: "CWE-489",
        wstg: "WSTG-CONF-02",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "Debug mode is turned on in the source rather than being read from the \
             environment. In production this returns stack traces, source fragments, \
             configuration values and often database queries to the caller on any error. In \
             several frameworks it goes further: Flask's debugger offers an interactive \
             console, and Django's debug pages print settings including credentials.",
        remediation:
            "Read the flag from the environment and default it to off, so that shipping the \
             file cannot ship the setting:\n\n\
             ```\n\
             DEBUG = os.environ.get('DEBUG', '').lower() == 'true'\n\
             ```\n\n\
             Pair it with an error handler that returns a generic message and an identifier, \
             and logs the detail server-side where the caller cannot read it.",
        references: &[
            "https://cwe.mitre.org/data/definitions/489.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "Debug is set true in source. Confirm this file is the production configuration \
             rather than a development override that is never deployed.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)(?:^|\s)(?:DEBUG|debug)\s*[=:]\s*(?:True|true|1)\s*(?:$|[,;#])|app\.run\s*\([^)]*debug\s*=\s*True|\.set\s*\(\s*['\x22]debug['\x22]\s*,\s*true|display_errors\s*[=,]\s*['\x22]?(?:On|1)",
    mode: Mode::Always,
    unless: &["os.environ", "process.env", "getenv", "ENV[", "Environment.Get"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-BIND-ALL-INTERFACES",
        title: "Service bound to every network interface",
        cvss_vector: V_PARTIAL_INFO,
        cwe: "CWE-1327",
        wstg: "WSTG-CONF-05",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "A listener is bound to `0.0.0.0` or `::`, which accepts connections on every \
             interface the host has. For a service intended to be reached only by another \
             process on the same machine, or only from inside a private network, this \
             exposes it to whatever else can route to the host — which on a cloud instance \
             with a public address means the internet.",
        remediation:
            "Bind to the narrowest address that works: `127.0.0.1` for same-host callers, or \
             the specific private address for a service reached across a known network. \
             Where a container genuinely must bind broadly for its runtime to route traffic, \
             keep the broad bind and put the access control in the network policy or security \
             group, and say so in a comment so the next reviewer does not have to work it out.",
        references: &[
            "https://cwe.mitre.org/data/definitions/1327.html",
        ],
        confidence: Confidence::Tentative,
        triage_note:
            "A wildcard bind is in the source. Inside a container this is routine and \
             correct; on a host with a public address it is exposure. The deployment decides, \
             not the line.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)(?:["']0\.0\.0\.0["']|["']::["']\s*,|host\s*=\s*["']0\.0\.0\.0["']|ListenAndServe\s*\(\s*["']:\d+["']|Listen\s*\(\s*["']tcp["']\s*,\s*["']:\d+["'])"#,
    mode: Mode::Always,
    unless: &["127.0.0.1", "localhost"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-PROTOTYPE-POLLUTION",
        title: "Recursive merge or dynamic property write without key filtering",
        cvss_vector: V_INTEGRITY,
        cwe: "CWE-1321",
        wstg: "WSTG-CLNT-13",
        owasp_2025: owasp::A08,
        api_top10: None,
        description:
            "An object is merged or a property is set from a key the application did not \
             choose. In JavaScript the keys `__proto__`, `constructor` and `prototype` do not \
             address a property — they address the prototype chain — so an attacker who \
             supplies one writes a property onto `Object.prototype`, and every object in the \
             process inherits it. Depending on what the application reads afterwards this \
             turns into authorisation bypass, denial of service, or code execution where the \
             polluted key reaches a template or a child-process option.",
        remediation:
            "Reject the three dangerous keys before writing, and prefer structures that have \
             no prototype at all:\n\n\
             ```\n\
             const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);\n\
             for (const [k, v] of Object.entries(input)) {\n\
             \x20 if (BLOCKED.has(k)) continue;\n\
             \x20 target[k] = v;\n\
             }\n\n\
             const safe = Object.create(null);   // or: new Map()\n\
             ```\n\n\
             `Object.freeze(Object.prototype)` at startup is a cheap belt-and-braces measure \
             for an application that never extends built-ins.",
        references: &[
            "https://cwe.mitre.org/data/definitions/1321.html",
            "https://portswigger.net/web-security/prototype-pollution",
        ],
        confidence: Confidence::Tentative,
        triage_note:
            "A dynamic key write or recursive merge was found. Modern lodash and most merge \
             libraries filter these keys themselves — check the version before rating, since \
             the same call is safe or unsafe depending on it.",
    },
    languages: JS,
    pattern: r"(?i)(?:\bmerge\s*\(|\bextend\s*\(|deepMerge|deepExtend|\$\.extend\s*\(\s*true|Object\.assign\s*\([^)]*(?:req|request)\.|\[\s*(?:key|k|prop|name|field)\s*\]\s*=)",
    mode: Mode::Tainted,
    unless: &["__proto__", "hasOwnProperty", "Object.create(null)", "BLOCKED"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-REDOS",
        title: "Regular expression with catastrophic backtracking",
        cvss_vector: V_DOS,
        cwe: "CWE-1333",
        wstg: "WSTG-BUSL-09",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "A regular expression contains nested quantifiers — a repeated group that is \
             itself repeated, such as `(a+)+` or `(\\w*\\s?)*`. On a backtracking engine, \
             which is what JavaScript, Python, Java, .NET and PCRE all use, a non-matching \
             input can force the engine through an exponential number of paths. A few dozen \
             characters in a request field then occupy a CPU core for minutes, and on a \
             single-threaded runtime such as Node that stops the whole process serving \
             anyone.",
        remediation:
            "Rewrite the expression so no repeated group can match the same text two ways — \
             usually by making the inner quantifier possessive, by anchoring, or by replacing \
             the pattern with a parser. Bound the input length before matching regardless, \
             and where the platform supports a match timeout, set one:\n\n\
             ```\n\
             new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));  // .NET\n\
             ```\n\n\
             Rust's `regex` and Go's `RE2` have no backtracking and are immune by \
             construction, which makes them a good choice for matching untrusted input.",
        references: &[
            "https://cwe.mitre.org/data/definitions/1333.html",
            "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
        ],
        confidence: Confidence::Tentative,
        triage_note:
            "The expression has the nested-quantifier shape associated with catastrophic \
             backtracking. Whether it is exploitable depends on the alternation inside it and \
             on whether untrusted input reaches it — confirm both before rating.",
    },
    languages: WEB_LANGS,
    pattern: r"(?:\([^)]*[+*]\s*\)\s*[+*]|\(\?:[^)]*[+*]\)[+*]|\[[^\]]+\][+*]\s*\)\s*[+*])",
    mode: Mode::Always,
    unless: &["(?i)", "regexp.MustCompile"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-INSECURE-TEMP-FILE",
        title: "Temporary file created at a predictable path",
        cvss_vector: V_LOCAL,
        cwe: "CWE-377",
        wstg: "WSTG-CONF-11",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "A temporary file is created at a path the code constructs itself, in a \
             world-writable directory. Between choosing the name and opening the file, \
             another local user can create that path — as a symlink to a file they want \
             overwritten, or as a file they then read. The window is small and entirely \
             winnable, and the deprecated functions that produce this pattern (`tmpnam`, \
             `mktemp`, `tempnam`) are deprecated precisely because it cannot be closed by the \
             caller.",
        remediation:
            "Use the atomic create-and-open API, which never returns a name that another \
             process could have raced:\n\n\
             ```\n\
             tempfile.NamedTemporaryFile(delete=True)   # Python\n\
             fs.mkdtemp() / os.MkdirTemp()              # a private directory\n\
             Files.createTempFile(attrs...)             # Java, with 0600 permissions\n\
             ```",
        references: &[
            "https://cwe.mitre.org/data/definitions/377.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A predictable temporary path is constructed. It matters where other local users \
             or processes share the host; in a single-tenant container it is largely \
             theoretical.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)(?:tmpnam\s*\(|mktemp\s*\(|tempnam\s*\(|["']/tmp/[a-z0-9_.-]+["']|os\.path\.join\s*\(\s*["']/tmp["']|new\s+File\s*\(\s*["']/tmp/)"#,
    mode: Mode::Always,
    unless: &["mkstemp", "NamedTemporaryFile", "TemporaryDirectory", "mkdtemp", "MkdirTemp", "createTempFile"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-UNSAFE-REFLECTION",
        title: "Class or method resolved by name from untrusted input",
        cvss_vector: V_RCE,
        cwe: "CWE-470",
        wstg: "WSTG-INPV-11",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "A class name, method name or module path comes from outside the application and \
             is used to load and invoke code. The set of things an attacker can reach is not \
             the set the developer had in mind — it is everything on the classpath or import \
             path, including classes whose constructors execute commands, open connections \
             or deserialise data. This is a code-execution primitive dressed as a dispatch \
             table.",
        remediation:
            "Replace the dynamic lookup with an explicit map from permitted input values to \
             the handlers they select:\n\n\
             ```\n\
             const HANDLERS = { csv: CsvExporter, pdf: PdfExporter };\n\
             const handler = HANDLERS[req.query.format];\n\
             if (!handler) return res.status(400).end();\n\
             ```\n\n\
             The map is also self-documenting: the set of legal values is visible in one \
             place rather than implied by what happens to be importable.",
        references: &[
            "https://cwe.mitre.org/data/definitions/470.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A name from outside the application selects code to run. Confirm whether the \
             value is checked against a fixed list first; without one, treat this as remote \
             code execution.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)\b(?:Class\.forName|getMethod|getDeclaredMethod|newInstance|importlib\.import_module|__import__|getattr|Activator\.CreateInstance|Type\.GetType|call_user_func(?:_array)?|new\s+\$|\$\$|constantize|const_get|Object\.const_get|send\s*\()\s*\(?(?P<arg>[^)\n]*)",
    mode: Mode::Tainted,
    unless: &["HANDLERS", "allowlist", "ALLOWED"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-ELECTRON-NODE-INTEGRATION",
        title: "Electron renderer given Node.js access",
        cvss_vector: V_RCE,
        cwe: "CWE-829",
        wstg: "WSTG-CLNT-13",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "An Electron window is created with `nodeIntegration` on or `contextIsolation` \
             off. Web content in that window can then reach Node's APIs directly, so any \
             cross-site scripting in the renderer — including one in a third-party script or \
             a rendered piece of remote content — becomes arbitrary code execution on the \
             user's machine, with the user's filesystem access, rather than a browser-scoped \
             problem.",
        remediation:
            "Keep the defaults Electron has shipped since v12 and expose only what the \
             renderer needs, through a preload script:\n\n\
             ```\n\
             new BrowserWindow({ webPreferences: {\n\
             \x20 nodeIntegration: false,\n\
             \x20 contextIsolation: true,\n\
             \x20 sandbox: true,\n\
             \x20 preload: path.join(__dirname, 'preload.js'),\n\
             }});\n\n\
             // preload.js — a narrow, audited surface\n\
             contextBridge.exposeInMainWorld('api', { readConfig: () => ipcRenderer.invoke('config:read') });\n\
             ```",
        references: &[
            "https://www.electronjs.org/docs/latest/tutorial/security",
            "https://cwe.mitre.org/data/definitions/829.html",
        ],
        confidence: Confidence::Certain,
        triage_note:
            "The window options set this explicitly. Read directly from the configuration \
             object; the only judgement left is what content that window loads.",
    },
    languages: JS,
    pattern: r"(?i)(?:nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false|webSecurity\s*:\s*false|allowRunningInsecureContent\s*:\s*true|enableRemoteModule\s*:\s*true)",
    mode: Mode::Always,
    unless: &[],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-GRAPHQL-INTROSPECTION",
        title: "GraphQL introspection left enabled with no depth limit",
        cvss_vector: V_PARTIAL_INFO,
        cwe: "CWE-200",
        wstg: "WSTG-CONF-05",
        owasp_2025: owasp::A02,
        api_top10: Some("API8:2023-Security Misconfiguration"),
        description:
            "The GraphQL server is configured with introspection on. Introspection publishes \
             the complete schema — every type, field, mutation and argument, including the \
             ones no client uses and the ones intended for internal tooling. It is the single \
             most useful thing an attacker can obtain about a GraphQL API, and it removes \
             the need to guess anything.",
        remediation:
            "Disable introspection outside development, and pair it with a query depth and \
             complexity limit — the schema is only half of the exposure, and a deeply nested \
             query against a cyclic schema is a denial of service on its own.\n\n\
             ```\n\
             new ApolloServer({\n\
             \x20 schema,\n\
             \x20 introspection: process.env.NODE_ENV !== 'production',\n\
             \x20 validationRules: [depthLimit(8), createComplexityRule({ maximumComplexity: 1000 })],\n\
             });\n\
             ```\n\n\
             Ship a published schema artifact to the clients that need one, rather than \
             letting every caller derive it at runtime.",
        references: &[
            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "Introspection is enabled in the server configuration. For a public API this is \
             often deliberate; for an internal one it is an inventory disclosure.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)(?:introspection\s*:\s*true|GraphiQL\s*:\s*true|graphiql\s*:\s*true|playground\s*:\s*true|__schema)",
    mode: Mode::Always,
    unless: &["NODE_ENV", "production", "process.env"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-TIMING-UNSAFE-COMPARE",
        title: "Secret compared with a short-circuiting equality test",
        cvss_vector: V_LIMITED,
        cwe: "CWE-208",
        wstg: "WSTG-CRYP-04",
        owasp_2025: owasp::A04,
        api_top10: None,
        description:
            "A secret — a token, a signature, an API key, a password hash — is compared with \
             the language's ordinary equality operator. Those comparisons return as soon as \
             two bytes differ, so how long the comparison takes reveals how many leading \
             bytes were correct. An attacker who can measure that difference across many \
             requests recovers the value one byte at a time, which turns an infeasible search \
             into a linear one.",
        remediation:
            "Use a constant-time comparison, which always examines every byte:\n\n\
             ```\n\
             crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));   // Node\n\
             hmac.compare_digest(a, b)                                 # Python\n\
             subtle.ConstantTimeCompare([]byte(a), []byte(b))          // Go\n\
             MessageDigest.isEqual(a, b)                               // Java\n\
             ```\n\n\
             Compare fixed-length values — hash both sides first if they can differ in \
             length, since the length itself leaks through any comparison.",
        references: &[
            "https://cwe.mitre.org/data/definitions/208.html",
        ],
        confidence: Confidence::Tentative,
        triage_note:
            "A comparison on a line naming a secret. Remote timing attacks over a network \
             need many samples and a low-jitter path; the risk is real but rating it needs \
             the deployment, not just the line.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)\b(?:token|signature|hmac|secret|apikey|api_key|password|digest|mac|hash)\w*\s*(?:===?|!==?|\.equals\s*\(|\.Equals\s*\(|==)\s*",
    mode: Mode::Always,
    unless: &["timingSafeEqual", "compare_digest", "ConstantTimeCompare", "MessageDigest.isEqual", "hash_equals", "secure_compare", "== null", "=== null", "== undefined", "!== undefined", "!= null", "=== ''", "== \"\""],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-BUFFER-UNSAFE",
        title: "Unbounded copy into a fixed-size buffer",
        cvss_vector: V_RCE,
        cwe: "CWE-120",
        wstg: "WSTG-INPV-13",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "A C string function that takes no destination size is used: `strcpy`, `strcat`, \
             `sprintf`, `gets`. None of them can stop at the end of the destination because \
             none of them is told where it is, so an input longer than the buffer writes past \
             it — over adjacent variables, saved registers and return addresses. This is the \
             original memory-safety defect and it remains directly exploitable.",
        remediation:
            "Use the bounded forms and check their results:\n\n\
             ```\n\
             snprintf(dst, sizeof dst, \"%s\", src);\n\
             strncat(dst, src, sizeof dst - strlen(dst) - 1);\n\
             // gets() has no safe form; use fgets(buf, sizeof buf, stdin)\n\
             ```\n\n\
             Better where it is possible: use a length-carrying string type, and build new \
             components in a memory-safe language.",
        references: &[
            "https://cwe.mitre.org/data/definitions/120.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "An unbounded copy function is called. Exploitability depends on whether the \
             source length is attacker-influenced — trace it before rating.",
    },
    languages: NATIVE_LANGS,
    pattern: r"(?:\bstrcpy\s*\(|\bstrcat\s*\(|\bsprintf\s*\(|\bgets\s*\(|\bvsprintf\s*\(|\bscanf\s*\(\s*\x22%s)",
    mode: Mode::Always,
    unless: &["strncpy", "strlcpy", "snprintf"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-HARDCODED-DB-CONNECTION",
        title: "Database connection string with an embedded password",
        cvss_vector: V_DISCLOSURE,
        cwe: "CWE-798",
        wstg: "WSTG-ATHN-07",
        owasp_2025: owasp::A07,
        api_top10: None,
        description:
            "A connection URI in the source carries a username and password. Anyone with \
             read access to the repository has the database credentials — which includes \
             everyone who has ever cloned it, every CI job, and anyone who obtains a copy of \
             the source later. Because it is committed, it is also in the history, so \
             deleting the line does not remove it.",
        remediation:
            "Read the connection string from the environment or a secret manager, and rotate \
             the credential that was committed — it must be treated as disclosed regardless \
             of who has seen it.\n\n\
             ```\n\
             const url = process.env.DATABASE_URL;\n\
             if (!url) throw new Error('DATABASE_URL is not set');\n\
             ```\n\n\
             Then purge it from history (`git filter-repo`) and, better still, move the \
             database to an identity-based authentication method — IAM auth, a workload \
             identity, a client certificate — so there is no long-lived password to leak next \
             time.",
        references: &[
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        ],
        confidence: Confidence::Certain,
        triage_note:
            "A connection URI with credentials in it. Placeholder passwords are common in \
             example configuration — check the value is real before escalating, but treat it \
             as real until shown otherwise.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|jdbc:[a-z]+)://[A-Za-z0-9_.-]+:[^@\s'\x22/]{4,}@",
    mode: Mode::Always,
    unless: &["password@", ":password", "user:pass@", "<password>", "${", "%s", "changeme", "example.com"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-DISABLED-CERT-PINNING",
        title: "Android WebView configured to run JavaScript from any source",
        cvss_vector: V_XSS,
        cwe: "CWE-749",
        wstg: "WSTG-CLNT-13",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "A WebView is configured with JavaScript enabled and either a JavaScript \
             interface bridge or file access to the application's own storage. Content \
             loaded into that WebView can then call into the application — and where file \
             access is allowed, read the app's private files and exfiltrate them — so any \
             page that ends up in the WebView, including one reached through a redirect, gets \
             the application's privileges.",
        remediation:
            "Leave JavaScript off unless the loaded content requires it. Where a bridge is \
             needed, annotate only the methods that must be exposed with \
             `@JavascriptInterface`, keep that surface as small as possible, and restrict the \
             WebView to an allow-list of URLs. Turn off `setAllowFileAccess`, \
             `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs`.",
        references: &[
            "https://developer.android.com/privacy-and-security/risks/insecure-webview",
            "https://cwe.mitre.org/data/definitions/749.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "WebView settings widen what loaded content can do. Rate on what the WebView \
             actually loads: bundled assets are a different matter from a remote URL.",
    },
    languages: JVM,
    pattern: r"(?i)(?:setJavaScriptEnabled\s*\(\s*true|addJavascriptInterface\s*\(|setAllowFileAccessFromFileURLs\s*\(\s*true|setAllowUniversalAccessFromFileURLs\s*\(\s*true|setAllowFileAccess\s*\(\s*true)",
    mode: Mode::Always,
    unless: &[],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-PERMISSIVE-FILE-MODE",
        title: "File or directory created world-writable",
        cvss_vector: V_LOCAL,
        cwe: "CWE-732",
        wstg: "WSTG-CONF-11",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "A file or directory is created with permissions that let any local user write \
             to it. Where the application later reads that path — a configuration file, a \
             script, an upload directory it serves — another user on the host can change what \
             it reads, which is a straightforward path to running code as the application's \
             user.",
        remediation:
            "Grant the narrowest permissions that work: `0600` for a file only the service \
             reads, `0700` for a directory only it uses, `0640`/`0750` where a group needs \
             read access. Set the mode at creation rather than with a `chmod` afterwards, so \
             there is no window where the file is world-writable.",
        references: &[
            "https://cwe.mitre.org/data/definitions/732.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A world-writable mode is set explicitly. On a single-tenant container the \
             practical exposure is small; on a shared host it is not.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)(?:chmod\s*\(\s*[^,]+,\s*0?o?7[0-7]7|chmod\s+(?:-R\s+)?7[0-7]7|os\.chmod\([^,]+,\s*0o?7[0-7]7|FileMode\s*\(\s*0?o?7[0-7]7|setReadable\s*\(\s*true\s*,\s*false|setWritable\s*\(\s*true\s*,\s*false|umask\s*\(\s*0\s*\))",
    mode: Mode::Always,
    unless: &[],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-MISSING-AUTH-CHECK",
        title: "State-changing route registered with no authorisation middleware",
        cvss_vector: V_INTEGRITY,
        cwe: "CWE-862",
        wstg: "WSTG-ATHZ-02",
        owasp_2025: owasp::A01,
        api_top10: Some("API5:2023-Broken Function Level Authorization"),
        description:
            "A route that changes state — POST, PUT, PATCH or DELETE — is registered on a \
             path that names an administrative or user-management operation, and no \
             authentication or authorisation middleware appears in its definition. Broken \
             access control is the most commonly exploited weakness class in web \
             applications, and it is almost never a subtle logic error: it is a route where \
             the check was not applied.",
        remediation:
            "Apply authorisation at the framework level so that it is on by default and \
             routes opt *out* rather than opting in — a default-deny router, a base \
             controller that requires a policy, or middleware mounted on the whole subtree. \
             Check ownership as well as role: confirming the caller is an administrator does \
             not confirm the record they are editing is theirs to edit.",
        references: &[
            "https://cwe.mitre.org/data/definitions/862.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
        ],
        confidence: Confidence::Tentative,
        triage_note:
            "This reads one route definition. A router-level or application-level guard would \
             protect it without appearing on this line, so confirm the request path end to \
             end before reporting it — the engine cannot see middleware mounted elsewhere.",
    },
    languages: WEB_LANGS,
    pattern: r#"(?i)(?:app|router|route)\.(?:post|put|patch|delete)\s*\(\s*["'][^"']*(?:admin|user|account|role|permission|setting|config|delete|remove|password|token)[^"']*["']\s*,\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>)"#,
    mode: Mode::Always,
    unless: &["requireAuth", "isAuthenticated", "authenticate", "authorize", "ensureLoggedIn", "passport", "guard", "verifyToken", "checkPermission"],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-EXCEPTION-SWALLOWED",
        title: "Exception caught and discarded",
        cvss_vector: V_HYGIENE,
        cwe: "CWE-390",
        wstg: "WSTG-ERRH-01",
        owasp_2025: owasp::A09,
        api_top10: None,
        description:
            "An exception is caught and the handler does nothing with it. Where the failing \
             operation was a security control — a signature check, a permission lookup, a \
             certificate validation — execution continues as though it had succeeded, which \
             converts a failure into a silent bypass. Even where it is not, the incident that \
             this code was the first symptom of will be invisible in the logs.",
        remediation:
            "Handle the failure or let it propagate. If the exception genuinely is expected \
             and safe to ignore, log it at debug level and say in a comment why it is \
             ignorable — an empty block cannot distinguish a deliberate decision from an \
             unfinished one.\n\n\
             For anything that decides access, fail closed: an error in a permission check \
             must deny, never allow.",
        references: &[
            "https://cwe.mitre.org/data/definitions/390.html",
        ],
        confidence: Confidence::Tentative,
        triage_note:
            "An empty catch block. Most are harmless; the ones that matter are those wrapping \
             a security decision, so read what is inside the `try` before judging.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)(?:catch\s*\([^)]*\)\s*\{\s*\}|except[^:]*:\s*pass\b|catch\s*\{\s*\}|rescue\s*(?:=>\s*\w+)?\s*(?:#[^\n]*)?\n\s*end)",
    mode: Mode::Always,
    unless: &[],
    scan_tests: false,
},

SastRule {
    spec: CodeSpec {
        id: "SENTINEL-STACK-TRACE-TO-CLIENT",
        title: "Exception detail returned in an HTTP response",
        cvss_vector: V_PARTIAL_INFO,
        cwe: "CWE-209",
        wstg: "WSTG-ERRH-01",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "An error handler puts the exception's message or stack trace into the response \
             body. Those strings routinely contain absolute filesystem paths, framework and \
             library versions, internal hostnames, SQL fragments and occasionally the values \
             that caused the failure. Individually minor, together they hand an attacker the \
             application's internal structure and the exact versions to look up.",
        remediation:
            "Return a generic message and a correlation identifier; log the detail where only \
             operators can read it.\n\n\
             ```\n\
             const ref = randomUUID();\n\
             logger.error({ ref, err });\n\
             res.status(500).json({ error: 'Internal error', reference: ref });\n\
             ```\n\n\
             The identifier keeps support able to find the real trace without publishing it.",
        references: &[
            "https://cwe.mitre.org/data/definitions/209.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "An exception field reaches a response. If this handler only runs when debug mode \
             is on, the finding is about the debug setting rather than the handler.",
    },
    languages: WEB_LANGS,
    pattern: r"(?i)(?:res\.(?:send|json|write)|response\.(?:write|json)|return\s+jsonify|echo|print|Response\.Write)\s*\(?[^;\n]*(?:err(?:or)?\.(?:stack|message)|e\.(?:stack|message)|traceback\.format_exc|getStackTrace|ex\.ToString|\$e->getMessage|err\.Error\(\))",
    mode: Mode::Always,
    unless: &["NODE_ENV", "isDev", "development"],
    scan_tests: false,
},

];

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use std::collections::HashSet;

    #[test]
    fn every_rule_pattern_compiles() {
        for rule in all() {
            Regex::new(rule.pattern)
                .unwrap_or_else(|e| panic!("{}: /{}/ does not compile: {e}", rule.spec.id, e));
        }
    }

    /// A duplicate id would make two different weaknesses indistinguishable in
    /// the exception register, so dismissing one would dismiss the other.
    #[test]
    fn rule_ids_are_unique() {
        let mut seen = HashSet::new();
        for rule in all() {
            assert!(seen.insert(rule.spec.id), "duplicate rule id {}", rule.spec.id);
        }
    }

    /// A vector that does not parse scores 0.0 and silently reports every
    /// finding from that rule as informational.
    #[test]
    fn every_vector_parses_and_scores_above_zero() {
        for rule in all() {
            let score = rule.spec.score();
            assert!(
                score > 0.0,
                "{} has an unparseable or zero-scoring vector: {}",
                rule.spec.id,
                rule.spec.cvss_vector
            );
            assert!(score <= 10.0, "{} scores above 10", rule.spec.id);
        }
    }

    #[test]
    fn vectors_score_as_documented() {
        for (vector, expected) in [
            (V_RCE, 9.3), (V_INJECTION, 9.3), (V_DISCLOSURE, 8.7), (V_INTEGRITY, 8.7),
            (V_DOS, 8.7), (V_XSS, 8.5), (V_CONDITIONAL, 8.2), (V_AUTHENTICATED, 7.1),
            (V_PARTIAL_INFO, 6.9), (V_PARTIAL_INTEGRITY, 6.9), (V_LIMITED, 6.3),
            (V_LIMITED_UI, 5.3), (V_LOCAL, 4.8), (V_HYGIENE, 2.3),
        ] {
            let parsed = sentinel_core::scoring::Cvss4Vector::parse(vector)
                .unwrap_or_else(|e| panic!("{vector} does not parse: {e}"));
            assert_eq!(
                (parsed.score() * 10.0).round() / 10.0,
                expected,
                "{vector} no longer scores {expected}"
            );
        }
    }

    /// Metadata is what makes a finding actionable rather than a grep hit. A
    /// rule missing any of it produces a report row nobody can triage.
    #[test]
    fn every_rule_carries_complete_taxonomy_and_guidance() {
        for rule in all() {
            let s = &rule.spec;
            assert!(s.id.starts_with("SENTINEL-"), "{} has an off-pattern id", s.id);
            assert!(s.cwe.starts_with("CWE-"), "{} has no CWE", s.id);
            assert!(s.wstg.starts_with("WSTG-"), "{} has no WSTG mapping", s.id);
            assert!(s.owasp_2025.contains(":2025-"), "{} has no OWASP mapping", s.id);
            assert!(!s.references.is_empty(), "{} cites nothing", s.id);
            assert!(!rule.languages.is_empty(), "{} applies to no language", s.id);
            assert!(
                s.description.len() > 200,
                "{} description is too thin to explain the weakness",
                s.id
            );
            assert!(
                s.remediation.len() > 120,
                "{} remediation does not tell a developer what to do",
                s.id
            );
            assert!(
                s.triage_note.len() > 40,
                "{} does not say what its match fails to prove",
                s.id
            );
        }
    }

    /// The triage note exists to say something the title does not.
    #[test]
    fn triage_notes_are_not_restatements_of_the_title() {
        for rule in all() {
            assert_ne!(
                rule.spec.triage_note.to_lowercase(),
                rule.spec.title.to_lowercase(),
                "{} restates its title",
                rule.spec.id
            );
        }
    }

    /// A `Tainted` rule that names no argument group hands the whole line to
    /// the classifier, which is allowed but should be a deliberate choice; a
    /// rule that names one must actually define it.
    #[test]
    fn declared_argument_groups_exist_in_their_patterns() {
        for rule in all() {
            if rule.pattern.contains("(?P<arg>") {
                let re = Regex::new(rule.pattern).unwrap();
                assert!(
                    re.capture_names().flatten().any(|n| n == "arg"),
                    "{} declares an arg group the regex does not expose",
                    rule.spec.id
                );
            }
        }
    }

    /// A category string the coverage matrix does not recognise puts the
    /// finding in a bucket that is never rendered, so it disappears from the
    /// OWASP section of the report while still appearing in the counts. The
    /// 2021 and 2025 lists number Injection differently, which is exactly how
    /// this happens by accident.
    #[test]
    fn every_rule_maps_to_a_real_owasp_2025_category() {
        for rule in all() {
            assert!(
                owasp::is_known(rule.spec.owasp_2025),
                "{} maps to {:?}, which is not an OWASP Top 10:2025 category",
                rule.spec.id,
                rule.spec.owasp_2025
            );
        }
    }

    #[test]
    fn the_catalog_covers_the_owasp_breadth_a_code_engine_can_reach() {
        let categories: HashSet<&str> = all().iter().map(|r| r.spec.owasp_2025).collect();
        for expected in [
            owasp::A01, owasp::A02, owasp::A04, owasp::A05, owasp::A07, owasp::A08, owasp::A09,
        ] {
            assert!(
                categories.contains(expected),
                "no rule maps to {expected}; the coverage matrix will show it unanswered"
            );
        }
    }

    #[test]
    fn injection_rules_require_taint_rather_than_firing_on_every_call() {
        for id in ["SENTINEL-SQLI", "SENTINEL-CMDI", "SENTINEL-PATH-TRAVERSAL", "SENTINEL-SSRF"] {
            let rule = all().iter().find(|r| r.spec.id == id).expect("rule exists");
            assert_eq!(
                rule.mode,
                Mode::Tainted,
                "{id} must not fire on a call with a constant argument"
            );
        }
    }

    /// A disabled certificate check is not made safe by its argument, so these
    /// must not be gated on dataflow.
    #[test]
    fn configuration_weaknesses_fire_regardless_of_dataflow() {
        for id in [
            "SENTINEL-TLS-VERIFY-DISABLED",
            "SENTINEL-JWT-UNVERIFIED",
            "SENTINEL-ELECTRON-NODE-INTEGRATION",
        ] {
            let rule = all().iter().find(|r| r.spec.id == id).expect("rule exists");
            assert_eq!(rule.mode, Mode::Always, "{id} does not depend on its argument");
        }
    }
}
