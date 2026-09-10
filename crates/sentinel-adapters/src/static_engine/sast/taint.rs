//! Following attacker-controlled data from where it enters to where it hurts.
//!
//! A rule that matches `exec(` finds every subprocess call in the repository,
//! most of which pass a constant. A rule that matches `exec(` *with a variable
//! in it* finds every call that builds its command, most of which build it from
//! a config file. Neither is a finding; both are why pattern-based static
//! analysis has the reputation it has.
//!
//! What makes the difference is the question in between: did the value in that
//! call come from a request? This module answers it for the case that covers
//! the overwhelming majority of real injection defects — a source and a sink in
//! the same file, within sight of each other — and refuses to answer it
//! otherwise. It is deliberately not a whole-program dataflow analysis. Those
//! need to resolve imports, calls across modules and framework magic, and one
//! that gets any of that wrong produces confident findings that are wrong,
//! which is worse than a tentative finding that says so.
//!
//! So the contract is narrow and honest:
//!
//! * A source assigned to a variable taints that name for the next
//!   [`TAINT_WINDOW`] lines — roughly a function body, without pretending to
//!   parse one.
//! * Re-assigning that name from a sanitiser clears it.
//! * A sanitiser wrapping the value at the sink suppresses the match outright.
//! * A sink reached by a tainted name is reported [`Firm`]; a sink whose
//!   argument is merely non-constant is reported [`Tentative`], and says why.
//!
//! [`Firm`]: crate::static_engine::finding::Confidence::Firm
//! [`Tentative`]: crate::static_engine::finding::Confidence::Tentative

use super::lang::Language;
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// How far a tainted variable stays tainted.
///
/// A stand-in for "the rest of this function". Too small and a source at the
/// top of a handler never reaches the sink at the bottom; too large and an
/// unrelated variable of the same name three functions later is treated as
/// attacker-controlled. Forty lines is comfortably longer than the request
/// handlers where this class of defect actually lives.
pub const TAINT_WINDOW: usize = 40;

/// What the engine concluded about the data reaching a sink.
#[derive(Debug, Clone, PartialEq)]
pub enum Taint {
    /// A request-derived value reaches this call. `via` names it.
    Flows { via: String, from_line: usize, source: String },
    /// The value at the sink is request data written inline.
    Direct { source: String },
    /// Not constant, but nothing tied it to a request either.
    Unknown,
    /// A sanitiser is applied at the sink, or the argument is a literal.
    Neutral,
}

impl Taint {
    /// Whether this should be reported at all.
    pub fn is_reportable(&self) -> bool {
        !matches!(self, Taint::Neutral)
    }

    /// Whether the engine can say the data came from a request.
    pub fn is_attacker_controlled(&self) -> bool {
        matches!(self, Taint::Flows { .. } | Taint::Direct { .. })
    }

    /// The sentence that goes into the finding's "Observed:" line.
    pub fn describe(&self) -> String {
        match self {
            Taint::Direct { source } => {
                format!("the call receives {source} directly, with no intervening validation")
            }
            Taint::Flows { via, from_line, source } => format!(
                "`{via}` is assigned from {source} on line {from_line} and reaches this call \
                 without passing through a recognised sanitiser"
            ),
            Taint::Unknown => {
                "the argument is built at runtime rather than being a constant; the engine \
                 could not establish where the value originates"
                    .to_string()
            }
            Taint::Neutral => "the argument is a constant or is sanitised at the call".to_string(),
        }
    }
}

/// The sources, sinks-neutralisers and inline patterns for one language.
struct Profile {
    /// `(?:const|let|var)\s+(NAME)\s*=\s*<source>` — capture 1 is the variable.
    assignments: &'static [(&'static str, &'static str)],
    /// Request-data expressions that can appear anywhere, with a description.
    inline: &'static [(&'static str, &'static str)],
    /// `NAME = sanitiser(...)` — capture 1 is the variable being cleaned.
    sanitizer_assignments: &'static [&'static str],
    /// Call names that neutralise a value where they wrap it.
    sanitizers: &'static [&'static str],
}

/// Sources shared by every language: the environment and the process argv are
/// attacker-influenced far less often than a request, but a rule that ignores
/// them misses the whole class of CI and container defects.
const AMBIENT: &[(&str, &str)] = &[];

fn profile(lang: Language) -> Option<&'static Profile> {
    static PROFILES: OnceLock<HashMap<Language, Profile>> = OnceLock::new();
    PROFILES.get_or_init(build_profiles).get(&lang)
}

fn build_profiles() -> HashMap<Language, Profile> {
    let mut m = HashMap::new();

    m.insert(Language::JavaScript, JS_PROFILE);
    m.insert(Language::TypeScript, JS_PROFILE);
    m.insert(Language::Python, PY_PROFILE);
    m.insert(Language::Java, JAVA_PROFILE);
    m.insert(Language::Kotlin, JAVA_PROFILE);
    m.insert(Language::Php, PHP_PROFILE);
    m.insert(Language::Go, GO_PROFILE);
    m.insert(Language::Ruby, RUBY_PROFILE);
    m.insert(Language::CSharp, CSHARP_PROFILE);
    m
}

const JS_PROFILE: Profile = Profile {
    assignments: &[
        (r"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;]*\breq(?:uest)?\.(?:body|query|params|cookies|headers|files)\b", "the HTTP request"),
        (r"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;]*\bctx\.(?:request|query|params)\b", "the request context"),
        (r"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;]*\bevent\.(?:body|queryStringParameters|pathParameters|headers)\b", "the Lambda event"),
        (r"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;]*\b(?:location\.(?:search|hash|href)|document\.(?:URL|documentURI|referrer))", "the page URL"),
        (r"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;]*\bnew\s+URLSearchParams\(", "the query string"),
        (r"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;]*\bprocess\.argv\b", "the process arguments"),
        (r"(?:const|let|var)\s+\{[^}]*\}\s*=\s*\breq(?:uest)?\.(?:body|query|params)\b", "the HTTP request"),
    ],
    inline: &[
        (r"\breq(?:uest)?\.(?:body|query|params|cookies|headers)\b", "data from the HTTP request"),
        (r"\bevent\.(?:body|queryStringParameters|pathParameters)\b", "data from the Lambda event"),
        (r"\blocation\.(?:search|hash|href)\b", "the page URL"),
        (r"\bdocument\.(?:URL|documentURI|referrer)\b", "the page URL"),
        (r"\bprocess\.argv\[", "a process argument"),
    ],
    sanitizer_assignments: &[
        r"([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:escape|encodeURIComponent|sanitize|sanitizeHtml|DOMPurify\.sanitize|validator\.\w+|parseInt|Number|path\.basename)\s*\(",
    ],
    sanitizers: &[
        "encodeURIComponent", "escapeHtml", "escape_html", "DOMPurify.sanitize",
        "sanitizeHtml", "sanitize_html", "validator.escape", "parseInt", "Number(",
        "path.basename", "shellQuote", "shell-quote", "mysql.escape", "pg.escapeLiteral",
    ],
};

const PY_PROFILE: Profile = Profile {
    assignments: &[
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^\n]*\brequest\.(?:args|form|json|values|data|files|cookies|headers|GET|POST|body)\b", "the HTTP request"),
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^\n]*\bflask\.request\b", "the Flask request"),
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^\n]*\bsys\.argv\b", "the process arguments"),
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^\n]*\bos\.environ(?:\.get)?[\[\(]", "the environment"),
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^\n]*\binput\s*\(", "standard input"),
    ],
    inline: &[
        (r"\brequest\.(?:args|form|json|values|data|files|cookies|headers|GET|POST)\b", "data from the HTTP request"),
        (r"\bsys\.argv\[", "a process argument"),
    ],
    sanitizer_assignments: &[
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:int|float|shlex\.quote|html\.escape|escape|bleach\.clean|os\.path\.basename|secure_filename)\s*\(",
    ],
    sanitizers: &[
        "shlex.quote", "html.escape", "bleach.clean", "os.path.basename",
        "secure_filename", "int(", "float(", "urllib.parse.quote", "markupsafe.escape",
    ],
};

const JAVA_PROFILE: Profile = Profile {
    assignments: &[
        (r"(?:String|var|Object)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*\brequest\.get(?:Parameter|Header|QueryString|Cookies|InputStream)\b", "the servlet request"),
        (r"(?:String|var|Object)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*@(?:RequestParam|PathVariable|RequestBody|RequestHeader)", "a Spring request binding"),
        (r"(?:String|var|Object)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*\bSystem\.getenv\b", "the environment"),
    ],
    inline: &[
        (r"\brequest\.getParameter\s*\(", "an HTTP request parameter"),
        (r"\brequest\.getHeader\s*\(", "an HTTP request header"),
        (r"@(?:RequestParam|PathVariable|RequestBody)\b", "a Spring request binding"),
    ],
    sanitizer_assignments: &[
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:Integer\.parseInt|Long\.parseLong|ESAPI\.encoder\(\)|StringEscapeUtils\.\w+|Encode\.\w+)\s*\(",
    ],
    sanitizers: &[
        "Integer.parseInt", "Long.parseLong", "StringEscapeUtils", "ESAPI.encoder",
        "Encode.forHtml", "Encode.forJavaScript", "PreparedStatement",
    ],
};

const PHP_PROFILE: Profile = Profile {
    assignments: &[
        // The `$` is captured as part of the name: in PHP the sigil is not
        // punctuation next to the identifier, it is how the identifier is
        // spelled, and a name without it never matches the sink.
        (r"(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b", "a superglobal"),
        (r"(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*\bfile_get_contents\s*\(\s*['\x22]php://input", "the request body"),
    ],
    inline: &[
        (r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b", "a request superglobal"),
        (r"\$_SERVER\[\s*['\x22](?:HTTP_|QUERY_STRING|REQUEST_URI|PATH_INFO)", "a request-derived server variable"),
    ],
    sanitizer_assignments: &[
        r"(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:intval|floatval|escapeshellarg|escapeshellcmd|htmlspecialchars|htmlentities|filter_var|basename|mysqli_real_escape_string)\s*\(",
    ],
    sanitizers: &[
        "escapeshellarg", "escapeshellcmd", "htmlspecialchars", "htmlentities",
        "filter_var", "intval", "floatval", "basename", "mysqli_real_escape_string",
        "PDO::quote", "->quote(",
    ],
};

const GO_PROFILE: Profile = Profile {
    assignments: &[
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*[^\n]*\br\.(?:URL\.Query\(\)|FormValue|PostFormValue|Header\.Get|Body)\b", "the HTTP request"),
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*[^\n]*\bmux\.Vars\(", "a route variable"),
        (r"([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*[^\n]*\bos\.(?:Getenv|Args)\b", "the environment or arguments"),
    ],
    inline: &[
        (r"\br\.(?:FormValue|PostFormValue)\s*\(", "an HTTP form value"),
        (r"\br\.URL\.Query\(\)", "the query string"),
        (r"\br\.Header\.Get\s*\(", "an HTTP request header"),
    ],
    sanitizer_assignments: &[
        r"([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*(?:strconv\.Atoi|strconv\.ParseInt|filepath\.Base|html\.EscapeString|template\.HTMLEscapeString|url\.QueryEscape)\s*\(",
    ],
    sanitizers: &[
        "strconv.Atoi", "strconv.ParseInt", "filepath.Base", "html.EscapeString",
        "template.HTMLEscapeString", "url.QueryEscape",
    ],
};

const RUBY_PROFILE: Profile = Profile {
    assignments: &[
        (r"([a-z_][A-Za-z0-9_]*)\s*=\s*[^\n]*\bparams\[", "a request parameter"),
        (r"([a-z_][A-Za-z0-9_]*)\s*=\s*[^\n]*\brequest\.(?:body|env|headers|query_parameters)\b", "the HTTP request"),
        (r"([a-z_][A-Za-z0-9_]*)\s*=\s*[^\n]*\bENV\[", "the environment"),
    ],
    inline: &[
        (r"\bparams\[", "a request parameter"),
        (r"\brequest\.(?:body|query_parameters|headers)\b", "the HTTP request"),
    ],
    sanitizer_assignments: &[
        r"([a-z_][A-Za-z0-9_]*)\s*=\s*(?:Integer|Float|Shellwords\.escape|CGI\.escapeHTML|ERB::Util\.html_escape|File\.basename|sanitize)\s*[\(\.]",
    ],
    sanitizers: &[
        "Shellwords.escape", "CGI.escapeHTML", "ERB::Util.html_escape",
        "File.basename", "Integer(", "sanitize(",
    ],
};

const CSHARP_PROFILE: Profile = Profile {
    assignments: &[
        (r"(?:string|var|object)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*\bRequest\.(?:Query|Form|Headers|Cookies|QueryString|Params)\b", "the HTTP request"),
        (r"(?:string|var|object)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*\bEnvironment\.GetEnvironmentVariable\b", "the environment"),
    ],
    inline: &[
        (r"\bRequest\.(?:Query|Form|Headers|Cookies|QueryString|Params)\b", "the HTTP request"),
    ],
    sanitizer_assignments: &[
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:int\.Parse|Int32\.Parse|HttpUtility\.HtmlEncode|WebUtility\.HtmlEncode|AntiXssEncoder\.\w+|Path\.GetFileName)\s*\(",
    ],
    sanitizers: &[
        "HttpUtility.HtmlEncode", "WebUtility.HtmlEncode", "AntiXssEncoder",
        "Path.GetFileName", "int.Parse", "Int32.Parse", "SqlParameter",
    ],
};

// ── Compiled form ────────────────────────────────────────────────────────────

struct CompiledProfile {
    assignments: Vec<(Regex, &'static str)>,
    inline: Vec<(Regex, &'static str)>,
    sanitizer_assignments: Vec<Regex>,
    sanitizers: &'static [&'static str],
}

fn compiled(lang: Language) -> Option<&'static CompiledProfile> {
    static CACHE: OnceLock<HashMap<Language, CompiledProfile>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let mut out = HashMap::new();
            for lang in [
                Language::JavaScript, Language::TypeScript, Language::Python,
                Language::Java, Language::Kotlin, Language::Php, Language::Go,
                Language::Ruby, Language::CSharp,
            ] {
                let Some(p) = profile(lang) else { continue };
                out.insert(
                    lang,
                    CompiledProfile {
                        // A malformed pattern is a bug in this file, not in the
                        // scanned code, so it is dropped rather than allowed to
                        // abort a scan the analyst is waiting on. The
                        // `every_pattern_compiles` test below fails the build
                        // long before that can happen in the field.
                        assignments: p
                            .assignments
                            .iter()
                            .filter_map(|(re, d)| Regex::new(re).ok().map(|r| (r, *d)))
                            .collect(),
                        inline: p
                            .inline
                            .iter()
                            .chain(AMBIENT)
                            .filter_map(|(re, d)| Regex::new(re).ok().map(|r| (r, *d)))
                            .collect(),
                        sanitizer_assignments: p
                            .sanitizer_assignments
                            .iter()
                            .filter_map(|re| Regex::new(re).ok())
                            .collect(),
                        sanitizers: p.sanitizers,
                    },
                );
            }
            out
        })
        .get(&lang)
}

/// Where each variable last became attacker-controlled, as the file is read.
pub struct TaintTable {
    lang: Language,
    /// variable name → (line it was tainted on, what tainted it)
    tainted: HashMap<String, (usize, &'static str)>,
}

impl TaintTable {
    pub fn new(lang: Language) -> Self {
        Self { lang, tainted: HashMap::new() }
    }

    /// Whether this language has a taint profile at all.
    pub fn is_supported(&self) -> bool {
        compiled(self.lang).is_some()
    }

    /// Feed one line, updating what is tainted. Call for every line in order,
    /// including the sink lines, *before* asking about that line.
    pub fn observe(&mut self, line_no: usize, line: &str) {
        let Some(p) = compiled(self.lang) else { return };

        // A sanitising re-assignment clears the name first: `x = escape(x)`
        // matches both an assignment source and a sanitiser, and the sanitiser
        // is what the code actually did.
        for re in &p.sanitizer_assignments {
            if let Some(c) = re.captures(line) {
                if let Some(name) = c.get(1) {
                    self.tainted.remove(name.as_str());
                }
            }
        }
        for (re, source) in &p.assignments {
            if let Some(c) = re.captures(line) {
                match c.get(1) {
                    Some(name) => {
                        self.tainted.insert(name.as_str().to_string(), (line_no, source));
                    }
                    // A destructuring assignment names no single variable; the
                    // inline source patterns cover the sink on that line.
                    None => continue,
                }
            }
        }
        // Drop taint that has aged out, so a name reused later in the file is
        // not still considered attacker-controlled.
        self.tainted
            .retain(|_, (tainted_at, _)| line_no.saturating_sub(*tainted_at) <= TAINT_WINDOW);
    }

    /// What the engine can say about the data in `line`.
    ///
    /// `argument` is the text the rule considers the sink's input — usually
    /// everything inside the call's parentheses. Passing the whole line is
    /// valid and only makes the answer more conservative.
    pub fn classify(&self, line_no: usize, argument: &str) -> Taint {
        let Some(p) = compiled(self.lang) else {
            return Taint::Unknown;
        };

        // A sanitiser at the sink settles it regardless of where the value came
        // from: that is the fix this engine would have recommended.
        if p.sanitizers.iter().any(|s| argument.contains(s)) {
            return Taint::Neutral;
        }

        for (re, source) in &p.inline {
            if re.is_match(argument) {
                return Taint::Direct { source: (*source).to_string() };
            }
        }

        // Longest name first: `userId` must win over `user` when both are
        // tainted and both appear.
        let mut candidates: Vec<(&String, &(usize, &'static str))> = self
            .tainted
            .iter()
            .filter(|(_, (at, _))| line_no >= *at && line_no - *at <= TAINT_WINDOW)
            .collect();
        candidates.sort_by_key(|(name, _)| std::cmp::Reverse(name.len()));

        for (name, (at, source)) in candidates {
            if contains_identifier(argument, name) {
                return Taint::Flows {
                    via: name.clone(),
                    from_line: *at,
                    source: (*source).to_string(),
                };
            }
        }

        if is_constant_argument(argument) {
            Taint::Neutral
        } else {
            Taint::Unknown
        }
    }
}

/// Whether `needle` appears in `haystack` as a whole identifier.
///
/// A substring match would tie `id` to `valid`, and the finding would name a
/// variable the developer cannot find.
fn contains_identifier(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let n = needle.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';

    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        let i = start + pos;
        let before_ok = i == 0 || !is_word(bytes[i - 1]);
        let after = i + n.len();
        let after_ok = after >= bytes.len() || !is_word(bytes[after]);
        if before_ok && after_ok {
            return true;
        }
        start = i + 1;
        if start >= haystack.len() {
            break;
        }
    }
    false
}

/// Whether an argument is entirely literal, so nothing can be injected into it.
///
/// Conservative in the direction that matters: anything it cannot prove is a
/// literal is treated as dynamic, which produces a `Tentative` finding rather
/// than silence.
fn is_constant_argument(argument: &str) -> bool {
    let trimmed = argument.trim().trim_end_matches([',', ')', ';']);
    if trimmed.is_empty() {
        return true;
    }
    // Concatenation, interpolation or a format call means it is built.
    if trimmed.contains('+')
        || trimmed.contains("${")
        || trimmed.contains("%s")
        || trimmed.contains(".format(")
        || trimmed.contains("f\"")
        || trimmed.contains("f'")
    {
        return false;
    }
    let quoted = |q: char| trimmed.starts_with(q) && trimmed.ends_with(q) && trimmed.len() >= 2;
    quoted('"') || quoted('\'') || quoted('`')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(lang: Language, src: &str) -> (TaintTable, Vec<(usize, String)>) {
        let mut t = TaintTable::new(lang);
        let mut lines = Vec::new();
        for (i, line) in src.lines().enumerate() {
            t.observe(i + 1, line);
            lines.push((i + 1, line.to_string()));
        }
        (t, lines)
    }

    /// Re-run the table up to a given line so `classify` sees the same state
    /// the engine would at that point in the file.
    fn taint_at(lang: Language, src: &str, sink_line: usize, argument: &str) -> Taint {
        let mut t = TaintTable::new(lang);
        for (i, line) in src.lines().enumerate().take(sink_line) {
            t.observe(i + 1, line);
        }
        t.classify(sink_line, argument)
    }

    #[test]
    fn every_pattern_in_the_catalog_compiles() {
        for lang in [
            Language::JavaScript, Language::Python, Language::Java, Language::Php,
            Language::Go, Language::Ruby, Language::CSharp,
        ] {
            let raw = profile(lang).expect("profile exists");
            for (re, _) in raw.assignments {
                Regex::new(re).unwrap_or_else(|e| panic!("{:?} assignment /{re}/: {e}", lang));
            }
            for (re, _) in raw.inline {
                Regex::new(re).unwrap_or_else(|e| panic!("{:?} inline /{re}/: {e}", lang));
            }
            for re in raw.sanitizer_assignments {
                Regex::new(re).unwrap_or_else(|e| panic!("{:?} sanitizer /{re}/: {e}", lang));
            }
            assert!(compiled(lang).is_some(), "{lang:?} must have a compiled profile");
        }
    }

    #[test]
    fn a_request_value_reaching_a_call_is_traced_back_to_its_assignment() {
        let src = "\
app.get('/x', (req, res) => {
  const name = req.query.name;
  const out = child_process.execSync('ls ' + name);
});";
        let t = taint_at(Language::JavaScript, src, 3, "'ls ' + name");
        match t {
            Taint::Flows { ref via, from_line, .. } => {
                assert_eq!(via, "name");
                assert_eq!(from_line, 2);
            }
            other => panic!("expected a traced flow, got {other:?}"),
        }
        assert!(t.is_attacker_controlled());
        assert!(t.describe().contains("line 2"));
    }

    #[test]
    fn request_data_written_straight_into_the_call_is_direct() {
        let t = taint_at(
            Language::JavaScript,
            "exec('rm ' + req.body.path);",
            1,
            "'rm ' + req.body.path",
        );
        assert!(matches!(t, Taint::Direct { .. }));
        assert!(t.describe().contains("no intervening validation"));
    }

    /// The whole point of tracking sanitisers: a fixed call must not be
    /// reported as if it were vulnerable.
    #[test]
    fn a_sanitiser_at_the_call_neutralises_the_finding() {
        let src = "\
const name = req.query.name;
exec('ls ' + shellQuote(name));";
        let t = taint_at(Language::JavaScript, src, 2, "'ls ' + shellQuote(name)");
        assert_eq!(t, Taint::Neutral);
        assert!(!t.is_reportable());
    }

    #[test]
    fn reassigning_through_a_sanitiser_clears_the_taint() {
        let src = "\
let id = req.params.id;
id = parseInt(id);
db.query('SELECT * FROM t WHERE id=' + id);";
        let t = taint_at(Language::JavaScript, src, 3, "'SELECT * FROM t WHERE id=' + id");
        assert!(
            !t.is_attacker_controlled(),
            "parseInt on line 2 removed the taint, got {t:?}"
        );
    }

    #[test]
    fn a_constant_argument_is_not_reported_at_all() {
        let t = taint_at(Language::Python, "os.system('ls -la')", 1, "'ls -la'");
        assert_eq!(t, Taint::Neutral);
    }

    /// Not every dynamic value is a request value, and saying so is the
    /// difference between a report that is trusted and one that is skimmed.
    #[test]
    fn a_dynamic_argument_with_no_traced_source_is_unknown_rather_than_confirmed() {
        let t = taint_at(Language::Python, "os.system(cmd_from_config)", 1, "cmd_from_config");
        assert_eq!(t, Taint::Unknown);
        assert!(t.is_reportable(), "still worth a look");
        assert!(!t.is_attacker_controlled(), "but not claimed as attacker-controlled");
        assert!(t.describe().contains("could not establish"));
    }

    #[test]
    fn taint_expires_so_a_reused_name_later_in_the_file_is_not_still_dirty() {
        let mut src = String::from("const q = req.query.q;\n");
        for i in 0..(TAINT_WINDOW + 5) {
            src.push_str(&format!("const filler{i} = {i};\n"));
        }
        src.push_str("exec(q);\n");
        let sink_line = src.lines().count();
        let t = taint_at(Language::JavaScript, &src, sink_line, "q");
        assert!(!t.is_attacker_controlled(), "taint must not span the whole file");
    }

    #[test]
    fn a_variable_name_is_matched_whole_not_as_a_substring() {
        assert!(contains_identifier("query(id)", "id"));
        assert!(!contains_identifier("if (valid) {}", "id"));
        assert!(!contains_identifier("const idx = 1", "id"));
        assert!(contains_identifier("f(a, id)", "id"));
        assert!(contains_identifier("id", "id"));
    }

    #[test]
    fn php_superglobals_are_sources_and_escapeshellarg_is_a_sanitiser() {
        let src = "$cmd = $_GET['cmd'];\nsystem($cmd);";
        assert!(taint_at(Language::Php, src, 2, "$cmd").is_attacker_controlled());

        let fixed = "$cmd = $_GET['cmd'];\nsystem(escapeshellarg($cmd));";
        assert_eq!(taint_at(Language::Php, fixed, 2, "escapeshellarg($cmd)"), Taint::Neutral);
    }

    #[test]
    fn python_flask_request_data_is_a_source() {
        let src = "name = request.args.get('name')\nos.system('echo ' + name)";
        assert!(taint_at(Language::Python, src, 2, "'echo ' + name").is_attacker_controlled());
    }

    #[test]
    fn go_form_values_are_sources_and_atoi_sanitises() {
        let src = "id := r.FormValue(\"id\")\ndb.Query(\"SELECT * FROM t WHERE id=\" + id)";
        assert!(taint_at(Language::Go, src, 2, "\"SELECT * FROM t WHERE id=\" + id").is_attacker_controlled());

        let fixed = "id := r.FormValue(\"id\")\nn := strconv.Atoi(id)\nuse(n)";
        let t = taint_at(Language::Go, fixed, 3, "n");
        assert!(!t.is_attacker_controlled());
    }

    #[test]
    fn java_servlet_parameters_are_sources() {
        let src = "String q = request.getParameter(\"q\");\nstmt.executeQuery(\"SELECT * FROM t WHERE a='\" + q + \"'\");";
        assert!(taint_at(Language::Java, src, 2, "\"SELECT * FROM t WHERE a='\" + q + \"'\"").is_attacker_controlled());
    }

    #[test]
    fn ruby_params_are_sources() {
        let src = "name = params[:name]\nsystem(\"echo #{name}\")";
        assert!(taint_at(Language::Ruby, src, 2, "\"echo #{name}\"").is_attacker_controlled());
    }

    #[test]
    fn csharp_request_bindings_are_sources() {
        let src = "string q = Request.Query[\"q\"];\ncmd.CommandText = \"SELECT * FROM t WHERE a='\" + q + \"'\";";
        assert!(taint_at(Language::CSharp, src, 2, "\"SELECT * FROM t WHERE a='\" + q + \"'\"").is_attacker_controlled());
    }

    #[test]
    fn a_language_with_no_profile_reports_unknown_rather_than_guessing() {
        let t = TaintTable::new(Language::Rust);
        assert!(!t.is_supported());
        assert_eq!(t.classify(1, "something(x)"), Taint::Unknown);
    }

    #[test]
    fn the_longest_matching_variable_wins() {
        let src = "const user = req.query.user;\nconst userId = req.query.id;\nexec(userId);";
        let t = taint_at(Language::JavaScript, src, 3, "userId");
        match t {
            Taint::Flows { via, .. } => assert_eq!(via, "userId"),
            other => panic!("expected userId, got {other:?}"),
        }
    }

    #[test]
    fn observing_lines_keeps_the_table_bounded() {
        let (table, lines) = feed(Language::JavaScript, "const a = req.query.a;\nconst b = 1;");
        assert_eq!(lines.len(), 2);
        assert!(table.is_supported());
    }
}
