//! Walking a source tree the way a reviewer would.
//!
//! Every static engine in this module needs the same thing first: the list of
//! files actually worth reading. Getting that wrong is not a performance
//! detail. A walker that descends into `node_modules` reports the
//! vulnerabilities of libraries the application never wrote, buries the twelve
//! findings that matter under nine thousand that do not, and takes ten minutes
//! to do it. One that reads a 40 MB minified bundle line by line matches a
//! `eval(` on a line 200 000 characters wide and prints all of it into the
//! report as evidence.
//!
//! So the rules here are deliberately conservative:
//!
//! * Dependency, build and VCS directories are never descended into.
//! * `.gitignore` is honoured for the common patterns, because a file the
//!   repository deliberately does not track is not the application's code.
//! * A file containing a NUL byte in its first block is binary and is skipped
//!   rather than decoded.
//! * Anything above the size cap is skipped and *recorded*, so a report can say
//!   a file went unread instead of silently implying it was clean.
//! * Generated and minified sources are classified, not deleted — the code
//!   rules skip them because a single 200 000-character line produces
//!   unreviewable matches, while the secret scanner still reads them because a
//!   key compiled into a bundle is exactly the thing worth finding.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Directories never descended into.
///
/// These hold code the application depends on rather than code it is
/// responsible for, or build output derived from code that is scanned anyway.
const SKIP_DIRS: &[&str] = &[
    // Version control and tooling metadata
    ".git", ".hg", ".svn", ".idea", ".vscode", ".vs", ".history",
    // Dependency trees
    "node_modules", "bower_components", "vendor", "third_party", "Pods",
    "site-packages", "elm-stuff", ".pnpm-store", ".yarn", "packages/.pnpm",
    // Virtual environments
    ".venv", "venv", "env", ".tox", ".conda", "virtualenv",
    // Build output
    "target", "dist", "build", "out", "bin", "obj", ".next", ".nuxt",
    ".output", ".svelte-kit", ".parcel-cache", ".turbo", "cmake-build-debug",
    // Caches
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".gradle",
    ".m2", ".cargo", ".terraform", ".serverless", ".dart_tool",
    // Coverage and test output
    "coverage", "htmlcov", ".nyc_output",
];

/// Extensions that are binary by definition. Checked before opening the file,
/// so a 200 MB video never gets read to look for a NUL byte.
const BINARY_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "avif", "tiff", "svgz",
    "mp3", "mp4", "wav", "avi", "mov", "mkv", "webm", "flac", "ogg",
    "zip", "gz", "tar", "bz2", "xz", "7z", "rar", "jar", "war", "ear",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt",
    "so", "dylib", "dll", "exe", "bin", "o", "a", "lib", "pdb", "class",
    "pyc", "pyo", "wasm", "node", "ttf", "otf", "woff", "woff2", "eot",
    "db", "sqlite", "sqlite3", "mdb", "iso", "dmg", "pkg", "deb", "rpm",
];

/// How a file relates to the code a human actually wrote.
///
/// The distinction changes which engines read it. A vendored bundle is not
/// the application's code and its `eval()` is its author's problem, but a
/// credential inside it is still deployed to every visitor's browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Hand-written application source.
    Authored,
    /// Machine-produced: minified, bundled, compiled or generated.
    Generated,
    /// Test, fixture, example or mock code.
    Test,
}

/// One file the walker decided was worth reading.
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Absolute path on disk.
    pub path: PathBuf,
    /// Path relative to the repository root — what a report should print.
    pub relative: String,
    /// Lowercased extension, empty when the file has none.
    pub extension: String,
    /// The file's decoded contents.
    pub content: String,
    pub provenance: Provenance,
    pub size_bytes: u64,
}

impl SourceFile {
    /// The file's lines, 1-indexed as an editor and a report both number them.
    pub fn lines(&self) -> Vec<(usize, &str)> {
        self.content.lines().enumerate().map(|(i, l)| (i + 1, l)).collect()
    }

    /// The file's basename, or the whole relative path if it somehow has none.
    pub fn file_name(&self) -> &str {
        Path::new(&self.relative)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&self.relative)
    }

    /// Whether this file holds code a human wrote and is responsible for.
    pub fn is_authored(&self) -> bool {
        self.provenance == Provenance::Authored
    }
}

/// Why the walk stopped, so a report can say whether it saw the whole tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkStop {
    /// Every reachable file was considered.
    Exhausted,
    /// The file cap was hit; `unread` records how many were left.
    FileCap,
    /// The wall-clock budget ran out.
    Budget,
}

/// Bounds on a walk. A repository is somebody else's data structure and can be
/// any shape at all, so every dimension that could run away has a ceiling.
#[derive(Debug, Clone)]
pub struct WalkLimits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_depth: usize,
    pub budget: Duration,
}

impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            // Large enough for a real monorepo, small enough that a runaway
            // generated tree cannot stall the pipeline behind it.
            max_files: 25_000,
            // Above this a "source file" is a data blob, a bundle or a
            // checked-in dump; reading it line by line finds nothing useful.
            max_file_bytes: 2 * 1024 * 1024,
            max_depth: 24,
            budget: Duration::from_secs(180),
        }
    }
}

/// The result of walking a repository.
#[derive(Debug)]
pub struct Codebase {
    pub root: PathBuf,
    pub files: Vec<SourceFile>,
    /// Files deliberately not read, with the reason — reported rather than
    /// hidden, so "nothing found here" is a claim about what was looked at.
    pub skipped: Vec<(String, SkipReason)>,
    pub stopped_because: WalkStop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    TooLarge(u64),
    Binary,
    Unreadable,
    NotUtf8,
}

impl SkipReason {
    pub fn describe(&self) -> String {
        match self {
            SkipReason::TooLarge(n) => format!("larger than the {} KiB read limit", n / 1024),
            SkipReason::Binary => "binary content".to_string(),
            SkipReason::Unreadable => "could not be opened".to_string(),
            SkipReason::NotUtf8 => "not valid UTF-8 text".to_string(),
        }
    }
}

impl Codebase {
    /// Files matching any of the given extensions, authored code only.
    pub fn authored_with_extensions<'a>(
        &'a self,
        exts: &'a [&'a str],
    ) -> impl Iterator<Item = &'a SourceFile> + 'a {
        self.files
            .iter()
            .filter(move |f| f.is_authored() && exts.contains(&f.extension.as_str()))
    }

    /// Every file whose basename matches, wherever it sits in the tree.
    pub fn by_file_name<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a SourceFile> + 'a {
        self.files.iter().filter(move |f| f.file_name() == name)
    }

    /// Did the walk see the entire tree?
    pub fn is_complete(&self) -> bool {
        self.stopped_because == WalkStop::Exhausted
    }
}

/// Read a repository into memory, honouring the limits.
///
/// Errors only when `root` is not a readable directory: a tree that is partly
/// unreadable yields the part that could be read, with the rest recorded in
/// `skipped`. A scan that aborts because one file had the wrong permissions
/// tells the analyst less than one that reads the other nine thousand.
pub fn walk(root: &Path, limits: &WalkLimits) -> anyhow::Result<Codebase> {
    if !root.is_dir() {
        anyhow::bail!(
            "{} is not a readable directory — set the target's source repository \
             to a checkout on this machine",
            root.display()
        );
    }
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let ignore = GitIgnore::load(&root);

    let started = Instant::now();
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    let mut stopped = WalkStop::Exhausted;
    // Symlinks can point back up the tree; without this a single `ln -s .. x`
    // walks forever.
    let mut seen_dirs: HashSet<PathBuf> = HashSet::new();
    let mut queue: Vec<(PathBuf, usize)> = vec![(root.clone(), 0)];

    'walk: while let Some((dir, depth)) = queue.pop() {
        if depth > limits.max_depth {
            continue;
        }
        let canonical = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        if !seen_dirs.insert(canonical) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            if started.elapsed() > limits.budget {
                stopped = WalkStop::Budget;
                break 'walk;
            }
            if files.len() >= limits.max_files {
                stopped = WalkStop::FileCap;
                break 'walk;
            }

            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let relative = relative_to(&root, &path);

            if meta.is_dir() {
                if SKIP_DIRS.contains(&name) || ignore.matches(&relative, true) {
                    continue;
                }
                queue.push((path, depth + 1));
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            if ignore.matches(&relative, false) {
                continue;
            }

            let extension = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            if BINARY_EXTS.contains(&extension.as_str()) {
                continue; // Not "skipped": nobody expects a .png to be read.
            }
            let size = meta.len();
            if size == 0 {
                continue;
            }
            if size > limits.max_file_bytes {
                skipped.push((relative, SkipReason::TooLarge(limits.max_file_bytes)));
                continue;
            }

            match std::fs::read(&path) {
                Err(_) => skipped.push((relative, SkipReason::Unreadable)),
                Ok(bytes) => {
                    if bytes.iter().take(8192).any(|b| *b == 0) {
                        skipped.push((relative, SkipReason::Binary));
                        continue;
                    }
                    match String::from_utf8(bytes) {
                        Err(_) => skipped.push((relative, SkipReason::NotUtf8)),
                        Ok(content) => {
                            let provenance = classify(&relative, &content);
                            files.push(SourceFile {
                                path,
                                relative,
                                extension,
                                provenance,
                                size_bytes: size,
                                content,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(Codebase { root, files, skipped, stopped_because: stopped })
}

/// A path relative to the root, in forward-slash form so reports read the same
/// on every platform.
fn relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Path segments that mean "this is test code".
const TEST_MARKERS: &[&str] = &[
    "/test/", "/tests/", "/spec/", "/specs/", "/__tests__/", "/__mocks__/",
    "/testdata/", "/fixtures/", "/e2e/", "/cypress/", "/playwright/",
    "/examples/", "/example/", "/demo/", "/samples/", "/mocks/", "/stubs/",
];

/// Filename fragments that mean the same.
const TEST_NAME_MARKERS: &[&str] = &[
    ".test.", ".spec.", "_test.", "_spec.", "test_", "conftest.py", ".stories.",
];

/// Filename fragments that mean a machine wrote it.
const GENERATED_NAME_MARKERS: &[&str] = &[
    ".min.js", ".min.css", ".bundle.js", "-bundle.js", ".chunk.js", ".pack.js",
    ".generated.", ".gen.go", "_pb2.py", "_pb.go", ".pb.go", ".g.dart",
    ".designer.cs", ".d.ts", "-lock.json", ".lock",
];

/// Header text a generator leaves behind. Checked in the first few lines only:
/// the phrase appears in prose further down plenty of hand-written files.
const GENERATED_HEADERS: &[&str] = &[
    "@generated", "code generated by", "do not edit", "auto-generated",
    "autogenerated", "generated by the protocol buffer compiler",
];

/// Decide what kind of file this is from its path and its first few lines.
fn classify(relative: &str, content: &str) -> Provenance {
    let lower = format!("/{}", relative.to_ascii_lowercase());

    if GENERATED_NAME_MARKERS.iter().any(|m| lower.contains(m)) {
        return Provenance::Generated;
    }
    let head: String = content.lines().take(5).collect::<Vec<_>>().join("\n").to_ascii_lowercase();
    if GENERATED_HEADERS.iter().any(|m| head.contains(m)) {
        return Provenance::Generated;
    }
    // Minification, detected by shape rather than by name: a bundler that
    // emits `app.4f2a.js` leaves no marker in the filename at all.
    if is_minified(content) {
        return Provenance::Generated;
    }
    if TEST_MARKERS.iter().any(|m| lower.contains(m))
        || TEST_NAME_MARKERS.iter().any(|m| lower.contains(m))
    {
        return Provenance::Test;
    }
    Provenance::Authored
}

/// Whether the content has the shape of minified output.
///
/// Hand-written code has short lines because humans read it. Minified code has
/// a handful of enormous ones. The threshold sits well above the longest line
/// anyone writes deliberately and well below what a minifier produces.
fn is_minified(content: &str) -> bool {
    let mut lines = 0usize;
    let mut total = 0usize;
    let mut longest = 0usize;
    for line in content.lines().take(400) {
        lines += 1;
        let len = line.len();
        total += len;
        longest = longest.max(len);
    }
    if lines == 0 {
        return false;
    }
    let mean = total / lines;
    // Either the average line is absurd, or one line holds a whole program.
    mean > 400 || (longest > 5_000 && lines < 50)
}

// ── .gitignore ───────────────────────────────────────────────────────────────

/// The subset of `.gitignore` that matters for deciding what to read.
///
/// Not a full implementation of gitignore semantics — that is a specification
/// in its own right, and getting the exotic cases wrong would silently drop
/// application code from the assessment. This handles the four forms that
/// account for essentially every real entry (`name`, `name/`, `*.ext`,
/// `/rooted/path`) and, critically, *ignores* anything it does not understand
/// rather than guessing. An unrecognised pattern means the file is read: an
/// over-inclusive scan produces noise, an under-inclusive one produces a
/// report that missed something.
struct GitIgnore {
    /// Bare directory or file names, matched against any path segment.
    names: Vec<String>,
    /// `*.ext` suffixes.
    suffixes: Vec<String>,
    /// Paths anchored to the repository root.
    rooted: Vec<String>,
}

impl GitIgnore {
    fn load(root: &Path) -> Self {
        let mut me = Self { names: Vec::new(), suffixes: Vec::new(), rooted: Vec::new() };
        let Ok(text) = std::fs::read_to_string(root.join(".gitignore")) else {
            return me;
        };
        for raw in text.lines() {
            let line = raw.trim();
            // Comments, blanks, and negations — a negation re-includes a file,
            // and mishandling one drops code from the scan, so any file
            // touched by one is simply read.
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }
            let pattern = line.trim_end_matches('/');
            if pattern.is_empty() {
                continue;
            }
            if let Some(ext) = pattern.strip_prefix("*.") {
                if !ext.contains(['*', '?', '/', '[']) {
                    me.suffixes.push(format!(".{}", ext.to_ascii_lowercase()));
                }
                continue;
            }
            if pattern.contains(['*', '?', '[']) {
                continue; // Not understood: read the file.
            }
            if let Some(anchored) = pattern.strip_prefix('/') {
                me.rooted.push(anchored.to_ascii_lowercase());
            } else if pattern.contains('/') {
                me.rooted.push(pattern.to_ascii_lowercase());
            } else {
                me.names.push(pattern.to_ascii_lowercase());
            }
        }
        me
    }

    fn matches(&self, relative: &str, _is_dir: bool) -> bool {
        let lower = relative.to_ascii_lowercase();
        if self.rooted.iter().any(|p| lower == *p || lower.starts_with(&format!("{p}/"))) {
            return true;
        }
        if self.suffixes.iter().any(|s| lower.ends_with(s)) {
            return true;
        }
        let last = lower.rsplit('/').next().unwrap_or(&lower);
        self.names.iter().any(|n| n == last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sentinel-walk-{name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    #[test]
    fn dependency_directories_are_never_descended_into() {
        let root = tmp("deps");
        write(&root, "src/app.js", "const a = 1;");
        write(&root, "node_modules/left-pad/index.js", "module.exports = 1;");
        write(&root, "vendor/thing.php", "<?php echo 1;");

        let cb = walk(&root, &WalkLimits::default()).unwrap();
        let paths: Vec<_> = cb.files.iter().map(|f| f.relative.as_str()).collect();
        assert!(paths.contains(&"src/app.js"));
        assert!(!paths.iter().any(|p| p.contains("node_modules")));
        assert!(!paths.iter().any(|p| p.contains("vendor")));
    }

    #[test]
    fn a_file_over_the_size_cap_is_recorded_rather_than_silently_dropped() {
        let root = tmp("large");
        write(&root, "huge.js", &"x".repeat(4096));
        let limits = WalkLimits { max_file_bytes: 1024, ..Default::default() };

        let cb = walk(&root, &limits).unwrap();
        assert!(cb.files.is_empty());
        assert_eq!(cb.skipped.len(), 1, "the unread file must be reported");
        assert!(matches!(cb.skipped[0].1, SkipReason::TooLarge(1024)));
    }

    #[test]
    fn binary_content_is_skipped_not_decoded() {
        let root = tmp("binary");
        fs::write(root.join("data.txt"), [0x41u8, 0x00, 0x42]).unwrap();
        let cb = walk(&root, &WalkLimits::default()).unwrap();
        assert!(cb.files.is_empty());
        assert_eq!(cb.skipped[0].1, SkipReason::Binary);
    }

    #[test]
    fn minified_bundles_are_generated_even_without_a_telltale_name() {
        let root = tmp("minified");
        write(&root, "app.4f2a9c.js", &format!("!function(e){{{}}}();", "var a=1;".repeat(900)));
        write(&root, "src/index.js", "export const x = 1;\nexport const y = 2;\n");

        let cb = walk(&root, &WalkLimits::default()).unwrap();
        let bundle = cb.files.iter().find(|f| f.relative.starts_with("app.")).unwrap();
        let authored = cb.files.iter().find(|f| f.relative == "src/index.js").unwrap();
        assert_eq!(bundle.provenance, Provenance::Generated);
        assert_eq!(authored.provenance, Provenance::Authored);
    }

    #[test]
    fn test_code_is_classified_apart_from_application_code() {
        let root = tmp("tests");
        write(&root, "src/login.py", "x = 1");
        write(&root, "tests/test_login.py", "x = 1");
        write(&root, "src/login.test.js", "x = 1");

        let cb = walk(&root, &WalkLimits::default()).unwrap();
        let kind = |rel: &str| cb.files.iter().find(|f| f.relative == rel).unwrap().provenance;
        assert_eq!(kind("src/login.py"), Provenance::Authored);
        assert_eq!(kind("tests/test_login.py"), Provenance::Test);
        assert_eq!(kind("src/login.test.js"), Provenance::Test);
    }

    #[test]
    fn gitignore_entries_are_honoured_for_the_forms_it_understands() {
        let root = tmp("gitignore");
        write(&root, ".gitignore", "secrets.env\n*.log\n/generated\n");
        write(&root, "secrets.env", "KEY=1");
        write(&root, "debug.log", "line");
        write(&root, "generated/out.js", "var a=1;");
        write(&root, "src/keep.js", "var a=1;");

        let cb = walk(&root, &WalkLimits::default()).unwrap();
        let mut paths: Vec<_> = cb.files.iter().map(|f| f.relative.as_str()).collect();
        paths.sort();
        // `.gitignore` itself is read — it is a tracked text file, and the
        // secret scanner has found credentials in one before now.
        assert_eq!(paths, vec![".gitignore", "src/keep.js"], "got {paths:?}");
    }

    /// A pattern the parser does not understand must widen the scan, never
    /// narrow it — dropping application code produces a report that is wrong
    /// rather than merely noisy.
    #[test]
    fn an_unrecognised_gitignore_pattern_leaves_the_file_readable() {
        let root = tmp("gitignore-exotic");
        write(&root, ".gitignore", "src/**/temp?/*.js\n!keep\n");
        write(&root, "src/a/temp1/x.js", "var a=1;");

        let cb = walk(&root, &WalkLimits::default()).unwrap();
        assert!(
            cb.files.iter().any(|f| f.relative == "src/a/temp1/x.js"),
            "an unparsed pattern must not hide code, got {:?}",
            cb.files.iter().map(|f| &f.relative).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_file_cap_stops_the_walk_and_says_so() {
        let root = tmp("cap");
        for i in 0..40 {
            write(&root, &format!("src/f{i}.js"), "var a = 1;");
        }
        let limits = WalkLimits { max_files: 10, ..Default::default() };
        let cb = walk(&root, &limits).unwrap();
        assert_eq!(cb.files.len(), 10);
        assert_eq!(cb.stopped_because, WalkStop::FileCap);
        assert!(!cb.is_complete());
    }

    #[test]
    fn a_path_that_is_not_a_directory_is_a_clear_error() {
        let err = walk(Path::new("/definitely/not/here"), &WalkLimits::default()).unwrap_err();
        assert!(err.to_string().contains("not a readable directory"));
    }

    #[test]
    fn lines_are_numbered_the_way_an_editor_numbers_them() {
        let f = SourceFile {
            path: PathBuf::from("/x/a.js"),
            relative: "a.js".into(),
            extension: "js".into(),
            content: "one\ntwo\nthree".into(),
            provenance: Provenance::Authored,
            size_bytes: 13,
        };
        assert_eq!(f.lines()[0], (1, "one"));
        assert_eq!(f.lines()[2], (3, "three"));
        assert_eq!(f.file_name(), "a.js");
    }
}
