//! Which language a file is, and which of its lines are actually code.
//!
//! Both questions exist for the same reason: a rule that fires on a commented-out
//! line is a false positive, and a rule written for PHP that fires on a Go file
//! because both spell a function `exec` is a worse one. The first thing this
//! engine does with a file is decide what it is, and the second is work out
//! which of its lines a compiler would care about.

/// A language the code engine has rules for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    JavaScript,
    TypeScript,
    Python,
    Java,
    Kotlin,
    Php,
    Go,
    Ruby,
    CSharp,
    C,
    Rust,
    Shell,
    /// Templates, configuration and markup — matched by the rules that care
    /// about markup rather than by any language-specific rule.
    Markup,
}

impl Language {
    /// The language a file extension implies, or `None` for anything with no
    /// rules — better to read nothing than to apply Java rules to a `.txt`.
    pub fn from_extension(ext: &str) -> Option<Language> {
        Some(match ext {
            "js" | "mjs" | "cjs" | "jsx" => Language::JavaScript,
            "ts" | "tsx" | "mts" | "cts" => Language::TypeScript,
            "py" | "pyw" | "pyi" => Language::Python,
            "java" => Language::Java,
            "kt" | "kts" => Language::Kotlin,
            "php" | "php5" | "php7" | "phtml" | "inc" => Language::Php,
            "go" => Language::Go,
            "rb" | "rake" | "erb" => Language::Ruby,
            "cs" | "cshtml" => Language::CSharp,
            "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" | "m" | "mm" => Language::C,
            "rs" => Language::Rust,
            "sh" | "bash" | "zsh" | "ksh" => Language::Shell,
            "html" | "htm" | "vue" | "svelte" | "hbs" | "handlebars" | "ejs" | "jsp"
            | "aspx" | "twig" | "blade" | "mustache" | "pug" | "razor" => Language::Markup,
            _ => return None,
        })
    }

    /// The name a report prints.
    pub fn label(self) -> &'static str {
        match self {
            Language::JavaScript => "JavaScript",
            Language::TypeScript => "TypeScript",
            Language::Python => "Python",
            Language::Java => "Java",
            Language::Kotlin => "Kotlin",
            Language::Php => "PHP",
            Language::Go => "Go",
            Language::Ruby => "Ruby",
            Language::CSharp => "C#",
            Language::C => "C/C++",
            Language::Rust => "Rust",
            Language::Shell => "Shell",
            Language::Markup => "Markup/Template",
        }
    }

    /// Line-comment tokens. A line whose first non-space characters are one of
    /// these is not code.
    fn line_comment(self) -> &'static [&'static str] {
        match self {
            Language::Python | Language::Ruby | Language::Shell => &["#"],
            Language::Php => &["//", "#"],
            Language::Markup => &[],
            _ => &["//"],
        }
    }

    /// Block-comment delimiters, if the language has them.
    fn block_comment(self) -> Option<(&'static str, &'static str)> {
        match self {
            Language::Python => Some(("\"\"\"", "\"\"\"")),
            Language::Ruby => Some(("=begin", "=end")),
            Language::Shell => None,
            Language::Markup => Some(("<!--", "-->")),
            _ => Some(("/*", "*/")),
        }
    }
}

/// Walks a file deciding, line by line, whether the line is code.
///
/// Deliberately a state machine over lines rather than a lexer. A real lexer
/// would also need to know that `"/* not a comment */"` inside a string is not
/// a comment, and getting that wrong in the *unsafe* direction — treating code
/// as a comment — silently drops findings. This errs the other way: a `/*`
/// inside a string literal will end the region early and the following lines
/// are treated as code, which at worst produces a finding a reviewer dismisses.
pub struct CommentState {
    lang: Language,
    in_block: bool,
}

impl CommentState {
    pub fn new(lang: Language) -> Self {
        Self { lang, in_block: false }
    }

    /// Feed the next line; returns true when the line contains code.
    pub fn is_code(&mut self, line: &str) -> bool {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return false;
        }

        if let Some((open, close)) = self.lang.block_comment() {
            if self.in_block {
                if let Some(rest) = trimmed.split_once(close) {
                    self.in_block = false;
                    // Code can follow the closing delimiter on the same line.
                    return !rest.1.trim().is_empty();
                }
                return false;
            }
            // Python's triple quote both opens and closes on one line when the
            // docstring is a one-liner, so count rather than assume.
            if let Some(idx) = trimmed.find(open) {
                let before = trimmed[..idx].trim();
                let after = &trimmed[idx + open.len()..];
                match after.find(close) {
                    // Opened and never closed: the region continues, and only
                    // whatever preceded the delimiter counts as code.
                    None => {
                        self.in_block = true;
                        return !before.is_empty();
                    }
                    // Opened and closed on this line. The line is code only if
                    // something outside the comment is left — otherwise a
                    // one-line `/* rejectUnauthorized: false */` reads as a
                    // live setting, which is exactly the false positive that
                    // makes an engine untrustworthy.
                    Some(end) => {
                        let tail = after[end + close.len()..].trim();
                        return !before.is_empty() || !tail.is_empty();
                    }
                }
            }
        }

        !self
            .lang
            .line_comment()
            .iter()
            .any(|token| trimmed.starts_with(token))
    }
}

/// The code lines of a file, 1-indexed, with comments removed.
///
/// The line numbers are the file's own, so a finding still points at the right
/// place in the analyst's editor.
pub fn code_lines(content: &str, lang: Language) -> Vec<(usize, &str)> {
    let mut state = CommentState::new(lang);
    content
        .lines()
        .enumerate()
        .filter_map(|(i, line)| state.is_code(line).then_some((i + 1, line)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_map_to_the_language_the_rules_were_written_for() {
        assert_eq!(Language::from_extension("tsx"), Some(Language::TypeScript));
        assert_eq!(Language::from_extension("phtml"), Some(Language::Php));
        assert_eq!(Language::from_extension("hpp"), Some(Language::C));
        assert_eq!(Language::from_extension("vue"), Some(Language::Markup));
    }

    /// A language with no rules must yield nothing rather than fall through to
    /// a default that would apply the wrong ones.
    #[test]
    fn an_unknown_extension_has_no_language() {
        assert_eq!(Language::from_extension("txt"), None);
        assert_eq!(Language::from_extension("csv"), None);
    }

    #[test]
    fn commented_out_code_is_not_code() {
        let src = "const a = 1;\n// exec(userInput);\nconst b = 2;";
        let lines = code_lines(src, Language::JavaScript);
        assert_eq!(lines.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![1, 3]);
    }

    #[test]
    fn a_block_comment_spanning_lines_is_skipped_entirely() {
        let src = "a();\n/*\n eval(x);\n danger();\n*/\nb();";
        let lines = code_lines(src, Language::JavaScript);
        assert_eq!(lines.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![1, 6]);
    }

    #[test]
    fn code_after_a_closing_block_delimiter_is_still_code() {
        let src = "/*\n note\n*/ run();";
        let lines = code_lines(src, Language::JavaScript);
        assert_eq!(lines, vec![(3, "*/ run();")]);
    }

    #[test]
    fn a_python_docstring_is_not_code_but_a_one_liner_does_not_swallow_the_file() {
        let multi = "def f():\n    \"\"\"\n    os.system(x)\n    \"\"\"\n    return 1";
        assert_eq!(
            code_lines(multi, Language::Python).iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![1, 5]
        );

        let one_liner = "def f():\n    \"\"\"docs\"\"\"\n    os.system(x)";
        let lines = code_lines(one_liner, Language::Python);
        assert!(
            lines.iter().any(|(n, _)| *n == 3),
            "a one-line docstring must not open a region that hides the rest of the file"
        );
    }

    #[test]
    fn php_accepts_both_of_its_comment_forms() {
        let src = "<?php\n// $a = shell_exec($x);\n# $b = shell_exec($y);\n$c = 1;";
        let lines = code_lines(src, Language::Php);
        assert_eq!(lines.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![1, 4]);
    }

    #[test]
    fn a_hash_in_javascript_is_not_a_comment() {
        let lines = code_lines("obj.#priv = 1;", Language::JavaScript);
        assert_eq!(lines.len(), 1);
    }
}
