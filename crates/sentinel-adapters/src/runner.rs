//! Cross-platform discovery and invocation of user-installed scanner binaries.
//!
//! Windows, macOS and Linux differ in three ways that matter here:
//!   • the lookup command (`where` vs `which`)
//!   • executable extensions (`.exe`, `.cmd`, `.bat` on Windows; none elsewhere)
//!   • the conventional install directories
//!
//! All three are handled explicitly so a scanner installed by any of the usual
//! package managers is found without the user editing PATH.

use crate::process::std_command;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub struct LocalCliRunner;

/// Directories searched on Unix-like systems in addition to PATH.
#[cfg(not(windows))]
const EXTRA_SEARCH_PATHS: &[&str] = &[
    "/usr/local/bin",
    "/opt/homebrew/bin",   // Homebrew on Apple Silicon
    "/usr/bin",
    "/bin",
    "/snap/bin",           // Ubuntu snaps (Semgrep / Trivy)
    "~/.local/bin",        // pipx and user-local installs
    "~/go/bin",            // go install (Nuclei / Gitleaks)
    "~/.cargo/bin",
    "/opt/local/bin",      // MacPorts
];

/// Directories searched on Windows in addition to PATH.
///
/// `%VAR%` placeholders are expanded from the environment at lookup time.
#[cfg(windows)]
const EXTRA_SEARCH_PATHS: &[&str] = &[
    r"%ProgramFiles%",
    r"%ProgramFiles(x86)%",
    r"%ProgramData%\chocolatey\bin",       // Chocolatey shims
    r"%USERPROFILE%\scoop\shims",          // Scoop shims
    r"%USERPROFILE%\go\bin",               // go install (Nuclei / Gitleaks)
    r"%USERPROFILE%\.cargo\bin",
    r"%LOCALAPPDATA%\Programs",
    r"%LOCALAPPDATA%\Microsoft\WindowsApps",
    r"%APPDATA%\npm",                      // npm global installs
    r"%LOCALAPPDATA%\Programs\Python\Scripts",
    r"%USERPROFILE%\AppData\Roaming\Python\Scripts",  // pip --user
];

/// Extensions appended to a bare binary name when probing the filesystem.
///
/// `.ps1` is deliberately absent. `CreateProcess` — which is what spawning a
/// command ultimately calls — does not consult file associations, so a
/// PowerShell script cannot be launched as a program. Probing for one would
/// make `is_installed` report an engine as available and the scan would then
/// fail when it tried to run it. Scoop and Chocolatey both write an `.exe`
/// shim alongside their `.ps1`, so the engine is still found by that.
#[cfg(windows)]
const EXECUTABLE_EXTENSIONS: &[&str] = &["", ".exe", ".cmd", ".bat", ".com"];

#[cfg(not(windows))]
const EXECUTABLE_EXTENSIONS: &[&str] = &[""];

impl LocalCliRunner {
    /// Execute a scanner CLI and capture stdout.
    ///
    /// A non-zero exit with output on stdout is treated as success: several
    /// scanners (Semgrep, Nuclei, Trivy) exit non-zero precisely *because* they
    /// found something, and that output is the result we want.
    pub fn run_cli(binary_name: &str, args: &[&str]) -> Result<String> {
        let executable = Self::find_binary_path(binary_name)
            .unwrap_or_else(|| binary_name.to_string());

        let output = std_command(&executable)
            .args(args)
            .output()
            .with_context(|| format!(
                "Failed to execute scanner '{binary_name}' (resolved to '{executable}'). \
                 Install it and make sure it is on your PATH."
            ))?;

        if !output.status.success() && output.stdout.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Scanner '{binary_name}' exited with failure: {stderr}");
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Whether a scanner binary can be located on this machine.
    pub fn is_installed(binary_name: &str) -> bool {
        Self::find_binary_path(binary_name).is_some()
    }

    /// Resolve the full path of a binary, or `None` when it is not installed.
    pub fn find_binary_path(binary_name: &str) -> Option<String> {
        // 1. Ask the OS first — it honours the user's real PATH.
        if let Some(path) = Self::query_os_lookup(binary_name) {
            return Some(path);
        }

        // 2. Walk PATH ourselves, applying platform executable extensions.
        //    Needed on Windows when a tool is on PATH without a PATHEXT entry.
        if let Some(paths) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&paths) {
                if let Some(hit) = Self::probe_directory(&dir, binary_name) {
                    return Some(hit);
                }
            }
        }

        // 3. Fall back to conventional install directories.
        for base in EXTRA_SEARCH_PATHS {
            let expanded = Self::expand_path(base);
            if expanded.as_os_str().is_empty() {
                continue;
            }
            if let Some(hit) = Self::probe_directory(&expanded, binary_name) {
                return Some(hit);
            }
            // Installers commonly nest one level: <ProgramFiles>\Tool\tool.exe
            if let Some(hit) = Self::probe_nested(&expanded, binary_name) {
                return Some(hit);
            }
        }

        None
    }

    /// Use the platform's own lookup command.
    fn query_os_lookup(binary_name: &str) -> Option<String> {
        #[cfg(windows)]
        let (program, args) = ("where", vec![binary_name]);
        #[cfg(not(windows))]
        let (program, args) = ("which", vec![binary_name]);

        let output = std_command(program).args(&args).output().ok()?;
        if !output.status.success() {
            return None;
        }
        // `where` can return several matches, one per line; take the first.
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && Path::new(line).exists())
            .map(str::to_string)
    }

    /// Look for `<dir>/<name><ext>` for each platform executable extension.
    fn probe_directory(dir: &Path, binary_name: &str) -> Option<String> {
        for ext in EXECUTABLE_EXTENSIONS {
            let candidate = dir.join(format!("{binary_name}{ext}"));
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
        None
    }

    /// Look one level down: `<dir>/<name>/<name><ext>` and `<dir>/<name>/bin/<name><ext>`.
    fn probe_nested(dir: &Path, binary_name: &str) -> Option<String> {
        let nested = dir.join(binary_name);
        if let Some(hit) = Self::probe_directory(&nested, binary_name) {
            return Some(hit);
        }
        Self::probe_directory(&nested.join("bin"), binary_name)
    }

    /// Expand `~` (Unix) and `%VAR%` (Windows) placeholders in a search path.
    pub fn expand_path(raw: &str) -> PathBuf {
        // Windows-style %VAR% expansion.
        if raw.contains('%') {
            let mut out = String::new();
            let mut rest = raw;
            while let Some(start) = rest.find('%') {
                out.push_str(&rest[..start]);
                let after = &rest[start + 1..];
                match after.find('%') {
                    Some(end) => {
                        let name = &after[..end];
                        match std::env::var(name) {
                            Ok(value) => out.push_str(&value),
                            // An unset variable makes the whole path meaningless
                            // (e.g. %ProgramFiles(x86)% on ARM-only installs).
                            Err(_) => return PathBuf::new(),
                        }
                        rest = &after[end + 1..];
                    }
                    None => {
                        out.push_str(after);
                        rest = "";
                    }
                }
            }
            out.push_str(rest);
            return PathBuf::from(out);
        }

        // Unix-style ~ expansion.
        if let Some(stripped) = raw.strip_prefix("~/") {
            if let Some(home) = Self::home_dir() {
                return home.join(stripped);
            }
            return PathBuf::new();
        }

        PathBuf::from(raw)
    }

    /// The user's home directory, using whichever variable the platform sets.
    fn home_dir() -> Option<PathBuf> {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locates_a_binary_that_exists_on_every_platform() {
        // `cargo` is present wherever these tests can run.
        assert!(
            LocalCliRunner::find_binary_path("cargo").is_some(),
            "cargo must be locatable in a Rust toolchain environment"
        );
    }

    #[test]
    fn reports_absent_binaries_as_not_installed() {
        assert!(!LocalCliRunner::is_installed("sentinel_nonexistent_binary_xyz_123"));
    }

    #[test]
    fn tilde_expansion_resolves_against_home() {
        let expanded = LocalCliRunner::expand_path("~/go/bin");
        // On Windows the literal has no tilde prefix, so only assert on Unix.
        if cfg!(not(windows)) {
            assert!(!expanded.to_string_lossy().starts_with('~'));
            assert!(expanded.to_string_lossy().ends_with("go/bin"));
        }
    }

    #[test]
    fn absolute_paths_pass_through_unchanged() {
        assert_eq!(LocalCliRunner::expand_path("/usr/local/bin"), PathBuf::from("/usr/local/bin"));
    }

    #[test]
    fn env_var_placeholders_are_expanded() {
        std::env::set_var("SENTINEL_TEST_ROOT", "/tmp/sentinel-test");
        let expanded = LocalCliRunner::expand_path("%SENTINEL_TEST_ROOT%/bin");
        assert_eq!(expanded, PathBuf::from("/tmp/sentinel-test/bin"));
        std::env::remove_var("SENTINEL_TEST_ROOT");
    }

    /// Runs only on Windows, where the list is compiled in. An entry the OS
    /// cannot launch would make `is_installed` promise an engine that fails
    /// the moment a scan tries to use it.
    #[cfg(windows)]
    #[test]
    fn every_probed_extension_is_something_the_os_can_actually_execute() {
        for ext in EXECUTABLE_EXTENSIONS {
            assert!(
                !matches!(*ext, ".ps1" | ".py" | ".sh"),
                "'{ext}' is a script, not an executable image; CreateProcess cannot run it"
            );
        }
    }

    #[test]
    fn unset_env_var_yields_an_empty_path_rather_than_a_literal() {
        let expanded = LocalCliRunner::expand_path("%SENTINEL_DEFINITELY_UNSET_VAR%\\bin");
        assert!(
            expanded.as_os_str().is_empty(),
            "an unset variable must not produce a bogus literal path"
        );
    }

    #[test]
    fn windows_extension_list_includes_exe() {
        if cfg!(windows) {
            assert!(EXECUTABLE_EXTENSIONS.contains(&".exe"));
            assert!(EXECUTABLE_EXTENSIONS.contains(&".cmd"));
        } else {
            assert_eq!(EXECUTABLE_EXTENSIONS, &[""]);
        }
    }

    #[test]
    fn search_paths_are_non_empty_on_every_platform() {
        assert!(!EXTRA_SEARCH_PATHS.is_empty());
    }

    #[test]
    fn probe_directory_finds_a_real_file() {
        let dir = std::env::temp_dir();
        let name = "sentinel_probe_test_file";
        let path = dir.join(name);
        std::fs::write(&path, b"x").unwrap();
        assert!(LocalCliRunner::probe_directory(&dir, name).is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn probe_directory_returns_none_for_a_missing_file() {
        assert!(LocalCliRunner::probe_directory(
            &std::env::temp_dir(),
            "sentinel_missing_probe_file_xyz"
        )
        .is_none());
    }
}
