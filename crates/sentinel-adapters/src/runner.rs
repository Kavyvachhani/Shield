use anyhow::{Result, Context};
use std::process::Command;
use std::path::Path;

pub struct LocalCliRunner;

impl LocalCliRunner {
    /// Probes likely installation directories for scanner binaries across macOS and Linux.
    const COMMON_SEARCH_PATHS: &'static [&'static str] = &[
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
        "/bin",
        "/snap/bin",           // Canonical Ubuntu snaps (Semgrep / Trivy)
        "~/.local/bin",        // Pipx / user local installs
        "~/go/bin",            // Go install path for Nuclei / Gitleaks
        "~/.cargo/bin",
    ];

    /// Executes a user-installed local scanner CLI binary with arguments and captures stdout.
    pub fn run_cli(binary_name: &str, args: &[&str]) -> Result<String> {
        let executable = Self::find_binary_path(binary_name)
            .unwrap_or_else(|| binary_name.to_string());

        let output = Command::new(&executable)
            .args(args)
            .output()
            .with_context(|| format!(
                "Failed to execute local scanner CLI binary: '{}' (path: '{}'). Make sure it is installed on your system PATH.",
                binary_name, executable
            ))?;

        if !output.status.success() && output.stdout.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Local CLI '{}' exited with failure: {}", binary_name, stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Checks if a scanner binary is installed and executable on PATH or common OS paths.
    pub fn is_installed(binary_name: &str) -> bool {
        Self::find_binary_path(binary_name).is_some()
    }

    /// Locate full path of binary via `which` or standard macOS/Linux search directories.
    pub fn find_binary_path(binary_name: &str) -> Option<String> {
        // 1. Try system `which`
        if let Ok(output) = Command::new("which").arg(binary_name).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() && Path::new(&path).exists() {
                    return Some(path);
                }
            }
        }

        // 2. Check common search paths on macOS / Linux
        let home = std::env::var("HOME").unwrap_or_default();
        for base in Self::COMMON_SEARCH_PATHS {
            let expanded = base.replace("~", &home);
            let candidate = Path::new(&expanded).join(binary_name);
            if candidate.exists() && candidate.is_file() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_binary_path_locates_sh_or_bash() {
        // 'sh' exists on all POSIX systems (macOS and Linux)
        let path = LocalCliRunner::find_binary_path("sh");
        assert!(path.is_some(), "Must locate 'sh' on POSIX systems");
    }

    #[test]
    fn is_installed_returns_false_for_nonexistent_binary() {
        assert!(!LocalCliRunner::is_installed("sentinel_nonexistent_binary_xyz_123"));
    }
}
