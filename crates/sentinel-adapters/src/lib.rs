pub mod adapter_trait;
pub mod runner;
pub mod dast_config;
pub mod auth_gated_runner;
pub mod orchestrator;

// Static SAST/SCA/Secrets adapters
pub mod semgrep;
pub mod trivy;
pub mod gitleaks;

// DAST adapters (always use via AuthGatedDastRunner)
pub mod zap;
pub mod nuclei;

// Built-in check engine — ships with the app, needs no external binary.
// Also always used via AuthGatedDastRunner: it issues live HTTP requests.
pub mod native;

#[cfg(test)]
pub mod keychain_test;

