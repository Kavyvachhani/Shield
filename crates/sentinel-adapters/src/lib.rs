pub mod adapter_trait;
pub mod process;
pub mod runner;
pub mod credentials;
pub mod dast_config;
pub mod auth_gated_runner;
pub mod orchestrator;

// Static SAST/SCA/Secrets adapters
pub mod semgrep;
pub mod trivy;
pub mod gitleaks;

// Additional engines: dependency vulnerabilities from a second database,
// verified secrets, client-side library versions, and web server discovery.
// Every one is optional — a missing binary is skipped and recorded as a
// coverage gap rather than failing the scan.
pub mod external_tools;

// DAST adapters (always use via AuthGatedDastRunner)
pub mod zap;
pub mod nuclei;

// Built-in check engine — ships with the app, needs no external binary.
// Also always used via AuthGatedDastRunner: it issues live HTTP requests.
pub mod native;

#[cfg(test)]
pub mod keychain_test;

