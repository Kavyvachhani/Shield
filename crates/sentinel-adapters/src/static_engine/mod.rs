//! The Sentinel Static engine — code, dependency, secret and infrastructure
//! analysis that ships inside the application.
//!
//! Until this existed, every static answer the tool could give depended on a
//! binary the analyst had to install first: Semgrep for code, Trivy or
//! OSV-Scanner for dependencies, Gitleaks for secrets, Checkov for
//! infrastructure. On a fresh machine all four skip, the coverage matrix
//! records four gaps, and a source repository is assessed by nothing at all.
//! The DAST side has not had that problem since the native check engine
//! landed; this is the same argument applied to the half of an assessment that
//! reads the code.
//!
//! Four engines live here, each an independent [`ScannerAdapter`]:
//!
//! | Module     | Engine name              | What it reads                        |
//! |------------|--------------------------|--------------------------------------|
//! | [`sast`]   | `Sentinel Code`          | source files, 12 languages           |
//! | [`sca`]    | `Sentinel Dependencies`  | lockfiles and manifests, 9 ecosystems|
//! | [`secrets`]| `Sentinel Secrets`       | every text file in the tree          |
//! | [`iac`]    | `Sentinel Infrastructure`| Dockerfiles, Compose, K8s, Terraform, CI |
//!
//! None of them touches the network except [`sca`], which asks OSV.dev whether
//! the versions it found are known-vulnerable and degrades to a bundled
//! advisory snapshot when it cannot reach it. That request carries package
//! names and versions and nothing else — no source, no path, no identifier for
//! the engagement.
//!
//! SAFETY
//! ──────
//! These engines read files. They execute nothing they find, resolve no
//! dependency, and run no build. A repository is opened read-only and a file
//! that is not valid UTF-8 is skipped rather than guessed at.

pub mod codebase;
pub mod finding;
pub mod iac;
pub mod sast;
pub mod sca;
pub mod secrets;

/// Engine names, matching the checklist coverage catalog.
pub mod engine {
    pub const CODE: &str = "Sentinel Code";
    pub const DEPENDENCIES: &str = "Sentinel Dependencies";
    pub const SECRETS: &str = "Sentinel Secrets";
    pub const INFRASTRUCTURE: &str = "Sentinel Infrastructure";
}
