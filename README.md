# SentinelVAPT

**A local-first, offline-capable web application security assessment and reporting workbench.**

SentinelVAPT orchestrates open-source scanners, normalises and de-duplicates their
output, ranks findings by real-world risk, and produces two deliverables from a single
assessment: a client-facing report and a developer remediation guide.

Everything runs on your machine. There is no telemetry, no account, and no cloud
dependency.

---

## Why it exists

Running Semgrep, Trivy, Gitleaks, ZAP and Nuclei against one target gives you five
incompatible result formats, heavy duplication, and severity ratings that disagree with
each other. Turning that into something a client or a developer can act on is manual work.

SentinelVAPT does that part: one normalised finding model, cross-engine deduplication,
a single priority ranking, and reports written for the two audiences that actually read them.

## What it does

- **Scans without setup.** A built-in native check engine covers security headers, TLS
  configuration, cookie flags, CORS policy, exposure surface and content analysis — no
  external tool required on a fresh machine.
- **Extends with what you have.** Semgrep, Trivy, Gitleaks, OWASP ZAP and Nuclei are
  detected automatically on `PATH` and in the conventional install locations. Missing
  engines are skipped with an explanation rather than failing the run.
- **Scans behind a login.** Supply a session cookie, HTTP Basic credentials, a bearer
  token or an API key header, and the native engine assesses the authenticated pages
  too. Secrets live in the OS keychain, never in the engagement database or a report.
- **Ranks by real risk.** Priority combines CVSS 4.0, EPSS probability, CISA KEV
  membership, reachability and exposure — so the list is ordered by what matters, not by
  raw scanner severity.
- **Tracks coverage honestly.** All 109 OWASP WSTG test cases are reported with their
  actual state, including checks that passed and those that genuinely need manual
  analysis.
- **Reports for two audiences.** A client report (posture, plain-language risk,
  remediation roadmap) and a developer report (location, CVSS vector, CWE/OWASP/WSTG
  mapping, reproduction, fix and verification). Also exports Markdown, SARIF 2.1.0 and JSON.

## Safety model

Dynamic testing is gated behind a signed Rules of Engagement record — the gate is
enforced in code and cannot be disabled by configuration.

- The native engine issues only `GET`, `HEAD` and `OPTIONS`. No payload, fuzzing or
  brute-force request is ever sent.
- Requests are rate-limited to the ceiling recorded in the signed RoE.
- Out-of-scope hosts and paths are refused before a socket is opened, and redirects are
  observed rather than followed, so a redirect cannot pull the scanner off-scope.
- Nuclei runs with `-etags dos,fuzzing,intrusive` and `-no-interactsh` regardless of user
  configuration.
- Credentials, session cookies and authorization headers are redacted before any evidence
  reaches a report. Scan credentials are held in the OS keychain and applied as request
  headers only — authenticating widens what the engine can read, never what it can change.

**Only test systems you are authorised to test.**

## Install

Download the installer for your platform from the
[latest release](../../releases/latest), or see **[INSTALL.md](INSTALL.md)** for the full
guide including building from source and setting up the optional scanner engines.

Builds are not code-signed, so both macOS and Windows show a first-run warning:

- **macOS** — open the `.dmg`, drag to Applications, then right-click the app →
  **Open** → **Open**.
- **Windows** — run the `.exe` and follow the setup wizard; at the SmartScreen
  prompt choose **More info** → **Run anyway**. Installs per-user, no admin rights
  needed. An `.msi` is also published for per-machine Intune / Group Policy rollout.
- **Linux** — install the `.deb`, or `chmod +x` the `.AppImage` and run it.

## Build from source

Requires [Rust](https://rustup.rs/) (stable) and [Node.js 20+](https://nodejs.org/).

```bash
git clone <your-repo-url> SentinelVAPT
cd SentinelVAPT/apps/desktop
npm ci
npm run tauri build
```

Tauri links against each platform's native webview, so installers must be built on the
platform they target — a Windows `.exe` cannot be cross-compiled from macOS or Linux.

- **On Windows**, run `scripts\build-windows.ps1`. It checks the toolchain, runs the
  tests, and builds both the `.exe` wizard and the `.msi`.
- **In CI**, the `.github/workflows/release.yml` workflow builds all three platforms.
  Push a `v*` tag to cut a release, or run it manually from the Actions tab and leave
  the platform choice on `windows` for a Windows-only build.

## Development

```bash
cd apps/desktop && npm ci
npm run tauri dev        # run the app with hot reload

cargo test --workspace   # backend test suite
cargo clippy --workspace --all-targets
npm run lint             # frontend
```

One test is opt-in: `e2e_real_run_test` drives the whole pipeline against a
live web target and a real source checkout, so it runs only when asked.

```bash
SENTINEL_E2E_LIVE=1 cargo test -p sentinel-core --test e2e_real_run_test
```

It defaults to a target at `http://localhost:3000` (an OWASP Juice Shop) and
the checkout at `scratch/target-repo`; override either with
`SENTINEL_E2E_TARGET_URL` and `SENTINEL_E2E_REPO_PATH`. With the switch set it
fails if those inputs are missing rather than passing over an empty scan.

### Layout

| Path | Purpose |
|---|---|
| `crates/sentinel-core` | Finding model, parsers, dedup, scoring, checklist, reporting |
| `crates/sentinel-adapters` | Native check engine and external scanner adapters |
| `crates/sentinel-db` | SQLite persistence layer |
| `crates/sentinel-mcp` | MCP server integration |
| `apps/desktop` | Tauri + React desktop application |

## Limits

Automated testing reliably finds configuration and known-pattern weaknesses. It cannot
fully evaluate business logic, authorisation between user accounts, or multi-step
workflow abuse. Those cases are marked **Manual review required** in the coverage matrix
rather than being silently counted as passed — a clean automated result is evidence of
good hygiene, not proof that no weakness exists.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Third-party dependency licenses are
documented in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
