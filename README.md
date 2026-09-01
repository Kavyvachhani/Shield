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

- **Scans without setup.** A built-in native check engine ships 67 checks covering
  security headers, TLS configuration, cookie flags, cross-origin isolation, CORS policy,
  exposure surface, content analysis, client-side patterns and information disclosure —
  credentials and private keys left in JavaScript, readable source maps, tokens written to
  browser storage, wildcard `postMessage`, plaintext WebSockets, DOM-XSS sink patterns,
  unprotected state-changing forms, unsandboxed third-party frames and unenforced CSP.
  No external tool is required on a fresh machine.
- **Says how much it looked at.** Every report records the pages reached, the in-scope
  URLs it did not get to and why, and the third-party origins the application depends on.
  "No weaknesses found" across eleven pages and the same words across four hundred are
  different claims, and the report now tells them apart.
- **Asks the application what it exposes, rather than guessing from its markup.** Before
  following a single link the engine reads the target's own descriptions of itself: the
  OpenAPI/Swagger specification — the authoritative route list, written by the people who
  built the service — plus `robots.txt` (a public list of what the operator did not want
  found), `sitemap.xml`, and the path literals inside JavaScript bundles. That last one is
  what makes a single-page application assessable at all: its routes and API calls exist
  only as strings in a bundle, and no link crawler will ever see them. Nothing is guessed,
  brute-forced or fuzzed — a path is requested because something the application published
  named it.
- **Tests each endpoint, not just the front page.** CORS policy, accepted HTTP methods,
  Host header handling and open redirects are configured per route, so they are assessed
  per route: one representative per path family, API routes first, bounded to a request
  budget the signed rate limit can afford.
- **Assesses the whole application, not the front page.** The engine walks the target
  same-origin, breadth-first, and runs every passive check against each page it reaches —
  so a policy set on `/` but missing on `/admin`, or a key compiled into a lazily loaded
  bundle, is actually found. Discovery is `GET`-only, scope-checked before each socket
  opens, held to the RoE rate limit, and bounded by page count, depth, wall clock and
  links-per-page so an unbounded URL space cannot stall a scan. Findings that describe the
  deployment rather than a page — a missing header, a cookie flag — collapse to one entry
  listing every affected URL, instead of one identical row per page.
- **Extends with what you have.** Eleven external engines are detected automatically on
  `PATH` and in the conventional install locations — Semgrep, Trivy, OSV-Scanner,
  Gitleaks, TruffleHog, retire.js, Checkov, OWASP ZAP, Nuclei, Nikto and testssl.sh.
  Missing engines are skipped with an explanation rather than failing the run, and the
  coverage matrix records which checks went unanswered as a result.
- **Looks under the application as well as at it.** Checkov reads the Terraform,
  Kubernetes and container definitions the application is deployed from. A security group
  open to the internet is not something application hardening compensates for, and an
  assessment that reads the code but not the infrastructure answers half the question.
- **Runs overlapping engines on purpose.** Trivy and OSV-Scanner use different
  vulnerability databases; Gitleaks finds credential-shaped strings while TruffleHog
  asks the provider whether they still authenticate. Two engines confirming one weakness
  is a stronger claim than either alone, and deduplication reflects that in the ranking.
- **Scans behind a login.** Supply a session cookie, HTTP Basic credentials, a bearer
  token or an API key header, and the native engine assesses the authenticated pages
  too. Secrets live in the OS keychain, never in the engagement database or a report.
- **Ranks by real risk.** Priority combines CVSS 4.0, EPSS probability, CISA KEV
  membership, reachability and exposure — so the list is ordered by what matters, not by
  raw scanner severity.
- **Triages each weakness once.** Dismissing a false positive or accepting a risk records
  an exception against the *target*, keyed by a fingerprint that survives a re-scan. The
  next assessment applies the decision automatically instead of raising the same finding
  with a new id. An acceptance can carry a review date, after which it lapses and the
  finding returns to the open list.
- **States its own confidence.** Every finding says what it was determined from — a live
  observation, a code match, a declared dependency version — and the specific condition
  that would make it wrong, so a reviewer can start with the ones worth checking.
- **Tracks coverage honestly.** All 106 OWASP WSTG test cases are reported with their
  actual state, including checks that passed and those that genuinely need manual
  analysis.
- **Reports for two audiences.** A client report — document control, the controls that
  were verified and what each protects against, the posture score, the accepted-risk
  register, standards conformance, evidence handling and a stated limitations section —
  and a developer report giving location, CVSS vector, CWE/OWASP/WSTG mapping,
  reproduction, validation confidence, fix and verification. Also exports Markdown,
  SARIF 2.1.0 and JSON.

### Re-testing

A second assessment of the same target compares itself against the previous one and reports
what closed, what appeared, and what is still open. Findings are matched across assessments by
location and classification — the same rule the exception register uses — rather than by any
identifier the scan generated, so a weakness carried from one report to the next is genuinely
the same issue.

The **Confirmed closed** list is the only place in either deliverable that evidences remediation
working, and it is why marking a finding `Remediated` by hand deliberately does *not* suppress
the re-test: a fix is confirmed by the finding failing to reappear, not by a status somebody set.

The verdict refuses to congratulate on volume. Closing nine low findings while introducing one
critical is not progress, and a report that reads it as progress misleads the person who
authorised the work.

### How an exception changes a report

Accepting a risk does not delete it. It moves out of the finding counts, the posture
score and the remediation roadmap, and into the client report's **Accepted Risk
Register** — with the justification, the person who accepted it and the review date. A
dismissed false positive is removed from the deliverables outright, and the count of
dismissals is disclosed in the assurance section so the report's silence is accounted
for. Accepted exposure is disclosed, never deleted.

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

Tauri links against each platform's native webview, so the supported path is to build
each installer on the platform it targets.

- **On Windows**, run `scripts\build-windows.ps1`. It checks the toolchain, runs the
  tests, and builds both the `.exe` wizard and the `.msi`.
- **In CI**, the `.github/workflows/release.yml` workflow builds all three platforms.
  Push a `v*` tag to cut a release, or run it manually from the Actions tab and leave
  the platform choice on `windows` for a Windows-only build. **This is what a release
  should use.**
- **From macOS**, `scripts/build-windows-from-macos.sh` produces the Windows `.exe`
  without a Windows machine, using `cargo-xwin` for the MSVC headers and import
  libraries and a local `makensis` for the installer. Tauri labels this experimental;
  it yields an unsigned NSIS installer only, no `.msi`, and nothing in the resulting
  build has been executed on Windows. Good for getting a testable build in front of
  someone quickly, not for cutting a release.

  One trap is worth knowing about: if Homebrew's `rust` formula is installed, its
  `rustc` shadows rustup's on `PATH` and has no Windows sysroot, so the build fails
  with ``can't find crate for `core` `` while `rustup target list --installed` insists
  the target is there. The script puts `~/.cargo/bin` first and refuses to run if the
  wrong `rustc` is still winning.

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
