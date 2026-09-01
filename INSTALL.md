# SentinelVAPT — Installation & User Guide

**SentinelVAPT** is a local-first, offline-capable web application security assessment
and reporting workbench. It orchestrates open-source scanners, normalises and
de-duplicates their output, ranks findings by real-world risk, and produces two
deliverables from one assessment: a client-facing report and a developer remediation guide.

---

## Getting the Windows installer

Tauri applications link against each platform's native webview, so a Windows `.exe`
must be built on Windows — it cannot be cross-compiled from macOS or Linux.

### Option A — build it in CI (recommended)

The repository ships `.github/workflows/release.yml`, which builds installers for
all three platforms.

```bash
git push origin main          # then, to cut a release:
git tag v0.3.0 && git push origin v0.3.0
```

A tag build attaches the installers to a GitHub Release, so they get a permanent
download link instead of expiring with the run's artifacts.

To get just a Windows build without waiting on macOS and Linux, trigger it
manually: **Actions → Build Installers → Run workflow**, leaving the platform
choice on `windows`.

Download from the run's artifacts:

| Artifact | Contents |
|---|---|
| `sentinelvapt-windows` | `SentinelVAPT_0.3.0_x64-setup.exe` (NSIS wizard) and `SentinelVAPT_0.3.0_x64_en-US.msi` (for Intune / Group Policy) |
| `sentinelvapt-macos` | `SentinelVAPT_0.3.0_universal.dmg` |
| `sentinelvapt-linux` | `.deb` and `.AppImage` |

### Option B — build on a Windows machine

Prerequisites:

1. [Rust](https://rustup.rs/) (stable, MSVC toolchain)
2. [Node.js 20+](https://nodejs.org/)
3. **Microsoft Visual Studio Build Tools** with the *Desktop development with C++* workload
4. WebView2 runtime — already present on Windows 11 and current Windows 10; the
   installer downloads it automatically if missing

```powershell
git clone <your-repo-url> SentinelVAPT
cd SentinelVAPT
powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1
```

The script verifies the toolchain first and tells you exactly what is missing
rather than failing part-way through a long build. It then installs the frontend
dependencies, runs the test suite, builds both installers, and prints where they
landed. Pass `-SkipTests` to skip the Rust suite.

To drive the build by hand instead:

```powershell
cd SentinelVAPT\apps\desktop
npm ci
npm run tauri build -- --bundles nsis,msi
```

The installer lands in `target\release\bundle\nsis\`.

### Installing on Windows

Run the `.exe`. The setup wizard walks through a welcome page, the Apache 2.0
licence, the install location, and a finish page that offers to launch the app.

It installs per-user by default, so no administrator rights are needed. For a
per-machine rollout, deploy the `.msi` through Intune or Group Policy instead.
The build is not code-signed, so SmartScreen shows a warning on first run — choose
**More info → Run anyway**. To remove the warning for wider distribution, sign the
binary with an EV code-signing certificate and set `signCommand` in `tauri.conf.json`.

### macOS

Open the `.dmg`, drag **SentinelVAPT** to Applications. On first launch, right-click
the app → **Open** → **Open** to bypass Gatekeeper on the unsigned build.

### Linux

```bash
sudo apt install -y ./sentinel-desktop_0.3.0_amd64.deb
# or
chmod +x SentinelVAPT_0.3.0_amd64.AppImage && ./SentinelVAPT_0.3.0_amd64.AppImage
```

---

## Scanner engines

SentinelVAPT ships **Sentinel Native**, a built-in check engine that requires no
installation and works on a fresh machine. Everything below is optional and extends
coverage further. A missing engine is **skipped, not failed** — the coverage matrix
records which WSTG cases went unanswered because of it, so the gap is visible in the
report rather than silently absent.

Two pairs are deliberately run together rather than one instead of the other:

- **Trivy + OSV-Scanner** use different vulnerability databases. A CVE both report is a
  stronger claim than one either reports alone, and deduplication raises the finding's
  reachability when two engines confirm it.
- **Sentinel Native + testssl.sh** split TLS between them. The built-in engine reads the
  certificate — validity, hostname, expiry, signature strength. testssl.sh establishes what
  the server will actually *negotiate*, which takes dozens of handshakes: protocol versions,
  cipher suites, forward secrecy, and the named attacks that come up in every assessment.
- **Gitleaks + TruffleHog** answer different questions. Gitleaks finds strings that look
  like credentials; TruffleHog asks the provider whether they still authenticate. A
  verified secret is Critical and cannot be an example key or a rotated one — which is
  what makes the rest of the secret findings triageable.

| Engine | Type | Ships with the app? | Install |
|---|---|---|---|
| **Sentinel Native** | 67 checks: headers, TLS, cookies, cross-origin isolation, CORS, exposure, content, information disclosure | ✅ Built in | — |
| **Semgrep** | SAST — source code | No | `pip install semgrep` |
| **Trivy** | SCA — dependency CVEs | No | `winget install AquaSecurity.Trivy` · `brew install trivy` |
| **Gitleaks** | Secret detection | No | `winget install Gitleaks.Gitleaks` · `brew install gitleaks` |
| **OWASP ZAP** | DAST — active scanning | No | [zaproxy.org](https://www.zaproxy.org/download/), run `zap.sh -daemon` |
| **Nuclei** | DAST — template scanning | No | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **OSV-Scanner** | SCA — a second vulnerability database | No | `go install github.com/google/osv-scanner/cmd/osv-scanner@v1` · `brew install osv-scanner` |
| **TruffleHog** | Secrets — verified against the provider | No | `brew install trufflehog` · [releases](https://github.com/trufflesecurity/trufflehog/releases) |
| **retire.js** | Vulnerable client-side JS libraries | No | `npm install -g retire` |
| **Nikto** | Web server misconfiguration and forgotten files | No | `brew install nikto` · `apt install nikto` |
| **testssl.sh** | Deep TLS — protocols, ciphers, named attacks | No | `brew install testssl` · [testssl.sh](https://testssl.sh/) |
| **Checkov** | Infrastructure-as-code (Terraform, K8s, Docker) | No | `pip install checkov` · `brew install checkov` |

SentinelVAPT finds these automatically on PATH, and also checks the conventional
install locations — Chocolatey and Scoop shims, `%ProgramFiles%`, `~/go/bin`,
Homebrew, snap and pipx directories. Nothing needs adding to PATH manually.

The **Coverage** screen shows exactly which checks each missing engine would unlock,
so you can decide whether installing it is worth it for a given engagement.

---

## Scanning behind a login

Most of an application sits behind a sign-in page, so an unauthenticated scan only
ever sees the front door. On the target setup step you can supply credentials, and
the native engine will then assess the authenticated pages too.

| Mode | Use it when | What to enter |
|---|---|---|
| **Session cookie** | The app has a normal login form. **This is usually the right one.** | Log in with your browser, open DevTools → Application → Cookies, copy the session cookie — e.g. `session=abc123` |
| **Username & password** | The app uses HTTP Basic (the browser popup, not a login page) | The username and password |
| **Bearer token** | REST/GraphQL APIs, JWT-based apps | The token — sent as `Authorization: Bearer <token>` |
| **API key header** | The API expects a custom header | The header name (default `X-API-Key`) and the key |

The engine cannot submit a login form itself, because doing so would mean sending a
POST — and it is restricted to `GET`, `HEAD` and `OPTIONS` by design. Pasting a
session cookie from a browser you have already logged into achieves the same result
without relaxing that guarantee. For full form-login automation, configure ZAP,
which drives a real login sequence.

**How the secret is handled**

- It goes to the OS keychain — macOS Keychain, Windows Credential Manager, Linux
  libsecret. Only an opaque handle is written to the engagement database, so the
  `.db` file can be copied or backed up without carrying the password.
- The app never reads it back to the screen. It can be replaced or removed, not viewed.
- `Authorization` and `Cookie` are redacted before any evidence reaches a report.
- Authenticating widens what the engine can **read**, never what it can change: the
  `GET`/`HEAD`/`OPTIONS` restriction still applies, and out-of-scope hosts are still
  refused.

Use an account created for testing rather than a real user's, and expect the scan to
generate activity in that account's audit log.

---

## Running an assessment

1. **Project Setup** — enter the client name and the target application URL.
2. **Auth Gate** — define the scope (allowed domains, excluded paths, request rate
   ceiling), complete the attestation checklist and sign the Rules of Engagement.
   This is mandatory: no dynamic testing runs without it, and the gate cannot be
   disabled by configuration.
3. **Scan Console** — start the pipeline and watch stages stream live. Missing
   scanners are skipped with an explanation rather than failing the run.

   **Engine config** opens a JSON panel for per-scan tuning; leave it blank and the
   defaults apply. Note that `rateLimitRps` is a ceiling *request* — the engine takes
   the lower of it and the rate in the signed RoE, so it can slow a scan but never
   speed it past what was agreed. The native engine's discovery is tunable here too:

   ```json
   {
     "crawl": { "enabled": true, "maxPages": 120, "maxDepth": 3,
                "budgetSeconds": 300, "maxLinksPerPage": 60 }
   }
   ```

   Raise `maxPages` and `maxDepth` for a thorough assessment of a large application;
   set `enabled` to `false` to assess only the entry page as a quick smoke test.
4. **Findings** — review findings ranked by priority score
   (CVSS 4.0 × EPSS × CISA KEV × reachability × exposure), filter, and triage. Each
   finding shows a validation confidence: what it was determined from, and the
   condition that would make it a false positive.

   Marking a finding **False Positive** or **Accepted Risk** records an exception
   against the target. It is applied automatically to every later scan, so the same
   weakness is triaged once rather than once per run — press **Exceptions** in the
   filter bar to see the register, and **Withdraw** to put a weakness back in the
   queue. An acceptance can carry a review date; when it passes, the exception lapses
   and the finding returns to the open list on the next scan.
5. **Coverage** — see every WSTG test case and its result, including checks that
   passed and those still needing manual analysis.
6. **Reports** — generate and export the deliverables.

---

## Reports

| Deliverable | Audience | Contents |
|---|---|---|
| **Client Report** | Business owners, auditors | Document control and sign-off, posture score, the controls that were verified and what each protects against, plain-language risks, the accepted-risk register, remediation roadmap with timeframes, compliance alignment, standards conformance and evidence handling, a stated limitations section, and the full coverage matrix showing every check performed |
| **Developer Report** | Engineers | A false-positive handling guide, then one section per finding: location, CVSS 4.0 vector, CWE/OWASP/WSTG mapping, validation confidence and what would make it wrong, reproduction steps, sanitized evidence, the fix and how to verify it. Closes with the accepted risks and the dismissals, so nothing is suppressed silently |
| **Markdown** | Issue trackers | The developer report as Markdown — paste into Jira, Linear or GitHub |
| **SARIF 2.1.0** | CI/CD | For GitHub code scanning and other SARIF consumers |
| **JSON** | Archival | Complete assessment data including the coverage matrix |

Both HTML reports are fully self-contained — inline styles, inline SVG charts, no
scripts and no network requests — so they render offline and survive being emailed.

### Adding the client's logo

In **Report Builder → Branding & Attribution**, choose **Upload logo** and pick the
client's image. It appears at the top of both the client and developer reports.

- **Accepted:** PNG, JPEG, GIF and WebP, up to 2 MB.
- **Not accepted:** SVG, and any remote URL. SVG can carry script, and a remote
  image would leak the reader's IP address and render blank without a network —
  neither belongs in a confidential security report.
- The logo is embedded directly in the HTML, so it still displays offline and
  when the file is forwarded on.
- It is saved with the engagement, so you upload it once and every later report
  for that client is branded automatically. **Remove** clears it.

**To produce a PDF:** open the exported HTML in any browser and choose
**Print → Save as PDF**. The stylesheet already sets A4 sizing, margins and page breaks.

---

## Safety guarantees

- Dynamic testing is blocked until a Rules of Engagement record is signed.
- The native engine issues only `GET`, `HEAD` and `OPTIONS` — enforced in code, not
  by configuration. No payload, fuzzing or brute-force request is ever sent.
- Requests are rate-limited to the ceiling recorded in the signed RoE.
- Out-of-scope hosts and paths are refused before a socket is opened, and redirects
  are observed rather than followed, so a redirect cannot pull the scanner off-scope.
- Nuclei runs with `-etags dos,fuzzing,intrusive` and `-no-interactsh` regardless of
  user configuration.
- Credentials, session cookies and authorization headers are redacted before any
  evidence reaches a report.
- No telemetry. Everything stays on the machine.

---

## Honest limits

Automated testing reliably finds configuration and known-pattern weaknesses. It
cannot fully evaluate business logic, authorisation between user accounts, or
multi-step workflow abuse. Those test cases are marked **Manual review required** in
the coverage matrix rather than being silently counted as passed — a clean automated
result is evidence of good hygiene, not proof that no weakness exists.
