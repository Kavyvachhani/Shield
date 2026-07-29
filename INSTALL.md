# SentinelVAPT — Installation & User Guide

**SentinelVAPT** is a local-first, offline-capable defensive AppSec orchestration and reporting workbench.

---

## Prerequisites (User-Installed Scanner Tools)

SentinelVAPT does **NOT** bundle scanner tools. Install the tools you wish to orchestrate:

| Scanner Tool | Purpose | Installation |
|---|---|---|
| **Semgrep** | SAST static analysis | `pip install semgrep` or `brew install semgrep` |
| **Trivy** | SCA & dependency audit | `brew install trivy` or `apt install trivy` |
| **Gitleaks** | Secret leak scanning | `brew install gitleaks` or `go install github.com/gitleaks/gitleaks/v8@latest` |
| **OWASP ZAP** | Web DAST spider & active scan | Download from [zaproxy.org](https://www.zaproxy.org/download/) (`zap.sh -daemon`) |
| **Nuclei** | Vulnerability template DAST | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

---

## Operating System Installation

### macOS (Apple Silicon / Intel)

1. Download `SentinelVAPT-0.1.0.dmg` or `SentinelVAPT.app`.
2. Drag `SentinelVAPT.app` to your `/Applications` folder.
3. **First-Run Gatekeeper Bypass** (Self-signed binary):
   - Right-click `SentinelVAPT.app` in Finder → Select **Open**.
   - Click **Open** on the macOS security prompt.
   *(Apple Developer Notarization: For enterprise deployment, sign with your Developer ID certificate via `codesign` and `xcrun notarytool`.)*

### Ubuntu Linux (24.04 LTS / Debian)

#### Package Installation (.deb)
```bash
sudo apt update
sudo apt install -y ./sentinel-desktop_0.1.0_amd64.deb
```

#### AppImage Execution
```bash
chmod +x SentinelVAPT-0.1.0.AppImage
./SentinelVAPT-0.1.0.AppImage
```

---

## First-Run Engagement Steps

1. Launch **SentinelVAPT Security Workbench**.
2. **Project Setup**: Click **New Project** → Enter Company Name & Target Application URL (e.g., `http://localhost:3000`).
3. **Authorization Gate (RoE)**:
   - Configure allowed domains and out-of-scope paths.
   - Complete the 4-item attestation checklist.
   - Sign the Rules of Engagement (RoE). The server-side SHA-256 hash will unlock DAST capabilities.
4. **Live Scan Console**: Click **Start Assessment Pipeline**. Monitor live stage progress and log stream.
5. **Findings Workbench**: Review deduplicated findings sorted by Priority Score (CVSS4 × EPSS × KEV × Reachability).
6. **Report Builder**: Generate and export branded **Executive Summary (Report A)** or **Developer Remediation Guide (Report B)**.
