# SentinelVAPT — Third-Party Open Source Software Licenses

All dependencies bundled or referenced by SentinelVAPT use permissive open-source licenses (MIT, Apache-2.0, BSD-3-Clause, ISC). No GPL, AGPL, or copyleft component is included.

Versions below reflect the resolved versions in `Cargo.lock` and `apps/desktop/package-lock.json` for release 0.2.1.

---

## Backend (Rust Crates)

| Dependency | Version | License | Description |
|---|---|---|---|
| `serde` / `serde_json` | 1.0.229 | MIT / Apache-2.0 | High-performance serialization framework |
| `tokio` | 1.53.1 | MIT | Asynchronous runtime |
| `reqwest` | 0.12.28 | MIT / Apache-2.0 | HTTP client |
| `keyring` | 2.3.3 | MIT / Apache-2.0 | OS keychain abstraction (macOS Security Framework / Linux libsecret) |
| `rusqlite` | 0.32.1 | MIT | SQLite bindings for engagement persistence |
| `sha2` | 0.10.9 | MIT / Apache-2.0 | Cryptographic SHA-256 hashing |
| `uuid` | 1.24.0 | MIT / Apache-2.0 | Unique identifier generation |
| `chrono` | 0.4.45 | MIT / Apache-2.0 | Date & time operations |
| `anyhow` / `thiserror` | 1.0 | MIT / Apache-2.0 | Error handling primitives |
| `tauri` / `tauri-build` | 2.11.5 | MIT / Apache-2.0 | Native desktop application framework |

---

## Frontend (npm Packages)

| Package | Version | License | Description |
|---|---|---|---|
| `react` / `react-dom` | 19.2.8 | MIT | UI library |
| `recharts` | 3.10.1 | MIT | Charting library for report visualisations |
| `lucide-react` | 1.27.0 | ISC | Icon set |
| `tailwind-merge` | 3.6.0 | MIT | Class name merging utility |
| `typescript` | 6.0.3 | Apache-2.0 | Type checker & compiler |
| `vite` | 8.1.5 | MIT | Frontend build tool |
| `oxlint` | 1.76.0 | MIT | Linter (development only) |
| `@tauri-apps/api` | 2.11.1 | MIT / Apache-2.0 | Tauri IPC bridge |
| `@tauri-apps/cli` | 2.11.4 | MIT / Apache-2.0 | Tauri build tooling (development only) |

---

## External Scanner Engines

SentinelVAPT invokes the following tools if the user has installed them. They are **not**
bundled or redistributed with the application, and each remains under its own license.

| Engine | License |
|---|---|
| Semgrep | LGPL-2.1 (invoked as a separate process; not linked or redistributed) |
| Trivy | Apache-2.0 |
| Gitleaks | MIT |
| OWASP ZAP | Apache-2.0 |
| Nuclei | MIT |

---

## License Compliance Statement

SentinelVAPT is licensed under the Apache License 2.0 — see [LICENSE](LICENSE). All bundled third-party libraries have been audited to ensure complete compliance with open-source redistribution policies.
