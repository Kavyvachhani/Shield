# SentinelVAPT — Third-Party Open Source Software Licenses

All dependencies bundled or referenced by SentinelVAPT use permissive open-source licenses (MIT, Apache-2.0, BSD-3-Clause). No GPL, AGPL, or copyleft component is included.

---

## Backend (Rust Crates)

| Dependency | Version | License | Description |
|---|---|---|---|
| `serde` / `serde_json` | 1.0 | MIT / Apache-2.0 | High-performance serialization framework |
| `tokio` | 1.38 | MIT | Asynchronous runtime |
| `reqwest` | 0.12 | MIT / Apache-2.0 | HTTP client |
| `keyring` | 2.3 | MIT / Apache-2.0 | OS keychain abstraction (macOS Security Framework / Linux libsecret) |
| `sha2` | 0.10 | MIT / Apache-2.0 | Cryptographic SHA-256 hashing |
| `uuid` | 1.24 | MIT / Apache-2.0 | Unique identifier generation |
| `chrono` | 0.4 | MIT / Apache-2.0 | Date & time operations |
| `anyhow` / `thiserror` | 1.0 | MIT / Apache-2.0 | Error handling primitives |
| `tauri` / `tauri-build` | 2.0 | MIT / Apache-2.0 | Native desktop application framework |

---

## Frontend (npm Packages)

| Package | Version | License | Description |
|---|---|---|---|
| `react` / `react-dom` | 18.x | MIT | UI library |
| `lucide-react` | 0.x | MIT | Icon set |
| `typescript` | 5.x | Apache-2.0 | Type checker & compiler |
| `vite` | 5.x | MIT | Frontend build tool |
| `@tauri-apps/api` | 2.0 | MIT / Apache-2.0 | Tauri IPC bridge |

---

## License Compliance Statement

SentinelVAPT is licensed under the Apache License 2.0. All bundled third-party libraries have been audited to ensure complete compliance with open-source redistribution policies.
