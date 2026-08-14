//! Per-target scan credentials, held in the OS keychain.
//!
//! Most of an application is behind a login, so an unauthenticated scan only
//! ever sees the front door. Supplying credentials lets the native engine
//! assess the pages that actually matter — session cookie flags on a real
//! session, headers on authenticated responses, exposure of authenticated-only
//! endpoints.
//!
//! STORAGE
//! ───────
//! The secret goes to the OS keychain (macOS Keychain, Windows Credential
//! Manager, Linux libsecret) under a per-target handle. Only that handle is
//! written to the engagement database, so the SQLite file can be copied or
//! backed up without carrying the password with it. This mirrors the rule the
//! schema already states: "OS Keyring handle ONLY, NO plaintext secrets".
//!
//! SAFETY
//! ──────
//! Credentials are applied as request headers only. The native engine still
//! issues nothing but GET, HEAD and OPTIONS, so authenticating widens what can
//! be *read*, never what can be changed. Injected values are request-side, and
//! `ProbeResponse::evidence_summary` redacts `authorization` and `cookie` on the
//! response side, so a secret cannot reach a report.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Keychain service name under which every credential is filed.
const KEYCHAIN_SERVICE: &str = "SentinelVAPT";

/// How the credential is presented to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// HTTP Basic — `Authorization: Basic base64(user:pass)`.
    Basic,
    /// `Authorization: Bearer <token>` for APIs and JWT-based apps.
    Bearer,
    /// A session cookie copied from an already-logged-in browser. This is the
    /// one that works against a normal form-login app, because the engine
    /// cannot POST a login form itself.
    Cookie,
    /// An arbitrary header, for APIs using `X-API-Key` and similar.
    Header,
}

impl CredentialKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Bearer => "bearer",
            Self::Cookie => "cookie",
            Self::Header => "header",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "basic" => Self::Basic,
            "bearer" => Self::Bearer,
            "cookie" => Self::Cookie,
            "header" => Self::Header,
            other => {
                return Err(anyhow!(
                    "unknown credential kind '{other}'; expected basic, bearer, cookie or header"
                ))
            }
        })
    }
}

/// A credential for one target. `secret` is only ever held in memory during a
/// scan; at rest it lives in the OS keychain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetCredential {
    pub kind: CredentialKind,
    /// Username, for `Basic`. Unused by the other kinds.
    #[serde(default)]
    pub username: Option<String>,
    /// Password, token, or cookie string depending on `kind`.
    pub secret: String,
    /// Header name, for `Header`. Defaults to `X-API-Key`.
    #[serde(default)]
    pub header_name: Option<String>,
}

impl TargetCredential {
    /// Reject a credential that cannot produce a usable header, so the failure
    /// surfaces when the analyst saves it rather than silently mid-scan.
    pub fn validate(&self) -> Result<()> {
        if self.secret.trim().is_empty() {
            return Err(anyhow!("the credential secret is empty"));
        }
        match self.kind {
            CredentialKind::Basic => {
                let user = self.username.as_deref().unwrap_or("").trim();
                if user.is_empty() {
                    return Err(anyhow!("HTTP Basic needs a username"));
                }
                if user.contains(':') {
                    // RFC 7617 splits on the first colon, so a colon in the
                    // username silently truncates the credential.
                    return Err(anyhow!("an HTTP Basic username cannot contain ':'"));
                }
            }
            CredentialKind::Header => {
                if let Some(name) = self.header_name.as_deref() {
                    if name.trim().is_empty() {
                        return Err(anyhow!("the header name is empty"));
                    }
                    if !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                    {
                        return Err(anyhow!(
                            "header name '{name}' may only contain letters, digits, '-' and '_'"
                        ));
                    }
                }
            }
            CredentialKind::Bearer | CredentialKind::Cookie => {}
        }
        Ok(())
    }

    /// The header name this credential sets, for `Bearer`, `Cookie` and
    /// `Header`. `Basic` is applied by the HTTP client itself.
    pub fn header(&self) -> Option<(String, String)> {
        match self.kind {
            CredentialKind::Basic => None,
            CredentialKind::Bearer => Some((
                "Authorization".into(),
                format!("Bearer {}", self.secret.trim()),
            )),
            CredentialKind::Cookie => Some(("Cookie".into(), self.secret.trim().into())),
            CredentialKind::Header => Some((
                self.header_name
                    .clone()
                    .unwrap_or_else(|| "X-API-Key".into()),
                self.secret.trim().into(),
            )),
        }
    }

    /// A description safe to show in the UI and write to logs — never the secret.
    pub fn describe(&self) -> String {
        match self.kind {
            CredentialKind::Basic => format!(
                "HTTP Basic as '{}'",
                self.username.as_deref().unwrap_or("?")
            ),
            CredentialKind::Bearer => "Bearer token".into(),
            CredentialKind::Cookie => "Session cookie".into(),
            CredentialKind::Header => format!(
                "Header '{}'",
                self.header_name.as_deref().unwrap_or("X-API-Key")
            ),
        }
    }

    /// The keychain handle for a target. Stable, so re-saving replaces.
    pub fn handle_for(target_id: &str) -> String {
        format!("target-credential:{target_id}")
    }

    pub fn store(&self, handle: &str) -> Result<()> {
        self.validate()?;
        let payload = serde_json::to_string(self).context("could not encode the credential")?;
        entry(handle)?
            .set_password(&payload)
            .map_err(|e| anyhow!("could not save the credential to the OS keychain: {e}"))
    }

    /// Load a credential, or `Ok(None)` when none is stored for this handle.
    ///
    /// A keychain miss is not an error: a target simply may not have
    /// credentials, and a scan must still run unauthenticated in that case.
    pub fn load(handle: &str) -> Result<Option<Self>> {
        let entry = entry(handle)?;
        match entry.get_password() {
            Ok(raw) => {
                let cred: Self = serde_json::from_str(&raw)
                    .context("the stored credential could not be decoded")?;
                Ok(Some(cred))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!("could not read the OS keychain: {e}")),
        }
    }

    /// Remove a credential. Removing one that is not there is a success.
    pub fn delete(handle: &str) -> Result<()> {
        match entry(handle)?.delete_password() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!("could not remove the credential: {e}")),
        }
    }
}

fn entry(handle: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(KEYCHAIN_SERVICE, handle)
        .map_err(|e| anyhow!("could not open the OS keychain: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(user: &str, pass: &str) -> TargetCredential {
        TargetCredential {
            kind: CredentialKind::Basic,
            username: Some(user.into()),
            secret: pass.into(),
            header_name: None,
        }
    }

    #[test]
    fn basic_is_applied_by_the_client_not_as_a_header() {
        // reqwest encodes Basic itself; emitting our own header too would send
        // the credential twice.
        assert!(basic("admin", "hunter2").header().is_none());
    }

    #[test]
    fn bearer_and_cookie_produce_the_expected_headers() {
        let bearer = TargetCredential {
            kind: CredentialKind::Bearer,
            username: None,
            secret: "  tok123  ".into(),
            header_name: None,
        };
        assert_eq!(
            bearer.header(),
            Some(("Authorization".into(), "Bearer tok123".into()))
        );

        let cookie = TargetCredential {
            kind: CredentialKind::Cookie,
            username: None,
            secret: "session=abc; other=1".into(),
            header_name: None,
        };
        assert_eq!(
            cookie.header(),
            Some(("Cookie".into(), "session=abc; other=1".into()))
        );
    }

    #[test]
    fn a_custom_header_defaults_to_x_api_key() {
        let cred = TargetCredential {
            kind: CredentialKind::Header,
            username: None,
            secret: "k".into(),
            header_name: None,
        };
        assert_eq!(cred.header().unwrap().0, "X-API-Key");
    }

    #[test]
    fn an_empty_secret_is_rejected() {
        let mut cred = basic("admin", "");
        assert!(cred.validate().is_err());
        cred.secret = "   ".into();
        assert!(cred.validate().is_err());
    }

    #[test]
    fn basic_requires_a_username_without_a_colon() {
        assert!(basic("", "pw").validate().is_err());
        // RFC 7617 splits on the first colon, so this would silently truncate.
        assert!(basic("ad:min", "pw").validate().is_err());
        assert!(basic("admin", "pw").validate().is_ok());
    }

    #[test]
    fn a_malformed_header_name_is_rejected() {
        let cred = TargetCredential {
            kind: CredentialKind::Header,
            username: None,
            secret: "k".into(),
            header_name: Some("X API Key".into()),
        };
        assert!(cred.validate().is_err(), "a space would break the header");
    }

    #[test]
    fn describe_never_contains_the_secret() {
        let cred = basic("admin", "hunter2");
        assert!(!cred.describe().contains("hunter2"));
        assert!(cred.describe().contains("admin"));

        let bearer = TargetCredential {
            kind: CredentialKind::Bearer,
            username: None,
            secret: "supersecrettoken".into(),
            header_name: None,
        };
        assert!(!bearer.describe().contains("supersecrettoken"));
    }

    #[test]
    fn the_handle_is_stable_and_target_scoped() {
        assert_eq!(
            TargetCredential::handle_for("t-1"),
            TargetCredential::handle_for("t-1")
        );
        assert_ne!(
            TargetCredential::handle_for("t-1"),
            TargetCredential::handle_for("t-2")
        );
    }

    #[test]
    fn kinds_round_trip_through_their_string_form() {
        for kind in [
            CredentialKind::Basic,
            CredentialKind::Bearer,
            CredentialKind::Cookie,
            CredentialKind::Header,
        ] {
            assert_eq!(CredentialKind::parse(kind.as_str()).unwrap(), kind);
        }
        assert!(CredentialKind::parse("ntlm").is_err());
    }
}
