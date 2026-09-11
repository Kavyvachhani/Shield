//! Multi-User Identity Context for Authorization & BOLA Testing.
//!
//! Production security verification requires assessing applications under multiple
//! concurrent identities (User A, User B, Admin, Anonymous) to verify that
//! tenant boundary isolation and object-level permissions are strictly enforced.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRole {
    Admin,
    UserA,
    UserB,
    Anonymous,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserIdentity {
    pub name: String,
    pub role: IdentityRole,
    pub token: Option<String>,
    pub cookies: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
}

impl UserIdentity {
    pub fn new(name: impl Into<String>, role: IdentityRole) -> Self {
        Self {
            name: name.into(),
            role,
            token: None,
            cookies: Vec::new(),
            headers: Vec::new(),
        }
    }

    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        let t = token.into();
        self.headers.push(("Authorization".into(), format!("Bearer {t}")));
        self.token = Some(t);
        self
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_cookie(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.cookies.push((name.into(), value.into()));
        self
    }

    /// Build Cookie header string if cookies are present.
    pub fn cookie_header(&self) -> Option<String> {
        if self.cookies.is_empty() {
            None
        } else {
            Some(
                self.cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityContext {
    pub user_a: Option<UserIdentity>,
    pub user_b: Option<UserIdentity>,
    pub admin: Option<UserIdentity>,
    pub anonymous: Option<UserIdentity>,
}

impl IdentityContext {
    pub fn new() -> Self {
        Self {
            user_a: None,
            user_b: None,
            admin: None,
            anonymous: Some(UserIdentity::new("Anonymous", IdentityRole::Anonymous)),
        }
    }

    pub fn has_multi_user(&self) -> bool {
        self.user_a.is_some() && self.user_b.is_some()
    }
}
