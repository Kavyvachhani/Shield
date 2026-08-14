//! Proves the native engine actually authenticates over a real socket.
//!
//! Unit tests can only show that a credential produces the right header value.
//! These stand up a server that rejects anonymous requests and assert the probe
//! gets through — and that an unauthenticated probe does not, so the test would
//! fail if the credential were silently dropped.

use sentinel_adapters::credentials::{CredentialKind, TargetCredential};
use sentinel_adapters::native::probe::Probe;
use sentinel_core::models::target::{AuthorizationRecord, ScopeDefinition, Target};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

/// What the server demands before it will serve the protected page.
#[derive(Clone, Copy)]
enum Require {
    /// `Authorization: Basic base64(admin:hunter2)`
    Basic,
    /// `Authorization: Bearer tok-123`
    Bearer,
    /// `Cookie:` containing `session=abc123`
    Cookie,
    /// `X-API-Key: key-123`
    ApiKey,
}

impl Require {
    fn is_satisfied_by(&self, request: &str) -> bool {
        let lower = request.to_ascii_lowercase();
        match self {
            // base64("admin:hunter2")
            Self::Basic => lower.contains("authorization: basic YWRtaW46aHVudGVyMg==".to_ascii_lowercase().as_str()),
            Self::Bearer => lower.contains("authorization: bearer tok-123"),
            Self::Cookie => lower.contains("cookie:") && lower.contains("session=abc123"),
            Self::ApiKey => lower.contains("x-api-key: key-123"),
        }
    }
}

/// Records every request line the server saw, so a test can assert on what was
/// actually sent rather than only on the status it got back.
type Seen = Arc<Mutex<Vec<String>>>;

async fn start_server(require: Require) -> (SocketAddr, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let seen_clone = seen.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let seen = seen_clone.clone();
            tokio::spawn(async move { handle(stream, require, seen).await });
        }
    });

    (addr, seen)
}

async fn handle(mut stream: TcpStream, require: Require, seen: Seen) {
    let mut buf = vec![0u8; 8192];
    let Ok(n) = stream.read(&mut buf).await else { return };
    let request = String::from_utf8_lossy(&buf[..n]).to_string();
    seen.lock().unwrap().push(request.clone());

    let response = if require.is_satisfied_by(&request) {
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html\r\n\
         Content-Length: 38\r\n\
         Connection: close\r\n\
         \r\n\
         <html><body>members only</body></html>"
            .to_string()
    } else {
        "HTTP/1.1 401 Unauthorized\r\n\
         WWW-Authenticate: Basic realm=\"test\"\r\n\
         Content-Length: 12\r\n\
         Connection: close\r\n\
         \r\n\
         unauthorized"
            .to_string()
    };

    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

fn authorized_target(addr: SocketAddr) -> Target {
    Target {
        id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        name: "Auth test".into(),
        target_type: "Web App".into(),
        base_url: format!("http://{addr}"),
        repo_ref: None,
        stack_description: None,
        // Deliberately None: these tests inject the credential directly so they
        // never touch the real OS keychain, which is not available in CI.
        auth_keychain_handle: None,
        authorization_record: Some(AuthorizationRecord {
            id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            scope: ScopeDefinition {
                allowed_domains: vec!["127.0.0.1".into()],
                allowed_ips_cidrs: vec![],
                out_of_scope_paths: vec![],
                rate_limit_rps: 50,
                prohibited_actions: vec![],
            },
            acknowledged_by: "Test".into(),
            signed_at: chrono::Utc::now(),
            roe_document_hash: "hash".into(),
            digital_signature: "sig".into(),
        }),
        created_at: chrono::Utc::now(),
    }
}

fn credential(kind: CredentialKind) -> TargetCredential {
    match kind {
        CredentialKind::Basic => TargetCredential {
            kind,
            username: Some("admin".into()),
            secret: "hunter2".into(),
            header_name: None,
        },
        CredentialKind::Bearer => TargetCredential {
            kind,
            username: None,
            secret: "tok-123".into(),
            header_name: None,
        },
        CredentialKind::Cookie => TargetCredential {
            kind,
            username: None,
            secret: "session=abc123".into(),
            header_name: None,
        },
        CredentialKind::Header => TargetCredential {
            kind,
            username: None,
            secret: "key-123".into(),
            header_name: Some("X-API-Key".into()),
        },
    }
}

async fn status_with(require: Require, cred: Option<TargetCredential>) -> (u16, Seen) {
    let (addr, seen) = start_server(require).await;
    let target = authorized_target(addr);
    let probe = Probe::with_credential(&target, 50, 10, cred).expect("probe");
    let response = probe
        .get(&format!("http://{addr}/"))
        .await
        .expect("request errored")
        .expect("no response — the URL was refused as out of scope");
    (response.status, seen)
}

/// The control: without a credential the protected page must stay closed. If
/// this ever returns 200 the other tests prove nothing.
#[tokio::test]
async fn without_a_credential_the_protected_page_is_refused() {
    let (status, _) = status_with(Require::Basic, None).await;
    assert_eq!(status, 401, "an anonymous probe must not reach the page");
}

#[tokio::test]
async fn basic_credentials_reach_the_protected_page() {
    let (status, seen) = status_with(Require::Basic, Some(credential(CredentialKind::Basic))).await;
    assert_eq!(status, 200, "username and password did not authenticate");

    let requests = seen.lock().unwrap();
    assert!(
        requests[0].to_ascii_lowercase().contains("authorization: basic"),
        "no Basic Authorization header was sent"
    );
}

#[tokio::test]
async fn a_bearer_token_reaches_the_protected_page() {
    let (status, _) = status_with(Require::Bearer, Some(credential(CredentialKind::Bearer))).await;
    assert_eq!(status, 200, "the bearer token did not authenticate");
}

/// The mode that matters for a normal form-login app: the analyst pastes a
/// session cookie from an already-logged-in browser.
#[tokio::test]
async fn a_session_cookie_reaches_the_protected_page() {
    let (status, _) = status_with(Require::Cookie, Some(credential(CredentialKind::Cookie))).await;
    assert_eq!(status, 200, "the session cookie did not authenticate");
}

#[tokio::test]
async fn a_custom_api_key_header_reaches_the_protected_page() {
    let (status, _) = status_with(Require::ApiKey, Some(credential(CredentialKind::Header))).await;
    assert_eq!(status, 200, "the API key header did not authenticate");
}

/// Authenticating must not widen what the engine is allowed to do: the method
/// allow-list is enforced regardless of credentials.
#[tokio::test]
async fn credentials_do_not_unlock_unsafe_methods() {
    let (addr, _) = start_server(Require::Basic).await;
    let target = authorized_target(addr);
    let probe = Probe::with_credential(&target, 50, 10, Some(credential(CredentialKind::Basic)))
        .expect("probe");

    for method in ["POST", "PUT", "DELETE", "PATCH"] {
        let result = probe.request(method, &format!("http://{addr}/"), &[]).await;
        assert!(
            result.is_err(),
            "{method} must stay refused even for an authenticated scan"
        );
    }
}

/// A credential must not follow the scan off-scope.
#[tokio::test]
async fn an_out_of_scope_host_is_still_refused_when_authenticated() {
    let (addr, _) = start_server(Require::Basic).await;
    let target = authorized_target(addr);
    let probe = Probe::with_credential(&target, 50, 10, Some(credential(CredentialKind::Basic)))
        .expect("probe");

    let result = probe
        .get("http://example.com/")
        .await
        .expect("scope refusal is not an error");
    assert!(
        result.is_none(),
        "an out-of-scope host must be refused before a socket is opened"
    );
}

#[tokio::test]
async fn the_probe_reports_how_it_is_authenticating_without_the_secret() {
    let (addr, _) = start_server(Require::Basic).await;
    let target = authorized_target(addr);

    let anonymous = Probe::with_credential(&target, 50, 10, None).expect("probe");
    assert!(!anonymous.is_authenticated());
    assert!(anonymous.auth_description().is_none());

    let probe = Probe::with_credential(&target, 50, 10, Some(credential(CredentialKind::Basic)))
        .expect("probe");
    assert!(probe.is_authenticated());
    let described = probe.auth_description().expect("a description");
    assert!(described.contains("admin"));
    assert!(!described.contains("hunter2"), "the secret leaked into the description");
}
