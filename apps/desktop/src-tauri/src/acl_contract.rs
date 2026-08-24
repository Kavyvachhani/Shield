//! Guards the Tauri v2 capability grants the frontend depends on.
//!
//! Tauri v2 denies every core-plugin call from a webview unless a capability
//! file grants it. The app shipped with no `capabilities/` directory at all, so
//! the generated capability set was literally `{}` and `listen()` was refused by
//! the ACL on every call.
//!
//! Nothing caught it. Commands declared in `generate_handler!` are *not*
//! ACL-gated, so `trigger_scan` was accepted, spawned its pipeline and ran to
//! completion — while all four of its event subscriptions had been rejected and
//! the console sat silent until a 20-second watchdog blamed a second copy of the
//! app. Both halves of the feature worked; only the channel between them was
//! shut, and no test could see it.
//!
//! These tests assert the capability files still grant what the frontend calls,
//! so removing or narrowing them fails here rather than in front of an analyst
//! mid-engagement.

use serde_json::Value;
use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn capability_files() -> Vec<(String, Value)> {
    let dir = manifest_dir().join("capabilities");
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!(
            "capabilities/ must exist at {} — without it Tauri grants the webview \
             nothing and every listen() call is denied by the ACL ({e})",
            dir.display()
        )
    });

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = std::fs::read_to_string(&path).expect("capability file must be readable");
        let json: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()));
        out.push((path.display().to_string(), json));
    }
    assert!(!out.is_empty(), "capabilities/ contains no .json capability files");
    out
}

fn tauri_conf() -> Value {
    let path = manifest_dir().join("tauri.conf.json");
    let raw = std::fs::read_to_string(&path).expect("tauri.conf.json must be readable");
    serde_json::from_str(&raw).expect("tauri.conf.json must be valid JSON")
}

/// Permissions that grant `event.listen`, either directly or through a set that
/// contains it. `core:default` includes `core:event:default`, which includes
/// `allow-listen`.
const GRANTS_EVENT_LISTEN: &[&str] = &[
    "core:default",
    "core:event:default",
    "core:event:allow-listen",
];

#[test]
fn some_capability_grants_event_listen() {
    let granted: Vec<String> = capability_files()
        .iter()
        .flat_map(|(_, c)| {
            c["permissions"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|p| p.as_str().map(str::to_string))
        })
        .collect();

    assert!(
        granted.iter().any(|p| GRANTS_EVENT_LISTEN.contains(&p.as_str())),
        "no capability grants event.listen (looked for one of {GRANTS_EVENT_LISTEN:?}, \
         found {granted:?}). The scan console receives every stage update, log line, \
         completion and error over the event channel — without this permission a scan \
         runs to completion and reports nothing."
    );
}

/// A capability only applies to the windows it names. If the window label in
/// tauri.conf.json and the label in the capability drift apart, the grant
/// silently applies to nothing — the same failure with a different cause.
#[test]
fn every_configured_window_is_covered_by_a_capability() {
    let conf = tauri_conf();
    let windows = conf["app"]["windows"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!windows.is_empty(), "tauri.conf.json declares no windows");

    let caps = capability_files();

    for window in &windows {
        // Tauri defaults an unlabelled window to "main".
        let label = window["label"].as_str().unwrap_or("main");

        let covered = caps.iter().any(|(_, c)| match c["windows"].as_array() {
            // A capability with no `windows` key applies to every window.
            None => true,
            Some(list) => list.iter().filter_map(|w| w.as_str()).any(|pattern| {
                pattern == label
                    || pattern == "*"
                    || pattern
                        .strip_suffix('*')
                        .is_some_and(|prefix| label.starts_with(prefix))
            }),
        });

        assert!(
            covered,
            "window '{label}' is not covered by any capability — its webview would be \
             granted nothing. Add it to a capability's `windows` list."
        );
    }
}

/// `getVersion()` in App.tsx is a core-plugin call too, and it fails the same
/// silent way — it has a `.catch` that renders the version as "unknown", which
/// is a much quieter symptom than a dead scan console but the same root cause.
#[test]
fn some_capability_grants_the_app_version() {
    let granted: Vec<String> = capability_files()
        .iter()
        .flat_map(|(_, c)| {
            c["permissions"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|p| p.as_str().map(str::to_string))
        })
        .collect();

    const GRANTS_VERSION: &[&str] = &["core:default", "core:app:default", "core:app:allow-version"];
    assert!(
        granted.iter().any(|p| GRANTS_VERSION.contains(&p.as_str())),
        "no capability grants app.getVersion (looked for one of {GRANTS_VERSION:?}, \
         found {granted:?}); the title bar would silently read 'unknown'."
    );
}

/// The strongest form of this guard: build the real app under Tauri's mock
/// runtime and push an actual `plugin:event|listen` call through the same IPC
/// entry point the webview uses.
///
/// The tests above read the capability JSON, which is a statement of intent.
/// This one exercises the machinery that actually denied the call: the
/// capability is compiled in by `generate_context!`, resolved against the core
/// plugin manifests, and enforced per window and per command on invoke.
#[cfg(any(windows, target_os = "android"))]
const LOCAL_URL: &str = "http://tauri.localhost";
#[cfg(not(any(windows, target_os = "android")))]
const LOCAL_URL: &str = "tauri://localhost";

#[test]
fn the_resolved_acl_permits_event_listen_from_the_main_window() {
    let app = tauri::test::mock_builder()
        .build(crate::app_context())
        .expect("app must build under the mock runtime");

    // The label must match the capability's `windows` list, which is the other
    // way this can silently break.
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("main webview must build");

    let response = tauri::test::get_ipc_response(
        &webview,
        tauri::webview::InvokeRequest {
            cmd: "plugin:event|listen".into(),
            callback: tauri::ipc::CallbackFn(0),
            error: tauri::ipc::CallbackFn(1),
            // A capability applies to local URLs only, and "local" is
            // platform-specific: the asset protocol is `tauri://localhost`
            // everywhere except Windows and Android, where it is served as
            // `http://tauri.localhost`. Using the wrong one here fails the
            // ACL check for a reason that has nothing to do with the grant.
            url: LOCAL_URL.parse().unwrap(),
            body: serde_json::json!({
                "event": crate::event_bridge::EVENT_LOG,
                "target": { "kind": "Any" },
                "handler": 0,
            })
            .into(),
            headers: Default::default(),
            invoke_key: tauri::test::INVOKE_KEY.to_string(),
        },
    );

    // An ACL denial is reported as "... not allowed. Permissions associated
    // with this command: core:event:allow-listen". Any other error would be a
    // payload-shape problem, which still proves the ACL let the call through —
    // so assert specifically on the denial, not on overall success.
    if let Err(e) = &response {
        let msg = e.to_string();
        assert!(
            !msg.contains("not allowed"),
            "event.listen is denied by the ACL for the main window: {msg}"
        );
    }
}
