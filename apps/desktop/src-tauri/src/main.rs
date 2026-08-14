#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;
mod store;
mod event_bridge;

use state::AppState;
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Open the engagement database. If it cannot be opened (read-only
            // volume, permissions), fall back to an in-memory store so the app
            // still runs — degraded, but usable — rather than refusing to start.
            let path = store::Store::default_path();
            let db = store::Store::open(&path).unwrap_or_else(|e| {
                eprintln!("[SentinelVAPT] could not open {}: {e:#}", path.display());
                eprintln!("[SentinelVAPT] continuing without saving — this session will not persist");
                store::Store::in_memory().expect("in-memory store must always open")
            });
            app.manage(AppState::new(db));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Project & Target CRUD
            commands::projects::create_project,
            commands::projects::list_projects,
            commands::projects::get_project,
            // Target commands
            commands::targets::create_target,
            commands::targets::list_targets,
            commands::targets::get_target,
            commands::targets::update_target_repo,
            // Authorization / RoE
            commands::auth::create_scope_and_roe,
            commands::auth::verify_authorization,
            commands::auth::get_authorization_record,
            // Scan orchestration
            commands::scan::trigger_scan,
            commands::scan::cancel_scan,
            commands::scan::get_scan_status,
            // Findings
            commands::findings::list_findings,
            commands::findings::get_finding,
            commands::findings::get_finding_detail,
            commands::findings::triage_finding,
            // Reports
            commands::reports::generate_report,
            commands::reports::export_report,
            commands::reports::default_export_dir,
            commands::reports::list_reports,
            // Checklist coverage
            commands::reports::get_coverage,
            commands::reports::get_checklist_catalog,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SentinelVAPT desktop application");
}
