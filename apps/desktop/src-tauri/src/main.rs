#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;
mod event_bridge;

use state::AppState;
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Initialize shared in-memory app state
            app.manage(AppState::new());
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
            commands::findings::triage_finding,
            // Reports
            commands::reports::generate_report,
            commands::reports::export_report,
            commands::reports::list_reports,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SentinelVAPT desktop application");
}
