/**
 * SentinelVAPT — Typed Tauri IPC Bridge
 *
 * All communication goes through this module — never raw `invoke()` calls.
 * Event listeners are typed to their specific payloads.
 */

import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type {
  Project, Target, AuthorizationRecord, ScanRun, Finding,
  ReportRecord, GenerateReportOutput, FindingDetail, CoverageReport,
  CreateProjectInput, CreateTargetInput, CreateRoEInput, SetProjectLogoInput,
  SetCredentialsInput, CredentialStatus,
  TriageInput, TriageOutcome, FindingFilter, GenerateReportInput,
  ExceptionRecord, RecordExceptionInput, ImportFindingsInput, ImportOutcome,
  ScanStageUpdatePayload, ScanLogPayload, ScanCompletePayload, ScanErrorPayload,
  ScanProfile, SaveScanProfileInput, EngineDescriptor,
} from '../types';

// ── Projects ──────────────────────────────────────────────────────────────────

export const api = {
  // Projects
  createProject: (input: CreateProjectInput): Promise<Project> =>
    invoke('create_project', { input }),

  listProjects: (): Promise<Project[]> =>
    invoke('list_projects'),

  getProject: (projectId: string): Promise<Project> =>
    invoke('get_project', { projectId }),

  setProjectLogo: (input: SetProjectLogoInput): Promise<Project> =>
    invoke('set_project_logo', { input }),

  // Targets
  createTarget: (input: CreateTargetInput): Promise<Target> =>
    invoke('create_target', { input }),

  listTargets: (projectId: string): Promise<Target[]> =>
    invoke('list_targets', { projectId }),

  getTarget: (targetId: string): Promise<Target> =>
    invoke('get_target', { targetId }),

  updateTargetRepo: (targetId: string, repoRef: string): Promise<Target> =>
    invoke('update_target_repo', { targetId, repoRef }),

  // Scan credentials. The secret goes straight to the OS keychain; only the
  // status ever comes back, never the value.
  setTargetCredentials: (input: SetCredentialsInput): Promise<CredentialStatus> =>
    invoke('set_target_credentials', { input }),

  clearTargetCredentials: (targetId: string): Promise<CredentialStatus> =>
    invoke('clear_target_credentials', { targetId }),

  getTargetCredentialStatus: (targetId: string): Promise<CredentialStatus> =>
    invoke('get_target_credential_status', { targetId }),

  // Authorization / RoE
  createScopeAndRoe: (input: CreateRoEInput): Promise<AuthorizationRecord> =>
    invoke('create_scope_and_roe', { input }),

  verifyAuthorization: (targetId: string): Promise<boolean> =>
    invoke('verify_authorization', { targetId }),

  getAuthorizationRecord: (targetId: string): Promise<AuthorizationRecord | null> =>
    invoke('get_authorization_record', { targetId }),

  // Scans
  //
  // `enabledStages` comes from the selected profile. Omitting it runs every
  // engine, which is what the pipeline did before profiles existed.
  triggerScan: (
    targetId: string,
    runDast: boolean,
    configJson?: string,
    enabledStages?: string[],
  ): Promise<string> =>
    invoke('trigger_scan', { input: { targetId, runDast, configJson, enabledStages } }),

  cancelScan: (scanRunId: string): Promise<void> =>
    invoke('cancel_scan', { scanRunId }),

  getScanStatus: (scanRunId: string): Promise<ScanRun | null> =>
    invoke('get_scan_status', { scanRunId }),

  // Findings
  listFindings: (filter: FindingFilter): Promise<Finding[]> =>
    invoke('list_findings', { filter }),

  getFinding: (findingId: string): Promise<Finding> =>
    invoke('get_finding', { findingId }),

  getFindingDetail: (findingId: string): Promise<FindingDetail> =>
    invoke('get_finding_detail', { findingId }),

  triageFinding: (input: TriageInput): Promise<TriageOutcome> =>
    invoke('triage_finding', { input }),

  // Import findings from another tool's SARIF output — CodeQL, Snyk, Grype,
  // GitHub code scanning. They are scored, deduplicated and exception-checked
  // on the same path as the engine's own results.
  importFindings: (input: ImportFindingsInput): Promise<ImportOutcome> =>
    invoke('import_findings', { input }),

  // Exception register. Decisions here outlive the scan that raised the
  // finding, so a dismissal or an acceptance is applied to every later scan
  // instead of being re-triaged on each run.
  listExceptions: (targetId: string): Promise<ExceptionRecord[]> =>
    invoke('list_exceptions', { targetId }),

  recordException: (input: RecordExceptionInput): Promise<ExceptionRecord> =>
    invoke('record_exception', { input }),

  revokeException: (exceptionId: string): Promise<void> =>
    invoke('revoke_exception', { exceptionId }),

  // Reports
  generateReport: (input: GenerateReportInput): Promise<GenerateReportOutput> =>
    invoke('generate_report', { input }),

  exportReport: (reportId: string, exportPath: string): Promise<string> =>
    invoke('export_report', { input: { reportId, exportPath } }),

  listReports: (scanId: string): Promise<ReportRecord[]> =>
    invoke('list_reports', { scanId }),

  // Opens the report in its own window and raises the system print dialog,
  // which is where "Save as PDF" lives on every desktop platform. Done in Rust
  // because JS `window.print()` is a silent no-op in the macOS webview.
  printReport: (reportId: string): Promise<void> =>
    invoke('print_report', { reportId }),

  defaultExportDir: (): Promise<string> =>
    invoke('default_export_dir'),

  // Scan profiles. The built-in presets are compile-time data prepended by the
  // backend, so a release that corrects one takes effect immediately rather
  // than leaving a stale copy in the database.
  listScanProfiles: (): Promise<ScanProfile[]> =>
    invoke('list_scan_profiles'),

  saveScanProfile: (input: SaveScanProfileInput): Promise<ScanProfile> =>
    invoke('save_scan_profile', { input }),

  deleteScanProfile: (profileId: string): Promise<void> =>
    invoke('delete_scan_profile', { profileId }),

  // Served from the backend rather than hardcoded here, so adding an engine
  // cannot leave the picker showing the old list.
  listEngines: (): Promise<EngineDescriptor[]> =>
    invoke('list_engines'),

  // Checklist coverage
  getCoverage: (scanId: string): Promise<CoverageReport> =>
    invoke('get_coverage', { scanId }),

  getChecklistCatalog: (): Promise<unknown[]> =>
    invoke('get_checklist_catalog'),
};

// ── Typed Event Listeners ─────────────────────────────────────────────────────

export const events = {
  onStageUpdate: (cb: (p: ScanStageUpdatePayload) => void): Promise<UnlistenFn> =>
    listen<ScanStageUpdatePayload>('sentinel://scan/stage-update', (e) => cb(e.payload)),

  onLog: (cb: (p: ScanLogPayload) => void): Promise<UnlistenFn> =>
    listen<ScanLogPayload>('sentinel://scan/log', (e) => cb(e.payload)),

  onComplete: (cb: (p: ScanCompletePayload) => void): Promise<UnlistenFn> =>
    listen<ScanCompletePayload>('sentinel://scan/complete', (e) => cb(e.payload)),

  onError: (cb: (p: ScanErrorPayload) => void): Promise<UnlistenFn> =>
    listen<ScanErrorPayload>('sentinel://scan/error', (e) => cb(e.payload)),
};
