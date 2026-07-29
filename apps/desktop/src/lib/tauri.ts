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
  ReportRecord, GenerateReportOutput,
  CreateProjectInput, CreateTargetInput, CreateRoEInput,
  TriageInput, FindingFilter, GenerateReportInput,
  ScanStageUpdatePayload, ScanLogPayload, ScanCompletePayload, ScanErrorPayload,
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

  // Targets
  createTarget: (input: CreateTargetInput): Promise<Target> =>
    invoke('create_target', { input }),

  listTargets: (projectId: string): Promise<Target[]> =>
    invoke('list_targets', { projectId }),

  getTarget: (targetId: string): Promise<Target> =>
    invoke('get_target', { targetId }),

  updateTargetRepo: (targetId: string, repoRef: string): Promise<Target> =>
    invoke('update_target_repo', { targetId, repoRef }),

  // Authorization / RoE
  createScopeAndRoe: (input: CreateRoEInput): Promise<AuthorizationRecord> =>
    invoke('create_scope_and_roe', { input }),

  verifyAuthorization: (targetId: string): Promise<boolean> =>
    invoke('verify_authorization', { targetId }),

  getAuthorizationRecord: (targetId: string): Promise<AuthorizationRecord | null> =>
    invoke('get_authorization_record', { targetId }),

  // Scans
  triggerScan: (targetId: string, runDast: boolean, configJson?: string): Promise<string> =>
    invoke('trigger_scan', { input: { targetId, runDast, configJson } }),

  cancelScan: (scanRunId: string): Promise<void> =>
    invoke('cancel_scan', { scanRunId }),

  getScanStatus: (scanRunId: string): Promise<ScanRun | null> =>
    invoke('get_scan_status', { scanRunId }),

  // Findings
  listFindings: (filter: FindingFilter): Promise<Finding[]> =>
    invoke('list_findings', { filter }),

  getFinding: (findingId: string): Promise<Finding> =>
    invoke('get_finding', { findingId }),

  triageFinding: (input: TriageInput): Promise<Finding> =>
    invoke('triage_finding', { input }),

  // Reports
  generateReport: (input: GenerateReportInput): Promise<GenerateReportOutput> =>
    invoke('generate_report', { input }),

  exportReport: (reportId: string, exportPath: string, format: string): Promise<string> =>
    invoke('export_report', { input: { reportId, exportPath, format } }),

  listReports: (scanId: string): Promise<ReportRecord[]> =>
    invoke('list_reports', { scanId }),
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
