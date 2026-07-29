// ─────────────────────────────────────────────────────────────────────────────
// SentinelVAPT — Complete Type System
// All types mirror the Rust state.rs structs exactly (snake_case → camelCase)
// ─────────────────────────────────────────────────────────────────────────────

export interface ScopeDefinition {
  allowedDomains: string[];
  allowedIpsCidrs: string[];
  outOfScopePaths: string[];
  rateLimitRps: number;
  prohibitedActions: string[];
}

export interface AuthorizationRecord {
  id: string;
  targetId: string;
  scope: ScopeDefinition;
  acknowledgedBy: string;
  signedAt: string;       // ISO 8601
  roeDocumentHash: string;
}

export type TargetType = 'Web App' | 'REST API' | 'GraphQL' | 'Host' | 'Mobile API';

export interface Target {
  id: string;
  projectId: string;
  name: string;
  targetType: TargetType;
  baseUrl: string;
  repoRef?: string;
  stackDescription?: string;
  authKeychainHandle?: string;
  authorizationRecord?: AuthorizationRecord;
  createdAt: string;
}

export interface Project {
  id: string;
  companyName: string;
  logoPath?: string;
  primaryColor?: string;
  name: string;
  createdAt: string;
}

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type FindingStatus = 'Open' | 'In Progress' | 'Remediated' | 'Accepted Risk' | 'False Positive';

export interface Finding {
  id: string;
  scanId: string;
  targetId: string;
  title: string;
  description: string;
  severity: Severity;
  cvss4Score: number;
  epssScore: number;
  kevListed: boolean;
  priorityScore: number;
  cweId?: string;
  owasp2025?: string;
  wstgId?: string;
  affectedComponent: string;
  reproSteps: string[];
  remediation: string;
  status: FindingStatus;
  sourceTools: string[];
  triageNote?: string;
  priorityRationale?: string;
  createdAt: string;
}

export type ScanRunStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ScanStage = 'semgrep' | 'trivy' | 'gitleaks' | 'zap_dast' | 'nuclei_dast';
export type StageState = 'pending' | 'running' | 'done' | 'skipped' | 'failed';

export interface ScanRun {
  id: string;
  targetId: string;
  status: ScanRunStatus;
  runDast: boolean;
  startedAt: string;
  completedAt?: string;
  findingCount: number;
  error?: string;
}

export interface FindingFilter {
  targetId?: string;
  scanId?: string;
  severity?: string;
  owasp2025?: string;
  status?: string;
  sourceTool?: string;
  minPriority?: number;
}

export interface CreateProjectInput {
  companyName: string;
  name: string;
  logoPath?: string;
  primaryColor?: string;
}

export interface CreateTargetInput {
  projectId: string;
  name: string;
  targetType: string;
  baseUrl: string;
  repoRef?: string;
  stackDescription?: string;
}

export interface CreateRoEInput {
  targetId: string;
  scope: ScopeDefinition;
  acknowledgedBy: string;
  roeDocumentText: string;
}

export interface TriageInput {
  findingId: string;
  newStatus: FindingStatus;
  triageNote: string;
  analystName: string;
}

export interface GenerateReportInput {
  scanId: string;
  reportType: 'executive' | 'developer' | 'sarif';
  companyName: string;
  targetName: string;
  logoPath?: string;
}

export interface GenerateReportOutput {
  reportId: string;
  reportType: string;
  htmlContent: string;
}

export interface ReportRecord {
  id: string;
  scanId: string;
  reportType: string;
  companyName: string;
  htmlContent: string;
  createdAt: string;
}

// ── Event Payloads (mirroring event_bridge.rs) ────────────────────────────────

export interface ScanStageUpdatePayload {
  scanRunId: string;
  stage: ScanStage | 'pipeline';
  state: StageState | 'running';
  stageFindings: number;
  totalFindings: number;
  timestamp: string;
  message: string;
}

export interface ScanLogPayload {
  scanRunId: string;
  stage: string;
  level: 'info' | 'warn' | 'error';
  message: string;
  timestamp: string;
}

export interface ScanCompletePayload {
  scanRunId: string;
  totalFindings: number;
  stageSummary: Array<{ stage: string; state: string; findings: number; error?: string }>;
  durationSeconds: number;
  completedAt: string;
}

export interface ScanErrorPayload {
  scanRunId: string;
  error: string;
  stage?: string;
  timestamp: string;
}
