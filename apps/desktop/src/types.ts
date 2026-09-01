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
  /** The client's logo as a base64 `data:image/...` URI, stamped on every report. */
  logoDataUri?: string;
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
  cvss4Vector?: string;
  epssScore: number;
  kevListed: boolean;
  priorityScore: number;
  cweId?: string;
  owasp2025?: string;
  wstgId?: string;
  apiTop10?: string;
  affectedComponent: string;
  reproSteps: string[];
  remediation: string;
  references: string[];
  evidenceCount: number;
  falsePositiveConfidence: number;
  status: FindingStatus;
  sourceTools: string[];
  triageNote?: string;
  priorityRationale?: string;
  /**
   * Stable identity of this weakness across scans. Findings are re-created with
   * fresh ids on every run, so this — not `id` — is what an exception is keyed
   * on and what the table matches against the register.
   */
  fingerprint: string;
  createdAt: string;
}

export interface Evidence {
  evidenceType: string;
  title: string;
  content: string;
  hash: string;
}

export interface FindingDetail {
  record: Finding;
  evidences: Evidence[];
}

// ── Checklist coverage ────────────────────────────────────────────────────────

export type CheckStatus = 'issues_found' | 'passed' | 'not_tested' | 'manual_required';
export type CoverageKind = 'automated' | 'partial' | 'manual';

export interface CheckResult {
  id: string;
  categoryCode: string;
  category: string;
  name: string;
  clientSummary: string;
  coverage: CoverageKind;
  coverageLabel: string;
  status: CheckStatus;
  statusLabel: string;
  enginesExecuted: string[];
  enginesMissing: string[];
  owasp2025: string;
  cwe: string;
  findingCount: number;
  highestSeverity?: Severity;
}

export interface CategorySummary {
  categoryCode: string;
  category: string;
  total: number;
  passed: number;
  issuesFound: number;
  notTested: number;
  manualRequired: number;
}

export interface CoverageReport {
  results: CheckResult[];
  categories: CategorySummary[];
  totalChecks: number;
  passed: number;
  issuesFound: number;
  notTested: number;
  manualRequired: number;
  enginesExecuted: string[];
  enginesUnavailable: string[];
  automatedCoveragePct: number;
}

export type ScanRunStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ScanStage =
  | 'semgrep' | 'trivy' | 'gitleaks' | 'osv' | 'trufflehog' | 'retirejs' | 'checkov'
  | 'native'
  | 'zap_dast' | 'nuclei_dast' | 'nikto_dast' | 'testssl_dast'
  | 'pipeline';
export type StageState = 'pending' | 'running' | 'done' | 'skipped' | 'failed';

export interface ScanRun {
  id: string;
  targetId: string;
  status: ScanRunStatus;
  runDast: boolean;
  startedAt: string;
  completedAt?: string;
  findingCount: number;
  enginesExecuted: string[];
  error?: string;
}

export interface FindingFilter {
  targetId?: string;
  scanId?: string;
  severity?: string;
  owasp2025?: string;
  wstgId?: string;
  status?: string;
  sourceTool?: string;
  minPriority?: number;
  search?: string;
}

export interface CreateProjectInput {
  companyName: string;
  name: string;
  logoPath?: string;
  logoDataUri?: string;
  primaryColor?: string;
}

export interface SetProjectLogoInput {
  projectId: string;
  /** Omit or pass an empty string to clear the logo. */
  logoDataUri?: string;
}

export interface CreateTargetInput {
  projectId: string;
  name: string;
  targetType: string;
  baseUrl: string;
  repoRef?: string;
  stackDescription?: string;
}

/** How a stored credential is presented to the target. */
export type CredentialKind = 'basic' | 'bearer' | 'cookie' | 'header';

export interface SetCredentialsInput {
  targetId: string;
  kind: CredentialKind;
  /** Username, for `basic`. */
  username?: string;
  /** Password, token, or cookie string, depending on `kind`. */
  secret: string;
  /** Header name, for `header`. Defaults to `X-API-Key`. */
  headerName?: string;
}

/**
 * What the UI is allowed to know about a stored credential. The secret lives in
 * the OS keychain and is never returned — it can be replaced or removed, but
 * not read back.
 */
export interface CredentialStatus {
  configured: boolean;
  description?: string;
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
  /**
   * Review date for an acceptance, as an RFC 3339 timestamp. Optional: an
   * acceptance without one stands until it is withdrawn.
   */
  expiresAt?: string;
}

/** What a triage decision did — to this scan, and to every later one. */
export interface TriageOutcome {
  finding: Finding;
  /** The exception the decision recorded, when it recorded one. */
  exception: ExceptionRecord | null;
  /** How many standing exceptions the decision withdrew. */
  withdrawn: number;
  /** Plain-language summary of what happens on the next scan. */
  effect: string;
}

export type ExceptionKind = 'False Positive' | 'Accepted Risk';

/**
 * One entry in the exception register.
 *
 * Held against the target rather than a scan, which is the point: a decision
 * taken once is re-applied to every later scan automatically instead of being
 * re-triaged on each run.
 */
export interface ExceptionRecord {
  id: string;
  targetId: string;
  fingerprint: string;
  kind: ExceptionKind;
  title: string;
  affectedComponent: string;
  severity: Severity;
  justification: string;
  raisedBy: string;
  createdAt: string;
  expiresAt: string | null;
  /** Whether it is still in force right now. */
  active: boolean;
  /** Days until it lapses; negative once lapsed, null when open-ended. */
  daysUntilExpiry: number | null;
}

export interface RecordExceptionInput {
  findingId: string;
  kind: ExceptionKind;
  justification: string;
  raisedBy: string;
  expiresAt?: string;
}

export type ReportType = 'client' | 'developer' | 'sarif' | 'markdown' | 'json';

export interface GenerateReportInput {
  scanId: string;
  reportType: ReportType;
  companyName: string;
  targetName: string;
  targetUrl?: string;
  analyst?: string;
  /** Base64 `data:image/...` logo. Remote URLs and SVG are ignored by the engine. */
  logoDataUri?: string;
  /** Named in the document-control table and the sign-off block. */
  reviewedBy?: string;
  /** Shown on the cover and in the banner on every page. Defaults to Confidential. */
  classification?: string;
  /** Report revision, e.g. "1.0". */
  revision?: string;
}

export interface GenerateReportOutput {
  reportId: string;
  reportType: string;
  content: string;
  contentType: string;
  suggestedFilename: string;
  findingCount: number;
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
  /** Cumulative Critical + High findings so far. */
  criticalHigh: number;
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
  criticalHigh: number;
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
