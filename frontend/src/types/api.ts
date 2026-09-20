export type ScanStatus =
  | 'queued'
  | 'running'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'canceled'
  | 'skipped';

export type ReportFormat = 'json' | 'markdown' | 'sarif';

export interface ScanProgress {
  total_files: number;
  reviewed_files: number;
  failed_files: number;
  skipped_files: number;
  percent: number;
}

export interface ScanCapabilities {
  file_progress: boolean;
  llm_requests: boolean;
  event_protocol: boolean;
}

export interface ScanCoverage {
  total: number | null;
  reviewed: number;
  failed: number;
  skipped: number;
  percent: number | null;
}

export interface ScanErrorSummary {
  code: string | null;
  message: string | null;
  retryable: boolean | null;
  suggestion: string | null;
  source: string | null;
}

export interface ScanObservation {
  stage: string;
  stage_started_at: string | null;
  elapsed_seconds: number;
  stage_elapsed_seconds: number;
  last_output_at: string | null;
  last_progress_at: string | null;
  worker_heartbeat_at: string | null;
  deadline_at: string | null;
  activity_state: string;
  capabilities: ScanCapabilities;
  coverage: ScanCoverage;
  report_ready: boolean;
  history_available: boolean;
  error_summary: ScanErrorSummary;
  warnings: string[];
  event_count: number;
  dropped_event_count: number;
  truncated_event_count: number;
}

export interface ScanResponse {
  id: string;
  repository_url: string;
  ref: string | null;
  commit_sha: string | null;
  include: string[];
  exclude: string[];
  background: string | null;
  status: ScanStatus;
  phase: string;
  progress: ScanProgress;
  finding_count: number;
  attempt: number;
  idempotency_key: string | null;
  session_id: string | null;
  metadata: Record<string, any>;
  error: string | null;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  finished_at: string | null;
  observation: ScanObservation;
}

export interface ScanListResponse {
  items: ScanResponse[];
  total: number;
}

export interface ScanEvent {
  schema_version: number;
  event_id: number | null;
  timestamp: string;
  id: number | null;
  cursor: number | null;
  scan_id: string;
  attempt: number;
  source: string | null;
  type: string;
  stage: string | null;
  level: string | null;
  code: string | null;
  message: string | null;
  data: Record<string, any>;
  created_at: string;
  truncated: boolean;
  accepted: boolean;
  dropped: boolean;
}

export interface ScanEventsResponse {
  items: ScanEvent[];
  next_cursor: number;
  has_more: boolean;
  oldest_cursor: number | null;
  history_truncated: boolean;
  expired_event_count: number;
}

export interface DiagnosticEvidence {
  event_id: number;
  timestamp: string;
  stage: string;
  code: string;
  data: Record<string, any>;
}

export interface ScanDiagnosticsResponse {
  scan_id: string;
  observation: ScanObservation;
  summary: Record<string, any>;
  recent_errors: ScanEvent[];
  evidence: DiagnosticEvidence[];
  suggestions: string[];
}

export interface FindingResponse {
  id: string;
  scan_id: string;
  rule_id: string;
  title: string;
  category: string;
  severity: string;
  confidence: string | null;
  file: string | null;
  start_line: number | null;
  end_line: number | null;
  message: string;
  evidence: string;
  remediation: string;
  metadata: Record<string, any>;
  created_at: string;
}

export interface FindingsListResponse {
  items: FindingResponse[];
  total: number;
}

export interface ScanCreateRequest {
  repository_url: string;
  ref?: string | null;
  include?: string[];
  exclude?: string[];
  background?: string | null;
  source_disclosure_confirmed: boolean;
}

export interface ReadyzResponse {
  status: 'ready' | 'not_ready';
  detail?: string;
}

export interface HealthzResponse {
  status: 'ok';
}
