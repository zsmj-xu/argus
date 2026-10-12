import { apiFetch, downloadProtectedBlob } from './client';
import {
  Project,
  ProjectListResponse,
  ProjectCreatePayload,
  ProjectUpdatePayload,
  ScanResponse,
  ScanListResponse,
  Vulnerability,
  VulnerabilityListResponse,
  VulnerabilityStatus,
  ReportFormat,
} from '../types/api';

export async function listProjects(
  limit: number = 50,
  offset: number = 0
): Promise<ProjectListResponse> {
  return apiFetch<ProjectListResponse>(`/v1/projects?limit=${limit}&offset=${offset}`);
}

export async function getProject(projectId: string): Promise<Project> {
  return apiFetch<Project>(`/v1/projects/${encodeURIComponent(projectId)}`);
}

export async function createProject(payload: ProjectCreatePayload): Promise<Project> {
  return apiFetch<Project>('/v1/projects', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function updateProject(
  projectId: string,
  payload: ProjectUpdatePayload
): Promise<Project> {
  return apiFetch<Project>(`/v1/projects/${encodeURIComponent(projectId)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function listProjectScans(
  projectId: string,
  limit: number = 20,
  offset: number = 0
): Promise<ScanListResponse> {
  return apiFetch<ScanListResponse>(
    `/v1/projects/${encodeURIComponent(projectId)}/scans?limit=${limit}&offset=${offset}`
  );
}

export async function triggerProjectScan(
  projectId: string,
  mode: 'auto' | 'full' = 'auto',
  sourceDisclosureConfirmed: boolean = true
): Promise<ScanResponse> {
  return apiFetch<ScanResponse>(`/v1/projects/${encodeURIComponent(projectId)}/scans`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Idempotency-Key': crypto.randomUUID(),
    },
    body: JSON.stringify({
      mode,
      source_disclosure_confirmed: sourceDisclosureConfirmed,
    }),
  });
}

export interface ListVulnerabilitiesParams {
  limit?: number;
  offset?: number;
  status?: string;
  severity?: string;
  category?: string;
  search?: string;
}

export async function listProjectVulnerabilities(
  projectId: string,
  params: ListVulnerabilitiesParams = {}
): Promise<VulnerabilityListResponse> {
  const query = new URLSearchParams();
  query.set('limit', String(params.limit ?? 20));
  query.set('offset', String(params.offset ?? 0));
  if (params.status) query.set('status', params.status);
  if (params.severity) query.set('severity', params.severity);
  if (params.category) query.set('category', params.category);
  if (params.search) query.set('search', params.search);

  return apiFetch<VulnerabilityListResponse>(
    `/v1/projects/${encodeURIComponent(projectId)}/vulnerabilities?${query.toString()}`
  );
}

export async function updateVulnerabilityStatus(
  projectId: string,
  vulnerabilityId: string,
  status: VulnerabilityStatus
): Promise<Vulnerability> {
  return apiFetch<Vulnerability>(
    `/v1/projects/${encodeURIComponent(projectId)}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    }
  );
}

export async function downloadProjectReport(
  projectId: string,
  format: ReportFormat
): Promise<void> {
  const ext = format === 'markdown' ? 'md' : format === 'sarif' ? 'sarif.json' : 'json';
  const fallbackName = `argus-project-${projectId.slice(0, 8)}-report.${ext}`;
  return downloadProtectedBlob(
    `/v1/projects/${encodeURIComponent(projectId)}/report?format=${encodeURIComponent(format)}`,
    fallbackName
  );
}
