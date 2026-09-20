import { apiFetch, downloadProtectedBlob } from './client';
import {
  ScanCreateRequest,
  ScanListResponse,
  ScanResponse,
  ReportFormat,
} from '../types/api';

export async function createScan(
  payload: ScanCreateRequest,
  idempotencyKey?: string
): Promise<ScanResponse> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  const key = idempotencyKey?.trim() || crypto.randomUUID();
  headers['Idempotency-Key'] = key;

  return apiFetch<ScanResponse>('/v1/scans', {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });
}

export async function listScans(
  limit: number = 50,
  offset: number = 0
): Promise<ScanListResponse> {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });
  return apiFetch<ScanListResponse>(`/v1/scans?${params.toString()}`);
}

export async function getScan(scanId: string): Promise<ScanResponse> {
  return apiFetch<ScanResponse>(`/v1/scans/${encodeURIComponent(scanId)}`);
}

export async function cancelScan(scanId: string): Promise<ScanResponse> {
  return apiFetch<ScanResponse>(`/v1/scans/${encodeURIComponent(scanId)}/cancel`, {
    method: 'POST',
  });
}

export async function retryScan(scanId: string): Promise<ScanResponse> {
  return apiFetch<ScanResponse>(`/v1/scans/${encodeURIComponent(scanId)}/retry`, {
    method: 'POST',
  });
}

export async function getReportText(
  scanId: string,
  format: ReportFormat
): Promise<string> {
  return apiFetch<string>(
    `/v1/scans/${encodeURIComponent(scanId)}/report?format=${encodeURIComponent(format)}`
  );
}

export async function downloadReport(
  scanId: string,
  format: ReportFormat
): Promise<void> {
  const ext = format === 'markdown' ? 'md' : format === 'sarif' ? 'sarif.json' : 'json';
  const defaultName = `argus-${scanId.slice(0, 8)}-report.${ext}`;
  const url = `/v1/scans/${encodeURIComponent(scanId)}/report?format=${encodeURIComponent(format)}`;
  return downloadProtectedBlob(url, defaultName);
}
