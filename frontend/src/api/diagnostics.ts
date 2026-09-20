import { apiFetch, downloadProtectedBlob } from './client';
import { ScanDiagnosticsResponse } from '../types/api';

export async function getDiagnostics(scanId: string): Promise<ScanDiagnosticsResponse> {
  return apiFetch<ScanDiagnosticsResponse>(
    `/v1/scans/${encodeURIComponent(scanId)}/diagnostics`
  );
}

export async function exportDiagnostics(scanId: string): Promise<void> {
  const url = `/v1/scans/${encodeURIComponent(scanId)}/diagnostics/export`;
  const defaultName = `argus-${scanId.slice(0, 8)}-diagnostics.json`;
  return downloadProtectedBlob(url, defaultName);
}
