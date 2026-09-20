import { apiFetch } from './client';
import { ScanEventsResponse } from '../types/api';

export async function listEvents(
  scanId: string,
  after: number = 0,
  limit: number = 100
): Promise<ScanEventsResponse> {
  const params = new URLSearchParams({
    after: String(after),
    limit: String(limit),
  });
  return apiFetch<ScanEventsResponse>(
    `/v1/scans/${encodeURIComponent(scanId)}/events?${params.toString()}`
  );
}
