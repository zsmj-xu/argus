import { apiFetch } from './client';
import { FindingsListResponse } from '../types/api';

export interface ListFindingsParams {
  limit?: number;
  offset?: number;
  severity?: string;
  category?: string;
}

export async function listFindings(
  scanId: string,
  params: ListFindingsParams = {}
): Promise<FindingsListResponse> {
  const query = new URLSearchParams();
  if (params.limit !== undefined) query.set('limit', String(params.limit));
  if (params.offset !== undefined) query.set('offset', String(params.offset));
  if (params.severity) query.set('severity', params.severity);
  if (params.category) query.set('category', params.category);

  return apiFetch<FindingsListResponse>(
    `/v1/scans/${encodeURIComponent(scanId)}/findings?${query.toString()}`
  );
}
