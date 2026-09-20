import { apiFetch } from './client';
import { ReadyzResponse, HealthzResponse } from '../types/api';

export async function getReadyz(): Promise<ReadyzResponse> {
  return apiFetch<ReadyzResponse>('/readyz', { requiresAuth: false });
}

export async function getHealthz(): Promise<HealthzResponse> {
  return apiFetch<HealthzResponse>('/healthz', { requiresAuth: false });
}
