import { authStore } from '../store/auth';

export class ApiError extends Error {
  constructor(public status: number, message: string, public data?: any) {
    super(message);
    this.name = 'ApiError';
  }
}

export class AuthRequiredError extends ApiError {
  constructor() {
    super(401, '需要配置 API Key 才能访问 Argus 服务');
    this.name = 'AuthRequiredError';
  }
}

export interface RequestOptions extends RequestInit {
  requiresAuth?: boolean;
}

/**
 * Standard fetch wrapper with memory-only Bearer token injection.
 */
export async function apiFetch<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { requiresAuth = true, headers: customHeaders, ...rest } = options;
  const headers = new Headers(customHeaders);

  if (requiresAuth) {
    const key = authStore.getApiKey();
    if (!key) {
      throw new AuthRequiredError();
    }
    headers.set('Authorization', `Bearer ${key}`);
  }

  const response = await fetch(endpoint, {
    ...rest,
    headers,
  });

  if (response.status === 401) {
    authStore.clearApiKey();
    throw new ApiError(401, 'API Key 无效或未配置，请重新输入');
  }

  if (!response.ok) {
    let errorDetail = `请求失败 (状态码: ${response.status})`;
    const responseBody = await response.text();
    try {
      const errorJson = JSON.parse(responseBody);
      if (errorJson.detail) {
        errorDetail = typeof errorJson.detail === 'string' ? errorJson.detail : JSON.stringify(errorJson.detail);
      }
    } catch {
      if (responseBody) errorDetail = responseBody;
    }
    throw new ApiError(response.status, errorDetail);
  }

  if (response.status === 204) {
    return {} as T;
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return (await response.json()) as T;
  }

  return (await response.text()) as unknown as T;
}

/**
 * Safely download protected blob (reports, diagnostics) using Bearer header in memory.
 * Never leaks token in URL. Immediately revokes temporary object URL.
 */
export async function downloadProtectedBlob(endpoint: string, fallbackFilename: string): Promise<void> {
  const key = authStore.getApiKey();
  if (!key) {
    throw new AuthRequiredError();
  }

  const response = await fetch(endpoint, {
    headers: {
      Authorization: `Bearer ${key}`,
    },
  });

  if (response.status === 401) {
    authStore.clearApiKey();
    throw new ApiError(401, 'API Key 无效或已过期');
  }

  if (!response.ok) {
    let msg = `下载失败 (状态码: ${response.status})`;
    try {
      const err = await response.json();
      if (err.detail) msg = err.detail;
    } catch {
      // ignore
    }
    throw new ApiError(response.status, msg);
  }

  // Extract filename from Content-Disposition header if available
  let filename = fallbackFilename;
  const disposition = response.headers.get('content-disposition');
  if (disposition) {
    const match = disposition.match(/filename=["']?([^"';]+)["']?/);
    if (match && match[1]) {
      filename = match[1].replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 160) || fallbackFilename;
    }
  }

  const blob = await response.blob();
  const blobUrl = window.URL.createObjectURL(blob);

  const anchor = document.createElement('a');
  anchor.href = blobUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);

  // Revoke immediately
  setTimeout(() => {
    window.URL.revokeObjectURL(blobUrl);
  }, 200);
}
