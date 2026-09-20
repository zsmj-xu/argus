/**
 * In-memory Auth Store for Argus API Key.
 *
 * CRITICAL SECURITY COMPLIANCE (from docs/observability.md):
 * The API key is stored ONLY in memory during the page session.
 * It is NEVER written to localStorage, sessionStorage, cookies, query parameters,
 * blob URLs, copied links, telemetry, or console logs.
 */

type AuthListener = (key: string | null) => void;

let memoryApiKey: string | null = null;
const listeners = new Set<AuthListener>();

export const authStore = {
  getApiKey(): string | null {
    return memoryApiKey;
  },

  setApiKey(key: string | null): void {
    memoryApiKey = key ? key.trim() : null;
    listeners.forEach((listener) => listener(memoryApiKey));
  },

  clearApiKey(): void {
    memoryApiKey = null;
    listeners.forEach((listener) => listener(null));
  },

  subscribe(listener: AuthListener): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
};
