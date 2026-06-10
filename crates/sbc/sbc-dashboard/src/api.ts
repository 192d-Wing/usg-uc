// Minimal fetch wrapper for the SBC's /api/v1 surface. Used by all pages.
// Same-origin in production (dashboard served by the sbc-frontend nginx pod,
// which reverse-proxies /api to sbc-api); the Vite dev server proxies /api
// (see vite.config.ts).
//
// Auth: sbc-api issues an HttpOnly sbc_session cookie on login, sent
// automatically on same-origin requests. A 401 on any call fires
// UNAUTHORIZED_EVENT so the auth gate can show the login view.

const API_BASE = '/api/v1';

export const UNAUTHORIZED_EVENT = 'sbc:unauthorized';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly url: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  });
  if (res.status === 401 && path !== '/auth/login') {
    globalThis.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
  }
  if (!res.ok) {
    let detail = '';
    try {
      detail = await res.text();
    } catch {
      // ignore
    }
    throw new ApiError(res.status, url, `${res.status} ${res.statusText}: ${detail}`);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return res.json() as Promise<T>;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body: unknown) =>
    request<T>(path, { method: 'POST', body: JSON.stringify(body) }),
  put: <T>(path: string, body: unknown) =>
    request<T>(path, { method: 'PUT', body: JSON.stringify(body) }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};
