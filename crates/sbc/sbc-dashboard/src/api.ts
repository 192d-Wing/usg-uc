// Minimal fetch wrapper for the per-site sbc-api `/api/v1` surface — the
// site-local RUNTIME data (registrations, CDRs, system health, users, phone
// reboot). Config entities go through ./centralApi instead.
//
// Auth: a single operator OIDC bearer token (the same one ./centralApi uses).
// sbc-api now accepts that token (config-admin scope) alongside its legacy
// cookie. A missing/expired token redirects to the IdP via login().

import { getAccessToken, login } from './auth/oidc';

const API_BASE = '/api/v1';

// Retained for import compatibility; the OIDC flow redirects via login()
// rather than dispatching this event.
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
  const token = await getAccessToken();
  if (!token) {
    void login();
    throw new ApiError(401, path, 'redirecting to sign-in');
  }
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...init?.headers,
    },
  });
  if (res.status === 401) {
    void login();
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
