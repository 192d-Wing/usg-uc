// Minimal OIDC Authorization-Code + PKCE client for the central config API.
//
// The central API only accepts OIDC bearer tokens carrying the base
// operator scope `config` (per-action authorization is then applied by the
// API's ABAC policy from the token's `roles`/`sites` claims), so the
// dashboard authenticates the operator against Keycloak and presents the
// resulting access token. This is a dependency-free
// PKCE implementation (Keycloak endpoint layout); a frontend team that
// prefers `oidc-client-ts` can swap it behind the same `getAccessToken()` /
// `login()` / `handleCallback()` surface.
//
// NOTE: the redirect/callback/refresh flow needs a live Keycloak to verify
// end-to-end; it is exercised here only by type-checking and build.
//
// SECURITY LIMITATION (C9): Tokens are stored in sessionStorage, which is
// accessible to any JS running in the same origin. An XSS vulnerability
// would allow an attacker to exfiltrate the access and refresh tokens.
//
// Mitigation plan:
//   1. CSP headers restrict script sources (see nginx.conf.template).
//   2. Future: migrate to a Backend-For-Frontend (BFF) pattern where the
//      server holds tokens in HttpOnly, Secure, SameSite=Strict cookies
//      and the browser never sees raw tokens. This eliminates the XSS
//      token-theft vector entirely.

import { runtimeConfig } from '../runtimeConfig';

const STORAGE_TOKEN = 'sbc.central.token';
const STORAGE_VERIFIER = 'sbc.central.pkce_verifier';
const STORAGE_STATE = 'sbc.central.oauth_state';
const STORAGE_RETURN = 'sbc.central.return_to';
/** Refresh this many seconds before expiry. */
const REFRESH_MARGIN = 30;

type StoredToken = {
  accessToken: string;
  refreshToken?: string;
  /** Epoch seconds when the access token expires. */
  expiresAt: number;
};

type TokenResponse = {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
};

/** Keycloak realm endpoints derived from the issuer. */
function endpoints() {
  const base = runtimeConfig().oidcIssuer.replace(/\/$/, '');
  return {
    authorize: `${base}/protocol/openid-connect/auth`,
    token: `${base}/protocol/openid-connect/token`,
    logout: `${base}/protocol/openid-connect/logout`,
  };
}

function redirectUri(): string {
  return `${globalThis.location.origin}/callback`;
}

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

function readToken(): StoredToken | null {
  const raw = sessionStorage.getItem(STORAGE_TOKEN);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as StoredToken;
  } catch {
    return null;
  }
}

function writeToken(r: TokenResponse): void {
  const t: StoredToken = {
    accessToken: r.access_token,
    refreshToken: r.refresh_token,
    expiresAt: nowSecs() + (r.expires_in ?? 300),
  };
  sessionStorage.setItem(STORAGE_TOKEN, JSON.stringify(t));
}

// --- PKCE helpers (Web Crypto) ---

function randomString(bytes = 32): string {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return base64url(a.buffer);
}

function base64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(digest);
}

/** Begin the login redirect. Stashes a PKCE verifier + state and where to
 *  return to, then navigates to the IdP. */
export async function login(returnTo?: string): Promise<void> {
  const cfg = runtimeConfig();
  const verifier = randomString();
  const state = randomString(16);
  sessionStorage.setItem(STORAGE_VERIFIER, verifier);
  sessionStorage.setItem(STORAGE_STATE, state);
  sessionStorage.setItem(STORAGE_RETURN, returnTo ?? globalThis.location.pathname);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: cfg.oidcClientId,
    redirect_uri: redirectUri(),
    scope: cfg.oidcScopes,
    state,
    code_challenge: await challenge(verifier),
    code_challenge_method: 'S256',
  });
  globalThis.location.assign(`${endpoints().authorize}?${params.toString()}`);
}

/** Handle the `/callback` redirect: exchange the code for tokens. Returns the
 *  path to navigate back to. */
export async function handleCallback(): Promise<string> {
  const url = new URL(globalThis.location.href);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const expectedState = sessionStorage.getItem(STORAGE_STATE);
  const verifier = sessionStorage.getItem(STORAGE_VERIFIER);
  if (!code || !state || state !== expectedState || !verifier) {
    throw new Error('OIDC callback: missing/invalid code or state');
  }
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: runtimeConfig().oidcClientId,
    redirect_uri: redirectUri(),
    code,
    code_verifier: verifier,
  });
  const res = await fetch(endpoints().token, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    throw new Error(`OIDC token exchange failed: ${res.status} ${await res.text()}`);
  }
  writeToken((await res.json()) as TokenResponse);
  sessionStorage.removeItem(STORAGE_VERIFIER);
  sessionStorage.removeItem(STORAGE_STATE);
  return sessionStorage.getItem(STORAGE_RETURN) ?? '/';
}

async function refresh(token: StoredToken): Promise<string | null> {
  if (!token.refreshToken) return null;
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: runtimeConfig().oidcClientId,
    refresh_token: token.refreshToken,
  });
  const res = await fetch(endpoints().token, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) return null;
  const r = (await res.json()) as TokenResponse;
  writeToken(r);
  return r.access_token;
}

/** A valid access token, refreshing if near expiry. Returns null if the
 *  operator must (re)authenticate — callers should then trigger [`login`]. */
export async function getAccessToken(): Promise<string | null> {
  const token = readToken();
  if (!token) return null;
  if (nowSecs() < token.expiresAt - REFRESH_MARGIN) return token.accessToken;
  return refresh(token);
}

/** True if an unexpired token is cached (no network). */
export function isAuthenticated(): boolean {
  const t = readToken();
  return !!t && nowSecs() < t.expiresAt - REFRESH_MARGIN;
}

/** Drop local tokens and redirect to the IdP logout. */
export function logout(): void {
  sessionStorage.removeItem(STORAGE_TOKEN);
  const params = new URLSearchParams({
    client_id: runtimeConfig().oidcClientId,
    post_logout_redirect_uri: globalThis.location.origin,
  });
  globalThis.location.assign(`${endpoints().logout}?${params.toString()}`);
}
