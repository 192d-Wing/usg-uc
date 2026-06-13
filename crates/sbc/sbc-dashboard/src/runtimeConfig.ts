// Runtime configuration for the central-config integration.
//
// Per-deployment values (OIDC issuer/client, the central API base) can't be
// baked into the static bundle — they differ per site/region. nginx serves a
// small `/config.js` that sets `window.SBC_CONFIG`; this module reads it with
// dev-friendly fallbacks so `npm run dev` works without that file.

export type SbcRuntimeConfig = {
  /** Central config API base path/URL (no trailing slash). */
  centralBase: string;
  /** OIDC issuer (Keycloak realm URL). */
  oidcIssuer: string;
  /** OIDC public client id for the dashboard (PKCE). */
  oidcClientId: string;
  /** Space-separated scopes; must include `config-admin`. */
  oidcScopes: string;
};

declare global {
  interface Window {
    SBC_CONFIG?: Partial<SbcRuntimeConfig>;
  }
}

const DEFAULTS: SbcRuntimeConfig = {
  // Same-origin in production: nginx proxies /v1 to central-config-api. In
  // dev, vite proxies /v1 (see vite.config.ts).
  centralBase: '/v1',
  oidcIssuer: 'http://localhost:8081/realms/usg',
  oidcClientId: 'usg-uc-config-admin',
  oidcScopes: 'openid config-admin',
};

let cached: SbcRuntimeConfig | null = null;

/** Resolved runtime config (window override merged over defaults). */
export function runtimeConfig(): SbcRuntimeConfig {
  if (!cached) {
    cached = { ...DEFAULTS, ...(globalThis.window?.SBC_CONFIG ?? {}) };
  }
  return cached;
}
