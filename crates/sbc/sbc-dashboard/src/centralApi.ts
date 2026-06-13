// Client for the central config API (site-sharded, OIDC-bearer).
//
// Config entities (phones, directory, trunk groups, dial plans, SBC routing
// entities, site config) are served by central-config-api under
// /v1/sites/{site}/…, authorized by a `config-admin` OIDC token. Runtime data
// (registrations, CDRs, system health, users) is NOT config and stays on the
// per-site `api` client in ./api.ts.
//
// Writes are upserts (POST) — central has no separate create/update. A 401
// means the operator must (re)authenticate; we surface it so the app can
// redirect to the IdP.

import { getAccessToken, login } from './auth/oidc';
import { ApiError } from './api';
import { runtimeConfig } from './runtimeConfig';

/** Config entity kinds the dashboard manages centrally. */
export type CentralEntity =
  | 'phones'
  | 'directory'
  | 'trunkgroups'
  | 'dialplans'
  | 'partitions'
  | 'css'
  | 'routepatterns'
  | 'routelists';

/** A site as listed for the selector. */
export type SiteInfo = {
  site_code: string;
  display_name: string;
  status: string;
  config_epoch: number;
};

/** Map a dashboard entity to its path under /v1/sites/{site}/. The four SBC
 *  routing entities live under routing/{kind}. */
function entityPath(entity: CentralEntity): string {
  switch (entity) {
    case 'phones':
      return 'phones';
    case 'directory':
      return 'directory';
    case 'trunkgroups':
      return 'trunkgroups';
    case 'dialplans':
      return 'dialplans';
    case 'partitions':
      return 'routing/partitions';
    case 'css':
      return 'routing/calling_search_spaces';
    case 'routepatterns':
      return 'routing/route_patterns';
    case 'routelists':
      return 'routing/route_lists';
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = await getAccessToken();
  if (!token) {
    // No usable token — start the OIDC login (full-page redirect to the
    // IdP, returning to the current path). The throw is moot once we
    // navigate away.
    void login();
    throw new ApiError(401, path, 'redirecting to central config sign-in');
  }
  const url = `${runtimeConfig().centralBase}${path}`;
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
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const centralApi = {
  /** List registered sites (the selector). */
  listSites: () => request<{ sites: SiteInfo[] }>('/sites').then((r) => r.sites),

  /** Register a new site. */
  registerSite: (body: { site_code: string; display_name?: string; fqdn_base: string }) =>
    request<{ site_code: string }>('/sites', { method: 'POST', body: JSON.stringify(body) }),

  /** List an entity's live rows for a site (payloads). */
  list: <T>(site: string, entity: CentralEntity) =>
    request<{ items: T[] }>(`/sites/${site}/${entityPath(entity)}`).then((r) => r.items ?? []),

  /** Fetch one row by id. */
  get: <T>(site: string, entity: CentralEntity, id: string) =>
    request<T>(`/sites/${site}/${entityPath(entity)}/${encodeURIComponent(id)}`),

  /** Upsert (create or update) a row. The body must carry its id (`did` for
   *  directory). Returns the new shard epoch. */
  upsert: (site: string, entity: CentralEntity, body: unknown) =>
    request<{ epoch: number }>(`/sites/${site}/${entityPath(entity)}`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  /** Delete (tombstone) a row by id. */
  remove: (site: string, entity: CentralEntity, id: string) =>
    request<{ epoch: number }>(`/sites/${site}/${entityPath(entity)}/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  /** Fetch the site telephony config document. */
  getConfig: <T>(site: string) => request<T>(`/sites/${site}/config`),

  /** Replace the site telephony config document. */
  putConfig: (site: string, body: unknown) =>
    request<{ epoch: number }>(`/sites/${site}/config`, {
      method: 'PUT',
      body: JSON.stringify(body),
    }),
};
