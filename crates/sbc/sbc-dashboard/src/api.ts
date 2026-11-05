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

// ---------------------------------------------------------------------------
// CDRs (schema v1, uc_cdr::CallRecord field names). Served by sbc-api from
// the daemon's recent-CDR ring; needs the cdr:read permission.
// ---------------------------------------------------------------------------

export type CdrDisposition =
  | 'answered'
  | 'failed'
  | 'cancelled'
  | 'rejected'
  | 'busy'
  | 'no_answer'
  | 'media_failure'
  | 'operator_terminated';

export const CDR_DISPOSITIONS: CdrDisposition[] = [
  'answered',
  'failed',
  'cancelled',
  'rejected',
  'busy',
  'no_answer',
  'media_failure',
  'operator_terminated',
];

export type CdrTrunkAttempt = {
  trunk_id: string;
  /** SIP status, or "timeout" / "transport_error". */
  status: number | 'timeout' | 'transport_error';
  at_ms: number;
};

export type CdrRecord = {
  schema_version: number;
  record_id: string;
  node_id: string;
  sequence: number;
  a_call_id: string;
  b_call_ids: string[];
  internal_call_id: string;
  direction: 'inbound' | 'outbound' | 'internal';
  caller: string;
  callee_dialed: string;
  callee_translated: string | null;
  caller_translated: string | null;
  source_ip: string;
  source_port: number;
  transport: 'udp' | 'tcp' | 'tls' | 'ws' | 'wss';
  ingress_zone: string | null;
  egress_zone: string | null;
  trunk_group: string | null;
  trunks_tried: CdrTrunkAttempt[];
  final_trunk: string | null;
  failover_count: number;
  setup_ms: number;
  ring_ms: number | null;
  answer_ms: number | null;
  end_ms: number;
  duration_ms: number;
  pdd_ms: number | null;
  disposition: CdrDisposition;
  final_sip_status: number;
  release_side: 'caller' | 'callee' | 'sbc';
  release_cause: string;
  q850_cause: number | null;
  media_node: string | null;
  media_anchored: boolean;
  codec: string | null;
  srtp: string | null;
  emergency: boolean;
  stir_attestation: 'A' | 'B' | 'C' | null;
  failover_takeover: boolean;
  prev_hash: string;
  hash: string;
};

export type CdrListResponse = {
  cdrs: CdrRecord[];
  next_page_token: string | null;
  /** Records currently held in the node's ring. */
  total: number;
  node_id: string;
};

export type CdrQuery = {
  /** Inclusive lower bound on setup time, epoch ms. */
  start?: number;
  /** Exclusive upper bound on setup time, epoch ms. */
  end?: number;
  caller?: string;
  callee?: string;
  disposition?: CdrDisposition;
  trunk?: string;
  page_token?: string;
  /** Capped at 500 by the server. */
  page_size?: number;
};

export function listCdrs(q: CdrQuery): Promise<CdrListResponse> {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v !== undefined && v !== '') {
      params.set(k, String(v));
    }
  }
  const qs = params.toString();
  return api.get<CdrListResponse>(qs ? `/cdrs?${qs}` : '/cdrs');
}
