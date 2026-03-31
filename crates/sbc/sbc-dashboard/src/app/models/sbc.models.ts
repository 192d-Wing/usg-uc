export interface SystemStats {
  calls_total: number;
  calls_active: number;
  registrations_total: number;
  registrations_active: number;
  messages_received: number;
  messages_sent: number;
  rate_limited: number;
}

export interface Registration {
  aor: string;
  contacts: Contact[];
  realm?: string;
  user_agent?: string;
  registered_at?: string;
}

export interface Contact {
  uri: string;
  expires?: number;
  q_value?: number;
  transport?: string;
  source_address?: string;
}

export interface DirectoryNumber {
  did: string;
  description: string;
  destination_type: 'trunk_group' | 'registered_user' | 'static_uri';
  destination: string;
  trunk_group?: string;
  transform_type?: string;
  transform_value?: string;
  enabled: boolean;
}

export interface CdrRecord {
  call_id: string;
  start_time: string;
  end_time?: string;
  duration_secs?: number;
  caller: string;
  callee: string;
  status: 'connected' | 'failed' | 'cancelled';
  cause_code?: number;
  a_leg_trunk?: string;
  b_leg_trunk?: string;
  codec?: string;
}

export interface SipMessage {
  timestamp: string;
  direction: 'sent' | 'received';
  source: string;
  destination: string;
  method_or_status: string;
  call_id: string;
  raw_message?: string;
}

export interface CallLadder {
  call_id: string;
  participants: string[];
  messages: SipMessage[];
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptime_secs: number;
  version: string;
  checks: HealthCheck[];
}

export interface HealthCheck {
  name: string;
  status: string;
}

export interface WebSocketEvent {
  type: 'stats_update' | 'call_event' | 'registration_event';
  data: unknown;
}

export interface CdrFilter {
  start_date?: string;
  end_date?: string;
  caller?: string;
  callee?: string;
  status?: string;
  page?: number;
  page_size?: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}
