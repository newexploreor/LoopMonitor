export interface HeaderView {
  name: string;
  masked: boolean;
}

export interface Assertion {
  type: "contains" | "json_eq";
  value: string;
  path?: string | null;
}

export interface Monitor {
  id: string;
  name: string;
  group_name: string | null;
  url: string;
  method: "GET" | "HEAD" | "POST";
  headers: HeaderView[];
  has_body: boolean;
  interval_seconds: number;
  timeout_seconds: number;
  expected_status: string;
  assertions: Assertion[];
  failure_threshold: number;
  recovery_threshold: number;
  follow_redirects: boolean;
  enabled: boolean;
  current_status: string;
  display_status: string;
  data_stale: boolean;
  next_run_at: string | null;
  last_checked_at: string | null;
  last_success: boolean | null;
  last_error_type: string | null;
  last_http_status: number | null;
  last_latency_ms: number | null;
  consecutive_failures: number;
  consecutive_successes: number;
  channel_ids: string[];
  availability: number | null;
  avg_latency_ms: number | null;
  recent: { success: boolean; valid: boolean; started_at: string }[];
  created_at: string;
  updated_at: string;
}

export interface Dashboard {
  total: number;
  up: number;
  down: number;
  paused: number;
  unknown: number;
  open_incidents: number;
  availability: number | null;
  avg_latency_ms: number | null;
  p95_latency_ms: number | null;
  window: string;
  trend: { start: string; availability: number | null; avg_latency_ms: number | null; total: number }[];
  monitors: Monitor[];
}

export interface CheckItem {
  id: string;
  trigger_type: string;
  started_at: string;
  success: boolean;
  valid: boolean;
  http_status: number | null;
  latency_ms: number | null;
  error_type: string | null;
  error_message: string | null;
}

export interface Incident {
  id: string;
  monitor_id: string;
  monitor_name: string | null;
  status: string;
  started_at: string;
  recovered_at: string | null;
  duration_seconds: number | null;
  error_type: string | null;
  http_status: number | null;
  summary: string;
}

export interface Channel {
  id: string;
  name: string;
  type: string;
  url: string;
  has_secret: boolean;
  enabled: boolean;
}

export interface Delivery {
  id: string;
  event_id: string;
  event_type: string;
  status: string;
  attempts: number;
  last_error: string | null;
  created_at: string;
  next_retry_at: string | null;
}

export interface Statistics {
  window: string;
  total: number;
  success: number;
  availability: number | null;
  avg_latency_ms: number | null;
  p95_latency_ms: number | null;
  manual_total: number;
  trend: { start: string; availability: number | null; avg_latency_ms: number | null; total: number }[];
  incidents: Incident[];
  certificate: {
    checked_at: string;
    expires_at: string | null;
    days_remaining: number | null;
    validation_status: string;
    fingerprint: string | null;
    error_message: string | null;
  } | null;
}

export interface SettingsView {
  version: string;
  env: string;
  check_retention_days: number;
  incident_retention_days: number;
  allow_private_targets: boolean;
  worker: string;
  worker_heartbeat: string | null;
  database: string;
}
