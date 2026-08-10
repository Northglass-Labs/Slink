export interface Detection {
  id: number;
  source: string;
  title: string;
  snippet: string;
  source_url: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "new" | "acknowledged" | "dismissed" | "escalated";
  matched_keywords: string[];
  first_seen: string;
  last_seen: string;
  raw_data?: Record<string, unknown>;
}

export interface DetectionListResponse {
  items: Detection[];
  total: number;
}

export interface Keyword {
  id: number;
  term: string;
  category: string;
  enabled: boolean;
  created_at: string;
}

export interface SourceStatus {
  source_name: string;
  last_poll: string | null;
  last_success: string | null;
  consecutive_failures: number;
  enabled: boolean;
  poll_interval_seconds: number;
}

export interface User {
  username: string;
  role: "admin" | "viewer";
}

export interface UserInfo {
  id: number;
  username: string;
  role: string;
  created_at: string | null;
}

export interface Webhook {
  id: number;
  name: string;
  url: string;
  enabled: boolean;
  severity_filter: string;
  created_at: string;
}

export interface DashboardStats {
  active_count: number;
  new_count: number;
  acknowledged_count: number;
  critical_count: number;
  high_count: number;
  last_critical: { id: number; severity: string; source: string; title: string; first_seen: string } | null;
  sources_healthy: number;
  sources_total: number;
  sources_failing: number;
  severity_distribution: { critical: number; high: number; medium: number; low: number };
  time_series: { date: string; critical: number; high: number; medium: number; low: number }[];
  needs_attention: { id: number; severity: string; source: string; title: string; first_seen: string }[];
}

export interface Note {
  id: number;
  detection_id: number;
  user_id: number;
  username: string;
  content: string;
  created_at: string;
}

export interface Indicator {
  id: number;
  detection_id: number;
  type: string;
  value: string;
  source: string;
  first_seen: string;
  last_seen: string;
}

export interface Incident {
  id: number;
  name: string;
  description: string | null;
  status: string; // "active" | "closed"
  created_at: string;
  closed_at: string | null;
  keywords: { id: number; term: string; category: string }[];
}

export interface SeverityRule {
  id: number;
  source_pattern: string | null;
  keyword_category: string | null;
  base_severity: string;
  priority: number;
  enabled: boolean;
}
