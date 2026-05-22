export function handleAbuseIpdbIpDetailRequest(
  request: Request,
  env?: Record<string, string | undefined>,
): Promise<Response>;

export function prewarmAbuseIpdbDetails(
  points: Array<{ ip?: string }>,
  env?: Record<string, string | undefined>,
  options?: { concurrency?: number; timeoutMs?: number },
): Promise<{ attempted: number; cached: number; skipped: number }>;

export function addAbuseIpdbSummariesToPoints<T extends { ip?: string }>(
  points: T[],
): Promise<Array<T & { abuseipdb_intelligence?: AbuseIpdbSummary }>>;

export type AbuseIpdbCategory = {
  id: number;
  label: string;
  count?: number;
};

export type MitreMatch = {
  technique_id: string;
  source: "abuseipdb" | "spamhaus";
  evidence: string;
  evidence_title: string;
  evidence_summary: string;
  raw_evidence: string;
  meaning: string;
  matched_field: string;
  confidence: "high" | "medium";
  pattern_label: string;
};

export type AbuseIpdbSummary = {
  provider: "abuseipdb";
  status: "reported" | "not_reported" | "unavailable" | "not_configured";
  abuse_confidence_score: number;
  total_reports: number;
  num_distinct_users: number;
  max_age_in_days: number;
  usage_type: string;
  isp: string;
  domain: string;
  country_code: string;
  country_name: string;
  is_tor: boolean;
  is_whitelisted: boolean | null;
  last_reported_at: string;
  top_categories: AbuseIpdbCategory[];
  generated_at: string;
  cache_status: "fresh" | "cached";
};
