export function handleSpamhausIpDetailRequest(
  request: Request,
  env?: Record<string, string | undefined>,
): Promise<Response>;

export function prewarmSpamhausDetails(
  points: Array<{ ip?: string }>,
  env?: Record<string, string | undefined>,
  options?: { concurrency?: number; timeoutMs?: number },
): Promise<{ attempted: number; cached: number; skipped: number }>;

export function addSpamhausSummariesToPoints<T extends { ip?: string }>(
  points: T[],
): Promise<Array<T & { ip_intelligence?: SpamhausSummary }>>;

export type SpamhausSummary = {
  status: "listed" | "not_listed" | "unavailable" | "not_configured";
  listing_count: number;
  codes: number[];
  datasets: Array<{
    code: number;
    dataset: string;
    label: string;
  }>;
  generated_at: string;
  cache_status: "fresh" | "cached";
};

export type SpamhausHistory = {
  status: "found" | "not_found" | "unavailable";
  events?: SpamhausHistoryEvent[];
  warnings: string[];
};

export type SpamhausHistoryEvent = {
  dataset?: string;
  listed_at?: string;
  removed_at?: string;
  valid_until_at?: string;
  seen_at?: string;
  detection?: string;
  heuristic?: string;
  botname?: string;
  source_ip?: string;
  source_port?: number | null;
  destination_ip?: string;
  destination_port?: number | null;
  protocol?: string;
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
