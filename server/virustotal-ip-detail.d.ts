export function handleVirusTotalIpDetailRequest(
  request: Request,
  env?: Record<string, string | undefined>,
): Promise<Response>;

export function handleVirusTotalPrewarmRequest(
  request: Request,
  env?: Record<string, string | undefined>,
): Promise<Response>;

export function storeVirusTotalPrewarmQueue(
  points: Array<{ ip?: string }>,
): Promise<{ status: string; queued: number }>;

export function prewarmVirusTotalQueuedIps(
  env?: Record<string, string | undefined>,
  options?: { limit?: number },
): Promise<{
  status: string;
  attempted: number;
  cached: number;
  remaining: number;
  next_run_at: string;
  warnings: string[];
}>;

export function addVirusTotalSummariesToPoints<T extends { ip?: string }>(
  points: T[],
): Promise<Array<T & { virustotal_intelligence?: VirusTotalSummary }>>;

export type VirusTotalSummary = {
  provider: "virustotal";
  status: "found" | "not_found" | "unavailable" | "not_configured";
  vendor_malicious: number;
  vendor_suspicious: number;
  vendor_harmless: number;
  vendor_undetected: number;
  vendor_timeout: number;
  vendor_total: number;
  reputation: number;
  community_harmless: number;
  community_malicious: number;
  asn: string;
  as_owner: string;
  country: string;
  last_analysis_date: string;
  permalink: string;
  generated_at: string;
  cache_status: "fresh" | "cached";
};
