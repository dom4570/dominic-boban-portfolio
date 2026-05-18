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
