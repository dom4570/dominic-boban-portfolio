export function handleAbuseOriginMapRequest(
  request: Request,
  env?: Record<string, string | undefined>,
  context?: { waitUntil?: (promise: Promise<unknown>) => void },
): Promise<Response>;

export function refreshThreatMapSnapshot(
  env?: Record<string, string | undefined>,
  context?: { waitUntil?: (promise: Promise<unknown>) => void },
): Promise<{
  status: string;
  refreshed: boolean;
  mode: string;
  cache_status: string;
  generated_at: string;
  cache_expires_at: string | null;
  next_refresh_at: string | null;
  point_count: number;
  prewarm: {
    abuseipdb: string;
    spamhaus: string;
    virustotal: string;
  };
  warnings: string[];
}>;

export function handleThreatMapRefreshRequest(
  request: Request,
  env?: Record<string, string | undefined>,
  context?: { waitUntil?: (promise: Promise<unknown>) => void },
): Promise<Response>;

export function isLiveThreatMapIp(ip: string): Promise<boolean>;
