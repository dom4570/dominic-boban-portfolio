export function handleAbuseOriginMapRequest(
  request: Request,
  env?: Record<string, string | undefined>,
  context?: { waitUntil?: (promise: Promise<unknown>) => void },
): Promise<Response>;

export function isLiveThreatMapIp(ip: string): Promise<boolean>;
