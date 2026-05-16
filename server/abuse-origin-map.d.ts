export function handleAbuseOriginMapRequest(
  request: Request,
  env?: Record<string, string | undefined>,
): Promise<Response>;

export function isLiveThreatMapIp(ip: string): Promise<boolean>;
