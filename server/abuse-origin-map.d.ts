export function handleAbuseOriginMapRequest(
  request: Request,
  env?: Record<string, string | undefined>,
): Promise<Response>;

export function handleAbuseOriginDetailRequest(
  request: Request,
  env?: Record<string, string | undefined>,
): Promise<Response>;
