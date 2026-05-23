export function scheduledRefreshSecret(env?: Record<string, string | undefined>): string;

export function scheduledRefreshAuthorized(
  request: Request,
  env?: Record<string, string | undefined>,
): boolean;

export function json(
  data: unknown,
  status?: number,
  headers?: Record<string, string>,
): Response;

export function rejectUnauthorizedScheduledRequest(
  env?: Record<string, string | undefined>,
): Response;
