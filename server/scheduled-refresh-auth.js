function cleanSecret(value) {
  return String(value || "")
    .trim()
    .replace(/^["']|["']$/g, "");
}

function timingSafeEqual(left, right) {
  if (!left || !right || left.length !== right.length) {
    return false;
  }

  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) {
    mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }

  return mismatch === 0;
}

export function scheduledRefreshSecret(env = {}) {
  return cleanSecret(env.THREAT_MAP_CRON_SECRET || env.CRON_SECRET);
}

export function scheduledRefreshAuthorized(request, env = {}) {
  const expected = scheduledRefreshSecret(env);
  if (!expected) {
    return false;
  }

  const authorization = request.headers.get("authorization") || "";
  const bearer = authorization.match(/^Bearer\s+(.+)$/i)?.[1] || "";
  const headerSecret = request.headers.get("x-threat-map-cron-secret") || "";
  const provided = cleanSecret(bearer || headerSecret);

  return timingSafeEqual(provided, expected);
}

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

export function rejectUnauthorizedScheduledRequest(env = {}) {
  return json(
    {
      message: scheduledRefreshSecret(env)
        ? "Forbidden."
        : "Scheduled refresh secret is not configured.",
    },
    scheduledRefreshSecret(env) ? 403 : 503,
  );
}
