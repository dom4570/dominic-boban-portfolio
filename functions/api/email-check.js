const LEAKCHECK_PUBLIC_URL = "https://leakcheck.io/api/public";
const LEAKCHECK_PRO_URL = "https://leakcheck.io/api";
const RATE_LIMIT_WINDOW_MS = 12_000;
const RATE_LIMIT_MAX_ENTRIES = 500;
const RESULT_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const PROVIDER_BUSY_TTL_MS = 60 * 1000;
const rateLimitStore = new Map();
const resultCache = new Map();

const baseRecommendations = [
  "Change reused passwords.",
  "Enable MFA.",
  "Use a password manager.",
];

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

function problem(message, status = 400, headers = {}) {
  return json({ success: false, message }, status, headers);
}

function isValidEmail(value) {
  const email = String(value || "").trim();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

function safeString(value) {
  return String(value || "")
    .trim()
    .replace(/[^\w .:@()#+-]/g, "")
    .slice(0, 120);
}

function buildResult(breachCount, sources = [], provider = "LeakCheck") {
  const compromised = breachCount > 0;
  const riskLevel = breachCount >= 3 ? "High" : breachCount >= 1 ? "Medium" : "Low";
  const recommendations = compromised
    ? [
        ...baseRecommendations,
        "Rotate passwords on affected accounts immediately.",
        "Watch for phishing attempts that reference breached services.",
      ]
    : baseRecommendations;

  return {
    compromised,
    breach_count: breachCount,
    risk_level: riskLevel,
    recommendations,
    message: compromised
      ? "This email appears in known breach data."
      : "No known breach exposure was found for this email.",
    provider,
    sources,
  };
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Prefix(value) {
  return (await sha256Hex(value)).slice(0, 24);
}

async function getEmailCacheKey(email) {
  return `leakcheck:${await sha256Hex(email)}`;
}

function cloneResult(result, cached = false) {
  return {
    ...result,
    recommendations: [...result.recommendations],
    sources: [...(result.sources || [])],
    cached,
  };
}

function pruneCache(cache, now) {
  if (cache.size <= RATE_LIMIT_MAX_ENTRIES) return;

  for (const [entryKey, entry] of cache) {
    if (entry.expiresAt <= now) {
      cache.delete(entryKey);
    }
  }
}

function getCachedResult(key) {
  const now = Date.now();
  const cached = resultCache.get(key);

  if (!cached) return null;
  if (cached.expiresAt <= now) {
    resultCache.delete(key);
    return null;
  }

  return cloneResult(cached.result, true);
}

function setCachedResult(key, result, ttl = RESULT_CACHE_TTL_MS) {
  const now = Date.now();
  resultCache.set(key, {
    result: cloneResult(result, false),
    expiresAt: now + ttl,
  });
  pruneCache(resultCache, now);
}

async function getRateLimitKey(request) {
  const ip =
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
    "unknown";

  return sha256Prefix(ip);
}

async function checkRateLimit(request) {
  const now = Date.now();
  const key = await getRateLimitKey(request);
  const lastSeen = rateLimitStore.get(key) || 0;
  const retryAfterMs = RATE_LIMIT_WINDOW_MS - (now - lastSeen);

  if (retryAfterMs > 0) {
    return {
      limited: true,
      retryAfterSeconds: Math.max(1, Math.ceil(retryAfterMs / 1000)),
    };
  }

  rateLimitStore.set(key, now);

  if (rateLimitStore.size > RATE_LIMIT_MAX_ENTRIES) {
    for (const [entryKey, timestamp] of rateLimitStore) {
      if (now - timestamp > RATE_LIMIT_WINDOW_MS) {
        rateLimitStore.delete(entryKey);
      }
    }
  }

  return { limited: false, retryAfterSeconds: 0 };
}

async function readJsonBody(request) {
  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    return { error: "Request body must be JSON." };
  }

  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return { error: "Invalid JSON body." };
  }

  return { body };
}

function sourceNamesFromPublicResponse(body) {
  if (!Array.isArray(body?.sources)) return [];

  return body.sources
    .map((source) => safeString(source?.name))
    .filter(Boolean)
    .slice(0, 12);
}

function sourceNamesFromProResponse(body) {
  const rows = Array.isArray(body?.result)
    ? body.result
    : Array.isArray(body?.data)
      ? body.data
      : Array.isArray(body)
        ? body
        : [];

  return rows
    .map((row) => safeString(row?.source?.name || row?.source || row?.database_name || row?.name))
    .filter(Boolean)
    .slice(0, 12);
}

function normalizeLeakCheckBody(body) {
  const errorText = safeString(body?.error || body?.Error || body?.message);
  const notFound = !body?.success && /not found|no results/i.test(errorText);

  if (notFound) {
    return buildResult(0);
  }

  if (typeof body?.found === "number") {
    return buildResult(Math.max(0, body.found), sourceNamesFromPublicResponse(body));
  }

  if (Array.isArray(body?.sources)) {
    return buildResult(body.sources.length, sourceNamesFromPublicResponse(body));
  }

  const proSources = sourceNamesFromProResponse(body);
  if (typeof body?.found === "boolean") {
    return buildResult(body.found ? Math.max(1, proSources.length) : 0, proSources);
  }

  if (typeof body?.success === "boolean" && body.success === false) {
    return buildResult(0);
  }

  return buildResult(proSources.length, proSources);
}

function providerBusyResult() {
  return {
    ...buildResult(0),
    message: "LeakCheck is temporarily rate limiting this lookup. Please try again shortly.",
    provider_limited: true,
  };
}

async function queryLeakCheckPublic(email) {
  const url = new URL(LEAKCHECK_PUBLIC_URL);
  url.searchParams.set("check", email);

  return fetch(url.toString(), {
    method: "GET",
    headers: {
      Accept: "application/json",
      "User-Agent": "DominicBobanPortfolio/1.0",
    },
  });
}

async function queryLeakCheckPro(email, apiKey) {
  const url = new URL(LEAKCHECK_PRO_URL);
  url.searchParams.set("key", apiKey);
  url.searchParams.set("check", email);
  url.searchParams.set("type", "email");

  return fetch(url.toString(), {
    method: "GET",
    headers: {
      Accept: "application/json",
      "User-Agent": "DominicBobanPortfolio/1.0",
    },
  });
}

export async function onRequest({ request, env }) {
  if (request.method !== "POST") {
    return problem("Method not allowed.", 405, { Allow: "POST" });
  }

  const rateLimit = await checkRateLimit(request);
  if (rateLimit.limited) {
    return problem("Too many checks. Please wait a few seconds and try again.", 429, {
      "Retry-After": String(rateLimit.retryAfterSeconds),
    });
  }

  const { body, error } = await readJsonBody(request);
  if (error) return problem(error, 400);

  const email = String(body.email || "").trim().toLowerCase();
  if (!isValidEmail(email)) {
    return problem("Enter a valid email address.", 400);
  }

  const emailCacheKey = await getEmailCacheKey(email);
  const cachedResult = getCachedResult(emailCacheKey);
  if (cachedResult) {
    return json(cachedResult);
  }

  try {
    // The submitted email is only forwarded to LeakCheck for lookup and is not stored or logged.
    const apiKey = String(env.LEAKCHECK_API_KEY || "").trim();
    let upstreamResponse = apiKey ? await queryLeakCheckPro(email, apiKey) : await queryLeakCheckPublic(email);
    let upstreamBody = await upstreamResponse.json().catch(() => null);

    const upstreamError = String(upstreamBody?.error || upstreamBody?.Error || upstreamBody?.message || "");

    if (apiKey && (!upstreamResponse.ok || upstreamBody?.success === false) && /missing params|wrong|license|ip linking/i.test(upstreamError)) {
      return problem("LeakCheck API key is not configured correctly. Check the Cloudflare secret and LeakCheck account/IP settings.", 502);
    }

    if (upstreamResponse.status === 429) {
      const result = providerBusyResult();
      setCachedResult(emailCacheKey, result, PROVIDER_BUSY_TTL_MS);
      return json(result, 200, { "X-Provider-Limited": "true" });
    }

    if (upstreamResponse.status >= 500) {
      return problem("LeakCheck is temporarily unavailable.", 503);
    }

    if (!upstreamResponse.ok) {
      return problem("Unable to complete the LeakCheck exposure lookup.", 502);
    }

    const result = normalizeLeakCheckBody(upstreamBody);
    setCachedResult(emailCacheKey, result);

    return json(result);
  } catch {
    return problem("Unable to reach LeakCheck right now.", 503);
  }
}
