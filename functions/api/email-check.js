const UPSTREAM_BASE_URL = "https://api.xposedornot.com/v1/check-email";
const RATE_LIMIT_WINDOW_MS = 12_000;
const RATE_LIMIT_MAX_ENTRIES = 500;
const RESULT_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const PROVIDER_BUSY_TTL_MS = 5 * 60 * 1000;
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

function flattenBreaches(value) {
  if (!Array.isArray(value)) return [];

  return value
    .flat(2)
    .map((breach) => String(breach || "").trim())
    .filter(Boolean);
}

function buildResult(breachCount) {
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
  return `email:${await sha256Hex(email)}`;
}

function cloneResult(result, cached = false) {
  return {
    ...result,
    recommendations: [...result.recommendations],
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

export async function onRequest({ request }) {
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
    // Email is encoded and only passed to the upstream breach lookup; it is not logged or stored.
    const upstreamResponse = await fetch(`${UPSTREAM_BASE_URL}/${encodeURIComponent(email)}`, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
    });

    const upstreamBody = await upstreamResponse.json().catch(() => null);
    const noBreachFound =
      upstreamResponse.status === 404 ||
      String(upstreamBody?.Error || "").toLowerCase().includes("not found");

    if (noBreachFound) {
      const result = buildResult(0);
      setCachedResult(emailCacheKey, result);
      return json(result);
    }

    if (upstreamResponse.status === 429) {
      const providerBusyResult = {
        ...buildResult(0),
        compromised: false,
        breach_count: 0,
        risk_level: "Low",
        message: "The exposure provider is busy right now. Please try again in a few minutes.",
        provider_limited: true,
      };

      setCachedResult(emailCacheKey, providerBusyResult, PROVIDER_BUSY_TTL_MS);
      return json(providerBusyResult, 200, { "X-Provider-Limited": "true" });
    }

    if (upstreamResponse.status >= 500) {
      return problem("Exposure data provider is temporarily unavailable.", 503);
    }

    if (!upstreamResponse.ok) {
      return problem("Unable to complete the exposure check.", 502);
    }

    const breachNames = flattenBreaches(upstreamBody?.breaches);
    const breachCount = new Set(breachNames).size;
    const result = buildResult(breachCount);

    setCachedResult(emailCacheKey, result);
    return json(result);
  } catch {
    return problem("Unable to reach the exposure data provider right now.", 503);
  }
}
