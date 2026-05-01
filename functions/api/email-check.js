const HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3";
const LEAKCHECK_PUBLIC_URL = "https://leakcheck.io/api/public";
const LEAKCHECK_PRO_URL = "https://leakcheck.io/api";
const RATE_LIMIT_WINDOW_MS = 7_000;
const HIBP_MIN_INTERVAL_MS = 7_000;
const RATE_LIMIT_MAX_ENTRIES = 500;
const RESULT_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const PARTIAL_RESULT_CACHE_TTL_MS = 60 * 1000;
const rateLimitStore = new Map();
const resultCache = new Map();
let hibpLastRequestAt = 0;

const providerNames = {
  hibp: "HIBP",
  leakCheck: "LeakCheck",
};

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

function safeString(value, maxLength = 160) {
  return String(value || "")
    .trim()
    .replace(/[^\w .:@()#+,&/-]/g, "")
    .slice(0, maxLength);
}

function safeNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : undefined;
}

function uniqueStrings(values, maxItems = 30) {
  const seen = new Set();
  const output = [];

  for (const value of values.flat()) {
    const cleaned = safeString(value).replace(/_/g, " ");
    const key = cleaned.toLowerCase();
    if (!cleaned || seen.has(key)) continue;
    seen.add(key);
    output.push(cleaned);
    if (output.length >= maxItems) break;
  }

  return output;
}

function normalizeKey(value) {
  return safeString(value, 120)
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/\.(com|net|org|io|co|uk|app|dev|info|biz)\b/g, "")
    .replace(/[^a-z0-9]+/g, "");
}

function normalizeDomain(value) {
  return safeString(value, 120)
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .split("/")[0]
    .trim();
}

function exposureKeys(exposure) {
  const keys = [
    normalizeKey(exposure.title),
    normalizeKey(exposure.name),
    normalizeKey(exposure.domain),
    normalizeDomain(exposure.domain),
  ].filter((key) => key && key.length >= 4);

  return [...new Set(keys)];
}

function exposuresLookSame(left, right) {
  const leftKeys = new Set(exposureKeys(left));
  const rightKeys = exposureKeys(right);

  if (rightKeys.some((key) => leftKeys.has(key))) return true;

  const leftTitle = normalizeKey(left.title);
  const rightTitle = normalizeKey(right.title);
  return Boolean(leftTitle && rightTitle && leftTitle.length >= 5 && rightTitle.length >= 5 && (leftTitle.includes(rightTitle) || rightTitle.includes(leftTitle)));
}

function exposureScore(exposure) {
  const flagScore = Object.values(exposure.flags || {}).filter(Boolean).length;
  return (
    (exposure.providers?.includes(providerNames.hibp) ? 20 : 0) +
    (exposure.domain ? 5 : 0) +
    (exposure.breach_date ? 4 : 0) +
    (exposure.added_date ? 3 : 0) +
    (exposure.pwn_count ? 3 : 0) +
    (exposure.data_classes?.length || 0) +
    (exposure.fields?.length || 0) +
    flagScore
  );
}

function mergeExposure(existing, incoming) {
  const base = exposureScore(incoming) > exposureScore(existing) ? incoming : existing;
  const other = base === incoming ? existing : incoming;

  return {
    ...base,
    title: base.title || other.title,
    name: base.name || other.name,
    domain: base.domain || other.domain,
    breach_date: base.breach_date || other.breach_date,
    added_date: base.added_date || other.added_date,
    modified_date: base.modified_date || other.modified_date,
    pwn_count: base.pwn_count || other.pwn_count,
    data_classes: uniqueStrings([base.data_classes || [], other.data_classes || []], 24),
    fields: uniqueStrings([base.fields || [], other.fields || []], 24),
    providers: uniqueStrings([base.providers || [], other.providers || []], 4),
    flags: {
      ...(other.flags || {}),
      ...(base.flags || {}),
      verified: Boolean(base.flags?.verified || other.flags?.verified),
      fabricated: Boolean(base.flags?.fabricated || other.flags?.fabricated),
      sensitive: Boolean(base.flags?.sensitive || other.flags?.sensitive),
      retired: Boolean(base.flags?.retired || other.flags?.retired),
      spam_list: Boolean(base.flags?.spam_list || other.flags?.spam_list),
      malware: Boolean(base.flags?.malware || other.flags?.malware),
      stealer_log: Boolean(base.flags?.stealer_log || other.flags?.stealer_log),
    },
  };
}

function mergeExposures(exposures) {
  const merged = [];

  for (const exposure of exposures) {
    const existingIndex = merged.findIndex((item) => exposuresLookSame(item, exposure));
    if (existingIndex === -1) {
      merged.push(exposure);
    } else {
      merged[existingIndex] = mergeExposure(merged[existingIndex], exposure);
    }
  }

  return merged.sort((left, right) => {
    const leftDate = left.breach_date || left.added_date || "";
    const rightDate = right.breach_date || right.added_date || "";
    return rightDate.localeCompare(leftDate);
  });
}

function cloneExposure(exposure) {
  return {
    ...exposure,
    data_classes: [...(exposure.data_classes || [])],
    fields: [...(exposure.fields || [])],
    providers: [...(exposure.providers || [])],
    flags: { ...(exposure.flags || {}) },
  };
}

function cloneResult(result, cached = false) {
  return {
    ...result,
    recommendations: [...(result.recommendations || [])],
    risk_reasons: [...(result.risk_reasons || [])],
    data_classes: [...(result.data_classes || [])],
    exposures: (result.exposures || []).map(cloneExposure),
    providers_checked: [...(result.providers_checked || [])],
    provider_status: { ...(result.provider_status || {}) },
    provider_errors: { ...(result.provider_errors || {}) },
    cached,
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
  return `aggregated:${await sha256Hex(email)}`;
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

function checkHibpSpacing() {
  const now = Date.now();
  const retryAfterMs = HIBP_MIN_INTERVAL_MS - (now - hibpLastRequestAt);

  if (retryAfterMs > 0) {
    return {
      limited: true,
      retryAfterSeconds: Math.max(1, Math.ceil(retryAfterMs / 1000)),
    };
  }

  hibpLastRequestAt = now;
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

function providerResult(provider, status, exposures = [], error = "") {
  return {
    provider,
    status,
    exposures,
    error: safeString(error, 180),
  };
}

function normalizeHibpBreach(breach) {
  const dataClasses = uniqueStrings(Array.isArray(breach?.DataClasses) ? breach.DataClasses : [], 24);

  return {
    name: safeString(breach?.Name),
    title: safeString(breach?.Title || breach?.Name || "HIBP breach"),
    domain: safeString(breach?.Domain),
    breach_date: safeString(breach?.BreachDate),
    added_date: safeString(breach?.AddedDate),
    modified_date: safeString(breach?.ModifiedDate),
    pwn_count: safeNumber(breach?.PwnCount),
    data_classes: dataClasses,
    fields: dataClasses,
    providers: [providerNames.hibp],
    flags: {
      verified: breach?.IsVerified === true,
      fabricated: breach?.IsFabricated === true,
      sensitive: breach?.IsSensitive === true,
      retired: breach?.IsRetired === true,
      spam_list: breach?.IsSpamList === true,
      malware: breach?.IsMalware === true,
      stealer_log: breach?.IsStealerLog === true,
    },
  };
}

async function queryHibpBreaches(email, apiKey) {
  const url = new URL(`${HIBP_BASE_URL}/breachedAccount/${encodeURIComponent(email)}`);
  url.searchParams.set("truncateResponse", "false");
  url.searchParams.set("IncludeUnverified", "false");

  return fetch(url.toString(), {
    method: "GET",
    headers: {
      Accept: "application/json",
      "hibp-api-key": apiKey,
      "User-Agent": "DominicBobanPortfolio/1.0 identity exposure scanner",
    },
  });
}

async function fetchHibp(email, env) {
  const apiKey = String(env.HIBP_API_KEY || "").trim();

  if (!apiKey) {
    return providerResult(providerNames.hibp, "not_configured", [], "HIBP provider is not configured.");
  }

  const spacing = checkHibpSpacing();
  if (spacing.limited) {
    return providerResult(providerNames.hibp, "rate_limited", [], `HIBP cooldown active. Try again in ${spacing.retryAfterSeconds} seconds.`);
  }

  try {
    const response = await queryHibpBreaches(email, apiKey);

    if (response.status === 404) {
      return providerResult(providerNames.hibp, "clean");
    }

    if (response.status === 429) {
      const retryAfter = safeString(response.headers.get("retry-after") || "");
      return providerResult(providerNames.hibp, "rate_limited", [], retryAfter ? `HIBP rate limit reached. Retry after ${retryAfter} seconds.` : "HIBP rate limit reached.");
    }

    if (response.status === 401 || response.status === 403) {
      return providerResult(providerNames.hibp, "error", [], "HIBP rejected the API request.");
    }

    if (response.status >= 500) {
      return providerResult(providerNames.hibp, "unavailable", [], "HIBP is temporarily unavailable.");
    }

    if (!response.ok) {
      return providerResult(providerNames.hibp, "error", [], "HIBP lookup failed.");
    }

    const body = await response.json().catch(() => null);
    const rows = Array.isArray(body) ? body : [];
    const exposures = rows.map(normalizeHibpBreach).filter((exposure) => exposure.title);

    return providerResult(providerNames.hibp, exposures.length > 0 ? "matched" : "clean", exposures);
  } catch {
    return providerResult(providerNames.hibp, "unavailable", [], "Unable to reach HIBP right now.");
  }
}

function sourcesFromPublicResponse(body) {
  if (!Array.isArray(body?.sources)) return [];

  return body.sources
    .map((source) => ({
      name: safeString(source?.name),
      date: safeString(source?.date),
    }))
    .filter((source) => source.name)
    .slice(0, 24);
}

function sourcesFromProResponse(body) {
  const rows = Array.isArray(body?.result)
    ? body.result
    : Array.isArray(body?.data)
      ? body.data
      : Array.isArray(body)
        ? body
        : [];

  return rows
    .map((row) => ({
      name: safeString(row?.source?.name || row?.source || row?.database_name || row?.name),
      date: safeString(row?.source?.date || row?.date || row?.breach_date || row?.last_breach),
    }))
    .filter((source) => source.name)
    .slice(0, 24);
}

function fieldsFromResponse(body) {
  const fields = Array.isArray(body?.fields) ? body.fields : [];
  return uniqueStrings(fields, 24);
}

function leakCheckExposure(source, fields) {
  return {
    title: safeString(source.name || "LeakCheck exposure"),
    name: safeString(source.name || "LeakCheck exposure"),
    breach_date: safeString(source.date),
    data_classes: fields,
    fields,
    providers: [providerNames.leakCheck],
    flags: {},
  };
}

function normalizeLeakCheckBody(body) {
  const errorText = safeString(body?.error || body?.Error || body?.message);
  const notFound = !body?.success && /not found|no results/i.test(errorText);

  if (notFound) {
    return { found: 0, exposures: [], fields: [] };
  }

  if (typeof body?.success === "boolean" && body.success === false) {
    return null;
  }

  const fields = fieldsFromResponse(body);
  const publicSources = sourcesFromPublicResponse(body);
  const proSources = publicSources.length > 0 ? publicSources : sourcesFromProResponse(body);
  const found = typeof body?.found === "number" ? Math.max(0, body.found) : proSources.length;
  const sources = proSources.length > 0 ? proSources : found > 0 ? [{ name: "LeakCheck exposure", date: "" }] : [];

  return {
    found,
    fields,
    exposures: sources.map((source) => leakCheckExposure(source, fields)),
  };
}

async function queryLeakCheckPublic(email) {
  const url = new URL(LEAKCHECK_PUBLIC_URL);
  url.searchParams.set("check", email);

  return fetch(url.toString(), {
    method: "GET",
    headers: {
      Accept: "application/json",
      "User-Agent": "DominicBobanPortfolio/1.0 identity exposure scanner",
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
      "User-Agent": "DominicBobanPortfolio/1.0 identity exposure scanner",
    },
  });
}

async function fetchLeakCheck(email, env) {
  try {
    const apiKey = String(env.LEAKCHECK_API_KEY || "").trim();
    const useApiKey = String(env.LEAKCHECK_USE_API_KEY || "").trim().toLowerCase() === "true";
    const response = useApiKey && apiKey ? await queryLeakCheckPro(email, apiKey) : await queryLeakCheckPublic(email);
    const body = await response.json().catch(() => null);
    const upstreamError = safeString(body?.error || body?.Error || body?.message);

    if (apiKey && (!response.ok || body?.success === false) && /missing params|wrong|license|ip linking/i.test(upstreamError)) {
      return providerResult(providerNames.leakCheck, "error", [], "LeakCheck API key is not configured correctly.");
    }

    if (response.status === 429) {
      return providerResult(providerNames.leakCheck, "rate_limited", [], "LeakCheck is temporarily rate limiting this lookup.");
    }

    if (response.status >= 500) {
      return providerResult(providerNames.leakCheck, "unavailable", [], "LeakCheck is temporarily unavailable.");
    }

    if (!response.ok) {
      return providerResult(providerNames.leakCheck, "error", [], "LeakCheck lookup failed.");
    }

    const result = normalizeLeakCheckBody(body);
    if (!result) {
      return providerResult(providerNames.leakCheck, "error", [], "LeakCheck lookup failed.");
    }

    return providerResult(providerNames.leakCheck, result.exposures.length > 0 ? "matched" : "clean", result.exposures);
  } catch {
    return providerResult(providerNames.leakCheck, "unavailable", [], "Unable to reach LeakCheck right now.");
  }
}

function riskSignals(exposures, dataClasses) {
  const joined = `${dataClasses.join(" ")} ${JSON.stringify(exposures.map((exposure) => exposure.flags || {}))}`.toLowerCase();
  const signals = [];

  if (/password|credential|secret|token|password hint/.test(joined)) {
    signals.push("Credential-related data appears in the exposure metadata.");
  }

  if (/phone|address|date of birth|dob|birth|passport|national|ssn|credit|card|financial/.test(joined)) {
    signals.push("Personal or financial data appears in the exposure metadata.");
  }

  if (exposures.some((exposure) => exposure.flags?.stealer_log)) {
    signals.push("At least one exposure is flagged as stealer-log related by HIBP.");
  }

  if (exposures.some((exposure) => exposure.flags?.malware)) {
    signals.push("At least one exposure is flagged as malware-sourced by HIBP.");
  }

  return signals;
}

function buildAggregatedResult(providerResults) {
  const exposures = mergeExposures(providerResults.flatMap((result) => result.exposures || []));
  const dataClasses = uniqueStrings(exposures.flatMap((exposure) => [...(exposure.data_classes || []), ...(exposure.fields || [])]), 30);
  const compromised = exposures.length > 0;
  const signals = riskSignals(exposures, dataClasses);
  const riskLevel = compromised && (exposures.length >= 3 || signals.length > 0) ? "High" : compromised ? "Medium" : "Low";
  const riskReasons = compromised
    ? uniqueStrings([`${exposures.length} unique exposure${exposures.length === 1 ? "" : "s"} found across configured providers.`, signals], 8)
    : ["No configured provider returned known breach exposure for this email."];
  const recommendations = compromised
    ? uniqueStrings(
        [
          baseRecommendations,
          "Rotate passwords on affected accounts immediately.",
          "Watch for phishing attempts that reference breached services.",
          signals.length > 0 ? "Prioritise accounts tied to credential or personal-data exposure." : "",
        ],
        8,
      )
    : baseRecommendations;
  const providerStatus = {};
  const providerErrors = {};
  const providersChecked = [];

  for (const result of providerResults) {
    providerStatus[result.provider] = result.status;
    if (result.status !== "not_configured") providersChecked.push(result.provider);
    if (result.error) providerErrors[result.provider] = result.error;
  }

  return {
    compromised,
    breach_count: exposures.length,
    risk_level: riskLevel,
    risk_reasons: riskReasons,
    recommendations,
    message: compromised
      ? "This email appears in known breach data."
      : "No known breach exposure was found for this email.",
    provider: "Have I Been Pwned + LeakCheck",
    providers_checked: uniqueStrings(providersChecked, 4),
    provider_status: providerStatus,
    provider_errors: providerErrors,
    data_classes: dataClasses,
    fields: dataClasses,
    exposures,
    sources: exposures.map((exposure) => ({
      name: exposure.title,
      date: exposure.breach_date || exposure.added_date || "",
    })),
  };
}

function hasUsableProviderResult(result) {
  return result.status === "matched" || result.status === "clean";
}

function hasOnlyCompleteProviderResults(providerResults) {
  return providerResults.every(hasUsableProviderResult);
}

export async function onRequest({ request, env }) {
  if (request.method !== "POST") {
    return problem("Method not allowed.", 405, { Allow: "POST" });
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

  const rateLimit = await checkRateLimit(request);
  if (rateLimit.limited) {
    return problem("Too many checks. Please wait a few seconds and try again.", 429, {
      "Retry-After": String(rateLimit.retryAfterSeconds),
    });
  }

  const providerResults = [
    await fetchHibp(email, env),
    await fetchLeakCheck(email, env),
  ];

  if (!providerResults.some(hasUsableProviderResult)) {
    return problem("Exposure providers are temporarily unavailable. Please try again shortly.", 503);
  }

  const result = buildAggregatedResult(providerResults);
  setCachedResult(emailCacheKey, result, hasOnlyCompleteProviderResults(providerResults) ? RESULT_CACHE_TTL_MS : PARTIAL_RESULT_CACHE_TTL_MS);

  return json(result);
}
