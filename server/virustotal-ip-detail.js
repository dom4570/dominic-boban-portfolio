import { isLiveThreatMapIp } from "./abuse-origin-map.js";

const VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_TTL_SECONDS = Math.floor(CACHE_TTL_MS / 1000);
const CACHE_SCHEMA_VERSION = 1;
const PREWARM_SCHEMA_VERSION = 1;
const PREWARM_LIMIT_PER_MINUTE = 4;
const LOCAL_CACHE_FILE = ".cache/virustotal-ip-detail.json";
const LOCAL_QUEUE_FILE = ".cache/virustotal-prewarm-queue.json";
const EDGE_CACHE_PREFIX = "https://portfolio-cache.local/virustotal-ip-detail/";
const EDGE_QUEUE_REQUEST = new Request("https://portfolio-cache.local/virustotal-prewarm-queue/current", { method: "GET" });

let memoryCache = new Map();
let pendingDetails = new Map();
let minuteWindowStartedAt = 0;
let minuteWindowCount = 0;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": data?.cache_status === "cached" ? `public, max-age=${CACHE_TTL_SECONDS}` : "no-store",
      ...headers,
    },
  });
}

function cleanString(value, fallback = "", maxLength = 220) {
  return String(value || fallback)
    .replace(/[^\w .,:()#+&/:?@-]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function normalizeSecretValue(value) {
  return String(value || "")
    .trim()
    .replace(/^["']|["']$/g, "")
    .replace(/^Bearer\s+/i, "")
    .trim();
}

function normalizeIp(value) {
  return cleanString(value, "", 80);
}

function numberOrNull(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function isIpAddress(value) {
  const ip = normalizeIp(value);
  const ipv4Parts = ip.split(".");

  if (
    ipv4Parts.length === 4 &&
    ipv4Parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255)
  ) {
    return true;
  }

  return ip.includes(":") && ip.length <= 45 && /^[0-9a-fA-F:.]+$/.test(ip);
}

function timeoutSignal(timeoutMs) {
  if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
    return AbortSignal.timeout(timeoutMs);
  }

  const controller = new AbortController();
  setTimeout(() => controller.abort(), timeoutMs);
  return controller.signal;
}

async function fetchJson(url, options = {}, timeoutMs = 9000) {
  const response = await fetch(url, {
    ...options,
    signal: options.signal || timeoutSignal(timeoutMs),
  });
  const body = await response.json().catch(() => null);

  return { response, body };
}

function messageFromError(error, fallback) {
  return cleanString(error?.message || error, fallback, 240);
}

function upstreamMessage(body, fallback) {
  return cleanString(body?.error?.message || body?.message || body?.error, fallback, 220);
}

function rateLimitWarning(response, fallback) {
  const retryAfter = numberOrNull(response.headers.get("Retry-After"));
  const reset = numberOrNull(response.headers.get("X-RateLimit-Reset"));

  if (reset) {
    return `${fallback} Limit resets at ${new Date(reset * 1000).toISOString()}.`;
  }

  if (retryAfter) {
    return `${fallback} Retry after ${retryAfter} seconds.`;
  }

  return fallback;
}

function expiresAtFromNow() {
  return new Date(Date.now() + CACHE_TTL_MS).toISOString();
}

function cacheExpiryTime(payload) {
  const expiry = new Date(payload?.cache_expires_at || 0).getTime();
  return Number.isFinite(expiry) ? expiry : 0;
}

function isCachePayloadUsable(payload, now = Date.now()) {
  return (
    payload?.cache_schema_version === CACHE_SCHEMA_VERSION &&
    payload?.ip &&
    (payload.status === "found" || payload.status === "not_found") &&
    cacheExpiryTime(payload) > now
  );
}

function edgeCacheRequest(ip) {
  return new Request(`${EDGE_CACHE_PREFIX}${encodeURIComponent(ip)}`, { method: "GET" });
}

async function readEdgeCache(ip) {
  if (!globalThis.caches?.default) {
    return null;
  }

  const response = await globalThis.caches.default.match(edgeCacheRequest(ip)).catch(() => null);
  if (!response?.ok) {
    return null;
  }

  const payload = await response.json().catch(() => null);
  return isCachePayloadUsable(payload) ? payload : null;
}

async function writeEdgeCache(payload) {
  if (!globalThis.caches?.default || !isCachePayloadUsable(payload)) {
    return;
  }

  const response = new Response(JSON.stringify(payload), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": `public, max-age=${CACHE_TTL_SECONDS}`,
    },
  });

  await globalThis.caches.default.put(edgeCacheRequest(payload.ip), response).catch(() => {});
}

function isNodeRuntime() {
  return typeof process !== "undefined" && Boolean(process.versions?.node);
}

async function localPath(fileName) {
  if (!isNodeRuntime()) {
    return "";
  }

  const path = await import("node:path");
  return path.resolve(process.cwd(), fileName);
}

async function readLocalJson(fileName, fallback) {
  const filePath = await localPath(fileName);
  if (!filePath) {
    return fallback;
  }

  try {
    const fs = await import("node:fs/promises");
    return JSON.parse(await fs.readFile(filePath, "utf8"));
  } catch {
    return fallback;
  }
}

async function writeLocalJson(fileName, payload) {
  const filePath = await localPath(fileName);
  if (!filePath) {
    return;
  }

  try {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(payload, null, 2), "utf8");
  } catch {
    // The in-memory cache still protects the VirusTotal quota for this process.
  }
}

async function readLocalCache(ip) {
  const payload = (await readLocalJson(LOCAL_CACHE_FILE, {}))[ip];
  return isCachePayloadUsable(payload) ? payload : null;
}

async function writeLocalCache(payload) {
  if (!isCachePayloadUsable(payload)) {
    return;
  }

  const cache = await readLocalJson(LOCAL_CACHE_FILE, {});
  cache[payload.ip] = payload;
  await writeLocalJson(LOCAL_CACHE_FILE, cache);
}

function cachedPayload(payload) {
  return {
    ...payload,
    cache_status: "cached",
  };
}

async function readCachedDetail(ip) {
  const normalizedIp = normalizeIp(ip);
  const memoryPayload = memoryCache.get(normalizedIp);
  if (isCachePayloadUsable(memoryPayload)) {
    return cachedPayload(memoryPayload);
  }

  const payload = (await readEdgeCache(normalizedIp)) || (await readLocalCache(normalizedIp));
  if (!payload) {
    return null;
  }

  memoryCache.set(normalizedIp, payload);
  return cachedPayload(payload);
}

async function writeCachedDetail(payload) {
  if (!isCachePayloadUsable(payload)) {
    return;
  }

  const normalized = {
    ...payload,
    cache_schema_version: CACHE_SCHEMA_VERSION,
  };

  memoryCache.set(normalized.ip, normalized);
  await Promise.all([writeEdgeCache(normalized), writeLocalCache(normalized)]);
}

function reserveMinuteBudget(limit = PREWARM_LIMIT_PER_MINUTE) {
  const now = Date.now();
  if (!minuteWindowStartedAt || now - minuteWindowStartedAt >= 60_000) {
    minuteWindowStartedAt = now;
    minuteWindowCount = 0;
  }

  if (minuteWindowCount >= limit) {
    return false;
  }

  minuteWindowCount += 1;
  return true;
}

function nextBudgetAt() {
  return minuteWindowStartedAt ? new Date(minuteWindowStartedAt + 60_000).toISOString() : new Date().toISOString();
}

function isoFromUnixSeconds(value) {
  const seconds = numberOrNull(value);
  return seconds && seconds > 0 ? new Date(seconds * 1000).toISOString() : "";
}

function statusPayload(ip, status, warnings = []) {
  return {
    cache_schema_version: CACHE_SCHEMA_VERSION,
    ip,
    provider: "virustotal",
    status,
    vendor_malicious: 0,
    vendor_suspicious: 0,
    vendor_harmless: 0,
    vendor_undetected: 0,
    vendor_timeout: 0,
    vendor_total: 0,
    reputation: 0,
    community_harmless: 0,
    community_malicious: 0,
    asn: "",
    as_owner: "",
    country: "",
    last_analysis_date: "",
    permalink: "",
    generated_at: new Date().toISOString(),
    cache_status: "fresh",
    cache_expires_at: expiresAtFromNow(),
    warnings,
  };
}

function normalizeVirusTotalPayload(ip, body) {
  const attributes = body?.data?.attributes || {};
  const stats = attributes.last_analysis_stats || {};
  const malicious = Math.max(0, numberOrNull(stats.malicious) || 0);
  const suspicious = Math.max(0, numberOrNull(stats.suspicious) || 0);
  const harmless = Math.max(0, numberOrNull(stats.harmless) || 0);
  const undetected = Math.max(0, numberOrNull(stats.undetected) || 0);
  const timeout = Math.max(0, numberOrNull(stats.timeout) || 0);
  const total = malicious + suspicious + harmless + undetected + timeout;

  return {
    ...statusPayload(ip, "found"),
    vendor_malicious: malicious,
    vendor_suspicious: suspicious,
    vendor_harmless: harmless,
    vendor_undetected: undetected,
    vendor_timeout: timeout,
    vendor_total: total,
    reputation: numberOrNull(attributes.reputation) || 0,
    community_harmless: Math.max(0, numberOrNull(attributes.total_votes?.harmless) || 0),
    community_malicious: Math.max(0, numberOrNull(attributes.total_votes?.malicious) || 0),
    asn: cleanString(attributes.asn, "", 40),
    as_owner: cleanString(attributes.as_owner, "", 160),
    country: cleanString(attributes.country, "", 8).toUpperCase(),
    last_analysis_date: isoFromUnixSeconds(attributes.last_analysis_date),
    permalink: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}/detection`,
  };
}

async function fetchVirusTotalIpReport(ip, apiKey) {
  let response;
  let body;

  try {
    ({ response, body } = await fetchJson(
      `${VIRUSTOTAL_IP_URL}/${encodeURIComponent(ip)}`,
      {
        headers: {
          Accept: "application/json",
          "x-apikey": apiKey,
          "User-Agent": "DominicBobanPortfolio/1.0 virustotal-ip-detail",
        },
      },
      9000,
    ));
  } catch (error) {
    return statusPayload(ip, "unavailable", [`VirusTotal lookup failed: ${messageFromError(error, "request failed")}.`]);
  }

  if (response.status === 404) {
    return statusPayload(ip, "not_found");
  }

  if (response.status === 401 || response.status === 403) {
    return statusPayload(ip, "unavailable", ["VirusTotal authorization failed. Check VIRUSTOTAL_API_KEY."]);
  }

  if (response.status === 429) {
    return statusPayload(ip, "unavailable", [rateLimitWarning(response, "VirusTotal public API is rate limited right now.")]);
  }

  if (!response.ok || body?.error) {
    return statusPayload(ip, "unavailable", [upstreamMessage(body, `VirusTotal returned status ${response.status}.`)]);
  }

  return normalizeVirusTotalPayload(ip, body);
}

async function buildVirusTotalIpPayload(ip, env, options = {}) {
  const cached = await readCachedDetail(ip);
  if (cached) {
    return cached;
  }

  const apiKey = normalizeSecretValue(env?.VIRUSTOTAL_API_KEY);
  if (!apiKey) {
    return statusPayload(ip, "not_configured", ["VIRUSTOTAL_API_KEY is not configured."]);
  }

  if (pendingDetails.has(ip)) {
    return pendingDetails.get(ip);
  }

  if (!options.ignoreBudget && !reserveMinuteBudget()) {
    return statusPayload(ip, "unavailable", [`VirusTotal data is warming under the public API rate limit. Try again after ${nextBudgetAt()}.`]);
  }

  const pending = fetchVirusTotalIpReport(ip, apiKey)
    .then(async (payload) => {
      await writeCachedDetail(payload);
      return payload;
    })
    .finally(() => pendingDetails.delete(ip));

  pendingDetails.set(ip, pending);

  return pendingDetails.get(ip);
}

function uniqueIpsFromPoints(points) {
  const unique = new Set();

  for (const point of Array.isArray(points) ? points : []) {
    const ip = normalizeIp(point?.ip);
    if (isIpAddress(ip)) {
      unique.add(ip);
    }
  }

  return [...unique];
}

function prewarmQueueUsable(queue) {
  return (
    queue?.cache_schema_version === PREWARM_SCHEMA_VERSION &&
    Array.isArray(queue.ips) &&
    cacheExpiryTime(queue) > Date.now()
  );
}

async function readEdgeQueue() {
  if (!globalThis.caches?.default) {
    return null;
  }

  const response = await globalThis.caches.default.match(EDGE_QUEUE_REQUEST).catch(() => null);
  if (!response?.ok) {
    return null;
  }

  const queue = await response.json().catch(() => null);
  return prewarmQueueUsable(queue) ? queue : null;
}

async function writeEdgeQueue(queue) {
  if (!globalThis.caches?.default || !prewarmQueueUsable(queue)) {
    return;
  }

  const response = new Response(JSON.stringify(queue), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": `public, max-age=${CACHE_TTL_SECONDS}`,
    },
  });

  await globalThis.caches.default.put(EDGE_QUEUE_REQUEST, response).catch(() => {});
}

async function readLocalQueue() {
  const queue = await readLocalJson(LOCAL_QUEUE_FILE, null);
  return prewarmQueueUsable(queue) ? queue : null;
}

async function writeLocalQueue(queue) {
  if (prewarmQueueUsable(queue)) {
    await writeLocalJson(LOCAL_QUEUE_FILE, queue);
  }
}

async function readPrewarmQueue() {
  return (await readEdgeQueue()) || (await readLocalQueue());
}

async function writePrewarmQueue(queue) {
  await Promise.all([writeEdgeQueue(queue), writeLocalQueue(queue)]);
}

function queueSignature(ips) {
  return ips.join("|");
}

export async function storeVirusTotalPrewarmQueue(points) {
  const ips = uniqueIpsFromPoints(points);
  if (!ips.length) {
    return {
      status: "empty",
      queued: 0,
    };
  }

  const existing = await readPrewarmQueue();
  const signature = queueSignature(ips);
  if (existing?.signature === signature && !existing.completed) {
    return {
      status: "existing",
      queued: existing.ips.length,
    };
  }

  const now = new Date().toISOString();
  const queue = {
    cache_schema_version: PREWARM_SCHEMA_VERSION,
    signature,
    ips,
    created_at: now,
    updated_at: now,
    last_run_at: "",
    completed: false,
    cache_expires_at: expiresAtFromNow(),
  };

  await writePrewarmQueue(queue);

  return {
    status: "queued",
    queued: ips.length,
  };
}

async function uncachedIps(ips) {
  const remaining = [];

  for (const ip of ips) {
    if (!(await readCachedDetail(ip))) {
      remaining.push(ip);
    }
  }

  return remaining;
}

export async function prewarmVirusTotalQueuedIps(env = {}, options = {}) {
  const apiKey = normalizeSecretValue(env?.VIRUSTOTAL_API_KEY);
  const queue = await readPrewarmQueue();

  if (!apiKey) {
    return {
      status: "not_configured",
      attempted: 0,
      cached: 0,
      remaining: queue?.ips?.length || 0,
      next_run_at: "",
      warnings: ["VIRUSTOTAL_API_KEY is not configured."],
    };
  }

  if (!queue) {
    return {
      status: "empty",
      attempted: 0,
      cached: 0,
      remaining: 0,
      next_run_at: "",
      warnings: [],
    };
  }

  const now = Date.now();
  const lastRun = new Date(queue.last_run_at || 0).getTime();
  if (Number.isFinite(lastRun) && lastRun > 0 && now - lastRun < 60_000) {
    return {
      status: "cooldown",
      attempted: 0,
      cached: 0,
      remaining: (await uncachedIps(queue.ips)).length,
      next_run_at: new Date(lastRun + 60_000).toISOString(),
      warnings: [],
    };
  }

  const limit = Math.max(1, Math.min(PREWARM_LIMIT_PER_MINUTE, numberOrNull(options.limit) || PREWARM_LIMIT_PER_MINUTE));
  const remainingBefore = await uncachedIps(queue.ips);
  const batch = remainingBefore.slice(0, limit);
  let attempted = 0;
  let cached = 0;

  for (const ip of batch) {
    if (!reserveMinuteBudget()) {
      break;
    }

    attempted += 1;
    try {
      const payload = await buildVirusTotalIpPayload(ip, env, { ignoreBudget: true });
      if (isCachePayloadUsable(payload)) {
        cached += 1;
      }
    } catch {
      // Warmup is opportunistic; selected-IP lookup can retry later.
    }
  }

  const remainingAfter = await uncachedIps(queue.ips);
  const updatedQueue = {
    ...queue,
    updated_at: new Date().toISOString(),
    last_run_at: new Date().toISOString(),
    completed: remainingAfter.length === 0,
  };

  await writePrewarmQueue(updatedQueue);

  return {
    status: remainingAfter.length ? "warming" : "complete",
    attempted,
    cached,
    remaining: remainingAfter.length,
    next_run_at: remainingAfter.length ? new Date(Date.now() + 60_000).toISOString() : "",
    warnings: [],
  };
}

function summaryFromPayload(payload) {
  if (!isCachePayloadUsable(payload)) {
    return null;
  }

  return {
    provider: "virustotal",
    status: payload.status,
    vendor_malicious: payload.vendor_malicious,
    vendor_suspicious: payload.vendor_suspicious,
    vendor_harmless: payload.vendor_harmless,
    vendor_undetected: payload.vendor_undetected,
    vendor_timeout: payload.vendor_timeout,
    vendor_total: payload.vendor_total,
    reputation: payload.reputation,
    community_harmless: payload.community_harmless,
    community_malicious: payload.community_malicious,
    asn: payload.asn,
    as_owner: payload.as_owner,
    country: payload.country,
    last_analysis_date: payload.last_analysis_date,
    permalink: payload.permalink,
    generated_at: payload.generated_at,
    cache_status: payload.cache_status || "cached",
  };
}

async function readCachedDetailSummary(ip) {
  const payload = await readCachedDetail(ip);
  return summaryFromPayload(payload);
}

export async function addVirusTotalSummariesToPoints(points) {
  if (!Array.isArray(points) || !points.length) {
    return [];
  }

  const summaries = await Promise.all(
    points.map(async (point) => {
      const ip = normalizeIp(point?.ip);
      return isIpAddress(ip) ? readCachedDetailSummary(ip) : null;
    }),
  );

  return points.map((point, index) => {
    const { virustotal_intelligence: _virusTotalIntelligence, ...cleanPoint } = point;
    const summary = summaries[index];
    return summary ? { ...cleanPoint, virustotal_intelligence: summary } : cleanPoint;
  });
}

export async function handleVirusTotalIpDetailRequest(request, env = {}) {
  if (request.method !== "GET") {
    return json({ message: "Method not allowed" }, 405, { Allow: "GET" });
  }

  const url = new URL(request.url);
  const ip = normalizeIp(url.searchParams.get("ip"));

  if (!isIpAddress(ip)) {
    return json({ message: "A valid IP address is required." }, 400);
  }

  try {
    const cached = await readCachedDetail(ip);
    if (cached) {
      return json(cached);
    }

    if (!(await isLiveThreatMapIp(ip))) {
      return json(statusPayload(ip, "unavailable", ["VirusTotal intelligence is only available for IPs from the current or recent Daily Top 50 map. Reload the map to refresh the selected source."]));
    }

    return json(await buildVirusTotalIpPayload(ip, env));
  } catch {
    return json(statusPayload(ip, "unavailable", ["VirusTotal detail is temporarily unavailable."]));
  }
}

export async function handleVirusTotalPrewarmRequest(request, env = {}) {
  if (request.method !== "POST") {
    return json({ message: "Method not allowed" }, 405, { Allow: "POST" });
  }

  try {
    return json(await prewarmVirusTotalQueuedIps(env));
  } catch {
    return json({
      status: "unavailable",
      attempted: 0,
      cached: 0,
      remaining: 0,
      next_run_at: "",
      warnings: ["VirusTotal prewarm is temporarily unavailable."],
    });
  }
}
