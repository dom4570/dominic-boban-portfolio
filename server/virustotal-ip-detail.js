import { isLiveThreatMapIp } from "./abuse-origin-map.js";
import {
  addMitrePatternAnalysis,
  normalizeVirusTotalEvidence,
} from "./threat-pattern-engine.js";

const VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_TTL_SECONDS = Math.floor(CACHE_TTL_MS / 1000);
const CACHE_SCHEMA_VERSION = 2;
const PREWARM_SCHEMA_VERSION = 1;
const PREWARM_LIMIT_PER_MINUTE = 4;
const LOCAL_CACHE_FILE = ".cache/virustotal-ip-detail.json";
const LOCAL_QUEUE_FILE = ".cache/virustotal-prewarm-queue.json";
const EDGE_CACHE_PREFIX = "https://portfolio-cache.local/virustotal-ip-detail/";
const EDGE_QUEUE_REQUEST = new Request("https://portfolio-cache.local/virustotal-prewarm-queue/current", { method: "GET" });
const KV_DETAIL_PREFIX = "virustotal:ip:";
const KV_QUEUE_KEY = "virustotal:prewarm:current";

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

function threatIntelKv(env = {}) {
  const namespace = env.THREAT_INTEL_KV || env.THREAT_MAP_KV || env.VIRUSTOTAL_KV;
  return namespace && typeof namespace.get === "function" && typeof namespace.put === "function" ? namespace : null;
}

async function readKvJson(env, key) {
  const namespace = threatIntelKv(env);
  if (!namespace) {
    return null;
  }

  return namespace.get(key, { type: "json" }).catch(() => null);
}

async function writeKvJson(env, key, payload) {
  const namespace = threatIntelKv(env);
  if (!namespace) {
    return;
  }

  await namespace
    .put(key, JSON.stringify(payload), {
      expirationTtl: CACHE_TTL_SECONDS,
    })
    .catch(() => {});
}

async function readKvCache(ip, env) {
  const payload = await readKvJson(env, `${KV_DETAIL_PREFIX}${normalizeIp(ip)}`);
  return isCachePayloadUsable(payload) ? payload : null;
}

async function writeKvCache(payload, env) {
  if (isCachePayloadUsable(payload)) {
    await writeKvJson(env, `${KV_DETAIL_PREFIX}${payload.ip}`, payload);
  }
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

async function readCachedDetail(ip, env = {}) {
  const normalizedIp = normalizeIp(ip);
  const memoryPayload = memoryCache.get(normalizedIp);
  if (isCachePayloadUsable(memoryPayload)) {
    return cachedPayload(memoryPayload);
  }

  const payload = (await readKvCache(normalizedIp, env)) || (await readEdgeCache(normalizedIp)) || (await readLocalCache(normalizedIp));
  if (!payload) {
    return null;
  }

  memoryCache.set(normalizedIp, payload);
  return cachedPayload(payload);
}

async function writeCachedDetail(payload, env = {}) {
  if (!isCachePayloadUsable(payload)) {
    return;
  }

  const normalized = {
    ...payload,
    cache_schema_version: CACHE_SCHEMA_VERSION,
  };

  memoryCache.set(normalized.ip, normalized);
  await Promise.all([writeKvCache(normalized, env), writeEdgeCache(normalized), writeLocalCache(normalized)]);
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
    tags: [],
    threat_labels: [],
    detection_names: [],
    last_analysis_date: "",
    permalink: "",
    generated_at: new Date().toISOString(),
    cache_status: "fresh",
    cache_expires_at: expiresAtFromNow(),
    mitre_techniques: [],
    mitre_matches: [],
    warnings,
  };
}

function uniqueCleanStrings(values, limit = 16) {
  const unique = new Set();

  for (const value of Array.isArray(values) ? values : []) {
    const cleaned = cleanString(value, "", 160);
    if (cleaned) {
      unique.add(cleaned);
    }
  }

  return [...unique].slice(0, limit);
}

function threatLabelsFromAttributes(attributes) {
  const classification = attributes?.popular_threat_classification || {};
  const labels = [
    classification.suggested_threat_label,
    ...(Array.isArray(classification.popular_threat_category)
      ? classification.popular_threat_category.map((item) => item?.value)
      : []),
    ...(Array.isArray(classification.popular_threat_name)
      ? classification.popular_threat_name.map((item) => item?.value)
      : []),
  ];

  return uniqueCleanStrings(labels, 12);
}

function detectionNamesFromAttributes(attributes) {
  const behaviorPattern = /\b(?:ssh|sshd|brute[-\s]?force|port scan|scan(?:ning|ned)?|phishing|ddos|denial of service|sql injection|web app|public[-\s]?facing|exploit|cve-\d{4}-\d+|citrix|netscaler|rce|botnet|c2|command and control)\b/i;
  const results = Object.values(attributes?.last_analysis_results || {})
    .filter((result) => result?.category === "malicious" || result?.category === "suspicious")
    .flatMap((result) => [result?.result, result?.method, result?.engine_name])
    .filter((value) => behaviorPattern.test(String(value || "")));

  return uniqueCleanStrings(results, 12);
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
    tags: uniqueCleanStrings(attributes.tags, 16),
    threat_labels: threatLabelsFromAttributes(attributes),
    detection_names: detectionNamesFromAttributes(attributes),
    last_analysis_date: isoFromUnixSeconds(attributes.last_analysis_date),
    permalink: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}/detection`,
  };
}

async function addMitreTechniques(payload) {
  return addMitrePatternAnalysis(payload, "virustotal", normalizeVirusTotalEvidence);
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
  const cached = await readCachedDetail(ip, env);
  if (cached) {
    return addMitreTechniques(cached);
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
      await writeCachedDetail(payload, env);
      return addMitreTechniques(payload);
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

async function readKvQueue(env) {
  const queue = await readKvJson(env, KV_QUEUE_KEY);
  return prewarmQueueUsable(queue) ? queue : null;
}

async function writeKvQueue(queue, env) {
  if (prewarmQueueUsable(queue)) {
    await writeKvJson(env, KV_QUEUE_KEY, queue);
  }
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

async function readPrewarmQueue(env = {}) {
  return (await readKvQueue(env)) || (await readEdgeQueue()) || (await readLocalQueue());
}

async function writePrewarmQueue(queue, env = {}) {
  await Promise.all([writeKvQueue(queue, env), writeEdgeQueue(queue), writeLocalQueue(queue)]);
}

function queueSignature(ips) {
  return ips.join("|");
}

function queueCompletedIps(queue) {
  return new Set(
    (Array.isArray(queue?.completed_ips) ? queue.completed_ips : [])
      .map((ip) => normalizeIp(ip))
      .filter((ip) => isIpAddress(ip)),
  );
}

function remainingQueueCount(ips, completedIps) {
  return (Array.isArray(ips) ? ips : []).filter((ip) => !completedIps.has(normalizeIp(ip))).length;
}

export async function storeVirusTotalPrewarmQueue(points, env = {}) {
  const ips = uniqueIpsFromPoints(points);
  if (!ips.length) {
    return {
      status: "empty",
      queued: 0,
    };
  }

  const existing = await readPrewarmQueue(env);
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
    cursor: 0,
    completed_ips: [],
    completed: false,
    cache_expires_at: expiresAtFromNow(),
  };

  await writePrewarmQueue(queue, env);

  return {
    status: "queued",
    queued: ips.length,
  };
}

function nextPendingEntries(queue, limit) {
  const ips = Array.isArray(queue?.ips) ? queue.ips : [];
  if (!ips.length) {
    return { entries: [], nextCursor: 0, completedIps: new Set() };
  }

  const start = Math.max(0, Math.min(ips.length - 1, numberOrNull(queue.cursor) || 0));
  const completedIps = queueCompletedIps(queue);
  const entries = [];
  let nextCursor = start;

  for (let offset = 0; offset < ips.length && entries.length < limit; offset += 1) {
    const index = (start + offset) % ips.length;
    const ip = normalizeIp(ips[index]);
    nextCursor = (index + 1) % ips.length;

    if (isIpAddress(ip) && !completedIps.has(ip)) {
      entries.push({ ip, index });
    }
  }

  return { entries, nextCursor, completedIps };
}

function prewarmFailureSummary(ip, payload) {
  const warning = cleanString(payload?.warnings?.[0] || "", "", 180);
  return {
    ip,
    status: cleanString(payload?.status, "unavailable", 40),
    warning,
  };
}

function blockingPrewarmFailure(payload) {
  const text = `${payload?.status || ""} ${(payload?.warnings || []).join(" ")}`.toLowerCase();
  if (text.includes("authorization failed") || text.includes("api_key") || text.includes("not configured")) {
    return "unavailable";
  }

  return "";
}

export async function prewarmVirusTotalQueuedIps(env = {}, options = {}) {
  const apiKey = normalizeSecretValue(env?.VIRUSTOTAL_API_KEY);
  const queue = await readPrewarmQueue(env);

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
    const completedIps = queueCompletedIps(queue);
    return {
      status: "cooldown",
      attempted: 0,
      cached: 0,
      remaining: remainingQueueCount(queue.ips, completedIps),
      next_run_at: new Date(lastRun + 60_000).toISOString(),
      warnings: [],
    };
  }

  const limit = Math.max(1, Math.min(PREWARM_LIMIT_PER_MINUTE, numberOrNull(options.limit) || PREWARM_LIMIT_PER_MINUTE));
  const { entries: batch, nextCursor, completedIps } = nextPendingEntries(queue, limit);
  let attempted = 0;
  let cached = 0;
  let cursor = nextCursor;
  let terminalStatus = "";
  const failures = [];

  for (const entry of batch) {
    if (!reserveMinuteBudget()) {
      break;
    }

    attempted += 1;
    cursor = (entry.index + 1) % queue.ips.length;

    try {
      const payload = await buildVirusTotalIpPayload(entry.ip, env, { ignoreBudget: true });
      if (isCachePayloadUsable(payload)) {
        cached += 1;
        completedIps.add(entry.ip);
      } else {
        failures.push(prewarmFailureSummary(entry.ip, payload));
        terminalStatus = terminalStatus || blockingPrewarmFailure(payload);
        if (terminalStatus) {
          break;
        }
      }
    } catch {
      failures.push({ ip: entry.ip, status: "error", warning: "VirusTotal warmup lookup failed." });
    }
  }

  const remainingAfter = remainingQueueCount(queue.ips, completedIps);
  const updatedQueue = {
    ...queue,
    cursor,
    completed_ips: [...completedIps],
    updated_at: new Date().toISOString(),
    last_run_at: new Date().toISOString(),
    completed: remainingAfter === 0,
    last_failures: failures.slice(0, 8),
  };

  await writePrewarmQueue(updatedQueue, env);

  return {
    status: terminalStatus || (remainingAfter ? "warming" : "complete"),
    attempted,
    cached,
    remaining: remainingAfter,
    next_run_at: remainingAfter && !terminalStatus ? new Date(Date.now() + 60_000).toISOString() : "",
    warnings: failures.map((failure) =>
      failure.warning
        ? `${failure.ip}: ${failure.status} - ${failure.warning}`
        : `${failure.ip}: ${failure.status}`,
    ).slice(0, 4),
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
    tags: payload.tags || [],
    threat_labels: payload.threat_labels || [],
    detection_names: payload.detection_names || [],
    last_analysis_date: payload.last_analysis_date,
    permalink: payload.permalink,
    generated_at: payload.generated_at,
    cache_status: payload.cache_status || "cached",
  };
}

async function readCachedDetailSummary(ip, env = {}) {
  const payload = await readCachedDetail(ip, env);
  return summaryFromPayload(payload);
}

export async function addVirusTotalSummariesToPoints(points, env = {}) {
  if (!Array.isArray(points) || !points.length) {
    return [];
  }

  const summaries = await Promise.all(
    points.map(async (point) => {
      const ip = normalizeIp(point?.ip);
      return isIpAddress(ip) ? readCachedDetailSummary(ip, env) : null;
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
    const cached = await readCachedDetail(ip, env);
    if (cached) {
      return json(await addMitreTechniques(cached));
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
