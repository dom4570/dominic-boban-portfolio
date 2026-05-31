import { isLiveThreatMapIp } from "./abuse-origin-map.js";
import {
  addMitrePatternAnalysis,
  normalizeAbuseIpdbEvidence,
} from "./threat-pattern-engine.js";

const ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check";
const ABUSEIPDB_REPORTS_URL = "https://api.abuseipdb.com/api/v2/reports";
const SUMMARY_MAX_AGE_DAYS = 90;
const REPORTS_MAX_AGE_DAYS = 7;
const REPORTS_PER_PAGE = 10;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_TTL_SECONDS = Math.floor(CACHE_TTL_MS / 1000);
const CACHE_SCHEMA_VERSION = 1;
const LOCAL_CACHE_FILE = ".cache/abuseipdb-ip-detail.json";
const EDGE_CACHE_PREFIX = "https://portfolio-cache.local/abuseipdb-ip-detail/";

const categoryDefinitions = new Map([
  [1, "DNS Compromise"],
  [2, "DNS Poisoning"],
  [3, "Fraud Orders"],
  [4, "DDoS Attack"],
  [5, "FTP Brute-Force"],
  [6, "Ping of Death"],
  [7, "Phishing"],
  [8, "Fraud VoIP"],
  [9, "Open Proxy"],
  [10, "Web Spam"],
  [11, "Email Spam"],
  [12, "Blog Spam"],
  [13, "VPN IP"],
  [14, "Port Scan"],
  [15, "Hacking"],
  [16, "SQL Injection"],
  [17, "Spoofing"],
  [18, "Brute-Force"],
  [19, "Bad Web Bot"],
  [20, "Exploited Host"],
  [21, "Web App Attack"],
  [22, "SSH"],
  [23, "IoT Targeted"],
]);

let memoryCache = new Map();
let pendingSummaries = new Map();
let pendingReports = new Map();

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

function cleanComment(value) {
  return cleanString(value, "", 260);
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

function booleanOrNull(value) {
  return value === true || value === false ? value : null;
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
  const detail = body?.errors?.[0]?.detail || body?.message || body?.error;
  return cleanString(detail, fallback, 220);
}

function rateLimitWarning(response, fallback) {
  const reset = numberOrNull(response.headers.get("X-RateLimit-Reset"));
  const retryAfter = numberOrNull(response.headers.get("Retry-After"));

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
    (payload.status === "reported" || payload.status === "not_reported") &&
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

async function localCachePath() {
  if (!isNodeRuntime()) {
    return "";
  }

  const path = await import("node:path");
  return path.resolve(process.cwd(), LOCAL_CACHE_FILE);
}

async function readLocalCacheFile() {
  const filePath = await localCachePath();
  if (!filePath) {
    return {};
  }

  try {
    const fs = await import("node:fs/promises");
    return JSON.parse(await fs.readFile(filePath, "utf8"));
  } catch {
    return {};
  }
}

async function readLocalCache(ip) {
  const payload = (await readLocalCacheFile())[ip];
  return isCachePayloadUsable(payload) ? payload : null;
}

async function writeLocalCache(payload) {
  const filePath = await localCachePath();
  if (!filePath || !isCachePayloadUsable(payload)) {
    return;
  }

  try {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    const cache = await readLocalCacheFile();
    cache[payload.ip] = payload;
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(cache, null, 2), "utf8");
  } catch {
    // The in-memory cache still protects AbuseIPDB for this process.
  }
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

function categoryLabel(id) {
  return categoryDefinitions.get(Number(id)) || `Category ${id}`;
}

function normalizeCategory(id, count = undefined) {
  const normalizedId = numberOrNull(id) || 0;
  return {
    id: normalizedId,
    label: categoryLabel(normalizedId),
    ...(typeof count === "number" ? { count } : {}),
  };
}

function categoriesFromIds(ids) {
  return [...new Set((Array.isArray(ids) ? ids : []).map((id) => numberOrNull(id)).filter(Boolean))].map((id) => normalizeCategory(id));
}

function topCategoriesFromReports(reports) {
  const counts = new Map();

  for (const report of Array.isArray(reports) ? reports : []) {
    for (const category of Array.isArray(report.categories) ? report.categories : []) {
      const id = numberOrNull(category?.id || category);
      if (id) {
        counts.set(id, (counts.get(id) || 0) + 1);
      }
    }
  }

  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0] - right[0])
    .slice(0, 6)
    .map(([id, count]) => normalizeCategory(id, count));
}

function statusPayload(ip, status, warnings = []) {
  return {
    cache_schema_version: CACHE_SCHEMA_VERSION,
    ip,
    provider: "abuseipdb",
    status,
    abuse_confidence_score: 0,
    total_reports: 0,
    num_distinct_users: 0,
    max_age_in_days: SUMMARY_MAX_AGE_DAYS,
    report_window_days: REPORTS_MAX_AGE_DAYS,
    usage_type: "",
    isp: "",
    domain: "",
    hostnames: [],
    country_code: "",
    country_name: "",
    is_tor: false,
    is_whitelisted: null,
    last_reported_at: "",
    recent_report_total: 0,
    recent_reports: [],
    reports_status: "not_loaded",
    top_categories: [],
    mitre_techniques: [],
    mitre_matches: [],
    generated_at: new Date().toISOString(),
    cache_status: "fresh",
    cache_expires_at: expiresAtFromNow(),
    warnings,
  };
}

function normalizeSummaryPayload(ip, data) {
  const totalReports = Math.max(0, numberOrNull(data?.totalReports) || 0);
  const abuseScore = Math.max(0, Math.min(100, numberOrNull(data?.abuseConfidenceScore) || 0));

  return {
    ...statusPayload(ip, totalReports > 0 || abuseScore > 0 ? "reported" : "not_reported"),
    abuse_confidence_score: abuseScore,
    total_reports: totalReports,
    num_distinct_users: Math.max(0, numberOrNull(data?.numDistinctUsers) || 0),
    usage_type: cleanString(data?.usageType, "", 120),
    isp: cleanString(data?.isp, "", 140),
    domain: cleanString(data?.domain, "", 140),
    hostnames: Array.isArray(data?.hostnames) ? data.hostnames.map((hostname) => cleanString(hostname, "", 140)).filter(Boolean).slice(0, 4) : [],
    country_code: cleanString(data?.countryCode, "", 4).toUpperCase(),
    country_name: cleanString(data?.countryName, "", 120),
    is_tor: data?.isTor === true,
    is_whitelisted: booleanOrNull(data?.isWhitelisted),
    last_reported_at: cleanString(data?.lastReportedAt, "", 80),
  };
}

function normalizeReport(report) {
  return {
    reported_at: cleanString(report?.reportedAt, "", 80),
    reporter_country_code: cleanString(report?.reporterCountryCode, "", 4).toUpperCase(),
    reporter_country_name: cleanString(report?.reporterCountryName, "", 120),
    comment: cleanComment(report?.comment),
    categories: categoriesFromIds(report?.categories),
  };
}

async function addMitreTechniques(payload) {
  return addMitrePatternAnalysis(payload, "abuseipdb", normalizeAbuseIpdbEvidence);
}

async function fetchAbuseIpdbCheck(ip, apiKey) {
  const url = new URL(ABUSEIPDB_CHECK_URL);
  url.searchParams.set("ipAddress", ip);
  url.searchParams.set("maxAgeInDays", String(SUMMARY_MAX_AGE_DAYS));

  let response;
  let body;

  try {
    ({ response, body } = await fetchJson(
      url.toString(),
      {
        headers: {
          Accept: "application/json",
          Key: apiKey,
          "User-Agent": "DominicBobanPortfolio/1.0 abuseipdb-ip-detail",
        },
      },
      9000,
    ));
  } catch (error) {
    return statusPayload(ip, "unavailable", [`AbuseIPDB check failed: ${messageFromError(error, "request failed")}.`]);
  }

  if (response.status === 401 || response.status === 403) {
    return statusPayload(ip, "unavailable", ["AbuseIPDB authorization failed. Check ABUSEIPDB_API_KEY."]);
  }

  if (response.status === 429) {
    return statusPayload(ip, "unavailable", [rateLimitWarning(response, "AbuseIPDB check is rate limited right now.")]);
  }

  if (!response.ok || body?.errors) {
    return statusPayload(ip, "unavailable", [upstreamMessage(body, `AbuseIPDB check returned status ${response.status}.`)]);
  }

  return normalizeSummaryPayload(ip, body?.data || {});
}

async function fetchAbuseIpdbReports(ip, apiKey) {
  const url = new URL(ABUSEIPDB_REPORTS_URL);
  url.searchParams.set("ipAddress", ip);
  url.searchParams.set("maxAgeInDays", String(REPORTS_MAX_AGE_DAYS));
  url.searchParams.set("perPage", String(REPORTS_PER_PAGE));
  url.searchParams.set("page", "1");

  let response;
  let body;

  try {
    ({ response, body } = await fetchJson(
      url.toString(),
      {
        headers: {
          Accept: "application/json",
          Key: apiKey,
          "User-Agent": "DominicBobanPortfolio/1.0 abuseipdb-ip-reports",
        },
      },
      9000,
    ));
  } catch (error) {
    return {
      reports_status: "unavailable",
      warning: `AbuseIPDB recent reports failed: ${messageFromError(error, "request failed")}.`,
    };
  }

  if (response.status === 401 || response.status === 403) {
    return {
      reports_status: "unavailable",
      warning: "AbuseIPDB reports authorization failed. Check ABUSEIPDB_API_KEY.",
    };
  }

  if (response.status === 429) {
    return {
      reports_status: "unavailable",
      warning: rateLimitWarning(response, "AbuseIPDB reports are rate limited right now."),
    };
  }

  if (!response.ok || body?.errors) {
    return {
      reports_status: "unavailable",
      warning: upstreamMessage(body, `AbuseIPDB reports returned status ${response.status}.`),
    };
  }

  const reports = (Array.isArray(body?.data?.results) ? body.data.results : []).map(normalizeReport).filter((report) => report.reported_at);

  return {
    reports_status: reports.length ? "found" : "not_found",
    recent_report_total: Math.max(0, numberOrNull(body?.data?.total) || reports.length),
    recent_reports: reports,
    top_categories: topCategoriesFromReports(reports),
    warning: "",
  };
}

async function addReportDetail(payload, env) {
  if (
    !isCachePayloadUsable(payload) ||
    payload.reports_status === "found" ||
    payload.reports_status === "not_found" ||
    payload.reports_status === "unavailable"
  ) {
    return payload;
  }

  const apiKey = normalizeSecretValue(env?.ABUSEIPDB_API_KEY);
  if (!apiKey) {
    return {
      ...payload,
      warnings: [...(payload.warnings || []), "ABUSEIPDB_API_KEY is not configured."],
    };
  }

  if (pendingReports.has(payload.ip)) {
    return pendingReports.get(payload.ip);
  }

  const pending = fetchAbuseIpdbReports(payload.ip, apiKey)
    .then((reportPayload) => {
      const warnings = [...(payload.warnings || [])];
      if (reportPayload.warning) {
        warnings.push(reportPayload.warning);
      }

      const merged = {
        ...payload,
        status: reportPayload.recent_report_total > 0 ? "reported" : payload.status,
        total_reports: Math.max(payload.total_reports || 0, reportPayload.recent_report_total || 0),
        reports_status: reportPayload.reports_status,
        recent_report_total: reportPayload.recent_report_total || 0,
        recent_reports: reportPayload.recent_reports || [],
        top_categories: reportPayload.top_categories?.length ? reportPayload.top_categories : payload.top_categories || [],
        warnings,
      };

      return merged;
    })
    .then(async (merged) => {
      await writeCachedDetail(merged);
      return merged;
    })
    .finally(() => pendingReports.delete(payload.ip));

  pendingReports.set(payload.ip, pending);
  return pending;
}

async function buildAbuseIpdbDetailPayload(ip, env, options = {}) {
  const cached = await readCachedDetail(ip);
  if (cached) {
    return options.includeReports ? addReportDetail(cached, env) : cached;
  }

  const apiKey = normalizeSecretValue(env?.ABUSEIPDB_API_KEY);
  if (!apiKey) {
    return statusPayload(ip, "not_configured", ["ABUSEIPDB_API_KEY is not configured."]);
  }

  if (!pendingSummaries.has(ip)) {
    const pending = fetchAbuseIpdbCheck(ip, apiKey)
      .then(async (payload) => {
        await writeCachedDetail(payload);
        return payload;
      })
      .finally(() => pendingSummaries.delete(ip));

    pendingSummaries.set(ip, pending);
  }

  const summary = await pendingSummaries.get(ip);
  return options.includeReports ? addReportDetail(summary, env) : summary;
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

async function runLimited(items, concurrency, timeoutMs, worker) {
  const startedAt = Date.now();
  let index = 0;
  let attempted = 0;
  let cached = 0;

  async function runWorker() {
    while (index < items.length && Date.now() - startedAt < timeoutMs) {
      const item = items[index];
      index += 1;
      attempted += 1;

      try {
        const result = await worker(item);
        if (isCachePayloadUsable(result)) {
          cached += 1;
        }
      } catch {
        // Prewarm is opportunistic; selected-IP lookup can retry later.
      }
    }
  }

  const workerCount = Math.max(1, Math.min(concurrency, items.length));
  await Promise.all(Array.from({ length: workerCount }, runWorker));

  return {
    attempted,
    cached,
    skipped: Math.max(0, items.length - attempted),
  };
}

function summaryFromPayload(payload) {
  if (!isCachePayloadUsable(payload)) {
    return null;
  }

  return {
    provider: "abuseipdb",
    status: payload.status,
    abuse_confidence_score: payload.abuse_confidence_score,
    total_reports: payload.total_reports,
    num_distinct_users: payload.num_distinct_users,
    max_age_in_days: payload.max_age_in_days,
    usage_type: payload.usage_type,
    isp: payload.isp,
    domain: payload.domain,
    country_code: payload.country_code,
    country_name: payload.country_name,
    is_tor: payload.is_tor,
    is_whitelisted: payload.is_whitelisted,
    last_reported_at: payload.last_reported_at,
    top_categories: payload.top_categories || [],
    generated_at: payload.generated_at,
    cache_status: payload.cache_status || "cached",
  };
}

async function readCachedDetailSummary(ip) {
  const payload = await readCachedDetail(ip);
  return summaryFromPayload(payload);
}

export async function prewarmAbuseIpdbDetails(points, env = {}, options = {}) {
  const apiKey = normalizeSecretValue(env?.ABUSEIPDB_API_KEY);
  const ips = uniqueIpsFromPoints(points);

  if (!apiKey || !ips.length) {
    return {
      attempted: 0,
      cached: 0,
      skipped: ips.length,
    };
  }

  const concurrency = Number.isFinite(Number(options.concurrency)) ? Number(options.concurrency) : 3;
  const timeoutMs = Number.isFinite(Number(options.timeoutMs)) ? Number(options.timeoutMs) : 25000;

  return runLimited(ips, concurrency, timeoutMs, (ip) => buildAbuseIpdbDetailPayload(ip, env));
}

export async function addAbuseIpdbSummariesToPoints(points) {
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
    const { abuseipdb_intelligence: _abuseIpdbIntelligence, ...cleanPoint } = point;
    const summary = summaries[index];
    return summary ? { ...cleanPoint, abuseipdb_intelligence: summary } : cleanPoint;
  });
}

export async function handleAbuseIpdbIpDetailRequest(request, env = {}) {
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
      return json(await addMitreTechniques(await addReportDetail(cached, env)));
    }

    if (!(await isLiveThreatMapIp(ip, env))) {
      return json(statusPayload(ip, "unavailable", ["IP Intelligence is only available for IPs from the current or recent Daily Top 50 map. Reload the map to refresh the selected source."]));
    }

    return json(await addMitreTechniques(await buildAbuseIpdbDetailPayload(ip, env, { includeReports: true })));
  } catch (error) {
    return json(statusPayload(ip, "unavailable", ["AbuseIPDB detail is temporarily unavailable."]));
  }
}
