const ABUSEIPDB_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist";
const IP_API_BATCH_URL = "http://ip-api.com/batch";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_TTL_SECONDS = Math.floor(CACHE_TTL_MS / 1000);
const POINT_LIMIT = 50;
const DEFAULT_CONFIDENCE_MINIMUM = 90;
const CACHE_SCHEMA_VERSION = 1;
const LOCAL_CACHE_FILE = ".cache/abuse-origin-map.json";
const EDGE_CACHE_URL = "https://portfolio-cache.local/abuse-origin-map/daily-top-50";
const KV_CACHE_KEY = "abuse-origin-map:daily-top-50";
const SPAMHAUS_PREWARM_CONCURRENCY = 3;
const SPAMHAUS_PREWARM_TIMEOUT_MS = 25000;
const ABUSEIPDB_PREWARM_CONCURRENCY = 3;
const ABUSEIPDB_PREWARM_TIMEOUT_MS = 25000;
const SCHEDULED_REFRESH_HOUR_LONDON = 1;
const SCHEDULED_REFRESH_MINUTE_LONDON = 30;

let cachedPayload = null;
let cachedUntil = 0;
let pendingLivePayload = null;
const regionNames = new Intl.DisplayNames(["en"], { type: "region" });

const countryCentroids = new Map(
  Object.entries({
    AE: [23.4241, 53.8478],
    AL: [41.1533, 20.1683],
    AR: [-38.4161, -63.6167],
    AT: [47.5162, 14.5501],
    AU: [-25.2744, 133.7751],
    AZ: [40.1431, 47.5769],
    BA: [43.9159, 17.6791],
    BD: [23.685, 90.3563],
    BE: [50.5039, 4.4699],
    BG: [42.7339, 25.4858],
    BO: [-16.2902, -63.5887],
    BR: [-14.235, -51.9253],
    BY: [53.7098, 27.9534],
    CA: [56.1304, -106.3468],
    CH: [46.8182, 8.2275],
    CL: [-35.6751, -71.543],
    CN: [35.8617, 104.1954],
    CO: [4.5709, -74.2973],
    CR: [9.7489, -83.7534],
    CZ: [49.8175, 15.473],
    DE: [51.1657, 10.4515],
    DK: [56.2639, 9.5018],
    DO: [18.7357, -70.1627],
    EC: [-1.8312, -78.1834],
    EE: [58.5953, 25.0136],
    EG: [26.8206, 30.8025],
    ES: [40.4637, -3.7492],
    FI: [61.9241, 25.7482],
    FR: [46.2276, 2.2137],
    GB: [55.3781, -3.436],
    GE: [42.3154, 43.3569],
    GR: [39.0742, 21.8243],
    HK: [22.3193, 114.1694],
    HR: [45.1, 15.2],
    HU: [47.1625, 19.5033],
    ID: [-0.7893, 113.9213],
    IE: [53.1424, -7.6921],
    IL: [31.0461, 34.8516],
    IN: [20.5937, 78.9629],
    IR: [32.4279, 53.688],
    IT: [41.8719, 12.5674],
    JP: [36.2048, 138.2529],
    KE: [-0.0236, 37.9062],
    KH: [12.5657, 104.991],
    KR: [35.9078, 127.7669],
    KZ: [48.0196, 66.9237],
    LA: [19.8563, 102.4955],
    LK: [7.8731, 80.7718],
    LT: [55.1694, 23.8813],
    LV: [56.8796, 24.6032],
    MA: [31.7917, -7.0926],
    MD: [47.4116, 28.3699],
    MK: [41.6086, 21.7453],
    MM: [21.9162, 95.956],
    MX: [23.6345, -102.5528],
    MY: [4.2105, 101.9758],
    NG: [9.082, 8.6753],
    NL: [52.1326, 5.2913],
    NO: [60.472, 8.4689],
    NP: [28.3949, 84.124],
    NZ: [-40.9006, 174.886],
    PA: [8.538, -80.7821],
    PE: [-9.19, -75.0152],
    PH: [12.8797, 121.774],
    PK: [30.3753, 69.3451],
    PL: [51.9194, 19.1451],
    PT: [39.3999, -8.2245],
    PY: [-23.4425, -58.4438],
    RO: [45.9432, 24.9668],
    RS: [44.0165, 21.0059],
    RU: [61.524, 105.3188],
    SA: [23.8859, 45.0792],
    SC: [-4.6796, 55.492],
    SE: [60.1282, 18.6435],
    SG: [1.3521, 103.8198],
    SI: [46.1512, 14.9955],
    SK: [48.669, 19.699],
    TH: [15.87, 100.9925],
    TR: [38.9637, 35.2433],
    TW: [23.6978, 120.9605],
    UA: [48.3794, 31.1656],
    US: [37.0902, -95.7129],
    UY: [-32.5228, -55.7658],
    UZ: [41.3775, 64.5853],
    VE: [6.4238, -66.5897],
    VN: [14.0583, 108.2772],
    ZA: [-30.5595, 22.9375],
  })
);

const fallbackPoints = [
  {
    id: "demo-london",
    ip: "203.0.113.41",
    latitude: 51.5072,
    longitude: -0.1276,
    city: "London",
    region: "England",
    country: "United Kingdom",
    country_code: "GB",
    abuse_confidence_score: 96,
    last_reported_at: "Demo data",
    asn: "AS-DOCS",
    as_name: "Documentation sample",
    isp: "Documentation sample",
    org: "Documentation sample",
    hosting: true,
    proxy: false,
    mobile: false,
    source: "fallback_demo",
  },
  {
    id: "demo-frankfurt",
    ip: "198.51.100.77",
    latitude: 50.1109,
    longitude: 8.6821,
    city: "Frankfurt",
    region: "Hesse",
    country: "Germany",
    country_code: "DE",
    abuse_confidence_score: 91,
    last_reported_at: "Demo data",
    asn: "AS-DOCS",
    as_name: "Documentation sample",
    isp: "Documentation sample",
    org: "Documentation sample",
    hosting: true,
    proxy: true,
    mobile: false,
    source: "fallback_demo",
  },
  {
    id: "demo-singapore",
    ip: "192.0.2.84",
    latitude: 1.3521,
    longitude: 103.8198,
    city: "Singapore",
    region: "Singapore",
    country: "Singapore",
    country_code: "SG",
    abuse_confidence_score: 88,
    last_reported_at: "Demo data",
    asn: "AS-DOCS",
    as_name: "Documentation sample",
    isp: "Documentation sample",
    org: "Documentation sample",
    hosting: true,
    proxy: false,
    mobile: false,
    source: "fallback_demo",
  },
  {
    id: "demo-sao-paulo",
    ip: "203.0.113.108",
    latitude: -23.5558,
    longitude: -46.6396,
    city: "Sao Paulo",
    region: "Sao Paulo",
    country: "Brazil",
    country_code: "BR",
    abuse_confidence_score: 82,
    last_reported_at: "Demo data",
    asn: "AS-DOCS",
    as_name: "Documentation sample",
    isp: "Documentation sample",
    org: "Documentation sample",
    hosting: false,
    proxy: false,
    mobile: false,
    source: "fallback_demo",
  },
  {
    id: "demo-toronto",
    ip: "198.51.100.142",
    latitude: 43.6532,
    longitude: -79.3832,
    city: "Toronto",
    region: "Ontario",
    country: "Canada",
    country_code: "CA",
    abuse_confidence_score: 79,
    last_reported_at: "Demo data",
    asn: "AS-DOCS",
    as_name: "Documentation sample",
    isp: "Documentation sample",
    org: "Documentation sample",
    hosting: false,
    proxy: true,
    mobile: false,
    source: "fallback_demo",
  },
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

function cleanString(value, fallback = "", maxLength = 160) {
  return String(value || fallback)
    .replace(/[^\w .,:()#+&/-]/g, "")
    .trim()
    .slice(0, maxLength);
}

function cleanCountryCode(value) {
  const code = cleanString(value, "", 4).toUpperCase();
  return /^[A-Z]{2}$/.test(code) ? code : "";
}

function numberOrNull(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function booleanValue(value) {
  return value === true;
}

function isUsableCoordinate(lat, lon) {
  return typeof lat === "number" && typeof lon === "number" && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

function isoFromTime(time) {
  return new Date(time).toISOString();
}

function londonDateParts(date) {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Europe/London",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);

  return Object.fromEntries(parts.filter((part) => part.type !== "literal").map((part) => [part.type, Number(part.value)]));
}

function londonOffsetMs(date) {
  const parts = londonDateParts(date);
  const londonAsUtc = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
  return londonAsUtc - date.getTime();
}

function utcTimeForLondonWallTime(year, month, day, hour, minute) {
  const roughUtc = Date.UTC(year, month - 1, day, hour, minute, 0);
  const firstPass = roughUtc - londonOffsetMs(new Date(roughUtc));
  const secondPass = roughUtc - londonOffsetMs(new Date(firstPass));
  return secondPass;
}

function nextScheduledRefreshTime(now = Date.now()) {
  const current = new Date(now);
  const parts = londonDateParts(current);
  const todayRefresh = utcTimeForLondonWallTime(
    parts.year,
    parts.month,
    parts.day,
    SCHEDULED_REFRESH_HOUR_LONDON,
    SCHEDULED_REFRESH_MINUTE_LONDON,
  );

  if (now < todayRefresh) {
    return todayRefresh;
  }

  const tomorrow = new Date(utcTimeForLondonWallTime(parts.year, parts.month, parts.day, 12, 0) + CACHE_TTL_MS);
  const tomorrowParts = londonDateParts(tomorrow);
  return utcTimeForLondonWallTime(
    tomorrowParts.year,
    tomorrowParts.month,
    tomorrowParts.day,
    SCHEDULED_REFRESH_HOUR_LONDON,
    SCHEDULED_REFRESH_MINUTE_LONDON,
  );
}

function isNodeRuntime() {
  return typeof process !== "undefined" && Boolean(process.versions?.node);
}

function threatIntelKv(env = {}) {
  const namespace = env.THREAT_INTEL_KV || env.THREAT_MAP_KV;
  return namespace && typeof namespace.get === "function" && typeof namespace.put === "function" ? namespace : null;
}

async function readKvCache(env = {}) {
  const namespace = threatIntelKv(env);
  if (!namespace) {
    return null;
  }

  const payload = await namespace.get(KV_CACHE_KEY, { type: "json" }).catch(() => null);
  return isCachePayloadUsable(payload) ? payload : null;
}

async function writeKvCache(payload, env = {}) {
  const namespace = threatIntelKv(env);
  if (!namespace || !isCachePayloadUsable(payload)) {
    return;
  }

  const ttl = Math.max(60, Math.min(CACHE_TTL_SECONDS, Math.floor((effectiveCacheExpiryTime(payload) - Date.now()) / 1000)));
  await namespace
    .put(KV_CACHE_KEY, JSON.stringify(payload), {
      expirationTtl: ttl,
    })
    .catch(() => {});
}

function cacheExpiryTime(payload) {
  const expiry = new Date(payload?.cache_expires_at || payload?.next_refresh_at || 0).getTime();
  return Number.isFinite(expiry) ? expiry : 0;
}

function payloadGeneratedTime(payload) {
  const generated = new Date(payload?.generated_at || 0).getTime();
  return Number.isFinite(generated) && generated > 0 ? generated : 0;
}

function effectiveCacheExpiryTime(payload, now = Date.now()) {
  const storedExpiry = cacheExpiryTime(payload);

  if (payload?.mode !== "live") {
    return storedExpiry;
  }

  const generated = payloadGeneratedTime(payload);
  const scheduledExpiry = nextScheduledRefreshTime(generated || now);

  if (!storedExpiry) {
    return scheduledExpiry;
  }

  return Math.min(storedExpiry, scheduledExpiry);
}

function isCachePayloadUsable(payload, now = Date.now()) {
  return payload?.mode === "live" && Array.isArray(payload.points) && payload.points.length > 0 && effectiveCacheExpiryTime(payload, now) > now;
}

function setMemoryCache(payload) {
  cachedUntil = effectiveCacheExpiryTime(payload);
  cachedPayload = {
    ...payload,
    cache_expires_at: isoFromTime(cachedUntil),
    next_refresh_at: isoFromTime(cachedUntil),
  };
}

function fallbackPayload(warning) {
  return {
    mode: "fallback",
    cache_status: "fallback",
    generated_at: new Date().toISOString(),
    cache_expires_at: null,
    next_refresh_at: null,
    source: "fallback_demo",
    points: fallbackPoints.map((point, index) => ({ ...point, rank: index + 1 })),
    warnings: [warning],
  };
}

function messageFromError(error, fallback) {
  return cleanString(error?.message || error, fallback, 240);
}

function cachedResponse(cacheStatus, warning) {
  const warnings = [...(cachedPayload?.warnings || [])];

  if (warning) {
    warnings.push(warning);
  }

  return {
    ...cachedPayload,
    cache_status: cacheStatus,
    cache_expires_at: isoFromTime(cachedUntil),
    next_refresh_at: isoFromTime(cachedUntil),
    warnings,
  };
}

function cacheablePayload(payload, cacheStatus = payload.cache_status || "fresh") {
  return {
    ...payload,
    cache_schema_version: CACHE_SCHEMA_VERSION,
    cache_status: cacheStatus,
    cache_expires_at: isoFromTime(cachedUntil),
    next_refresh_at: isoFromTime(cachedUntil),
  };
}

function edgeCacheRequest() {
  return new Request(EDGE_CACHE_URL, { method: "GET" });
}

async function readEdgeCache() {
  if (!globalThis.caches?.default) {
    return null;
  }

  const response = await globalThis.caches.default.match(edgeCacheRequest()).catch(() => null);
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

  const maxAge = Math.max(1, Math.min(CACHE_TTL_SECONDS, Math.floor((effectiveCacheExpiryTime(payload) - Date.now()) / 1000)));
  const response = new Response(JSON.stringify(payload), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": `public, max-age=${maxAge}`,
    },
  });

  await globalThis.caches.default.put(edgeCacheRequest(), response).catch(() => {});
}

async function localCachePath() {
  if (!isNodeRuntime()) {
    return "";
  }

  const path = await import("node:path");
  return path.resolve(process.cwd(), LOCAL_CACHE_FILE);
}

async function readLocalCache() {
  const filePath = await localCachePath();
  if (!filePath) {
    return null;
  }

  try {
    const fs = await import("node:fs/promises");
    const payload = JSON.parse(await fs.readFile(filePath, "utf8"));
    return isCachePayloadUsable(payload) ? payload : null;
  } catch {
    return null;
  }
}

async function writeLocalCache(payload) {
  const filePath = await localCachePath();
  if (!filePath || !isCachePayloadUsable(payload)) {
    return;
  }

  try {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(payload, null, 2), "utf8");
  } catch {
    // The in-memory cache still protects the API quota for this process.
  }
}

async function readPersistentCache(env = {}) {
  const payload = (await readKvCache(env)) || (await readEdgeCache()) || (await readLocalCache());

  if (!payload) {
    return null;
  }

  setMemoryCache(payload);
  return cachedResponse(payload.cache_status === "stale" ? "stale" : "cached");
}

async function writePersistentCache(payload, env = {}) {
  await Promise.all([writeKvCache(payload, env), writeEdgeCache(payload), writeLocalCache(payload)]);
}

async function withIpIntelligenceSummaries(payload, env = {}) {
  if (payload?.mode !== "live" || !Array.isArray(payload.points) || !payload.points.length) {
    return payload;
  }

  let points = payload.points;

  try {
    const { addSpamhausSummariesToPoints } = await import("./spamhaus-ip-detail.js");
    points = await addSpamhausSummariesToPoints(points);
  } catch {
    // Summary enrichment is best-effort; the map should still render.
  }

  try {
    const { addAbuseIpdbSummariesToPoints } = await import("./abuseipdb-ip-detail.js");
    points = await addAbuseIpdbSummariesToPoints(points);
  } catch {
    // Summary enrichment is best-effort; selected-IP detail can retry later.
  }

  try {
    const { addVirusTotalSummariesToPoints } = await import("./virustotal-ip-detail.js");
    points = await addVirusTotalSummariesToPoints(points, env);
  } catch {
    // VirusTotal summary enrichment is best-effort and rate-limit aware.
  }

  return {
    ...payload,
    points,
  };
}

function scheduleSpamhausPrewarm(points, env, context) {
  if (!Array.isArray(points) || !points.length) {
    return;
  }

  const task = import("./spamhaus-ip-detail.js")
    .then(({ prewarmSpamhausDetails }) =>
      prewarmSpamhausDetails(points, env, {
        concurrency: SPAMHAUS_PREWARM_CONCURRENCY,
        timeoutMs: SPAMHAUS_PREWARM_TIMEOUT_MS,
      }),
    )
    .catch(() => null);

  if (typeof context?.waitUntil === "function") {
    context.waitUntil(task);
    return;
  }

  void task;
}

function scheduleAbuseIpdbPrewarm(points, env, context) {
  if (!Array.isArray(points) || !points.length) {
    return;
  }

  const task = import("./abuseipdb-ip-detail.js")
    .then(({ prewarmAbuseIpdbDetails }) =>
      prewarmAbuseIpdbDetails(points, env, {
        concurrency: ABUSEIPDB_PREWARM_CONCURRENCY,
        timeoutMs: ABUSEIPDB_PREWARM_TIMEOUT_MS,
      }),
    )
    .catch(() => null);

  if (typeof context?.waitUntil === "function") {
    context.waitUntil(task);
    return;
  }

  void task;
}

async function scheduleVirusTotalQueue(points, env, context) {
  if (!Array.isArray(points) || !points.length) {
    return;
  }

  try {
    const { storeVirusTotalPrewarmQueue } = await import("./virustotal-ip-detail.js");
    await storeVirusTotalPrewarmQueue(points, env);
  } catch {
    void context;
  }
}

function countryNameFromCode(countryCode) {
  try {
    return regionNames.of(countryCode) || countryCode;
  } catch {
    return countryCode;
  }
}

function upstreamMessage(body, fallback) {
  const detail = body?.errors?.[0]?.detail || body?.message || body?.error;
  return cleanString(detail, fallback, 220);
}

async function fetchAbuseIpdbBlacklist(apiKey) {
  const url = new URL(ABUSEIPDB_BLACKLIST_URL);
  url.searchParams.set("confidenceMinimum", String(DEFAULT_CONFIDENCE_MINIMUM));
  url.searchParams.set("limit", String(POINT_LIMIT));

  const response = await fetch(url.toString(), {
    headers: {
      Accept: "application/json",
      Key: apiKey,
      "User-Agent": "DominicBobanPortfolio/1.0 live-threat-map",
    },
  });
  const body = await response.json().catch(() => null);

  if (!response.ok || body?.errors) {
    throw new Error(upstreamMessage(body, "AbuseIPDB is temporarily unavailable."));
  }

  const rows = Array.isArray(body?.data) ? body.data : [];
  const unique = new Map();

  rows.forEach((row) => {
    const ip = cleanString(row?.ipAddress, "", 80);
    if (!ip || unique.has(ip)) return;

    unique.set(ip, {
      rank: unique.size + 1,
      ip,
      abuse_confidence_score: Math.max(0, Math.min(100, numberOrNull(row?.abuseConfidenceScore) ?? 0)),
      last_reported_at: cleanString(row?.lastReportedAt, "", 80),
      abuse_country_code: cleanCountryCode(row?.countryCode),
    });
  });

  return {
    generated_at: cleanString(body?.meta?.generatedAt, new Date().toISOString(), 80),
    rows: [...unique.values()].slice(0, POINT_LIMIT),
  };
}

async function fetchGeoBatch(ips) {
  const url = new URL(IP_API_BATCH_URL);
  url.searchParams.set("fields", "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,mobile,proxy,hosting");

  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": "DominicBobanPortfolio/1.0 live-threat-map",
    },
    body: JSON.stringify(ips.slice(0, 100)),
  });
  const body = await response.json().catch(() => null);

  if (!response.ok || !Array.isArray(body)) {
    throw new Error("Geo-IP lookup is temporarily unavailable.");
  }

  return body;
}

function normalizePoint(row, geo, index) {
  const latitude = numberOrNull(geo?.lat);
  const longitude = numberOrNull(geo?.lon);

  if (geo?.status !== "success" || !isUsableCoordinate(latitude, longitude)) {
    return null;
  }

  return {
    rank: numberOrNull(row.rank) || index + 1,
    id: `${cleanString(row.ip, "ip")}-${index}`,
    ip: row.ip,
    latitude,
    longitude,
    city: cleanString(geo?.city, "Unknown city"),
    region: cleanString(geo?.regionName, ""),
    country: cleanString(geo?.country, row.abuse_country_code || "Unknown country"),
    country_code: cleanCountryCode(geo?.countryCode) || row.abuse_country_code,
    abuse_confidence_score: row.abuse_confidence_score,
    last_reported_at: row.last_reported_at,
    asn: cleanString(geo?.as, ""),
    as_name: cleanString(geo?.asname, ""),
    isp: cleanString(geo?.isp, ""),
    org: cleanString(geo?.org, ""),
    hosting: booleanValue(geo?.hosting),
    proxy: booleanValue(geo?.proxy),
    mobile: booleanValue(geo?.mobile),
    source: "abuseipdb_blacklist",
  };
}

async function buildLivePayload(env, context) {
  const now = Date.now();
  if (cachedPayload && cachedUntil > now) {
    return cachedResponse(cachedPayload.cache_status === "stale" ? "stale" : "cached");
  }

  const persistentPayload = await readPersistentCache(env);
  if (persistentPayload) {
    return persistentPayload;
  }

  if (pendingLivePayload) {
    return pendingLivePayload;
  }

  const apiKey = cleanString(env?.ABUSEIPDB_API_KEY, "", 256);
  if (!apiKey) {
    return fallbackPayload("ABUSEIPDB_API_KEY is not configured. Showing demo source locations.");
  }

  pendingLivePayload = refreshLivePayload(apiKey, now, env, context).finally(() => {
    pendingLivePayload = null;
  });

  return pendingLivePayload;
}

function scheduledRefreshSummary(payload, status = "refreshed") {
  return {
    status,
    refreshed: payload?.mode === "live" && status === "refreshed",
    mode: payload?.mode || "unavailable",
    cache_status: payload?.cache_status || status,
    generated_at: payload?.generated_at || new Date().toISOString(),
    cache_expires_at: payload?.cache_expires_at || null,
    next_refresh_at: payload?.next_refresh_at || null,
    point_count: Array.isArray(payload?.points) ? payload.points.length : 0,
    prewarm: payload?.mode === "live"
      ? {
          abuseipdb: "queued",
          spamhaus: "queued",
          virustotal: "queued",
        }
      : {
          abuseipdb: "skipped",
          spamhaus: "skipped",
          virustotal: "skipped",
        },
    warnings: payload?.warnings || [],
  };
}

export async function refreshThreatMapSnapshot(env = {}, context = {}) {
  const apiKey = cleanString(env?.ABUSEIPDB_API_KEY, "", 256);
  if (!apiKey) {
    return {
      status: "not_configured",
      refreshed: false,
      mode: "unavailable",
      cache_status: "not_configured",
      generated_at: new Date().toISOString(),
      cache_expires_at: null,
      next_refresh_at: null,
      point_count: 0,
      prewarm: {
        abuseipdb: "skipped",
        spamhaus: "skipped",
        virustotal: "skipped",
      },
      warnings: ["ABUSEIPDB_API_KEY is not configured."],
    };
  }

  try {
    if (!pendingLivePayload) {
      pendingLivePayload = refreshLivePayload(apiKey, Date.now(), env, context).finally(() => {
        pendingLivePayload = null;
      });
    }

    return scheduledRefreshSummary(await pendingLivePayload);
  } catch (error) {
    const message = messageFromError(error, "Threat origin providers are temporarily unavailable.");

    if (cachedPayload?.mode === "live") {
      cachedUntil = nextScheduledRefreshTime(Date.now());
      cachedPayload = cacheablePayload(cachedResponse("stale", `Scheduled refresh failed, so the last daily snapshot is still being shown. ${message}`), "stale");
      await writePersistentCache(cachedPayload, env);
      return scheduledRefreshSummary(cachedPayload, "stale");
    }

    return scheduledRefreshSummary(fallbackPayload(message), "fallback");
  }
}

export async function handleThreatMapRefreshRequest(request, env = {}, context = {}) {
  if (request.method !== "POST") {
    return json({ message: "Method not allowed" }, 405, { Allow: "POST" });
  }

  return json(await refreshThreatMapSnapshot(env, context));
}

async function refreshLivePayload(apiKey, now, env, context) {
  const blacklist = await fetchAbuseIpdbBlacklist(apiKey);
  if (!blacklist.rows.length) {
    return fallbackPayload("AbuseIPDB returned no blacklist rows. Showing demo source locations.");
  }

  let geoWarning = "";
  let geoRows = [];
  try {
    geoRows = await fetchGeoBatch(blacklist.rows.map((row) => row.ip));
  } catch (error) {
    geoWarning = `${messageFromError(error, "Geo-IP lookup is temporarily unavailable.")} Showing country-level estimates where AbuseIPDB provides a country code.`;
  }

  const geoByIp = new Map(geoRows.map((geo) => [cleanString(geo?.query, "", 80), geo]));
  const points = blacklist.rows
    .map((row, index) => normalizePoint(row, geoByIp.get(row.ip), index) || normalizeCountryPoint(row, index))
    .filter(Boolean)
    .slice(0, POINT_LIMIT);
  const failedGeoCount = blacklist.rows.length - points.length;
  const warnings = [];

  if (geoWarning) {
    warnings.push(geoWarning);
  }

  if (failedGeoCount > 0) {
    warnings.push(`${failedGeoCount} AbuseIPDB IP ${failedGeoCount === 1 ? "location was" : "locations were"} unavailable from geo-IP and hidden from the map.`);
  }

  if (!points.length) {
    return fallbackPayload("Geo-IP returned no usable coordinates. Showing demo source locations.");
  }

  cachedUntil = nextScheduledRefreshTime(now);
  const payload = {
    mode: "live",
    cache_status: "fresh",
    generated_at: blacklist.generated_at || new Date().toISOString(),
    cache_expires_at: isoFromTime(cachedUntil),
    next_refresh_at: isoFromTime(cachedUntil),
    source: "abuseipdb_blacklist",
    points,
    warnings,
  };

  cachedPayload = payload;
  await writePersistentCache(cacheablePayload(payload), env);
  scheduleSpamhausPrewarm(points, env, context);
  scheduleAbuseIpdbPrewarm(points, env, context);
  await scheduleVirusTotalQueue(points, env, context);

  return payload;
}

function normalizeCountryPoint(row, index) {
  const countryCode = cleanCountryCode(row.abuse_country_code);
  const centroid = countryCentroids.get(countryCode);

  if (!centroid) {
    return null;
  }

  return {
    rank: numberOrNull(row.rank) || index + 1,
    id: `${cleanString(row.ip, "ip")}-${index}-country`,
    ip: row.ip,
    latitude: centroid[0],
    longitude: centroid[1],
    city: "",
    region: "Country-level estimate",
    country: cleanString(countryNameFromCode(countryCode), countryCode),
    country_code: countryCode,
    abuse_confidence_score: row.abuse_confidence_score,
    last_reported_at: row.last_reported_at,
    asn: "",
    as_name: "",
    isp: "",
    org: "",
    hosting: false,
    proxy: false,
    mobile: false,
    source: "abuseipdb_blacklist_country",
  };
}

export async function handleAbuseOriginMapRequest(request, env = {}, context = {}) {
  if (request.method !== "GET") {
    return json({ message: "Method not allowed" }, 405, { Allow: "GET" });
  }

  try {
    return json(await withIpIntelligenceSummaries(await buildLivePayload(env, context), env));
  } catch (error) {
    const message = messageFromError(error, "Threat origin providers are temporarily unavailable.");
    if (cachedPayload?.mode === "live") {
      cachedUntil = nextScheduledRefreshTime(Date.now());
      cachedPayload = cacheablePayload(cachedResponse("stale", `Live refresh failed, so the last daily snapshot is still being shown. ${message}`), "stale");
      await writePersistentCache(cachedPayload, env);
      return json(await withIpIntelligenceSummaries(cachedPayload, env));
    }

    return json(fallbackPayload(message));
  }
}

export async function isLiveThreatMapIp(ip, env = {}) {
  const normalizedIp = cleanString(ip, "", 80);
  if (!normalizedIp) {
    return false;
  }

  const now = Date.now();
  if (cachedPayload?.mode === "live" && cachedUntil > now) {
    return cachedPayload.points?.some((point) => point.ip === normalizedIp) || false;
  }

  const persistentPayload = await readPersistentCache(env);
  return persistentPayload?.mode === "live" && persistentPayload.points?.some((point) => point.ip === normalizedIp);
}
