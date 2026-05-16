import { isLiveThreatMapIp } from "./abuse-origin-map.js";

const SPAMHAUS_WQS_URL = "https://apibl.spamhaus.net/lookup/v1/ZEN";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_TTL_SECONDS = Math.floor(CACHE_TTL_MS / 1000);
const CACHE_SCHEMA_VERSION = 1;
const LOCAL_CACHE_FILE = ".cache/spamhaus-ip-detail.json";
const EDGE_CACHE_PREFIX = "https://portfolio-cache.local/spamhaus-ip-detail/";

const codeDefinitions = new Map([
  [
    1002,
    {
      code: 1002,
      dataset: "SBL",
      label: "Spamhaus Blocklist",
      explanation: "IP appears to be controlled by, used by, or made available to spammers or other abusive activity.",
      url: "https://www.spamhaus.org/sbl/",
    },
  ],
  [
    1003,
    {
      code: 1003,
      dataset: "CSS",
      label: "CSS Blocklist",
      explanation: "Low-reputation email source, often associated with spam emission, snowshoe spam, or compromised hosts.",
      url: "https://www.spamhaus.org/css/",
    },
  ],
  [
    1004,
    {
      code: 1004,
      dataset: "XBL / CBL",
      label: "Exploits Blocklist",
      explanation: "Exploited or infected system, open proxy, trojan, or other malware-related abuse vector.",
      url: "https://www.abuseat.org/",
    },
  ],
  [
    1009,
    {
      code: 1009,
      dataset: "DROP",
      label: "DROP",
      explanation: "Part of a hijacked or leased netblock used by spam or cyber-crime operations.",
      url: "https://www.spamhaus.org/drop/",
    },
  ],
  [
    1010,
    {
      code: 1010,
      dataset: "PBL",
      label: "Policy Blocklist",
      explanation: "ISP-maintained IP range not expected to send direct unauthenticated SMTP email.",
      url: "https://www.spamhaus.org/pbl/",
    },
  ],
  [
    1011,
    {
      code: 1011,
      dataset: "PBL",
      label: "Policy Blocklist",
      explanation: "Spamhaus-maintained dynamic or residential IP range not expected to send direct unauthenticated SMTP email.",
      url: "https://www.spamhaus.org/pbl/",
    },
  ],
  [
    1020,
    {
      code: 1020,
      dataset: "AuthBL",
      label: "Authentication Blocklist",
      explanation: "Known authentication brute-force source or host associated with stolen-credential activity.",
      url: "https://www.spamhaus.org/",
    },
  ],
]);

let memoryCache = new Map();
let pendingDetails = new Map();

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
    .replace(/[^\w .,:()#+&/:?-]/g, "")
    .trim()
    .slice(0, maxLength);
}

function messageFromError(error, fallback) {
  return cleanString(error?.message || error, fallback, 240);
}

function normalizeIp(value) {
  return cleanString(value, "", 80);
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
    (payload.status === "listed" || payload.status === "not_listed") &&
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
    // The in-memory cache still protects Spamhaus for this process.
  }
}

function cachedPayload(payload) {
  return {
    ...payload,
    cache_status: "cached",
  };
}

async function readCachedDetail(ip) {
  const memoryPayload = memoryCache.get(ip);
  if (isCachePayloadUsable(memoryPayload)) {
    return cachedPayload(memoryPayload);
  }

  const payload = (await readEdgeCache(ip)) || (await readLocalCache(ip));
  if (!payload) {
    return null;
  }

  memoryCache.set(ip, payload);
  return cachedPayload(payload);
}

async function writeCachedDetail(payload) {
  if (!isCachePayloadUsable(payload)) {
    return;
  }

  memoryCache.set(payload.ip, payload);
  await Promise.all([writeEdgeCache(payload), writeLocalCache(payload)]);
}

function statusPayload(ip, status, warnings = []) {
  const expiresAt = expiresAtFromNow();
  return {
    cache_schema_version: CACHE_SCHEMA_VERSION,
    ip,
    status,
    listing_count: 0,
    codes: [],
    datasets: [],
    generated_at: new Date().toISOString(),
    cache_status: "fresh",
    cache_expires_at: expiresAt,
    warnings,
  };
}

function listedPayload(ip, codes) {
  const uniqueCodes = [...new Set(codes.map((code) => Number(code)).filter(Number.isFinite))];
  const datasets = uniqueCodes.map((code) => codeDefinitions.get(code) || {
    code,
    dataset: "Unknown",
    label: `Spamhaus code ${code}`,
    explanation: "Spamhaus returned this listing code, but the local code map does not describe it yet.",
    url: "https://www.spamhaus.org/",
  });
  const expiresAt = expiresAtFromNow();

  return {
    cache_schema_version: CACHE_SCHEMA_VERSION,
    ip,
    status: "listed",
    listing_count: datasets.length,
    codes: uniqueCodes,
    datasets,
    generated_at: new Date().toISOString(),
    cache_status: "fresh",
    cache_expires_at: expiresAt,
    warnings: [],
  };
}

async function fetchSpamhausDetail(ip, apiKey) {
  const response = await fetch(`${SPAMHAUS_WQS_URL}/${encodeURIComponent(ip)}`, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${apiKey}`,
      "User-Agent": "DominicBobanPortfolio/1.0 spamhaus-ip-detail",
    },
  });
  const body = await response.json().catch(() => null);

  if (response.status === 200 && Array.isArray(body?.resp)) {
    return listedPayload(ip, body.resp);
  }

  if (response.status === 404) {
    return statusPayload(ip, "not_listed");
  }

  if (response.status === 401 || response.status === 403) {
    return statusPayload(ip, "unavailable", ["Spamhaus authorization failed. Check the SPAMHAUS_DQS_KEY secret."]);
  }

  if (response.status === 429) {
    return statusPayload(ip, "unavailable", ["Spamhaus rate limiting is in effect. Showing cached or unavailable detail only."]);
  }

  if (response.status === 504) {
    return statusPayload(ip, "unavailable", ["Spamhaus query timed out. Try this IP again later."]);
  }

  return statusPayload(ip, "unavailable", [`Spamhaus detail is temporarily unavailable. Status ${response.status}.`]);
}

async function buildSpamhausDetailPayload(ip, env) {
  const cached = await readCachedDetail(ip);
  if (cached) {
    return cached;
  }

  const apiKey = cleanString(env?.SPAMHAUS_DQS_KEY, "", 256);
  if (!apiKey) {
    return statusPayload(ip, "not_configured", ["SPAMHAUS_DQS_KEY is not configured."]);
  }

  if (pendingDetails.has(ip)) {
    return pendingDetails.get(ip);
  }

  const pending = fetchSpamhausDetail(ip, apiKey)
    .then(async (payload) => {
      await writeCachedDetail(payload);
      return payload;
    })
    .finally(() => pendingDetails.delete(ip));

  pendingDetails.set(ip, pending);
  return pending;
}

export async function handleSpamhausIpDetailRequest(request, env = {}) {
  if (request.method !== "GET") {
    return json({ message: "Method not allowed" }, 405, { Allow: "GET" });
  }

  const url = new URL(request.url);
  const ip = normalizeIp(url.searchParams.get("ip"));

  if (!isIpAddress(ip)) {
    return json({ message: "A valid IP address is required." }, 400);
  }

  try {
    if (!(await isLiveThreatMapIp(ip))) {
      return json(statusPayload(ip, "unavailable", ["Spamhaus detail is only available for IPs in the current live daily AbuseIPDB map."]));
    }

    return json(await buildSpamhausDetailPayload(ip, env));
  } catch (error) {
    return json(statusPayload(ip, "unavailable", [messageFromError(error, "Spamhaus detail is temporarily unavailable.")]));
  }
}
