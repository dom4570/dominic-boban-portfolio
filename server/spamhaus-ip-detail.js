import { isLiveThreatMapIp } from "./abuse-origin-map.js";

const SPAMHAUS_WQS_URL = "https://apibl.spamhaus.net/lookup/v1/zen";
const SPAMHAUS_SIA_LOGIN_URL = "https://api.spamhaus.org/api/v1/login";
const SPAMHAUS_SIA_CIDR_URL = "https://api.spamhaus.org/api/intel/v1/byobject/cidr";
const DNS_JSON_PROVIDERS = [
  { name: "Cloudflare DNS", url: "https://cloudflare-dns.com/dns-query" },
  { name: "Google DNS", url: "https://dns.google/resolve" },
  { name: "Quad9 DNS", url: "https://dns.quad9.net/dns-query" },
];
const DQS_IP_ZONES = ["sbl", "xbl", "pbl", "authbl"];
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_TTL_SECONDS = Math.floor(CACHE_TTL_MS / 1000);
const CACHE_SCHEMA_VERSION = 2;
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
    1030,
    {
      code: 1030,
      dataset: "BCL",
      label: "Botnet Controller List",
      explanation: "Host is associated with botnet command-and-control infrastructure according to Spamhaus.",
      url: "https://www.spamhaus.org/",
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
let cachedSiaToken = "";
let cachedSiaTokenExpiresAt = 0;
let pendingSiaLogin = null;

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

function normalizeSecretValue(value) {
  return String(value || "")
    .trim()
    .replace(/^["']|["']$/g, "")
    .replace(/^Bearer\s+/i, "")
    .trim();
}

function isDnsLabel(value) {
  return /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(value);
}

function spamhausDqsKeyWarning(apiKey) {
  if (!apiKey) {
    return "SPAMHAUS_DQS_KEY is not configured.";
  }

  if (!isDnsLabel(apiKey) || apiKey.length !== 26) {
    return "SPAMHAUS_DQS_KEY must be the bare 26-character Spamhaus DQS customer code, without Bearer, quotes, spaces, headers, or curl text.";
  }

  return "";
}

function messageFromError(error, fallback) {
  return cleanString(error?.message || error, fallback, 240);
}

function normalizeIp(value) {
  return cleanString(value, "", 80);
}

function numberOrNull(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function isoFromUnixSeconds(value) {
  const seconds = numberOrNull(value);
  if (!seconds || seconds <= 0) {
    return "";
  }

  return new Date(seconds * 1000).toISOString();
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

function reversedIpv4(ip) {
  const parts = normalizeIp(ip).split(".");
  if (parts.length !== 4 || !parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255)) {
    return "";
  }

  return parts.reverse().join(".");
}

function timeoutSignal(timeoutMs) {
  if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
    return AbortSignal.timeout(timeoutMs);
  }

  const controller = new AbortController();
  setTimeout(() => controller.abort(), timeoutMs);
  return controller.signal;
}

async function fetchJson(url, options = {}, timeoutMs = 8000) {
  const response = await fetch(url, {
    ...options,
    signal: options.signal || timeoutSignal(timeoutMs),
  });
  const body = await response.json().catch(() => null);

  return { response, body };
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
  const cachePayload = cacheSafePayload(payload);

  if (!isCachePayloadUsable(cachePayload)) {
    return;
  }

  memoryCache.set(cachePayload.ip, cachePayload);
  await Promise.all([writeEdgeCache(cachePayload), writeLocalCache(cachePayload)]);
}

function cacheSafePayload(payload) {
  if (payload?.history?.status !== "unavailable") {
    return payload;
  }

  const { history: _history, ...rest } = payload;
  return rest;
}

function detailSummary(payload) {
  if (!payload) {
    return null;
  }

  return {
    status: payload.status,
    listing_count: payload.listing_count || 0,
    codes: Array.isArray(payload.codes) ? payload.codes : [],
    datasets: Array.isArray(payload.datasets)
      ? payload.datasets.map((dataset) => ({
          code: dataset.code,
          dataset: dataset.dataset,
          label: dataset.label,
        }))
      : [],
    generated_at: payload.generated_at,
    cache_status: payload.cache_status || "cached",
  };
}

async function readCachedDetailSummary(ip) {
  const cached = await readCachedDetail(ip);
  return detailSummary(cached);
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

function withHistory(payload, history) {
  if (!history) {
    return payload;
  }

  return {
    ...payload,
    history,
  };
}

function listedPayload(ip, codes, warnings = []) {
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
    warnings,
  };
}

function dqsCodeFromAnswer(answer) {
  const match = /^127\.0\.0\.(\d+)$/.exec(String(answer || ""));
  if (!match) {
    return null;
  }

  const suffix = Number(match[1]);
  if ([2, 3, 4, 9, 10, 11, 20, 30].includes(suffix)) {
    return 1000 + suffix;
  }

  return null;
}

function dqsResultFromAnswers(answers) {
  const errorAnswer = answers.find((answer) => /^127\.255\.255\./.test(String(answer)));
  if (errorAnswer) {
    return {
      status: "unavailable",
      codes: [],
      warnings: [`Spamhaus DQS returned an error response (${errorAnswer}). Check the DQS key and enabled IP datasets.`],
    };
  }

  const codes = answers.map(dqsCodeFromAnswer).filter(Number.isFinite);
  if (codes.length) {
    return {
      status: "listed",
      codes,
      warnings: [],
    };
  }

  return null;
}

function dqsPayloadFromAnswers(ip, answers) {
  const result = dqsResultFromAnswers(answers);
  if (!result) {
    return null;
  }

  if (result.status === "listed") {
    return listedPayload(ip, result.codes, result.warnings);
  }

  return statusPayload(ip, result.status, result.warnings);
}

function dqsDnsStatusMessage(providerName, status) {
  if (status === 2) {
    return `${providerName} returned DNS status 2 (SERVFAIL). For Spamhaus DQS this usually means the configured key is not active for this IP dataset, the DQS service is disabled on the key, or the contract/key is not active.`;
  }

  if (status === 5) {
    return `${providerName} returned DNS status 5 (REFUSED). Check that the DQS key has IP Data lookups enabled.`;
  }

  return `${providerName} returned DNS status ${status}.`;
}

async function withTimeout(promise, timeoutMs, message) {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(message)), timeoutMs);
  });

  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timeoutId);
  }
}

async function fetchNativeDqs(ip, hostname) {
  if (!isNodeRuntime()) {
    return null;
  }

  try {
    const dns = await import("node:dns/promises");
    const resolver = new dns.Resolver();
    const answers = await withTimeout(resolver.resolve4(hostname), 5000, "Native DNS timed out.").finally(() => {
      resolver.cancel?.();
    });
    const result = dqsResultFromAnswers(answers);
    if (!result) {
      return { status: "not_listed", codes: [], warnings: [] };
    }

    return result;
  } catch (error) {
    if (error?.code === "ENOTFOUND" || error?.code === "ENODATA") {
      return { status: "not_listed", codes: [], warnings: [] };
    }

    if (error?.code === "ESERVFAIL") {
      return {
        warning: "Native DNS returned SERVFAIL. Check that the Spamhaus DQS key is active and enabled for this IP lookup dataset.",
      };
    }

    return {
      warning: `Native DNS failed: ${messageFromError(error, "lookup failed")}.`,
    };
  }
}

async function fetchDqsZoneResult(ip, hostname) {
  const warnings = [];
  const nativePayload = await fetchNativeDqs(ip, hostname);

  if (nativePayload?.status) {
    return nativePayload;
  }

  if (nativePayload?.warning) {
    warnings.push(nativePayload.warning);
  }

  for (const provider of DNS_JSON_PROVIDERS) {
    try {
      const url = new URL(provider.url);
      url.searchParams.set("name", hostname);
      url.searchParams.set("type", "A");

      const { response, body } = await fetchJson(
        url.toString(),
        {
          headers: {
            Accept: "application/dns-json",
            "User-Agent": "DominicBobanPortfolio/1.0 spamhaus-ip-detail",
          },
        },
        6000,
      );

      if (!response.ok || !body) {
        warnings.push(`${provider.name} returned status ${response.status}.`);
        continue;
      }

      if (body.Status === 3) {
        return { status: "not_listed", codes: [], warnings: [] };
      }

      const answers = Array.isArray(body.Answer) ? body.Answer.map((answer) => answer?.data).filter(Boolean) : [];
      const result = dqsResultFromAnswers(answers);
      if (result) {
        return result;
      }

      if (body.Status === 0) {
        return { status: "not_listed", codes: [], warnings: [] };
      }

      warnings.push(dqsDnsStatusMessage(provider.name, body.Status));
    } catch (error) {
      warnings.push(`${provider.name} failed: ${messageFromError(error, "lookup failed")}.`);
    }
  }

  return {
    status: "unavailable",
    codes: [],
    warnings,
  };
}

async function fetchSpamhausDqsDetail(ip, apiKey, lookupLabel = "Spamhaus DQS IP lookup") {
  const reversed = reversedIpv4(ip);
  if (!reversed) {
    return statusPayload(ip, "unavailable", [`${lookupLabel} currently supports IPv4 lookups only.`]);
  }

  const keyWarning = spamhausDqsKeyWarning(apiKey);
  if (keyWarning) {
    return statusPayload(ip, "unavailable", [`${lookupLabel} could not run because ${keyWarning}`]);
  }

  const results = await Promise.all(
    DQS_IP_ZONES.map(async (zone) => ({
      zone,
      result: await fetchDqsZoneResult(ip, `${reversed}.${apiKey}.${zone}.dq.spamhaus.net`),
    })),
  );
  const warnings = [];
  const codes = [];

  for (const { zone, result } of results) {
    if (result?.status === "listed") {
      codes.push(...result.codes);
    }

    if (result?.status === "unavailable" || result?.warning) {
      const resultWarnings = result.warnings || [result.warning];
      warnings.push(...resultWarnings.map((warning) => `${zone.toUpperCase()} lookup: ${warning}`));
    }
  }

  if (codes.length) {
    return listedPayload(ip, codes, warnings);
  }

  if (!warnings.length && results.every(({ result }) => result?.status === "not_listed")) {
    return statusPayload(ip, "not_listed");
  }

  return statusPayload(ip, "unavailable", [`${lookupLabel} failed. ${warnings.join(" ")}`]);
}

function isResolvedSpamhausPayload(payload) {
  return payload?.status === "listed" || payload?.status === "not_listed";
}

function hasSpamhausKeyProblem(payload) {
  return payload?.warnings?.some((warning) => warning.includes("SPAMHAUS_DQS_KEY")) || false;
}

function historyEventFromRecord(record) {
  const sourceIp = normalizeIp(record?.srcip || record?.ipaddress);
  const destinationIp = normalizeIp(record?.dstip);

  return {
    status: "found",
    dataset: cleanString(record?.dataset, "", 32),
    listed_at: isoFromUnixSeconds(record?.listed),
    removed_at: isoFromUnixSeconds(record?.remove_timestamp),
    valid_until_at: isoFromUnixSeconds(record?.valid_until),
    seen_at: isoFromUnixSeconds(record?.seen),
    detection: cleanString(record?.detection, "", 260),
    heuristic: cleanString(record?.heuristic, "", 120),
    botname: cleanString(record?.botname, "", 120),
    source_ip: sourceIp,
    source_port: numberOrNull(record?.srcport),
    destination_ip: destinationIp,
    destination_port: numberOrNull(record?.dstport),
    protocol: cleanString(record?.protocol, "", 20).toUpperCase(),
    warnings: [],
  };
}

function latestHistoryRecord(records) {
  return [...records].sort((left, right) => {
    const leftTime = numberOrNull(left?.seen) || numberOrNull(left?.listed) || 0;
    const rightTime = numberOrNull(right?.seen) || numberOrNull(right?.listed) || 0;
    return rightTime - leftTime;
  })[0] || null;
}

async function fetchSpamhausSiaToken(env) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (cachedSiaToken && cachedSiaTokenExpiresAt - 300 > nowSeconds) {
    return {
      token: cachedSiaToken,
      warning: "",
    };
  }

  const username = normalizeSecretValue(env?.SPAMHAUS_SIA_USERNAME);
  const password = normalizeSecretValue(env?.SPAMHAUS_SIA_PASSWORD);

  if (!username || !password) {
    return {
      token: "",
      warning: "",
    };
  }

  if (!pendingSiaLogin) {
    pendingSiaLogin = fetchJson(
      SPAMHAUS_SIA_LOGIN_URL,
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "User-Agent": "DominicBobanPortfolio/1.0 spamhaus-history-login",
        },
        body: JSON.stringify({
          username,
          password,
          realm: "intel",
        }),
      },
      9000,
    )
      .then(({ response, body }) => {
        if (!response.ok || body?.code !== 200 || !body?.token) {
          return {
            token: "",
            warning: "Spamhaus historical intelligence login failed. Check SPAMHAUS_SIA_USERNAME and SPAMHAUS_SIA_PASSWORD.",
          };
        }

        cachedSiaToken = normalizeSecretValue(body.token);
        cachedSiaTokenExpiresAt = numberOrNull(body.expires) || nowSeconds + CACHE_TTL_SECONDS;

        return {
          token: cachedSiaToken,
          warning: "",
        };
      })
      .catch((error) => ({
        token: "",
        warning: `Spamhaus historical intelligence login failed: ${messageFromError(error, "request failed")}.`,
      }))
      .finally(() => {
        pendingSiaLogin = null;
      });
  }

  return pendingSiaLogin;
}

async function fetchSpamhausHistory(ip, env) {
  const { token, warning } = await fetchSpamhausSiaToken(env);
  if (!token) {
    if (warning) {
      return {
        status: "unavailable",
        warnings: [warning],
      };
    }

    return null;
  }

  const url = new URL(`${SPAMHAUS_SIA_CIDR_URL}/ALL/listed/history/${encodeURIComponent(ip)}`);
  url.searchParams.set("limit", "1");

  try {
    const { response, body } = await fetchJson(
      url.toString(),
      {
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
          "User-Agent": "DominicBobanPortfolio/1.0 spamhaus-history",
        },
      },
      9000,
    );

    if (response.status === 404 || body?.code === 404) {
      return {
        status: "not_found",
        warnings: [],
      };
    }

    if (response.status === 401 || response.status === 403) {
      cachedSiaToken = "";
      cachedSiaTokenExpiresAt = 0;

      return {
        status: "unavailable",
        warnings: ["Spamhaus historical intelligence authorization failed. Check SPAMHAUS_SIA_USERNAME and SPAMHAUS_SIA_PASSWORD."],
      };
    }

    if (response.status === 429) {
      return {
        status: "unavailable",
        warnings: ["Spamhaus historical intelligence is rate limited right now."],
      };
    }

    if (!response.ok) {
      return {
        status: "unavailable",
        warnings: [`Spamhaus historical intelligence returned status ${response.status}.`],
      };
    }

    const records = Array.isArray(body?.results) ? body.results : [];
    const latest = latestHistoryRecord(records);

    if (!latest) {
      return {
        status: "not_found",
        warnings: [],
      };
    }

    return historyEventFromRecord(latest);
  } catch (error) {
    return {
      status: "unavailable",
      warnings: [`Spamhaus historical intelligence failed: ${messageFromError(error, "request failed")}.`],
    };
  }
}

async function addHistoricalDetail(payload, env) {
  if (!isResolvedSpamhausPayload(payload) || (payload.history && payload.history.status !== "unavailable")) {
    return payload;
  }

  const history = await fetchSpamhausHistory(payload.ip, env);
  return withHistory(payload, history);
}

async function fetchSpamhausDetail(ip, apiKey) {
  const dqsPayload = await fetchSpamhausDqsDetail(ip, apiKey);
  if (isResolvedSpamhausPayload(dqsPayload) || hasSpamhausKeyProblem(dqsPayload)) {
    return dqsPayload;
  }

  let response;
  let body;

  try {
    ({ response, body } = await fetchJson(
      `${SPAMHAUS_WQS_URL}/${encodeURIComponent(ip)}`,
      {
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${apiKey}`,
          "User-Agent": "DominicBobanPortfolio/1.0 spamhaus-ip-detail",
        },
      },
      9000,
    ));
  } catch (error) {
    return {
      ...dqsPayload,
      warnings: [
        ...dqsPayload.warnings,
        `Spamhaus WQS also failed: ${messageFromError(error, "request failed")}.`,
      ],
    };
  }

  if (response.status === 200 && Array.isArray(body?.resp)) {
    return listedPayload(ip, body.resp);
  }

  if (response.status === 404) {
    return statusPayload(ip, "not_listed");
  }

  if (response.status === 401 || response.status === 403) {
    return {
      ...dqsPayload,
      warnings: [
        ...dqsPayload.warnings,
        "Spamhaus WQS backup rejected the configured key. Check that SPAMHAUS_DQS_KEY is the active DQS key with IP Data lookups enabled.",
      ],
    };
  }

  if (response.status === 429) {
    return {
      ...dqsPayload,
      warnings: [
        ...dqsPayload.warnings,
        "Spamhaus WQS backup is rate limited. DQS remains the primary lookup path for this feature.",
      ],
    };
  }

  if (response.status === 504) {
    return {
      ...dqsPayload,
      warnings: [
        ...dqsPayload.warnings,
        "Spamhaus WQS also returned 504, so neither official Spamhaus lookup path could complete for this IP.",
      ],
    };
  }

  return {
    ...dqsPayload,
    warnings: [
      ...dqsPayload.warnings,
      `Spamhaus WQS also returned status ${response.status}.`,
    ],
  };
}

async function buildSpamhausDetailPayload(ip, env, options = {}) {
  const cached = await readCachedDetail(ip);
  if (cached) {
    if (options.includeHistory) {
      const enriched = await addHistoricalDetail(cached, env);
      if (enriched !== cached) {
        await writeCachedDetail(enriched);
      }

      return enriched;
    }

    return cached;
  }

  const apiKey = normalizeSecretValue(env?.SPAMHAUS_DQS_KEY);
  if (!apiKey) {
    return statusPayload(ip, "not_configured", ["SPAMHAUS_DQS_KEY is not configured."]);
  }

  if (pendingDetails.has(ip)) {
    const pending = pendingDetails.get(ip);
    if (options.includeHistory) {
      return pending.then(async (payload) => {
        const enriched = await addHistoricalDetail(payload, env);
        if (enriched !== payload) {
          await writeCachedDetail(enriched);
        }

        return enriched;
      });
    }

    return pending;
  }

  const pending = fetchSpamhausDetail(ip, apiKey)
    .then((payload) => (options.includeHistory ? addHistoricalDetail(payload, env) : payload))
    .then(async (payload) => {
      await writeCachedDetail(payload);
      return payload;
    })
    .finally(() => pendingDetails.delete(ip));

  pendingDetails.set(ip, pending);
  return pending;
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
        if (isResolvedSpamhausPayload(result)) {
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

export async function prewarmSpamhausDetails(points, env = {}, options = {}) {
  const apiKey = normalizeSecretValue(env?.SPAMHAUS_DQS_KEY);
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

  return runLimited(ips, concurrency, timeoutMs, (ip) => buildSpamhausDetailPayload(ip, env));
}

export async function addSpamhausSummariesToPoints(points) {
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
    const { ip_intelligence: _ipIntelligence, ...cleanPoint } = point;
    const summary = summaries[index];
    return summary ? { ...cleanPoint, ip_intelligence: summary } : cleanPoint;
  });
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
    const cached = await readCachedDetail(ip);
    if (cached) {
      const enriched = await addHistoricalDetail(cached, env);
      if (enriched !== cached) {
        await writeCachedDetail(enriched);
      }

      return json(enriched);
    }

    if (!(await isLiveThreatMapIp(ip))) {
      return json(statusPayload(ip, "unavailable", ["IP Intelligence is only available for IPs from the current or recent Daily Top 50 map. Reload the map to refresh the selected source."]));
    }

    return json(await buildSpamhausDetailPayload(ip, env, { includeHistory: true }));
  } catch (error) {
    return json(statusPayload(ip, "unavailable", [messageFromError(error, "Spamhaus detail is temporarily unavailable.")]));
  }
}
