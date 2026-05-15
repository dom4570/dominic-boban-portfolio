const ABUSEIPDB_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist";
const IP_API_BATCH_URL = "http://ip-api.com/batch";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_TTL_SECONDS = Math.floor(CACHE_TTL_MS / 1000);
const POINT_LIMIT = 50;
const DEFAULT_CONFIDENCE_MINIMUM = 90;

let cachedPayload = null;
let cachedUntil = 0;

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
      "Cache-Control": data?.mode === "live" ? `public, max-age=${CACHE_TTL_SECONDS}` : "no-store",
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

async function buildLivePayload(env) {
  const now = Date.now();
  if (cachedPayload && cachedUntil > now) {
    return cachedResponse(cachedPayload.cache_status === "stale" ? "stale" : "cached");
  }

  const apiKey = cleanString(env?.ABUSEIPDB_API_KEY, "", 256);
  if (!apiKey) {
    return fallbackPayload("ABUSEIPDB_API_KEY is not configured. Showing demo source locations.");
  }

  const blacklist = await fetchAbuseIpdbBlacklist(apiKey);
  if (!blacklist.rows.length) {
    return fallbackPayload("AbuseIPDB returned no blacklist rows. Showing demo source locations.");
  }

  const geoRows = await fetchGeoBatch(blacklist.rows.map((row) => row.ip));
  const geoByIp = new Map(geoRows.map((geo) => [cleanString(geo?.query, "", 80), geo]));
  const points = blacklist.rows
    .map((row, index) => normalizePoint(row, geoByIp.get(row.ip), index))
    .filter(Boolean)
    .slice(0, POINT_LIMIT);
  const failedGeoCount = blacklist.rows.length - points.length;
  const warnings = [];

  if (failedGeoCount > 0) {
    warnings.push(`${failedGeoCount} AbuseIPDB IP ${failedGeoCount === 1 ? "location was" : "locations were"} unavailable from geo-IP and hidden from the map.`);
  }

  if (!points.length) {
    return fallbackPayload("Geo-IP returned no usable coordinates. Showing demo source locations.");
  }

  cachedUntil = now + CACHE_TTL_MS;
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

  return payload;
}

export async function handleAbuseOriginMapRequest(request, env = {}) {
  if (request.method !== "GET") {
    return json({ message: "Method not allowed" }, 405, { Allow: "GET" });
  }

  try {
    return json(await buildLivePayload(env));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Threat origin providers are temporarily unavailable.";
    if (cachedPayload?.mode === "live") {
      cachedUntil = Date.now() + CACHE_TTL_MS;
      cachedPayload = cachedResponse("stale", `Live refresh failed, so the last daily snapshot is still being shown. ${message}`);
      return json(cachedPayload);
    }

    return json(fallbackPayload(message));
  }
}
