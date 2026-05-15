const ABUSEIPDB_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist";
const ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check";
const IP_API_BATCH_URL = "http://ip-api.com/batch";
const CACHE_TTL_MS = 10 * 60 * 1000;
const DETAIL_CACHE_TTL_MS = 5 * 60 * 1000;
const POINT_LIMIT = 50;
const DEFAULT_CONFIDENCE_MINIMUM = 90;
const REPORT_LIMIT = 10;

let cachedPayload = null;
let cachedUntil = 0;
const detailCache = new Map();

const categoryLabels = {
  3: "Fraud Orders",
  4: "DDoS Attack",
  5: "FTP Brute-Force",
  6: "Ping of Death",
  7: "Phishing",
  8: "Fraud VoIP",
  9: "Open Proxy",
  10: "Web Spam",
  11: "Email Spam",
  12: "Blog Spam",
  13: "VPN IP",
  14: "Port Scan",
  15: "Hacking",
  16: "SQL Injection",
  17: "Spoofing",
  18: "Brute-Force",
  19: "Bad Web Bot",
  20: "Exploited Host / possible malware-compromised host",
  21: "Web App Attack",
  22: "SSH",
  23: "IoT Targeted",
};

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
    usage_type: "Data center/web hosting/transit",
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
    usage_type: "Data center/web hosting/transit",
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
    usage_type: "Data center/web hosting/transit",
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
    usage_type: "Fixed line ISP",
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
    usage_type: "Fixed line ISP",
  },
];

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": data?.mode === "live" ? "public, max-age=120" : "no-store",
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

function cleanComment(value) {
  return cleanString(value, "", 260);
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

function isValidIp(value) {
  const ip = cleanString(value, "", 80);
  return (
    /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) ||
    /^[0-9a-f:]{3,45}$/i.test(ip)
  );
}

function isUsableCoordinate(lat, lon) {
  return typeof lat === "number" && typeof lon === "number" && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

function fallbackPayload(warning) {
  return {
    mode: "fallback",
    generated_at: new Date().toISOString(),
    source: "fallback_demo",
    points: fallbackPoints,
    warnings: [warning],
  };
}

function upstreamMessage(body, fallback) {
  const detail = body?.errors?.[0]?.detail || body?.message || body?.error;
  return cleanString(detail, fallback, 220);
}

function categoryLabel(categoryId) {
  const id = Number(categoryId);
  return categoryLabels[id] || `Category ${id}`;
}

function normalizeCategories(categoryIds) {
  const categories = new Map();

  (Array.isArray(categoryIds) ? categoryIds : []).forEach((category) => {
    const id = Number(typeof category === "object" && category !== null ? category.id : category);
    if (!Number.isFinite(id)) return;

    categories.set(id, {
      id,
      label: typeof category === "object" && category !== null && category.label ? cleanString(category.label, categoryLabel(id), 120) : categoryLabel(id),
    });
  });

  return Array.from(categories.values());
}

function aggregateCategories(reports) {
  const counts = new Map();

  reports.forEach((report) => {
    normalizeCategories(report.categories).forEach((category) => {
      const existing = counts.get(category.id) || { ...category, count: 0 };
      existing.count += 1;
      counts.set(category.id, existing);
    });
  });

  return Array.from(counts.values()).sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
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
      ip,
        abuse_confidence_score: Math.max(0, Math.min(100, numberOrNull(row?.abuseConfidenceScore) ?? 0)),
        last_reported_at: cleanString(row?.lastReportedAt, "", 80),
        abuse_country_code: cleanCountryCode(row?.countryCode),
        usage_type: cleanString(row?.usageType, ""),
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
    usage_type: row.usage_type || cleanString(geo?.usageType, ""),
  };
}

async function fetchAbuseIpdbDetail(ip, apiKey) {
  const url = new URL(ABUSEIPDB_CHECK_URL);
  url.searchParams.set("ipAddress", ip);
  url.searchParams.set("maxAgeInDays", "90");
  url.searchParams.set("verbose", "");

  const response = await fetch(url.toString(), {
    headers: {
      Accept: "application/json",
      Key: apiKey,
      "User-Agent": "DominicBobanPortfolio/1.0 live-threat-map",
    },
  });
  const body = await response.json().catch(() => null);

  if (!response.ok || body?.errors) {
    throw new Error(upstreamMessage(body, "AbuseIPDB detail lookup is temporarily unavailable."));
  }

  return body?.data || {};
}

function unavailableDetail(ip, warning) {
  return {
    mode: "unavailable",
    ip,
    generated_at: new Date().toISOString(),
    available: false,
    total_reports: null,
    distinct_reporters: null,
    usage_type: "",
    domain: "",
    hostnames: [],
    categories: [],
    recent_reports: [],
    warnings: [warning],
  };
}

function normalizeDetail(ip, detail) {
  const reports = Array.isArray(detail?.reports) ? detail.reports.slice(0, REPORT_LIMIT) : [];
  const recentReports = reports.map((report, index) => ({
    id: `${ip}-report-${index}`,
    reported_at: cleanString(report?.reportedAt, "", 80),
    comment: cleanComment(report?.comment),
    categories: normalizeCategories(report?.categories),
  }));

  return {
    mode: "live",
    ip,
    generated_at: new Date().toISOString(),
    available: true,
    total_reports: numberOrNull(detail?.totalReports),
    distinct_reporters: numberOrNull(detail?.numDistinctUsers),
    usage_type: cleanString(detail?.usageType, ""),
    domain: cleanString(detail?.domain, ""),
    hostnames: Array.isArray(detail?.hostnames) ? detail.hostnames.map((host) => cleanString(host, "", 120)).filter(Boolean).slice(0, 5) : [],
    categories: aggregateCategories(recentReports),
    recent_reports: recentReports,
    warnings: reports.length ? [] : ["AbuseIPDB returned no verbose recent reports for this IP."],
  };
}

async function buildDetailPayload(request, env) {
  const url = new URL(request.url);
  const ip = cleanString(url.searchParams.get("ip"), "", 80);

  if (!ip || !isValidIp(ip)) {
    return unavailableDetail(ip, "A valid IP address is required.");
  }

  const apiKey = cleanString(env?.ABUSEIPDB_API_KEY, "", 256);
  if (!apiKey) {
    return unavailableDetail(ip, "ABUSEIPDB_API_KEY is not configured. Detail lookup is unavailable.");
  }

  const now = Date.now();
  const cached = detailCache.get(ip);
  if (cached && cached.expiresAt > now) {
    return cached.payload;
  }

  const payload = normalizeDetail(ip, await fetchAbuseIpdbDetail(ip, apiKey));
  detailCache.set(ip, {
    payload,
    expiresAt: now + DETAIL_CACHE_TTL_MS,
  });

  return payload;
}

async function buildLivePayload(env) {
  const apiKey = cleanString(env?.ABUSEIPDB_API_KEY, "", 256);
  if (!apiKey) {
    return fallbackPayload("ABUSEIPDB_API_KEY is not configured. Showing demo source locations.");
  }

  const now = Date.now();
  if (cachedPayload && cachedUntil > now) {
    return cachedPayload;
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

  const payload = {
    mode: "live",
    generated_at: blacklist.generated_at || new Date().toISOString(),
    source: "abuseipdb_blacklist",
    points,
    warnings,
  };

  cachedPayload = payload;
  cachedUntil = now + CACHE_TTL_MS;

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
    return json(fallbackPayload(message));
  }
}

export async function handleAbuseOriginDetailRequest(request, env = {}) {
  if (request.method !== "GET") {
    return json({ message: "Method not allowed" }, 405, { Allow: "GET" });
  }

  try {
    return json(await buildDetailPayload(request, env), 200, { "Cache-Control": "no-store" });
  } catch (error) {
    const url = new URL(request.url);
    const ip = cleanString(url.searchParams.get("ip"), "", 80);
    const message = error instanceof Error ? error.message : "Threat origin detail is temporarily unavailable.";
    return json(unavailableDetail(ip, message), 200, { "Cache-Control": "no-store" });
  }
}
