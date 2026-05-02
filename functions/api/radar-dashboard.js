const RADAR_BASE_URL = "https://api.cloudflare.com/client/v4/radar";
const CACHE_TTL_SECONDS = 600;
const DATE_RANGES = {
  "24h": { radar: "1d", aggInterval: "1h", label: "24 hours" },
  "7d": { radar: "7d", aggInterval: "1d", label: "7 days" },
  "30d": { radar: "30d", aggInterval: "1d", label: "30 days" },
};
const LOCATION_TRAFFIC = {
  all: {},
  bot: { botClass: "LIKELY_AUTOMATED" },
  human: { botClass: "LIKELY_HUMAN" },
};

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": status >= 200 && status < 300 ? `public, max-age=${CACHE_TTL_SECONDS}` : "no-store",
      ...headers,
    },
  });
}

function providerUnavailable() {
  return json(
    {
      error: "provider_unavailable",
      message: "Threat data temporarily unavailable",
    },
    503,
  );
}

function numberOrNull(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function cleanString(value, fallback = "") {
  return String(value || fallback)
    .replace(/[^\w .,:()#+&/-]/g, "")
    .trim()
    .slice(0, 120);
}

function radarUrl(path, params = {}) {
  const url = new URL(`${RADAR_BASE_URL}${path}`);

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    url.searchParams.set(key, String(value));
  }

  return url;
}

async function fetchRadar(path, token, params = {}) {
  const response = await fetch(radarUrl(path, params), {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
    },
  });

  const body = await response.json().catch(() => null);

  if (!response.ok || body?.success === false) {
    throw new Error("Radar request failed");
  }

  return body;
}

async function fetchFirstRadar(paths, token, params = {}) {
  let lastError;

  for (const path of paths) {
    try {
      return await fetchRadar(path, token, params);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error("Radar request failed");
}

function findSeriesContainer(raw) {
  const result = raw?.result || {};
  const candidates = [result.serie_0, result.series_0, result.meta, result];

  return candidates.find((candidate) => candidate && Array.isArray(candidate.timestamps));
}

function normalizeTimeseries(raw) {
  const series = findSeriesContainer(raw);
  if (!series) return [];

  const values =
    Array.isArray(series.values) && series.values.length > 0
      ? series.values
      : Object.entries(series).find(([key, value]) => key !== "timestamps" && Array.isArray(value))?.[1];

  if (!Array.isArray(values)) return [];

  return series.timestamps
    .map((timestamp, index) => ({
      timestamp: cleanString(timestamp, "unknown"),
      value: numberOrNull(values[index]),
    }))
    .filter((point) => point.timestamp && point.value !== null);
}

function summaryObject(raw) {
  return raw?.result?.summary_0 || raw?.result?.summary || raw?.result || {};
}

function getSummaryValue(summary, matchers) {
  const entry = Object.entries(summary).find(([key]) => {
    const normalized = key.toLowerCase();
    return matchers.some((matcher) => normalized.includes(matcher));
  });

  return entry ? numberOrNull(entry[1]) : null;
}

function normalizeBotHuman(raw) {
  const summary = summaryObject(raw);
  const bot = getSummaryValue(summary, ["likely_automated", "automated", "bot"]);
  const human = getSummaryValue(summary, ["likely_human", "human"]);

  if (bot === null && human === null) {
    throw new Error("Bot summary unavailable");
  }

  const botPercent = bot !== null ? bot : Math.max(0, 100 - human);
  const humanPercent = human !== null ? human : Math.max(0, 100 - botPercent);

  return [
    { label: "Bot", value: Number(botPercent.toFixed(2)) },
    { label: "Human", value: Number(humanPercent.toFixed(2)) },
  ];
}

function normalizeLayer7Insight(raw) {
  const summary = summaryObject(raw);
  const rows = Object.entries(summary)
    .map(([key, value]) => ({
      label: cleanString(key.replace(/_/g, " "), "Unknown"),
      value: numberOrNull(value),
    }))
    .filter((row) => row.value !== null)
    .sort((a, b) => b.value - a.value);

  if (!rows.length) return "";

  return `${rows[0].label} leads the current Layer 7 mitigation mix (${rows[0].value.toFixed(1)}%).`;
}

function normalizeLocations(raw) {
  const result = raw?.result || {};
  const top = result.top_0 || result.top || result.locations || [];
  const rows = Array.isArray(top) ? top : Object.entries(top).map(([name, value]) => ({ name, value }));

  return rows
    .map((row) => {
      const name = row.clientCountryName || row.countryName || row.locationName || row.name || row.key;
      const code = row.clientCountryAlpha2 || row.countryCode || row.alpha2 || row.code || "";
      const value = numberOrNull(row.value ?? row.requests ?? row.count);

      return {
        code: cleanString(code, ""),
        name: cleanString(name, code || "Unknown"),
        value,
      };
    })
    .filter((row) => row.name && row.value !== null)
    .slice(0, 8);
}

function latestUpdated(...responses) {
  const updated = responses
    .map((response) => response?.result?.meta?.lastUpdated)
    .filter(Boolean)
    .sort();

  return updated.at(-1) || new Date().toISOString();
}

function requestOptions(request) {
  const url = new URL(request.url);
  const rangeKey = DATE_RANGES[url.searchParams.get("range")] ? url.searchParams.get("range") : "24h";
  const trafficKey = LOCATION_TRAFFIC[url.searchParams.get("traffic")] ? url.searchParams.get("traffic") : "all";

  return {
    rangeKey,
    trafficKey,
    range: DATE_RANGES[rangeKey],
    locationTraffic: LOCATION_TRAFFIC[trafficKey],
  };
}

async function readCached(request) {
  if (typeof caches === "undefined") return null;

  const url = new URL(request.url);
  const cacheKey = new Request(`${url.origin}/api/radar-dashboard?range=${url.searchParams.get("range") || "24h"}&traffic=${url.searchParams.get("traffic") || "all"}`);
  return caches.default.match(cacheKey);
}

async function writeCached(request, response) {
  if (typeof caches === "undefined") return;

  const url = new URL(request.url);
  const cacheKey = new Request(`${url.origin}/api/radar-dashboard?range=${url.searchParams.get("range") || "24h"}&traffic=${url.searchParams.get("traffic") || "all"}`);
  await caches.default.put(cacheKey, response.clone());
}

async function buildDashboard(request, token) {
  const options = requestOptions(request);
  const commonParams = {
    dateRange: options.range.radar,
    aggInterval: options.range.aggInterval,
    format: "json",
  };

  const [httpResponse, botResponse] = await Promise.all([
    fetchRadar("/http/timeseries", token, commonParams),
    fetchFirstRadar(["/http/summary/BOT_CLASS", "/http/summary/bot_class"], token, {
      dateRange: options.range.radar,
      format: "json",
    }),
  ]);

  const warnings = [];
  const httpTrend = normalizeTimeseries(httpResponse);
  const botHuman = normalizeBotHuman(botResponse);

  if (!httpTrend.length || !botHuman.length) {
    throw new Error("Core Radar data unavailable");
  }

  let layer7Trend = [];
  let applicationAttackInsight = "";
  let topLocations = [];

  const [layer7TimeResult, layer7SummaryResult, topLocationsResult] = await Promise.allSettled([
    fetchRadar("/attacks/layer7/timeseries", token, commonParams),
    fetchFirstRadar(["/attacks/layer7/summary/MITIGATION_PRODUCT", "/attacks/layer7/summary/mitigation_product"], token, {
      dateRange: options.range.radar,
      format: "json",
    }),
    fetchRadar("/http/top/locations", token, {
      dateRange: options.range.radar,
      format: "json",
      limit: 8,
      ...options.locationTraffic,
    }),
  ]);

  if (layer7TimeResult.status === "fulfilled") {
    layer7Trend = normalizeTimeseries(layer7TimeResult.value);
  } else {
    warnings.push("Layer 7 attack trend is temporarily unavailable.");
  }

  if (layer7SummaryResult.status === "fulfilled") {
    applicationAttackInsight = normalizeLayer7Insight(layer7SummaryResult.value);
  } else {
    warnings.push("Layer 7 attack summary is temporarily unavailable.");
  }

  if (topLocationsResult.status === "fulfilled") {
    topLocations = normalizeLocations(topLocationsResult.value);
  } else {
    warnings.push("Top locations are temporarily unavailable.");
  }

  const botPercent = botHuman.find((row) => row.label === "Bot")?.value ?? null;
  const humanPercent = botHuman.find((row) => row.label === "Human")?.value ?? null;
  const lastUpdated = latestUpdated(
    httpResponse,
    botResponse,
    layer7TimeResult.status === "fulfilled" ? layer7TimeResult.value : null,
    layer7SummaryResult.status === "fulfilled" ? layer7SummaryResult.value : null,
    topLocationsResult.status === "fulfilled" ? topLocationsResult.value : null,
  );

  return {
    summary: {
      bot_percent: botPercent,
      human_percent: humanPercent,
      application_attack_insight: applicationAttackInsight || "Layer 7 attack insight unavailable.",
      last_updated: lastUpdated,
    },
    http_trend: httpTrend,
    bot_human: botHuman,
    top_locations: topLocations,
    layer7_trend: layer7Trend,
    warnings,
    filters: {
      range: options.rangeKey,
      range_label: options.range.label,
      location_traffic: options.trafficKey,
    },
    note: "This dashboard uses aggregated Cloudflare Radar data, not individual live attack events.",
  };
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "GET") {
    return json({ message: "Method not allowed" }, 405, { Allow: "GET" });
  }

  const token = env.CLOUDFLARE_RADAR_TOKEN;
  if (!token) {
    return json(
      {
        error: "missing_config",
        message: "CLOUDFLARE_RADAR_TOKEN is not configured",
      },
      500,
    );
  }

  const cached = await readCached(request);
  if (cached) return cached;

  try {
    const dashboard = await buildDashboard(request, token);
    const response = json(dashboard);

    // Successful Radar responses are cached briefly at the edge to reduce token
    // use and keep the public dashboard fast. Error responses are never cached.
    await writeCached(request, response);

    return response;
  } catch {
    return providerUnavailable();
  }
}
