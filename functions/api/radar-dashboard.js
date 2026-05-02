const RADAR_BASE_URL = "https://api.cloudflare.com/client/v4/radar";
const CACHE_TTL_SECONDS = 600;
const CACHE_VERSION = "attack-map-v1";
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
const DEFAULT_SCOPE = {
  key: "worldwide",
  type: "worldwide",
  value: "",
  label: "Worldwide",
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
  const rows = normalizeLayer7Mix(raw);

  if (!rows.length) return "";

  return `${rows[0].label} leads the current Layer 7 mitigation mix (${rows[0].value.toFixed(1)}%).`;
}

function normalizeLayer7Mix(raw) {
  const summary = summaryObject(raw);

  return Object.entries(summary)
    .map(([key, value]) => ({
      label: cleanString(key.replace(/_/g, " "), "Unknown"),
      value: numberOrNull(value),
    }))
    .filter((row) => row.value !== null)
    .sort((a, b) => b.value - a.value)
    .slice(0, 5);
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

function normalizeAttackLocations(raw, kind) {
  const result = raw?.result || {};
  const rows = Array.isArray(result.top_0) ? result.top_0 : [];
  const prefix = kind === "origin" ? "origin" : "target";

  return rows
    .map((row, index) => {
      const code =
        row[`${prefix}CountryAlpha2`] ||
        row[`${prefix}LocationAlpha2`] ||
        row[`${prefix}CountryCode`] ||
        row.countryCode ||
        row.alpha2 ||
        "";
      const name =
        row[`${prefix}CountryName`] ||
        row[`${prefix}LocationName`] ||
        row.countryName ||
        row.locationName ||
        row.name ||
        code ||
        "Unknown";
      const value = numberOrNull(row.value ?? row.requests ?? row.count);

      return {
        rank: numberOrNull(row.rank) || index + 1,
        code: cleanString(code, ""),
        name: cleanString(name, code || "Unknown"),
        value,
      };
    })
    .filter((row) => row.name && row.value !== null)
    .slice(0, 8);
}

function normalizeAttackFlows(raw) {
  const result = raw?.result || {};
  const rows = Array.isArray(result.top_0) ? result.top_0 : [];

  return rows
    .map((row, index) => {
      const originCode = row.originCountryAlpha2 || row.originLocationAlpha2 || row.originCountryCode || "";
      const targetCode = row.targetCountryAlpha2 || row.targetLocationAlpha2 || row.targetCountryCode || "";
      const originName = row.originCountryName || row.originLocationName || originCode || "Unknown origin";
      const targetName = row.targetCountryName || row.targetLocationName || targetCode || "Unknown target";
      const value = numberOrNull(row.value ?? row.requests ?? row.count);

      return {
        rank: numberOrNull(row.rank) || index + 1,
        origin_code: cleanString(originCode, ""),
        origin_name: cleanString(originName, originCode || "Unknown origin"),
        target_code: cleanString(targetCode, ""),
        target_name: cleanString(targetName, targetCode || "Unknown target"),
        value,
      };
    })
    .filter((row) => row.origin_name && row.target_name && row.value !== null)
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
  const [scopeType, ...scopeValueParts] = String(url.searchParams.get("scope") || DEFAULT_SCOPE.key).split(":");
  const scopeValue = scopeValueParts.join(":");
  const scopeLabel = cleanString(url.searchParams.get("scopeLabel"), "");
  const scope =
    scopeType === "continent" && /^[A-Z]{2}$/.test(scopeValue)
      ? { key: `continent:${scopeValue}`, type: "continent", value: scopeValue, label: scopeLabel || scopeValue }
      : scopeType === "country" && /^[A-Z]{2}$/.test(scopeValue)
        ? { key: `country:${scopeValue}`, type: "country", value: scopeValue, label: scopeLabel || scopeValue }
        : scopeType === "asn" && /^\d{1,10}$/.test(scopeValue)
          ? { key: `asn:${scopeValue}`, type: "asn", value: scopeValue, label: scopeLabel || `AS${scopeValue}` }
          : DEFAULT_SCOPE;

  return {
    rangeKey,
    trafficKey,
    range: DATE_RANGES[rangeKey],
    locationTraffic: LOCATION_TRAFFIC[trafficKey],
    scope,
  };
}

function scopeParams(scope, capabilities = ["continent", "location", "asn"]) {
  if (!scope || scope.type === "worldwide") return {};
  if (scope.type === "continent" && capabilities.includes("continent")) return { continent: scope.value };
  if (scope.type === "country" && capabilities.includes("location")) return { location: scope.value };
  if (scope.type === "asn" && capabilities.includes("asn")) return { asn: scope.value };
  return {};
}

async function readCached(request) {
  if (typeof caches === "undefined") return null;

  const url = new URL(request.url);
  const cacheKey = new Request(
    `${url.origin}/api/radar-dashboard?version=${CACHE_VERSION}&range=${url.searchParams.get("range") || "24h"}&traffic=${url.searchParams.get("traffic") || "all"}&scope=${url.searchParams.get("scope") || DEFAULT_SCOPE.key}`,
  );
  const cached = await caches.default.match(cacheKey);
  if (!cached) return null;

  return new Response(cached.body, {
    status: cached.status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

async function writeCached(request, response) {
  if (typeof caches === "undefined") return;

  const url = new URL(request.url);
  const cacheKey = new Request(
    `${url.origin}/api/radar-dashboard?version=${CACHE_VERSION}&range=${url.searchParams.get("range") || "24h"}&traffic=${url.searchParams.get("traffic") || "all"}&scope=${url.searchParams.get("scope") || DEFAULT_SCOPE.key}`,
  );
  await caches.default.put(cacheKey, response.clone());
}

async function buildDashboard(request, token) {
  const options = requestOptions(request);
  const commonParams = {
    dateRange: options.range.radar,
    aggInterval: options.range.aggInterval,
    format: "json",
    ...scopeParams(options.scope),
  };

  const [httpResponse, botResponse] = await Promise.all([
    fetchRadar("/http/timeseries", token, commonParams),
    fetchFirstRadar(["/http/summary/BOT_CLASS", "/http/summary/bot_class"], token, {
      dateRange: options.range.radar,
      format: "json",
      ...scopeParams(options.scope),
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
  let layer7MitigationMix = [];
  let topLocations = [];
  let attackOrigins = [];
  let attackTargets = [];
  let attackFlows = [];

  const [layer7TimeResult, layer7SummaryResult, topLocationsResult, attackOriginResult, attackTargetResult, attackFlowResult] = await Promise.allSettled([
    fetchRadar("/attacks/layer7/timeseries", token, commonParams),
    fetchFirstRadar(["/attacks/layer7/summary/MITIGATION_PRODUCT", "/attacks/layer7/summary/mitigation_product"], token, {
      dateRange: options.range.radar,
      format: "json",
      ...scopeParams(options.scope, ["continent", "location", "asn"]),
    }),
    fetchRadar("/http/top/locations", token, {
      dateRange: options.range.radar,
      format: "json",
      limit: 8,
      ...options.locationTraffic,
      ...scopeParams(options.scope),
    }),
    fetchRadar("/attacks/layer7/top/locations/origin", token, {
      dateRange: options.range.radar,
      format: "json",
      limit: 8,
      ...scopeParams(options.scope, ["continent", "asn"]),
    }),
    fetchRadar("/attacks/layer7/top/locations/target", token, {
      dateRange: options.range.radar,
      format: "json",
      limit: 8,
      ...scopeParams(options.scope, ["continent"]),
    }),
    fetchRadar("/attacks/layer7/top/attacks", token, {
      dateRange: options.range.radar,
      format: "json",
      limit: 8,
      limitDirection: "ORIGIN",
      limitPerLocation: 3,
      ...scopeParams(options.scope, ["continent", "location", "asn"]),
    }),
  ]);

  if (layer7TimeResult.status === "fulfilled") {
    layer7Trend = normalizeTimeseries(layer7TimeResult.value);
  } else {
    warnings.push("Layer 7 attack trend is temporarily unavailable.");
  }

  if (layer7SummaryResult.status === "fulfilled") {
    applicationAttackInsight = normalizeLayer7Insight(layer7SummaryResult.value);
    layer7MitigationMix = normalizeLayer7Mix(layer7SummaryResult.value);
  } else {
    warnings.push("Layer 7 attack summary is temporarily unavailable.");
  }

  if (topLocationsResult.status === "fulfilled") {
    topLocations = normalizeLocations(topLocationsResult.value);
  } else {
    warnings.push("Top locations are temporarily unavailable.");
  }

  if (attackOriginResult.status === "fulfilled") {
    attackOrigins = normalizeAttackLocations(attackOriginResult.value, "origin");
  } else {
    warnings.push("Layer 7 attack origin countries are temporarily unavailable.");
  }

  if (attackTargetResult.status === "fulfilled") {
    attackTargets = normalizeAttackLocations(attackTargetResult.value, "target");
  } else {
    warnings.push("Layer 7 attack target countries are temporarily unavailable.");
  }

  if (attackFlowResult.status === "fulfilled") {
    attackFlows = normalizeAttackFlows(attackFlowResult.value);
  } else {
    warnings.push("Layer 7 attack flow pairs are temporarily unavailable.");
  }

  const botPercent = botHuman.find((row) => row.label === "Bot")?.value ?? null;
  const humanPercent = botHuman.find((row) => row.label === "Human")?.value ?? null;
  const lastUpdated = latestUpdated(
    httpResponse,
    botResponse,
    layer7TimeResult.status === "fulfilled" ? layer7TimeResult.value : null,
    layer7SummaryResult.status === "fulfilled" ? layer7SummaryResult.value : null,
    topLocationsResult.status === "fulfilled" ? topLocationsResult.value : null,
    attackOriginResult.status === "fulfilled" ? attackOriginResult.value : null,
    attackTargetResult.status === "fulfilled" ? attackTargetResult.value : null,
    attackFlowResult.status === "fulfilled" ? attackFlowResult.value : null,
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
    layer7_mitigation_mix: layer7MitigationMix,
    attack_geography: {
      origins: attackOrigins,
      targets: attackTargets,
      flows: attackFlows,
    },
    warnings,
    filters: {
      range: options.rangeKey,
      range_label: options.range.label,
      location_traffic: options.trafficKey,
      scope: options.scope.key,
      scope_type: options.scope.type,
      scope_value: options.scope.value,
      scope_label: options.scope.label,
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
    const response = json(dashboard, 200, { "Cache-Control": "no-store" });
    const cacheResponse = json(dashboard);

    // Successful Radar responses are cached briefly at the edge to reduce token
    // use and keep the public dashboard fast. The browser receives no-store so
    // old schema responses do not linger after dashboard upgrades.
    await writeCached(request, cacheResponse);

    return response;
  } catch {
    return providerUnavailable();
  }
}
