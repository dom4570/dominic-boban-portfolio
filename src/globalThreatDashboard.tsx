import {
  geoCentroid,
  geoEqualEarth,
  geoPath,
  type GeoProjection,
} from "d3-geo";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  BarChart3,
  ChevronDown,
  Globe2,
  Loader2,
  MapPin,
  Network,
  Minus,
  Plus,
  Radar,
  RotateCcw,
  Search,
  ShieldAlert,
} from "lucide-react";
import { ReactNode, useEffect, useMemo, useState } from "react";

type TrendPoint = {
  timestamp: string;
  value: number;
};

type SplitPoint = {
  label: string;
  value: number;
};

type LocationPoint = {
  code?: string;
  name: string;
  label?: string;
  full_name?: string;
  type?: "country" | "continent" | "unknown";
  value: number;
};

type AttackLocationPoint = {
  rank?: number;
  code?: string;
  name: string;
  label?: string;
  full_name?: string;
  type?: "country" | "continent" | "unknown";
  value: number;
  focus?: boolean;
};

type AttackFlowPoint = {
  rank?: number;
  origin_code?: string;
  origin_name: string;
  origin_label?: string;
  origin_full_name?: string;
  origin_type?: "country" | "continent" | "unknown";
  target_code?: string;
  target_name: string;
  target_label?: string;
  target_full_name?: string;
  target_type?: "country" | "continent" | "unknown";
  value: number;
};

type RadarDashboard = {
  summary: {
    bot_percent: number | null;
    human_percent: number | null;
    application_attack_insight: string;
    last_updated: string;
  };
  http_trend: TrendPoint[];
  bot_human: SplitPoint[];
  top_locations: LocationPoint[];
  layer7_trend: TrendPoint[];
  layer7_mitigation_mix?: SplitPoint[];
  attack_geography?: {
    origins: AttackLocationPoint[];
    targets: AttackLocationPoint[];
    flows: AttackFlowPoint[];
    flow_mode?: "merged_flows" | "partial_flows" | "rankings_only";
    flow_scope_note?: string;
    flow_status?: {
      origin_limited?: string;
      target_limited?: string;
      fallback?: string;
    };
    flow_coverage?: {
      flow_count: number;
      fallback_used: boolean;
    };
    scope_strategy?: string;
    scope_direction?: string;
    flow_filter_strategy?: string;
  };
  warnings: string[];
  filters?: {
    range: string;
    range_label: string;
    location_traffic: string;
    scope?: string;
    scope_type?: string;
    scope_value?: string;
    scope_label?: string;
  };
  note: string;
};

type RangeKey = "24h" | "7d" | "30d";
type AttackGeoTab = "origins" | "targets" | "flows";
type RadarScopeKey = "worldwide" | `continent:${string}` | `country:${string}` | `asn:${string}`;
type RadarScopeOption = {
  key: RadarScopeKey;
  label: string;
  meta: string;
  group: "Global" | "Continents" | "Countries / Territories" | "Autonomous Systems";
  icon: typeof Radar;
};

const rangeOptions: Array<{ key: RangeKey; label: string }> = [
  { key: "24h", label: "24h" },
  { key: "7d", label: "7d" },
  { key: "30d", label: "30d" },
];

const attackGeoTabs: Array<{ key: AttackGeoTab; label: string }> = [
  { key: "origins", label: "Sources" },
  { key: "targets", label: "Targets" },
  { key: "flows", label: "Flows" },
];

const radarScopeOptions: RadarScopeOption[] = [
  { key: "worldwide", label: "Worldwide", meta: "Global Radar view", group: "Global", icon: Globe2 },
  { key: "continent:AF", label: "Africa", meta: "Continent", group: "Continents", icon: Globe2 },
  { key: "continent:AS", label: "Asia", meta: "Continent", group: "Continents", icon: Globe2 },
  { key: "continent:EU", label: "Europe", meta: "Continent", group: "Continents", icon: Globe2 },
  { key: "continent:NA", label: "North America", meta: "Continent", group: "Continents", icon: Globe2 },
  { key: "continent:OC", label: "Oceania", meta: "Continent", group: "Continents", icon: Globe2 },
  { key: "continent:SA", label: "South America", meta: "Continent", group: "Continents", icon: Globe2 },
  { key: "country:GB", label: "United Kingdom", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "country:US", label: "United States", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "country:IN", label: "India", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "country:BR", label: "Brazil", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "country:CN", label: "China", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "country:DE", label: "Germany", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "country:FR", label: "France", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "country:NL", label: "Netherlands", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "country:JP", label: "Japan", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "country:SG", label: "Singapore", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "country:CA", label: "Canada", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "country:AU", label: "Australia", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "country:ZA", label: "South Africa", meta: "Country / territory", group: "Countries / Territories", icon: MapPin },
  { key: "asn:13335", label: "AS13335 - Cloudflare", meta: "Autonomous system", group: "Autonomous Systems", icon: Network },
  { key: "asn:8075", label: "AS8075 - Microsoft", meta: "Autonomous system", group: "Autonomous Systems", icon: Network },
  { key: "asn:15169", label: "AS15169 - Google", meta: "Autonomous system", group: "Autonomous Systems", icon: Network },
  { key: "asn:16509", label: "AS16509 - Amazon", meta: "Autonomous system", group: "Autonomous Systems", icon: Network },
  { key: "asn:32934", label: "AS32934 - Meta", meta: "Autonomous system", group: "Autonomous Systems", icon: Network },
  { key: "asn:14061", label: "AS14061 - DigitalOcean", meta: "Autonomous system", group: "Autonomous Systems", icon: Network },
];

type WorldFeature = Feature<Geometry, { name?: string }> & { id?: string };
type WorldFeatureCollection = FeatureCollection<Geometry, { name?: string }>;
type MapPoint = {
  code?: string;
  name: string;
  label: string;
  type?: "country" | "continent" | "unknown";
  value: number;
  color: string;
  x: number;
  y: number;
  kind: "source" | "target";
  connected: boolean;
};
type MapFlowEdge = {
  id: string;
  flow: AttackFlowPoint;
  source: MapPoint;
  target: MapPoint;
  path: string;
  color: string;
  width: number;
};

const mapWidth = 960;
const mapHeight = 520;
const minMapZoom = 1;
const maxMapZoom = 3.5;
const mapZoomStep = 0.5;
const continentNames: Record<string, string> = {
  AF: "Africa",
  AS: "Asia",
  EU: "Europe",
  NA: "North America",
  OC: "Oceania",
  SA: "South America",
};
const continentCoordinates: Record<string, [number, number]> = {
  AF: [20, 3],
  AS: [86, 34],
  EU: [15, 51],
  NA: [-100, 44],
  OC: [135, -25],
  SA: [-60, -15],
};
const fallbackCoordinates: Record<string, [number, number]> = {
  AD: [1.6, 42.5],
  AE: [54.3, 24.4],
  AF: [66, 34],
  AG: [-61.8, 17.1],
  AI: [-63.1, 18.2],
  AL: [20, 41],
  AM: [45, 40],
  AO: [18.5, -12.5],
  AR: [-64, -34],
  AS: [-170, -14.3],
  AT: [14.5, 47.5],
  AU: [134, -25],
  AZ: [47.5, 40.5],
  BA: [17.8, 44.2],
  BD: [90.3, 23.7],
  BE: [4.6, 50.8],
  BF: [-1.5, 12.3],
  BG: [25.5, 42.7],
  BH: [50.6, 26.1],
  BI: [29.9, -3.4],
  BJ: [2.3, 9.3],
  BO: [-64.7, -16.3],
  BR: [-52, -10],
  BS: [-76, 24.5],
  BW: [24, -22],
  BY: [28, 53],
  BZ: [-88.8, 17.2],
  CA: [-106, 56],
  CD: [23.7, -3],
  CF: [20.9, 6.6],
  CG: [15, -1],
  CH: [8.2, 46.8],
  CI: [-5.5, 7.5],
  CL: [-71, -30],
  CM: [12.4, 5.8],
  CN: [104, 35],
  CO: [-74, 4],
  CR: [-84, 9.8],
  CU: [-79.5, 21.5],
  CV: [-23.6, 15.1],
  CY: [33.4, 35],
  CZ: [15.5, 49.8],
  DE: [10.4, 51.2],
  DJ: [42.6, 11.8],
  DK: [10, 56],
  DO: [-70.2, 18.7],
  DZ: [2.6, 28],
  EC: [-78.2, -1.5],
  EE: [25, 58.7],
  EG: [30.8, 26.8],
  ES: [-3.7, 40.4],
  ET: [40.5, 9],
  FI: [26, 64],
  FJ: [178, -17.8],
  FR: [2.2, 46.2],
  GB: [-2.5, 54],
  GE: [43.5, 42],
  GH: [-1, 7.8],
  GR: [22, 39],
  GT: [-90.2, 15.7],
  HK: [114.1, 22.3],
  HN: [-86.5, 15.2],
  HR: [15.2, 45.1],
  HU: [19.5, 47.2],
  ID: [113.9, -0.8],
  IE: [-8, 53.3],
  IL: [34.8, 31.5],
  IN: [78.9, 22.8],
  IQ: [44.4, 33.2],
  IR: [53.7, 32.4],
  IS: [-19, 65],
  IT: [12.6, 42.8],
  JM: [-77.3, 18.1],
  JO: [36.2, 31.2],
  JP: [138, 37.5],
  KE: [37.9, 0.2],
  KG: [74.8, 41.2],
  KH: [104.9, 12.6],
  KR: [127.8, 36.5],
  KW: [47.5, 29.3],
  KZ: [67, 48],
  LA: [102.5, 19.9],
  LB: [35.9, 33.9],
  LK: [80.7, 7.9],
  LT: [23.9, 55.1],
  LU: [6.1, 49.8],
  LV: [24.6, 56.9],
  LY: [17, 26.3],
  MA: [-6, 31.8],
  MD: [28.4, 47.2],
  ME: [19.3, 42.7],
  MG: [46.9, -19],
  MK: [21.7, 41.6],
  ML: [-3.9, 17.6],
  MM: [96, 21],
  MN: [103, 46],
  MO: [113.5, 22.2],
  MR: [-10.9, 20.3],
  MT: [14.4, 35.9],
  MU: [57.5, -20.2],
  MV: [73.2, 3.2],
  MX: [-102, 23],
  MY: [102, 4.2],
  MZ: [35, -18.5],
  NA: [17.1, -22.6],
  NC: [165.6, -21.3],
  NE: [8, 17.6],
  NG: [8.7, 9.1],
  NL: [5.3, 52.1],
  NO: [8.5, 61],
  NP: [84.1, 28.4],
  NZ: [172, -41],
  OM: [57, 21],
  PA: [-80, 8.5],
  PE: [-75, -9],
  PH: [122, 12.9],
  PK: [69.3, 30.4],
  PL: [19, 52],
  PR: [-66.5, 18.2],
  PT: [-8, 39.4],
  PY: [-58.4, -23.4],
  QA: [51.2, 25.3],
  RO: [25, 45.9],
  RS: [21, 44],
  RU: [90, 60],
  RW: [29.9, -1.9],
  SA: [45, 24],
  SC: [55.5, -4.6],
  SD: [30, 15.6],
  SE: [18, 62],
  SG: [103.8, 1.35],
  SI: [14.8, 46.1],
  SK: [19.7, 48.7],
  SN: [-14.4, 14.5],
  SO: [46, 5],
  TH: [101, 15.8],
  TN: [9.5, 34],
  TR: [35, 39],
  TW: [121, 23.7],
  TZ: [35, -6],
  UA: [31, 49],
  UG: [32.3, 1.3],
  US: [-98, 39],
  UY: [-56, -32.5],
  UZ: [64, 41],
  VE: [-66, 7],
  VN: [108, 14],
  ZA: [24, -29],
  ZM: [27.8, -13.1],
  ZW: [29.2, -19],
};

async function readJson<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => null);

  if (!response.ok) {
    throw new Error(body?.message || "Threat data temporarily unavailable.");
  }

  return body as T;
}

function formatPercent(value: number | null | undefined) {
  return typeof value === "number" ? `${value.toFixed(1)}%` : "N/A";
}

function formatCompact(value: number | null | undefined) {
  if (typeof value !== "number") return "N/A";
  return Intl.NumberFormat("en", { maximumFractionDigits: value < 10 ? 2 : 1 }).format(value);
}

function formatTime(value?: string) {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(date);
}

function lastItem<T>(items: T[]) {
  return items.length ? items[items.length - 1] : undefined;
}

function trendDelta(data: TrendPoint[]) {
  if (data.length < 2) return null;
  const previous = data[data.length - 2].value;
  const current = data[data.length - 1].value;
  if (previous === 0) return null;
  return ((current - previous) / previous) * 100;
}

function peakPoint(data: TrendPoint[]) {
  if (!data.length) return null;
  return data.reduce((peak, point) => (point.value > peak.value ? point : peak), data[0]);
}

function buildAnalystInsights(data: RadarDashboard) {
  const insights = [];
  const layer7Peak = peakPoint(data.layer7_trend);
  const layer7Delta = trendDelta(data.layer7_trend);
  const topOrigin = data.attack_geography?.origins?.[0];
  const topTarget = data.attack_geography?.targets?.[0];
  const topFlow = data.attack_geography?.flows?.[0];
  const topMitigation = data.layer7_mitigation_mix?.[0];
  const scopeLabel = data.filters?.scope_label || "Worldwide";

  if (scopeLabel !== "Worldwide") {
    insights.push(`Scope filter active: ${scopeLabel}. Radar endpoints that support this scope are filtered before results are normalized.`);
  }

  if (topMitigation) {
    insights.push(`${topMitigation.label} leads the application-layer mitigation mix at ${formatPercent(topMitigation.value)}.`);
  }

  if (layer7Peak) {
    insights.push(`Layer 7 activity peaked around ${formatTime(layer7Peak.timestamp)} with an index value of ${formatCompact(layer7Peak.value)}.`);
  }

  if (layer7Delta !== null) {
    const direction = layer7Delta >= 0 ? "up" : "down";
    insights.push(`The latest Layer 7 point is ${direction} ${Math.abs(layer7Delta).toFixed(1)}% compared with the previous point.`);
  }

  if (topOrigin) {
    insights.push(`Top Layer 7 attack origin: ${locationDisplayLabel(topOrigin)} at ${formatCompact(topOrigin.value)}% of observed attack origin share.`);
  }

  if (topTarget) {
    insights.push(`Most targeted country: ${locationDisplayLabel(topTarget)} at ${formatCompact(topTarget.value)}% of observed target share.`);
  }

  if (topFlow) {
    insights.push(`Strongest country attack flow: ${flowDisplayLabel(topFlow)} at ${formatCompact(topFlow.value)}%.`);
  }

  return insights.slice(0, 7);
}

function selectedScope(scopeKey: RadarScopeKey) {
  return radarScopeOptions.find((option) => option.key === scopeKey) || radarScopeOptions[0];
}

function groupedScopeOptions(query: string) {
  const normalized = query.trim().toLowerCase();
  const options = radarScopeOptions.filter((option) => {
    if (!normalized) return true;
    return `${option.label} ${option.meta} ${option.key}`.toLowerCase().includes(normalized);
  });

  return ["Global", "Continents", "Countries / Territories", "Autonomous Systems"].map((group) => ({
    group,
    options: options.filter((option) => option.group === group),
    total: radarScopeOptions.filter((option) => option.group === group).length,
  }));
}

function normalizeMapLookup(value: string | undefined) {
  return String(value || "")
    .toLowerCase()
    .replace(/^the\s+/, "")
    .replace(/&/g, "and")
    .replace(/[^a-z0-9]/g, "");
}

function locationFullName(point: { name?: string; full_name?: string }) {
  return point.full_name || point.name || "Unknown";
}

function locationDisplayLabel(point: { code?: string; name?: string; label?: string; full_name?: string }) {
  if (point.label) return point.label;
  const name = locationFullName(point);
  const code = point.code?.toUpperCase();

  return code ? `${name} (${code})` : name;
}

function flowDisplayLabel(flow: AttackFlowPoint) {
  const origin = flow.origin_label || locationDisplayLabel({ code: flow.origin_code, name: flow.origin_name, full_name: flow.origin_full_name });
  const target = flow.target_label || locationDisplayLabel({ code: flow.target_code, name: flow.target_name, full_name: flow.target_full_name });

  return `${origin} -> ${target}`;
}

function mapAliases(name: string) {
  const normalized = normalizeMapLookup(name);

  return [
    normalized,
    normalized.replace("unitedstatesofamerica", "unitedstates"),
    normalized.replace("unitedstates", "unitedstatesofamerica"),
    normalized.replace("unitedkingdom", "unitedkingdomofgreatbritainandnorthernireland"),
    normalized.replace("russianfederation", "russia"),
    normalized.replace("czechia", "czechrepublic"),
    normalized.replace("vietNam".toLowerCase(), "vietnam"),
    normalized.replace("hongkongsar", "hongkong"),
  ];
}

function useWorldFeatures() {
  const [features, setFeatures] = useState<WorldFeature[]>([]);

  useEffect(() => {
    let cancelled = false;

    fetch("/world-countries.geojson")
      .then((response) => (response.ok ? response.json() : null))
      .then((payload: WorldFeatureCollection | null) => {
        if (!cancelled && payload?.features) {
          setFeatures(payload.features as WorldFeature[]);
        }
      })
      .catch(() => {
        if (!cancelled) setFeatures([]);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return features;
}

function buildFeatureLookup(features: WorldFeature[]) {
  const lookup = new Map<string, WorldFeature>();

  features.forEach((feature) => {
    const name = feature.properties?.name;
    if (!name) return;
    mapAliases(name).forEach((alias) => lookup.set(alias, feature));
  });

  return lookup;
}

function projectedPoint(
  point: { code?: string; name?: string; full_name?: string; type?: string },
  projection: GeoProjection,
  featureLookup: Map<string, WorldFeature>,
) {
  const code = point.code?.toUpperCase();
  const name = locationFullName(point);
  const isContinent = point.type === "continent" || (code && continentNames[code] && normalizeMapLookup(name) === normalizeMapLookup(continentNames[code]));

  if (isContinent && code && continentCoordinates[code]) {
    const projected = projection(continentCoordinates[code]);
    return projected ? { x: projected[0], y: projected[1] } : null;
  }

  if (code && fallbackCoordinates[code]) {
    const projected = projection(fallbackCoordinates[code]);
    if (projected) return { x: projected[0], y: projected[1] };
  }

  const feature = mapAliases(name).map((alias) => featureLookup.get(alias)).find(Boolean);
  if (!feature) return null;

  const centroid = geoCentroid(feature);
  const projected = projection(centroid);
  return projected ? { x: projected[0], y: projected[1] } : null;
}

function curvedMapPath(source: MapPoint, target: MapPoint) {
  const midX = (source.x + target.x) / 2;
  const midY = (source.y + target.y) / 2;
  const distance = Math.hypot(target.x - source.x, target.y - source.y);
  const lift = Math.min(120, Math.max(34, distance * 0.18));
  const controlY = midY - lift;

  return `M ${source.x.toFixed(2)} ${source.y.toFixed(2)} Q ${midX.toFixed(2)} ${controlY.toFixed(2)} ${target.x.toFixed(2)} ${target.y.toFixed(2)}`;
}

function chartPath(points: TrendPoint[], width: number, height: number, padding: number) {
  if (!points.length) return "";

  const values = points.map((point) => point.value);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const usableWidth = width - padding * 2;
  const usableHeight = height - padding * 2;

  return points
    .map((point, index) => {
      const x = padding + (points.length === 1 ? usableWidth / 2 : (index / (points.length - 1)) * usableWidth);
      const y = padding + (1 - (point.value - min) / span) * usableHeight;
      return `${index === 0 ? "M" : "L"} ${x.toFixed(2)} ${y.toFixed(2)}`;
    })
    .join(" ");
}

function LineChart({
  data,
  tone = "signal",
  compact = false,
  selectedIndex,
  onSelect,
}: {
  data: TrendPoint[];
  tone?: "signal" | "trace";
  compact?: boolean;
  selectedIndex?: number;
  onSelect?: (index: number) => void;
}) {
  const width = 760;
  const height = 240;
  const padding = 26;
  const path = chartPath(data, width, height, padding);
  const values = data.map((point) => point.value);
  const latest = lastItem(values);
  const stroke = tone === "trace" ? "#ff2a3d" : "#fcee0a";
  const shadow = tone === "trace" ? "rgba(255,42,61,0.35)" : "rgba(252,238,10,0.35)";
  const chartPoint = (point: TrendPoint, index: number) => {
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = max - min || 1;
    const usableWidth = width - padding * 2;
    const usableHeight = height - padding * 2;
    const x = padding + (data.length === 1 ? usableWidth / 2 : (index / (data.length - 1)) * usableWidth);
    const y = padding + (1 - (point.value - min) / span) * usableHeight;
    return { x, y };
  };
  const safeSelectedIndex = typeof selectedIndex === "number" ? Math.min(Math.max(selectedIndex, 0), data.length - 1) : data.length - 1;
  const selectedDatum = data[safeSelectedIndex];
  const selectedCoords = selectedDatum ? chartPoint(selectedDatum, safeSelectedIndex) : null;
  const tooltipX = selectedCoords ? Math.min(Math.max(selectedCoords.x + 14, padding), width - 250) : 0;
  const tooltipY = selectedCoords ? Math.max(selectedCoords.y - 78, padding) : 0;

  if (!data.length) {
    return (
      <div className="flex min-h-[240px] items-center justify-center rounded-lg border border-white/10 bg-black/20 text-sm text-haze">
        No trend data returned.
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-white/10 bg-black/20 p-4">
      <svg viewBox={`0 0 ${width} ${height}`} className={`${compact ? "h-44 md:h-48" : "h-60"} w-full overflow-visible`} role="img" aria-label="Radar time series chart">
        <defs>
          <linearGradient id={`line-fill-${tone}`} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={stroke} stopOpacity="0.25" />
            <stop offset="100%" stopColor={stroke} stopOpacity="0" />
          </linearGradient>
          <filter id={`line-glow-${tone}`}>
            <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor={shadow} />
          </filter>
        </defs>
        {[0, 1, 2, 3].map((line) => (
          <line
            key={line}
            x1={padding}
            x2={width - padding}
            y1={padding + line * ((height - padding * 2) / 3)}
            y2={padding + line * ((height - padding * 2) / 3)}
            stroke="rgba(255,255,255,0.08)"
            strokeDasharray="5 8"
          />
        ))}
        {selectedCoords && (
          <line
            x1={selectedCoords.x}
            x2={selectedCoords.x}
            y1={padding}
            y2={height - padding}
            stroke="rgba(255,255,255,0.42)"
            strokeWidth="1"
          />
        )}
        <path d={`${path} L ${width - padding} ${height - padding} L ${padding} ${height - padding} Z`} fill={`url(#line-fill-${tone})`} />
        <path d={path} fill="none" stroke={stroke} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" filter={`url(#line-glow-${tone})`} />
        {data.map((point, index) => {
          const { x, y } = chartPoint(point, index);
          const selected = safeSelectedIndex === index;

          return (
            <circle
              key={`${point.timestamp}-${index}`}
              cx={x}
              cy={y}
              r={selected ? 7 : 4}
              fill={selected ? "#ffffff" : stroke}
              stroke={stroke}
              strokeWidth="2"
              className="cursor-crosshair"
              onMouseEnter={() => onSelect?.(index)}
              onFocus={() => onSelect?.(index)}
              tabIndex={0}
            />
          );
        })}
        {selectedDatum && selectedCoords && (
          <g>
            <rect x={tooltipX} y={tooltipY} width="236" height="68" rx="8" fill="rgba(16,16,16,0.92)" stroke="rgba(255,255,255,0.16)" />
            <text x={tooltipX + 14} y={tooltipY + 23} fill="#ffffff" fontSize="13" fontWeight="700">
              {formatTime(selectedDatum.timestamp)}
            </text>
            <circle cx={tooltipX + 18} cy={tooltipY + 45} r="5" fill={stroke} />
            <text x={tooltipX + 32} y={tooltipY + 49} fill="#d7c99e" fontSize="13">
              Index: {formatCompact(selectedDatum.value)}
            </text>
          </g>
        )}
      </svg>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-xs text-haze">
        <span>{formatTime(data[0]?.timestamp)}</span>
        <span className="font-mono uppercase text-white/70">Latest index: {formatCompact(latest)}</span>
        <span>{formatTime(lastItem(data)?.timestamp)}</span>
      </div>
    </div>
  );
}

const attackPalette = ["#67e8f9", "#f97316", "#3b82f6", "#fcee0a", "#22c55e", "#d946ef", "#ef4444", "#a855f7"];

function DonutChart({ data, centerLabel = "Top share", compact = false }: { data: SplitPoint[]; centerLabel?: string; compact?: boolean }) {
  const rows = data.length ? data.slice(0, compact ? 3 : 4) : [{ label: "Unavailable", value: 100 }];
  const total = rows.reduce((sum, row) => sum + row.value, 0) || 1;
  let cursor = 0;
  const gradient = rows
    .map((row, index) => {
      const start = cursor;
      cursor += (row.value / total) * 360;
      return `${attackPalette[index % attackPalette.length]} ${start}deg ${cursor}deg`;
    })
    .join(", ");
  const lead = rows[0];

  return (
    <div className={`grid rounded-lg border border-white/10 bg-black/20 ${compact ? "gap-3 p-3" : "gap-5 p-4"}`}>
      <div
        className={`relative mx-auto rounded-full ${compact ? "h-32 w-32 2xl:h-36 2xl:w-36" : "h-48 w-48"}`}
        style={{
          background: `conic-gradient(${gradient})`,
          boxShadow: "0 0 38px rgba(252,238,10,0.12)",
        }}
      >
        <div className={`absolute grid place-items-center rounded-full border border-white/10 bg-obsidian text-center ${compact ? "inset-4" : "inset-5"}`}>
          <span className="font-mono text-[10px] uppercase text-haze sm:text-xs">{centerLabel}</span>
          <span className={`font-semibold text-white ${compact ? "text-2xl" : "text-3xl"}`}>{formatPercent(lead.value)}</span>
        </div>
      </div>
      <div className={`grid ${compact ? "gap-2" : "gap-3"}`}>
        {rows.map((row, index) => (
          <div key={row.label} className={`grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 rounded-md border border-white/10 bg-white/[0.035] ${compact ? "px-3 py-2" : "px-4 py-3"}`}>
            <span className={`flex min-w-0 items-center gap-3 leading-5 text-haze ${compact ? "text-xs sm:text-sm" : "text-sm"}`}>
              <span className={`${compact ? "h-2.5 w-2.5" : "h-3 w-3"} shrink-0 rounded-full`} style={{ backgroundColor: attackPalette[index % attackPalette.length] }} />
              <span className="min-w-0 break-words">{row.label}</span>
            </span>
            <span className={`font-mono font-semibold text-white ${compact ? "text-xs" : "text-sm"}`}>{formatPercent(row.value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function LocationBars({ data }: { data: LocationPoint[] }) {
  const max = Math.max(...data.map((point) => point.value), 1);

  if (!data.length) {
    return (
      <div className="flex min-h-[220px] items-center justify-center rounded-lg border border-white/10 bg-black/20 text-sm text-haze">
        Top location data unavailable.
      </div>
    );
  }

  return (
    <div className="grid gap-3 rounded-lg border border-white/10 bg-black/20 p-4">
      {data.map((location) => (
        <div key={`${location.code}-${location.name}`} className="grid gap-2">
          <div className="flex items-center justify-between gap-3 text-sm">
            <span className="truncate text-white">{locationDisplayLabel(location)}</span>
            <span className="font-mono text-xs text-haze">{formatCompact(location.value)}</span>
          </div>
          <div className="h-3 overflow-hidden rounded-full bg-white/10">
            <div className="h-full rounded-full bg-gradient-to-r from-signal via-volt to-trace" style={{ width: `${Math.max(5, (location.value / max) * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function flowEndpointPoints(flows: AttackFlowPoint[]) {
  const endpoints = new Map<string, AttackLocationPoint>();

  flows.forEach((flow, index) => {
    [
      { code: flow.origin_code, name: flow.origin_name, value: flow.value },
      { code: flow.target_code, name: flow.target_name, value: flow.value },
    ].forEach((point) => {
      const key = point.code || point.name || `endpoint-${index}`;
      const existing = endpoints.get(key);
      if (!existing || point.value > existing.value) {
        endpoints.set(key, {
          code: point.code,
          name: point.name,
          value: point.value,
          rank: existing?.rank || endpoints.size + 1,
        });
      }
    });
  });

  return Array.from(endpoints.values())
    .sort((a, b) => b.value - a.value)
    .slice(0, 12);
}

function LocationRankList({ title, data }: { title: string; data: AttackLocationPoint[] }) {
  const max = Math.max(...data.map((point) => point.value), 1);

  return (
    <div className="rounded-md border border-white/10 bg-black/25 p-3">
      <p className="mb-3 font-mono text-xs uppercase text-signal">{title}</p>
      <div className="grid gap-2">
        {data.slice(0, 6).map((point, index) => (
          <div key={`${point.code}-${point.name}-${index}`} className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 rounded-md border border-white/10 bg-white/[0.035] px-3 py-2">
            <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: attackPalette[index % attackPalette.length] }} />
            <span className="truncate text-sm text-white">{point.name}</span>
            <span className="font-mono text-xs text-haze">{formatPercent(point.value)}</span>
            <span className="col-span-3 h-1.5 overflow-hidden rounded-full bg-white/10">
              <span className="block h-full rounded-full" style={{ width: `${Math.max(5, (point.value / max) * 100)}%`, backgroundColor: attackPalette[index % attackPalette.length] }} />
            </span>
          </div>
        ))}
        {!data.length && <p className="rounded-md border border-white/10 bg-black/20 p-4 text-sm text-haze">Radar did not return geography rows for this view.</p>}
      </div>
    </div>
  );
}

function AttackFlowRibbon({ flows }: { flows: AttackFlowPoint[] }) {
  const rows = flows.slice(0, 8);
  const max = Math.max(...rows.map((flow) => flow.value), 1);
  const sourceTotals = new Map<string, number>();
  const targetTotals = new Map<string, number>();

  rows.forEach((flow) => {
    const source = flow.origin_code || flow.origin_name.slice(0, 3);
    const target = flow.target_code || flow.target_name.slice(0, 3);
    sourceTotals.set(source, (sourceTotals.get(source) || 0) + flow.value);
    targetTotals.set(target, (targetTotals.get(target) || 0) + flow.value);
  });

  const sources = Array.from(sourceTotals.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);
  const targets = Array.from(targetTotals.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);
  const sourceY = new Map(sources.map(([label], index) => [label, 70 + index * 36]));
  const targetY = new Map(targets.map(([label], index) => [label, 70 + index * 36]));

  if (!rows.length) {
    return (
      <div className="grid h-full min-h-[360px] place-items-center rounded-md border border-white/10 bg-black/25 p-5 text-center text-sm text-haze">
        Attack flow data unavailable.
      </div>
    );
  }

  return (
    <div className="rounded-md border border-white/10 bg-black/25 p-3">
      <div className="mb-3 flex items-center justify-between gap-3">
        <p className="font-mono text-xs uppercase text-signal">Attacks by flow</p>
        <span className="rounded border border-white/10 bg-white/[0.05] px-2 py-1 font-mono text-[11px] uppercase text-haze">Source {"->"} Target</span>
      </div>
      <svg viewBox="0 0 360 390" className="h-[360px] w-full" role="img" aria-label="Source to target attack flow">
        <rect x="0" y="0" width="360" height="390" fill="rgba(255,255,255,0.015)" />
        {rows.map((flow, index) => {
          const source = flow.origin_code || flow.origin_name.slice(0, 3);
          const target = flow.target_code || flow.target_name.slice(0, 3);
          const y1 = sourceY.get(source) || 70;
          const y2 = targetY.get(target) || 70;
          const width = Math.max(1.5, Math.min(30, (flow.value / max) * 30));
          const color = attackPalette[index % attackPalette.length];

          return (
            <path
              key={`${flow.origin_code}-${flow.target_code}-${index}`}
              d={`M 72 ${y1} C 150 ${y1}, 210 ${y2}, 288 ${y2}`}
              fill="none"
              stroke={color}
              strokeOpacity="0.52"
              strokeWidth={width}
              strokeLinecap="round"
            />
          );
        })}
        {sources.map(([source, value], index) => {
          const y = sourceY.get(source) || 70;
          const height = Math.max(8, Math.min(56, (value / max) * 56));

          return (
            <g key={source}>
              <rect x="16" y={y - height / 2} width="46" height={height} rx="3" fill={attackPalette[index % attackPalette.length]} opacity="0.58" />
              <text x="25" y={y + 4} fill="#ffffff" fontSize="12" fontWeight="800">
                {source}
              </text>
            </g>
          );
        })}
        {targets.map(([target, value], index) => {
          const y = targetY.get(target) || 70;
          const height = Math.max(8, Math.min(56, (value / max) * 56));

          return (
            <g key={target}>
              <rect x="298" y={y - height / 2} width="46" height={height} rx="3" fill={attackPalette[(index + 2) % attackPalette.length]} opacity="0.58" />
              <text x="321" y={y + 4} fill="#ffffff" fontSize="12" fontWeight="800" textAnchor="middle">
                {target}
              </text>
            </g>
          );
        })}
        <text x="18" y="372" fill="#67e8f9" fontSize="12" fontWeight="800">
          Source
        </text>
        <text x="338" y="372" fill="#67e8f9" fontSize="12" fontWeight="800" textAnchor="end">
          Target
        </text>
      </svg>
    </div>
  );
}

function mapPointKey(point: { code?: string; name?: string; type?: string }, kind: "source" | "target") {
  return `${kind}:${point.type || "country"}:${point.code || point.name}`.toUpperCase();
}

function mergeMapPoints(points: Array<MapPoint | null>) {
  const merged = new Map<string, MapPoint>();

  points.filter(Boolean).forEach((point) => {
    const item = point as MapPoint;
    const key = mapPointKey(item, item.kind);
    const existing = merged.get(key);

    if (!existing || item.connected || item.value > existing.value) {
      merged.set(key, {
        ...item,
        value: Math.max(item.value, existing?.value || 0),
        connected: Boolean(item.connected || existing?.connected),
      });
    }
  });

  return Array.from(merged.values()).sort((a, b) => {
    if (a.connected !== b.connected) return a.connected ? -1 : 1;
    return b.value - a.value;
  });
}

function mapPointFromLocation(
  point: AttackLocationPoint,
  kind: "source" | "target",
  index: number,
  projection: GeoProjection,
  featureLookup: Map<string, WorldFeature>,
  connected = false,
): MapPoint | null {
  const coords = projectedPoint(point, projection, featureLookup);
  if (!coords) return null;

  return {
    code: point.code,
    name: locationFullName(point),
    label: locationDisplayLabel(point),
    type: point.type,
    value: point.value,
    color: attackPalette[index % attackPalette.length],
    kind,
    connected,
    ...coords,
  };
}

function mapPointFromFlow(
  flow: AttackFlowPoint,
  side: "origin" | "target",
  index: number,
  projection: GeoProjection,
  featureLookup: Map<string, WorldFeature>,
): MapPoint | null {
  const sourceLike =
    side === "origin"
      ? {
          code: flow.origin_code,
          name: flow.origin_name,
          label: flow.origin_label,
          full_name: flow.origin_full_name,
          type: flow.origin_type,
          value: flow.value,
        }
      : {
          code: flow.target_code,
          name: flow.target_name,
          label: flow.target_label,
          full_name: flow.target_full_name,
          type: flow.target_type,
          value: flow.value,
        };
  const coords = projectedPoint(sourceLike, projection, featureLookup);
  if (!coords) return null;

  return {
    code: sourceLike.code,
    name: locationFullName(sourceLike),
    label: locationDisplayLabel(sourceLike),
    type: sourceLike.type,
    value: flow.value,
    color: attackPalette[index % attackPalette.length],
    kind: side === "origin" ? "source" : "target",
    connected: true,
    ...coords,
  };
}

function WorldMapFlowPanel({
  activeSignal,
  flows,
  rankings,
  rankingTitle,
  maxFlow,
  setSelectedSignal,
}: {
  activeSignal: GraphSignal;
  flows: AttackFlowPoint[];
  rankings: AttackLocationPoint[];
  rankingTitle: string;
  maxFlow: number;
  setSelectedSignal: (signal: GraphSignal) => void;
}) {
  const maxRanking = Math.max(...rankings.map((row) => row.value), 1);
  const visibleFlows = flows.slice(0, 4);
  const visibleRankings = rankings.slice(0, 4);

  return (
    <aside className="grid gap-3 xl:grid-cols-[minmax(210px,0.9fr)_minmax(260px,1.1fr)_minmax(210px,0.9fr)] xl:items-start">
      <div className="rounded-md border border-white/10 bg-black/35 p-3">
        <p className="font-mono text-xs uppercase text-signal">Selected signal</p>
        <div className="mt-3 rounded-md border border-white/10 bg-white/[0.035] p-3">
          <div className="mb-3 flex items-center gap-3">
            <span className="h-3 w-3 rounded-full" style={{ backgroundColor: activeSignal.color }} />
            <div className="min-w-0">
              <h3 className="break-words text-base font-semibold text-white">{activeSignal.title}</h3>
              <p className="mt-1 font-mono text-[11px] uppercase text-haze">{activeSignal.meta}</p>
            </div>
          </div>
          {typeof activeSignal.value === "number" && <p className="mb-2 text-2xl font-semibold text-white">{formatPercent(activeSignal.value)}</p>}
          <p className="text-xs leading-5 text-haze">{activeSignal.body}</p>
        </div>
      </div>

      <div className="rounded-md border border-white/10 bg-black/35 p-3">
        <p className="font-mono text-xs uppercase text-signal">Top flows</p>
        <div className="mt-3 grid gap-2">
          {visibleFlows.length ? (
            visibleFlows.map((flow, index) => (
              <button
                key={`${flow.origin_code}-${flow.target_code}-${index}`}
                type="button"
                onClick={() =>
                  setSelectedSignal({
                    title: flowDisplayLabel(flow),
                    meta: "Origin to target flow",
                    body: `${flow.origin_label || locationDisplayLabel({ code: flow.origin_code, name: flow.origin_name })} to ${flow.target_label || locationDisplayLabel({ code: flow.target_code, name: flow.target_name })} represents ${formatPercent(flow.value)} of the returned Layer 7 attack flow share.`,
                    value: flow.value,
                    color: attackPalette[index % attackPalette.length],
                  })
                }
                className="grid gap-2 rounded-md border border-white/10 bg-white/[0.035] px-3 py-2 text-left transition hover:border-signal/35 hover:bg-white/[0.06]"
              >
                <span className="text-xs font-semibold leading-5 text-white sm:text-sm">{flowDisplayLabel(flow)}</span>
                <span className="flex items-center gap-3">
                  <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/10">
                    <span
                      className="block h-full rounded-full"
                      style={{
                        width: `${Math.max(5, (flow.value / maxFlow) * 100)}%`,
                        backgroundColor: attackPalette[index % attackPalette.length],
                      }}
                    />
                  </span>
                  <span className="font-mono text-xs text-haze">{formatPercent(flow.value)}</span>
                </span>
              </button>
            ))
          ) : (
            <p className="rounded-md border border-white/10 bg-black/20 p-3 text-sm text-haze">Radar returned rankings, but no real origin-target flow pairs for this scope.</p>
          )}
        </div>
      </div>

      <div className="rounded-md border border-white/10 bg-black/35 p-3">
        <p className="font-mono text-xs uppercase text-signal">{rankingTitle}</p>
        <div className="mt-3 grid gap-2">
          {visibleRankings.map((point, index) => (
            <div key={`${point.code}-${point.name}-${index}`} className="grid gap-2 rounded-md border border-white/10 bg-white/[0.035] px-3 py-2">
              <span className="flex items-center justify-between gap-3 text-sm">
                <span className="min-w-0 truncate font-semibold text-white">{locationDisplayLabel(point)}</span>
                <span className="font-mono text-xs text-haze">{formatPercent(point.value)}</span>
              </span>
              <span className="h-1.5 overflow-hidden rounded-full bg-white/10">
                <span className="block h-full rounded-full" style={{ width: `${Math.max(5, (point.value / maxRanking) * 100)}%`, backgroundColor: attackPalette[index % attackPalette.length] }} />
              </span>
            </div>
          ))}
          {!visibleRankings.length && <p className="rounded-md border border-white/10 bg-black/20 p-3 text-sm text-haze">Ranking rows unavailable for this scope.</p>}
        </div>
      </div>
    </aside>
  );
}

function WorldAttackMap({
  mode,
  origins,
  targets,
  flows,
  flowMode,
  flowScopeNote,
  controls,
  onModeChange,
}: {
  mode: AttackGeoTab;
  origins: AttackLocationPoint[];
  targets: AttackLocationPoint[];
  flows: AttackFlowPoint[];
  flowMode?: "merged_flows" | "partial_flows" | "rankings_only";
  flowScopeNote?: string;
  controls?: ReactNode;
  onModeChange: (mode: AttackGeoTab) => void;
}) {
  const features = useWorldFeatures();
  const reducedMotion = useReducedMotionPreference();
  const [selectedSignal, setSelectedSignal] = useState<GraphSignal | null>(null);
  const [mapZoom, setMapZoom] = useState(minMapZoom);
  const featureCollection = useMemo<WorldFeatureCollection>(
    () => ({ type: "FeatureCollection", features }) as WorldFeatureCollection,
    [features],
  );
  const projection = useMemo(() => {
    const base = geoEqualEarth();
    if (!features.length) return base.scale(150).translate([mapWidth / 2, mapHeight / 2]);
    return base.fitExtent([[18, 22], [mapWidth - 18, mapHeight - 22]], featureCollection as never);
  }, [featureCollection, features.length]);
  const pathGenerator = useMemo(() => geoPath(projection), [projection]);
  const featureLookup = useMemo(() => buildFeatureLookup(features), [features]);
  const flowRows = flows.slice(0, 20);
  const maxFlow = Math.max(...flowRows.map((flow) => flow.value), 1);
  const sourcePointsFromFlows = flowRows.map((flow, index) => mapPointFromFlow(flow, "origin", index, projection, featureLookup));
  const targetPointsFromFlows = flowRows.map((flow, index) => mapPointFromFlow(flow, "target", index, projection, featureLookup));
  const sourcePoints = mergeMapPoints([
    ...sourcePointsFromFlows,
    ...origins.slice(0, 12).map((origin, index) => mapPointFromLocation(origin, "source", index, projection, featureLookup, false)),
  ]);
  const targetPoints = mergeMapPoints([
    ...targetPointsFromFlows,
    ...targets.slice(0, 12).map((target, index) => mapPointFromLocation(target, "target", index + 2, projection, featureLookup, false)),
  ]);
  const sourceByKey = new Map(sourcePoints.map((point) => [mapPointKey(point, "source"), point]));
  const targetByKey = new Map(targetPoints.map((point) => [mapPointKey(point, "target"), point]));
  const edges = flowRows
    .map((flow, index) => {
      const source = mapPointFromFlow(flow, "origin", index, projection, featureLookup);
      const target = mapPointFromFlow(flow, "target", index, projection, featureLookup);
      if (!source || !target) return null;
      const sourcePoint = sourceByKey.get(mapPointKey(source, "source")) || source;
      const targetPoint = targetByKey.get(mapPointKey(target, "target")) || target;

      return {
        id: `map-flow-${index}`,
        flow,
        source: sourcePoint,
        target: targetPoint,
        path: curvedMapPath(sourcePoint, targetPoint),
        color: attackPalette[index % attackPalette.length],
        width: Math.max(1.4, Math.min(12, 1.5 + (flow.value / maxFlow) * 10.5)),
      };
    })
    .filter(Boolean) as MapFlowEdge[];
  const activeRows = mode === "targets" ? targets : origins;
  const coverageLabel = flows.length ? `${flows.length} flow pairs` : "rankings only";
  const coverageClass =
    flowMode === "rankings_only"
      ? "border-volt/35 bg-volt/10 text-volt"
      : flowMode === "partial_flows"
        ? "border-trace/35 bg-trace/10 text-trace"
        : "border-cyan-300/35 bg-cyan-400/10 text-cyan-100";
  const defaultSignal = flowRows[0]
    ? {
        title: flowDisplayLabel(flowRows[0]),
        meta: "Strongest Radar flow",
        body: `${flowRows[0].origin_label || locationDisplayLabel({ code: flowRows[0].origin_code, name: flowRows[0].origin_name })} to ${flowRows[0].target_label || locationDisplayLabel({ code: flowRows[0].target_code, name: flowRows[0].target_name })} represents ${formatPercent(flowRows[0].value)} of the returned Layer 7 country flow share.`,
        value: flowRows[0].value,
        color: attackPalette[0],
      }
    : {
        title: "Rankings only",
        meta: "No Radar flow pairs returned",
        body: flowScopeNote || "Radar returned source or target rankings for this scope, but no origin-target pairs.",
        color: "#fcee0a",
      };
  const activeSignal = selectedSignal || defaultSignal;
  const sourceOpacity = mode === "targets" ? 0.36 : 1;
  const targetOpacity = mode === "origins" ? 0.36 : 1;
  const edgeOpacity = mode === "flows" ? 0.55 : 0.18;
  const zoomOffsetX = (mapWidth - mapWidth * mapZoom) / 2;
  const zoomOffsetY = (mapHeight - mapHeight * mapZoom) / 2;
  const mapTransform = `translate(${zoomOffsetX} ${zoomOffsetY}) scale(${mapZoom})`;
  const showCompactCodes = mapZoom >= 1.65;
  const zoomedMarkerOuterRadius = 4.8 / mapZoom;
  const zoomedMarkerInnerRadius = 2.2 / mapZoom;
  const zoomedUnconnectedOuterRadius = 3.6 / mapZoom;
  const zoomedUnconnectedInnerRadius = 1.7 / mapZoom;
  const zoomedMarkerStroke = 1.6 / mapZoom;
  const zoomedPacketRadius = (width: number) => Math.max(1.5, Math.min(3.2, width / 3.7)) / mapZoom;
  const zoomedEdgeWidth = (width: number) => Math.max(0.85, width * 0.72) / mapZoom;
  const zoomLabel = `${mapZoom.toFixed(mapZoom % 1 === 0 ? 0 : 1)}x`;
  const zoomIn = () => setMapZoom((current) => Math.min(maxMapZoom, Number((current + mapZoomStep).toFixed(2))));
  const zoomOut = () => setMapZoom((current) => Math.max(minMapZoom, Number((current - mapZoomStep).toFixed(2))));
  const resetZoom = () => setMapZoom(minMapZoom);

  useEffect(() => {
    setSelectedSignal(null);
  }, [mode, origins, targets, flows]);

  useEffect(() => {
    setMapZoom(minMapZoom);
  }, [origins, targets, flows]);

  return (
    <div className="rounded-lg border border-white/10 bg-[#07090b] p-4">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="font-mono text-xs uppercase text-signal">Application layer attack activity</p>
          <p className="mt-1 text-sm text-haze">{flowScopeNote || "Top attacks by source and target location from aggregated Cloudflare Radar Layer 7 data"}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className={`rounded border px-3 py-1.5 font-mono text-[11px] uppercase ${coverageClass}`}>{coverageLabel}</span>
          <span className="font-mono text-xs uppercase text-white">Attacks by</span>
          {attackGeoTabs.map((tab) => (
            <button
              key={tab.key}
              type="button"
              onClick={() => onModeChange(tab.key)}
              className={`rounded border px-3 py-1.5 text-sm transition ${
                mode === tab.key ? "border-white/15 bg-white/15 text-white" : "border-white/10 bg-black/20 text-haze hover:border-white/25 hover:text-white"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {controls ? <div className="mb-4">{controls}</div> : null}

      <div className="grid gap-4">
        <div className="relative overflow-hidden rounded-md border border-white/10 bg-black/45">
          <div className="absolute right-3 top-3 z-10 flex items-center overflow-hidden rounded-md border border-white/10 bg-[#050608]/90 shadow-[0_12px_36px_rgba(0,0,0,0.45)] backdrop-blur">
            <button
              type="button"
              onClick={zoomOut}
              disabled={mapZoom <= minMapZoom}
              className="grid h-9 w-9 place-items-center border-r border-white/10 text-haze transition hover:bg-white/10 hover:text-white disabled:cursor-not-allowed disabled:opacity-35"
              aria-label="Zoom map out"
            >
              <Minus size={15} />
            </button>
            <span className="min-w-12 px-3 text-center font-mono text-[11px] uppercase text-signal">{zoomLabel}</span>
            <button
              type="button"
              onClick={zoomIn}
              disabled={mapZoom >= maxMapZoom}
              className="grid h-9 w-9 place-items-center border-l border-r border-white/10 text-haze transition hover:bg-white/10 hover:text-white disabled:cursor-not-allowed disabled:opacity-35"
              aria-label="Zoom map in"
            >
              <Plus size={15} />
            </button>
            <button
              type="button"
              onClick={resetZoom}
              disabled={mapZoom === minMapZoom}
              className="grid h-9 w-9 place-items-center text-haze transition hover:bg-white/10 hover:text-white disabled:cursor-not-allowed disabled:opacity-35"
              aria-label="Reset map zoom"
            >
              <RotateCcw size={14} />
            </button>
          </div>
          <svg
            viewBox={`0 0 ${mapWidth} ${mapHeight}`}
            className="h-[280px] w-full sm:h-[320px] lg:h-[360px] 2xl:h-auto 2xl:aspect-[960/520]"
            preserveAspectRatio="xMidYMid meet"
            role="img"
            aria-label="World map showing Layer 7 attack source and target flows"
          >
            <defs>
              <radialGradient id="world-map-glow" cx="50%" cy="50%" r="70%">
                <stop offset="0%" stopColor="#67e8f9" stopOpacity="0.16" />
                <stop offset="100%" stopColor="#050608" stopOpacity="0" />
              </radialGradient>
              <filter id="world-marker-glow">
                <feDropShadow dx="0" dy="0" stdDeviation="5" floodColor="rgba(103,232,249,0.55)" />
              </filter>
            </defs>
            <rect width={mapWidth} height={mapHeight} fill="#050608" />
            <rect width={mapWidth} height={mapHeight} fill="url(#world-map-glow)" />
            {[0, 1, 2, 3, 4, 5].map((line) => (
              <line key={`map-h-${line}`} x1="28" x2={mapWidth - 28} y1={72 + line * 66} y2={72 + line * 66} stroke="rgba(255,255,255,0.045)" strokeDasharray="4 10" />
            ))}
            {[0, 1, 2, 3, 4, 5, 6, 7].map((line) => (
              <line key={`map-v-${line}`} x1={70 + line * 118} x2={70 + line * 118} y1="36" y2={mapHeight - 36} stroke="rgba(255,255,255,0.04)" strokeDasharray="4 10" />
            ))}

            <g transform={mapTransform}>
              {features.length ? (
                features.map((feature, index) => {
                  const path = pathGenerator(feature as never);
                  if (!path) return null;

                  return (
                    <path
                      key={`${feature.id || feature.properties?.name || index}`}
                      d={path}
                      fill="#9bd7e1"
                      fillOpacity="0.82"
                      stroke="rgba(5,6,8,0.68)"
                      strokeWidth={0.55 / mapZoom}
                    >
                      <title>{feature.properties?.name}</title>
                    </path>
                  );
                })
              ) : (
                <text x={mapWidth / 2} y={mapHeight / 2} fill="#d7c99e" fontSize="14" textAnchor="middle">
                  Loading world map...
                </text>
              )}

              {edges.map((edge) => (
                <path
                  key={edge.id}
                  id={edge.id}
                  d={edge.path}
                  fill="none"
                  stroke={edge.color}
                  strokeLinecap="round"
                  strokeOpacity={edgeOpacity}
                  strokeWidth={zoomedEdgeWidth(edge.width)}
                  className="cursor-pointer transition-opacity hover:opacity-100"
                  onMouseEnter={() =>
                    setSelectedSignal({
                      title: flowDisplayLabel(edge.flow),
                      meta: "Origin to target flow",
                      body: `${edge.source.label} to ${edge.target.label} represents ${formatPercent(edge.flow.value)} of the returned Layer 7 attack flow share.`,
                      value: edge.flow.value,
                      color: edge.color,
                    })
                  }
                  onFocus={() =>
                    setSelectedSignal({
                      title: flowDisplayLabel(edge.flow),
                      meta: "Origin to target flow",
                      body: `${edge.source.label} to ${edge.target.label} represents ${formatPercent(edge.flow.value)} of the returned Layer 7 attack flow share.`,
                      value: edge.flow.value,
                      color: edge.color,
                    })
                  }
                  tabIndex={0}
                />
              ))}

              {!reducedMotion &&
                edges.map((edge, index) => (
                  <circle key={`${edge.id}-packet`} r={zoomedPacketRadius(edge.width)} fill={edge.color} opacity={mode === "flows" ? "0.82" : "0.34"}>
                    <animateMotion dur={`${5.6 + index * 0.32}s`} repeatCount="indefinite">
                      <mpath href={`#${edge.id}`} />
                    </animateMotion>
                  </circle>
                ))}

              {sourcePoints.slice(0, 14).map((point, index) => (
                <g
                  key={`source-${point.code}-${point.name}-${index}`}
                  opacity={point.connected ? sourceOpacity : Math.min(sourceOpacity, 0.5)}
                  className="cursor-pointer"
                  onMouseEnter={() =>
                    setSelectedSignal({
                      title: point.label,
                      meta: "Source location",
                      body: `${point.label} is present in the attack origin signal for this Radar scope at ${formatPercent(point.value)}.`,
                      value: point.value,
                      color: point.color,
                    })
                  }
                  onFocus={() =>
                    setSelectedSignal({
                      title: point.label,
                      meta: "Source location",
                      body: `${point.label} is present in the attack origin signal for this Radar scope at ${formatPercent(point.value)}.`,
                      value: point.value,
                      color: point.color,
                    })
                  }
                  tabIndex={0}
                >
                  <circle
                    cx={point.x}
                    cy={point.y}
                    r={point.connected ? zoomedMarkerOuterRadius : zoomedUnconnectedOuterRadius}
                    fill="#050608"
                    stroke={point.color}
                    strokeWidth={zoomedMarkerStroke}
                    filter={point.connected ? "url(#world-marker-glow)" : undefined}
                  />
                  <circle cx={point.x} cy={point.y} r={point.connected ? zoomedMarkerInnerRadius : zoomedUnconnectedInnerRadius} fill={point.color} />
                  {showCompactCodes && point.connected && point.code ? (
                    <text x={point.x + 7 / mapZoom} y={point.y - 7 / mapZoom} fill="#ffffff" fontSize={9 / mapZoom} fontWeight="800">
                      {point.code}
                    </text>
                  ) : null}
                  <title>{`${point.label}: ${formatPercent(point.value)}`}</title>
                </g>
              ))}

              {targetPoints.slice(0, 14).map((point, index) => (
                <g
                  key={`target-${point.code}-${point.name}-${index}`}
                  opacity={point.connected ? targetOpacity : Math.min(targetOpacity, 0.5)}
                  className="cursor-pointer"
                  onMouseEnter={() =>
                    setSelectedSignal({
                      title: point.label,
                      meta: "Target location",
                      body: `${point.label} is present in the attack target signal for this Radar scope at ${formatPercent(point.value)}.`,
                      value: point.value,
                      color: point.color,
                    })
                  }
                  onFocus={() =>
                    setSelectedSignal({
                      title: point.label,
                      meta: "Target location",
                      body: `${point.label} is present in the attack target signal for this Radar scope at ${formatPercent(point.value)}.`,
                      value: point.value,
                      color: point.color,
                    })
                  }
                  tabIndex={0}
                >
                  <circle
                    cx={point.x}
                    cy={point.y}
                    r={point.connected ? zoomedMarkerOuterRadius : zoomedUnconnectedOuterRadius}
                    fill="#050608"
                    stroke={point.color}
                    strokeWidth={zoomedMarkerStroke}
                    filter={point.connected ? "url(#world-marker-glow)" : undefined}
                  />
                  <circle cx={point.x} cy={point.y} r={point.connected ? zoomedMarkerInnerRadius : zoomedUnconnectedInnerRadius} fill={point.color} />
                  {showCompactCodes && point.connected && point.code ? (
                    <text x={point.x + 7 / mapZoom} y={point.y - 7 / mapZoom} fill="#ffffff" fontSize={9 / mapZoom} fontWeight="800">
                      {point.code}
                    </text>
                  ) : null}
                  <title>{`${point.label}: ${formatPercent(point.value)}`}</title>
                </g>
              ))}
            </g>
          </svg>

          {!edges.length && (
            <div className="absolute inset-x-6 bottom-6 rounded-md border border-volt/30 bg-volt/10 px-4 py-3 text-sm text-haze">
              {flowScopeNote || "Radar returned rankings, but no origin-target flow pairs for this scope."}
            </div>
          )}
        </div>

        <WorldMapFlowPanel
          activeSignal={activeSignal}
          flows={flowRows}
          rankings={activeRows}
          rankingTitle={mode === "targets" ? "Top targets" : "Top sources"}
          maxFlow={maxFlow}
          setSelectedSignal={setSelectedSignal}
        />
      </div>
    </div>
  );
}

type GraphSignal = {
  title: string;
  meta: string;
  body: string;
  value?: number;
  color: string;
};

type AttackGraphNodeInput = AttackLocationPoint & {
  connected?: boolean;
};

type PositionedAttackNode = AttackGraphNodeInput & {
  id: string;
  shortLabel: string;
  side: "source" | "target";
  x: number;
  y: number;
  radius: number;
  color: string;
};

function useReducedMotionPreference() {
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;

    const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    const syncPreference = () => setReducedMotion(mediaQuery.matches);

    syncPreference();
    mediaQuery.addEventListener?.("change", syncPreference);

    return () => {
      mediaQuery.removeEventListener?.("change", syncPreference);
    };
  }, []);

  return reducedMotion;
}

function graphNodeId(code?: string, name?: string) {
  return (code || name || "unknown").toUpperCase();
}

function graphShortLabel(code?: string, name = "") {
  if (code) return code.toUpperCase();
  return name
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part[0])
    .join("")
    .slice(0, 3)
    .toUpperCase();
}

function truncateGraphLabel(value: string, maxLength = 18) {
  return value.length > maxLength ? `${value.slice(0, maxLength - 1)}.` : value;
}

function mergeGraphNode(nodes: Map<string, AttackGraphNodeInput>, node: AttackGraphNodeInput) {
  const id = graphNodeId(node.code, node.name);
  const existing = nodes.get(id);

  nodes.set(id, {
    code: node.code,
    name: node.name,
    value: existing ? Math.max(existing.value, node.value) : node.value,
    rank: existing?.rank || node.rank || nodes.size + 1,
    connected: Boolean(existing?.connected || node.connected),
    focus: Boolean(existing?.focus || node.focus),
  });
}

function selectedScopeOrigin(scopeType: string | undefined, scopeValue: string | undefined, scopeLabel: string | undefined, flows: AttackFlowPoint[], origins: AttackLocationPoint[]) {
  if (scopeType !== "country" || !scopeValue) return origins;

  const selected = scopeValue.toUpperCase();
  const existing = origins.find((origin) => origin.code?.toUpperCase() === selected);
  const flowValue = flows
    .filter((flow) => flow.origin_code?.toUpperCase() === selected)
    .reduce((sum, flow) => sum + flow.value, 0);

  return [
    {
      rank: 1,
      code: selected,
      name: scopeLabel || existing?.name || selected,
      value: flowValue || existing?.value || 0,
      focus: true,
    },
  ];
}

function buildAttackGraphBaseNodes(
  flows: AttackFlowPoint[],
  origins: AttackLocationPoint[],
  targets: AttackLocationPoint[],
  scopeType?: string,
  scopeValue?: string,
  scopeLabel?: string,
) {
  const sourceMap = new Map<string, AttackGraphNodeInput>();
  const targetMap = new Map<string, AttackGraphNodeInput>();
  const visibleOrigins = selectedScopeOrigin(scopeType, scopeValue, scopeLabel, flows, origins);

  flows.slice(0, 10).forEach((flow) => {
    if (scopeType === "country" && scopeValue && flow.origin_code?.toUpperCase() !== scopeValue.toUpperCase()) {
      return;
    }

    const sourceId = graphNodeId(flow.origin_code, flow.origin_name);
    const targetId = graphNodeId(flow.target_code, flow.target_name);
    const source = sourceMap.get(sourceId);
    const target = targetMap.get(targetId);

    sourceMap.set(sourceId, {
      code: flow.origin_code,
      name: flow.origin_name,
      value: (source?.value || 0) + flow.value,
      rank: source?.rank || sourceMap.size + 1,
      connected: true,
    });
    targetMap.set(targetId, {
      code: flow.target_code,
      name: flow.target_name,
      value: (target?.value || 0) + flow.value,
      rank: target?.rank || targetMap.size + 1,
      connected: true,
    });
  });

  visibleOrigins.forEach((origin) => mergeGraphNode(sourceMap, origin));
  targets.forEach((target) => mergeGraphNode(targetMap, target));

  const sources = sortGraphNodes(Array.from(sourceMap.values()));
  const targetRows = sortGraphNodes(Array.from(targetMap.values()));

  return {
    sources: (sources.length ? sources : visibleOrigins).slice(0, scopeType === "country" ? 1 : 10),
    targets: (targetRows.length ? targetRows : targets).slice(0, 10),
  };
}

function sortGraphNodes(nodes: AttackGraphNodeInput[]) {
  return nodes.sort((a, b) => {
    if (a.focus !== b.focus) return a.focus ? -1 : 1;
    if (a.connected !== b.connected) return a.connected ? -1 : 1;
    return b.value - a.value;
  });
}

function positionAttackNodes(nodes: AttackGraphNodeInput[], side: "source" | "target", graphHeight: number): PositionedAttackNode[] {
  const top = 88;
  const bottom = graphHeight - 92;
  const max = Math.max(...nodes.map((node) => node.value), 1);
  const x = side === "source" ? 150 : 890;
  const usable = Math.max(bottom - top, 1);

  return nodes.map((node, index) => {
    const y = nodes.length === 1 ? graphHeight / 2 : top + (index / Math.max(nodes.length - 1, 1)) * usable;
    const radius = 11 + Math.sqrt(Math.max(node.value, 0) / max) * 18;

    return {
      ...node,
      id: graphNodeId(node.code, node.name),
      shortLabel: graphShortLabel(node.code, node.name),
      side,
      x,
      y,
      radius,
      color: attackPalette[index % attackPalette.length],
    };
  });
}

function AttackFlowGraph({
  mode,
  origins,
  targets,
  flows,
  flowMode,
  flowScopeNote,
  flowStatus,
  flowFilterStrategy,
  scopeType,
  scopeValue,
  scopeLabel,
  onModeChange,
}: {
  mode: AttackGeoTab;
  origins: AttackLocationPoint[];
  targets: AttackLocationPoint[];
  flows: AttackFlowPoint[];
  flowMode?: "merged_flows" | "partial_flows" | "rankings_only";
  flowScopeNote?: string;
  flowStatus?: {
    origin_limited?: string;
    target_limited?: string;
    fallback?: string;
  };
  flowFilterStrategy?: string;
  scopeType?: string;
  scopeValue?: string;
  scopeLabel?: string;
  onModeChange: (mode: AttackGeoTab) => void;
}) {
  const reducedMotion = useReducedMotionPreference();
  const [selectedSignal, setSelectedSignal] = useState<GraphSignal | null>(null);
  const graphWidth = 1040;
  const graphHeight = 700;
  const surface = { x: graphWidth / 2, y: graphHeight / 2 };
  const flowRows = flows.slice(0, 16);
  const maxFlow = Math.max(...flowRows.map((flow) => flow.value), 1);
  const baseNodes = buildAttackGraphBaseNodes(flowRows, origins, targets, scopeType, scopeValue, scopeLabel);
  const sourceNodes = positionAttackNodes(baseNodes.sources, "source", graphHeight);
  const targetNodes = positionAttackNodes(baseNodes.targets, "target", graphHeight);
  const sourceById = new Map(sourceNodes.map((node) => [node.id, node]));
  const targetById = new Map(targetNodes.map((node) => [node.id, node]));
  const graphTitle =
    mode === "targets"
      ? "Target country pressure"
      : mode === "flows"
        ? "Merged origin-target attack flows"
        : "Source country pressure";
  const coverageLabel = flows.length ? `${flows.length} flow pairs` : "rankings only";
  const coverageClass =
    flowMode === "rankings_only"
      ? "border-volt/35 bg-volt/10 text-volt"
      : flowMode === "partial_flows"
        ? "border-trace/35 bg-trace/10 text-trace"
        : "border-cyan-300/35 bg-cyan-400/10 text-cyan-100";
  const strategyLabel =
    flowFilterStrategy === "global_filtered"
      ? "filtered global fallback"
      : flowFilterStrategy === "native_fallback"
        ? "native fallback"
        : flowFilterStrategy === "native_scope"
          ? "native Radar scope"
          : flowFilterStrategy === "rankings_only"
            ? "rankings only"
            : flowFilterStrategy || "";
  const defaultSignal = flowRows[0]
    ? {
        title: `${flowRows[0].origin_code || flowRows[0].origin_name} -> ${flowRows[0].target_code || flowRows[0].target_name}`,
        meta: "Strongest Radar flow",
        body: `${flowRows[0].origin_name} to ${flowRows[0].target_name} represents ${formatPercent(flowRows[0].value)} of the returned Layer 7 country flow share.`,
        value: flowRows[0].value,
        color: attackPalette[0],
      }
    : {
        title: "Layer 7 attack surface",
        meta: "Aggregated Radar signal",
        body: flowScopeNote || "Flow pairs are unavailable for this filter, so the graph is showing source and target country rankings only.",
        color: "#fcee0a",
      };
  const activeSignal = selectedSignal || defaultSignal;
  const topRanking = mode === "targets" ? targets : origins;

  useEffect(() => {
    setSelectedSignal(null);
  }, [mode, origins, targets, flows]);

  const edges = flowRows
    .map((flow, index) => {
      const source = sourceById.get(graphNodeId(flow.origin_code, flow.origin_name));
      const target = targetById.get(graphNodeId(flow.target_code, flow.target_name));

      if (!source || !target) return null;

      const path = `M ${source.x + source.radius + 4} ${source.y} C ${source.x + 210} ${source.y}, ${surface.x - 120} ${surface.y}, ${surface.x - 54} ${surface.y} C ${surface.x + 54} ${surface.y}, ${target.x - 210} ${target.y}, ${target.x - target.radius - 4} ${target.y}`;
      const width = Math.max(1.8, Math.min(16, 2 + (flow.value / maxFlow) * 14));

      return {
        id: `attack-flow-${index}`,
        flow,
        source,
        target,
        color: attackPalette[index % attackPalette.length],
        path,
        width,
      };
    })
    .filter(Boolean) as Array<{
      id: string;
      flow: AttackFlowPoint;
      source: PositionedAttackNode;
      target: PositionedAttackNode;
      color: string;
      path: string;
      width: number;
    }>;

  const edgeOpacity = mode === "flows" ? 0.72 : 0.26;
  const sourceOpacity = mode === "targets" ? 0.48 : 1;
  const targetOpacity = mode === "origins" ? 0.48 : 1;

  return (
    <div className="overflow-hidden rounded-lg border border-white/10 bg-[#07090b] p-4">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="font-mono text-xs uppercase text-signal">Attack flow graph</p>
          <p className="mt-1 text-sm text-haze">{flowScopeNote || `${graphTitle} from aggregated Cloudflare Radar Layer 7 data`}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className={`rounded border px-3 py-1.5 font-mono text-[11px] uppercase ${coverageClass}`}>{coverageLabel}</span>
          {strategyLabel ? <span className="rounded border border-white/10 bg-black/25 px-3 py-1.5 font-mono text-[11px] uppercase text-haze">{strategyLabel}</span> : null}
          <span className="font-mono text-xs uppercase text-white">Attacks by</span>
          {attackGeoTabs.map((tab) => (
            <button
              key={tab.key}
              type="button"
              onClick={() => onModeChange(tab.key)}
              className={`rounded border px-3 py-1.5 text-sm transition ${
                mode === tab.key ? "border-white/15 bg-white/15 text-white" : "border-white/10 bg-black/20 text-haze hover:border-white/25 hover:text-white"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>
      {flowStatus && (
        <div className="mb-4 flex flex-wrap gap-2 font-mono text-[11px] uppercase text-haze">
          <span className="rounded border border-white/10 bg-black/25 px-2.5 py-1">Origin view: {flowStatus.origin_limited || "unknown"}</span>
          <span className="rounded border border-white/10 bg-black/25 px-2.5 py-1">Target view: {flowStatus.target_limited || "unknown"}</span>
          <span className="rounded border border-white/10 bg-black/25 px-2.5 py-1">Fallback: {flowStatus.fallback || "not needed"}</span>
        </div>
      )}

      <div className="grid gap-4">
        <div className="relative overflow-hidden rounded-md border border-white/10 bg-black/45">
          <svg
            viewBox={`0 0 ${graphWidth} ${graphHeight}`}
            className="aspect-[1040/700] w-full"
            role="img"
            aria-label="Node graph showing source to target Layer 7 attack flows"
          >
            <defs>
              <radialGradient id="flow-graph-glow" cx="50%" cy="50%" r="72%">
                <stop offset="0%" stopColor="#67e8f9" stopOpacity="0.16" />
                <stop offset="100%" stopColor="#67e8f9" stopOpacity="0" />
              </radialGradient>
              <filter id="flow-node-glow">
                <feDropShadow dx="0" dy="0" stdDeviation="6" floodColor="rgba(103,232,249,0.5)" />
              </filter>
            </defs>

            <rect width={graphWidth} height={graphHeight} fill="url(#flow-graph-glow)" />
            {[0, 1, 2, 3, 4, 5, 6].map((line) => (
              <line key={`v-${line}`} x1={80 + line * 148} x2={80 + line * 148} y1="58" y2={graphHeight - 58} stroke="rgba(255,255,255,0.06)" strokeDasharray="4 12" />
            ))}
            {[0, 1, 2, 3, 4, 5, 6].map((line) => (
              <line key={`h-${line}`} x1="56" x2={graphWidth - 56} y1={74 + line * 92} y2={74 + line * 92} stroke="rgba(255,255,255,0.055)" strokeDasharray="4 12" />
            ))}
            {[92, 154, 216].map((radius) => (
              <circle key={radius} cx={surface.x} cy={surface.y} r={radius} fill="none" stroke="rgba(103,232,249,0.08)" strokeWidth="1" />
            ))}

            <text x="74" y="44" fill="#d7c99e" fontSize="13" fontWeight="800" letterSpacing="1.5">
              SOURCES
            </text>
            <text x={surface.x} y="44" fill="#fcee0a" fontSize="13" fontWeight="800" letterSpacing="1.5" textAnchor="middle">
              LAYER 7 ATTACK SURFACE
            </text>
            <text x={graphWidth - 74} y="44" fill="#d7c99e" fontSize="13" fontWeight="800" letterSpacing="1.5" textAnchor="end">
              TARGETS
            </text>

            {edges.map((edge) => (
              <path
                key={edge.id}
                id={edge.id}
                d={edge.path}
                fill="none"
                stroke={edge.color}
                strokeLinecap="round"
                strokeOpacity={edgeOpacity}
                strokeWidth={edge.width}
                className="cursor-pointer transition-opacity"
                onMouseEnter={() =>
                  setSelectedSignal({
                    title: `${edge.flow.origin_code || edge.flow.origin_name} -> ${edge.flow.target_code || edge.flow.target_name}`,
                    meta: "Origin to target flow",
                    body: `${edge.flow.origin_name} to ${edge.flow.target_name} represents ${formatPercent(edge.flow.value)} of the returned Layer 7 attack flow share.`,
                    value: edge.flow.value,
                    color: edge.color,
                  })
                }
                onFocus={() =>
                  setSelectedSignal({
                    title: `${edge.flow.origin_code || edge.flow.origin_name} -> ${edge.flow.target_code || edge.flow.target_name}`,
                    meta: "Origin to target flow",
                    body: `${edge.flow.origin_name} to ${edge.flow.target_name} represents ${formatPercent(edge.flow.value)} of the returned Layer 7 attack flow share.`,
                    value: edge.flow.value,
                    color: edge.color,
                  })
                }
                tabIndex={0}
              />
            ))}

            {edges.length === 0 &&
              sourceNodes.map((node) => (
                <path
                  key={`ghost-source-${node.id}`}
                  d={`M ${node.x + node.radius + 4} ${node.y} C ${node.x + 220} ${node.y}, ${surface.x - 138} ${surface.y}, ${surface.x - 86} ${surface.y}`}
                  fill="none"
                  stroke={node.color}
                  strokeDasharray="8 10"
                  strokeLinecap="round"
                  strokeOpacity="0.2"
                  strokeWidth="1.6"
                />
              ))}
            {edges.length === 0 &&
              targetNodes.map((node) => (
                <path
                  key={`ghost-target-${node.id}`}
                  d={`M ${surface.x + 86} ${surface.y} C ${surface.x + 138} ${surface.y}, ${node.x - 220} ${node.y}, ${node.x - node.radius - 4} ${node.y}`}
                  fill="none"
                  stroke={node.color}
                  strokeDasharray="8 10"
                  strokeLinecap="round"
                  strokeOpacity="0.16"
                  strokeWidth="1.6"
                />
              ))}
            {edges.length === 0 && (
              <text x={surface.x} y={surface.y + 102} fill="#d7c99e" fontSize="11" fontWeight="700" opacity="0.72" textAnchor="middle">
                Rankings only - Radar returned no origin-target pairs for this scope
              </text>
            )}

            {!reducedMotion &&
              edges.map((edge, index) => (
                <circle key={`${edge.id}-packet`} r={Math.max(3.5, Math.min(7, edge.width / 2.8))} fill={edge.color} opacity={mode === "flows" ? "0.95" : "0.38"}>
                  <animateMotion dur={`${4.8 + index * 0.38}s`} repeatCount="indefinite">
                    <mpath href={`#${edge.id}`} />
                  </animateMotion>
                </circle>
              ))}

            <g
              className="cursor-pointer"
              onMouseEnter={() =>
                setSelectedSignal({
                  title: "Layer 7 attack surface",
                  meta: "Central application-layer signal",
                  body: "Radar country rankings and source-target flow pairs are converging here as an aggregated application-layer attack surface signal.",
                  color: "#fcee0a",
                })
              }
              onFocus={() =>
                setSelectedSignal({
                  title: "Layer 7 attack surface",
                  meta: "Central application-layer signal",
                  body: "Radar country rankings and source-target flow pairs are converging here as an aggregated application-layer attack surface signal.",
                  color: "#fcee0a",
                })
              }
              tabIndex={0}
            >
              <circle cx={surface.x} cy={surface.y} r="86" fill="rgba(252,238,10,0.08)" stroke="rgba(252,238,10,0.45)" strokeWidth="2" />
              <circle cx={surface.x} cy={surface.y} r="54" fill="#060809" stroke="#fcee0a" strokeWidth="3" filter="url(#flow-node-glow)" />
              <text x={surface.x} y={surface.y - 5} fill="#ffffff" fontSize="17" fontWeight="900" textAnchor="middle">
                LAYER 7
              </text>
              <text x={surface.x} y={surface.y + 20} fill="#d7c99e" fontSize="12" fontWeight="700" textAnchor="middle">
                ATTACK SURFACE
              </text>
            </g>

            {[...sourceNodes, ...targetNodes].map((node) => {
              const baseOpacity = node.side === "source" ? sourceOpacity : targetOpacity;
              const nodeOpacity = node.connected || node.focus ? baseOpacity : Math.min(baseOpacity, 0.5);
              const nodeStroke = node.connected || node.focus ? node.color : "rgba(215,201,158,0.72)";

              return (
                <g
                  key={`${node.side}-${node.id}`}
                  opacity={nodeOpacity}
                  className="cursor-pointer transition-opacity"
                  onMouseEnter={() =>
                    setSelectedSignal({
                      title: node.name,
                      meta: node.side === "source" ? "Source country / region" : "Target country / region",
                      body:
                        node.focus && !node.connected
                          ? `${node.name} is the selected country focus. Radar did not return origin flow pairs for this filter, so it is shown as ranking context.`
                          : `${node.name} is returning ${formatPercent(node.value)} in the ${node.side === "source" ? "attack origin" : "target country"} signal for this Radar filter.`,
                      value: node.value,
                      color: node.color,
                    })
                  }
                  onFocus={() =>
                    setSelectedSignal({
                      title: node.name,
                      meta: node.side === "source" ? "Source country / region" : "Target country / region",
                      body:
                        node.focus && !node.connected
                          ? `${node.name} is the selected country focus. Radar did not return origin flow pairs for this filter, so it is shown as ranking context.`
                          : `${node.name} is returning ${formatPercent(node.value)} in the ${node.side === "source" ? "attack origin" : "target country"} signal for this Radar filter.`,
                      value: node.value,
                      color: node.color,
                    })
                  }
                  tabIndex={0}
                >
                  <circle cx={node.x} cy={node.y} r={node.radius + 10} fill={node.color} opacity={node.connected || node.focus ? "0.09" : "0.035"} />
                  <circle cx={node.x} cy={node.y} r={node.radius} fill="#050608" stroke={nodeStroke} strokeWidth={node.connected || node.focus ? "3" : "1.8"} filter={node.connected || node.focus ? "url(#flow-node-glow)" : undefined} />
                  <circle cx={node.x} cy={node.y} r={Math.max(4, node.radius * 0.24)} fill={node.connected || node.focus ? node.color : "#d7c99e"} />
                  <text x={node.x} y={node.y + 4} fill="#ffffff" fontSize={node.connected ? "15" : "12"} fontWeight="900" textAnchor="middle">
                    {node.shortLabel}
                  </text>
                  <text x={node.x} y={node.y + node.radius + 19} fill="#d7c99e" fontSize="10" fontWeight="700" textAnchor="middle">
                    {truncateGraphLabel(node.name)}
                  </text>
                  <title>{`${node.name}: ${formatPercent(node.value)}`}</title>
                </g>
              );
            })}
          </svg>

          {!edges.length && (
            <div className="absolute inset-x-6 bottom-6 rounded-md border border-volt/30 bg-volt/10 px-4 py-3 text-sm text-haze">
              {flowScopeNote || "Flow pairs unavailable from Radar for this filter."} Source and target rankings are still shown when available.
            </div>
          )}
        </div>

        <div className="grid gap-4 xl:grid-cols-[minmax(260px,0.9fr)_minmax(360px,1.25fr)_minmax(260px,0.9fr)] xl:items-start">
          <div className="rounded-md border border-white/10 bg-black/25 p-4">
            <p className="font-mono text-xs uppercase text-signal">Selected signal</p>
            <div className="mt-4 rounded-md border border-white/10 bg-white/[0.035] p-4">
              <div className="mb-4 flex items-center gap-3">
                <span className="h-3 w-3 rounded-full" style={{ backgroundColor: activeSignal.color }} />
                <div className="min-w-0">
                  <h3 className="truncate text-lg font-semibold text-white">{activeSignal.title}</h3>
                  <p className="mt-1 font-mono text-[11px] uppercase text-haze">{activeSignal.meta}</p>
                </div>
              </div>
              {typeof activeSignal.value === "number" && <p className="mb-3 text-3xl font-semibold text-white">{formatPercent(activeSignal.value)}</p>}
              <p className="text-sm leading-6 text-haze">{activeSignal.body}</p>
            </div>
          </div>

          <div className="rounded-md border border-white/10 bg-black/25 p-4">
            <p className="font-mono text-xs uppercase text-signal">Top flows</p>
            <div className="mt-4 grid gap-3">
              {flowRows.length ? (
                flowRows.slice(0, 7).map((flow, index) => (
                  <button
                    key={`${flow.origin_code}-${flow.target_code}-${index}`}
                    type="button"
                    onClick={() =>
                      setSelectedSignal({
                        title: `${flow.origin_code || flow.origin_name} -> ${flow.target_code || flow.target_name}`,
                        meta: "Origin to target flow",
                        body: `${flow.origin_name} to ${flow.target_name} represents ${formatPercent(flow.value)} of the returned Layer 7 attack flow share.`,
                        value: flow.value,
                        color: attackPalette[index % attackPalette.length],
                      })
                    }
                    className="grid gap-2 rounded-md border border-white/10 bg-white/[0.035] px-3 py-2 text-left transition hover:border-signal/35 hover:bg-white/[0.06]"
                  >
                    <span className="flex items-center justify-between gap-3 text-sm text-white">
                      <span className="font-mono font-bold">
                        {flow.origin_code || graphShortLabel(undefined, flow.origin_name)} {"->"} {flow.target_code || graphShortLabel(undefined, flow.target_name)}
                      </span>
                      <span className="font-mono text-xs text-haze">{formatPercent(flow.value)}</span>
                    </span>
                    <span className="h-1.5 overflow-hidden rounded-full bg-white/10">
                      <span
                        className="block h-full rounded-full"
                        style={{
                          width: `${Math.max(5, (flow.value / maxFlow) * 100)}%`,
                          backgroundColor: attackPalette[index % attackPalette.length],
                        }}
                      />
                    </span>
                  </button>
                ))
              ) : (
                <p className="rounded-md border border-white/10 bg-black/20 p-4 text-sm text-haze">Flow pairs unavailable from Radar for this filter.</p>
              )}
            </div>
          </div>

          <LocationRankList title={mode === "targets" ? "Top targets" : "Top sources"} data={topRanking} />
        </div>
      </div>
    </div>
  );
}

function AttackFlowDiagram({ data }: { data: AttackFlowPoint[] }) {
  const rows = data.slice(0, 6);
  const max = Math.max(...rows.map((point) => point.value), 1);

  if (!rows.length) {
    return (
      <div className="flex min-h-[220px] items-center justify-center rounded-lg border border-white/10 bg-black/20 text-sm text-haze">
        Attack flow data unavailable.
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-white/10 bg-black/20 p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <p className="font-mono text-xs uppercase text-signal">Attacks by flow</p>
        <span className="rounded-md border border-white/10 bg-white/[0.04] px-3 py-1.5 font-mono text-xs uppercase text-haze">Source {"->"} Target</span>
      </div>
      <div className="grid gap-2">
        {rows.map((flow, index) => {
          const color = attackPalette[index % attackPalette.length];

          return (
            <div key={`${flow.origin_code}-${flow.target_code}-${index}`} className="grid gap-2 rounded-md border border-white/10 bg-white/[0.035] px-3 py-2.5">
              <div className="grid grid-cols-[52px_minmax(0,1fr)_52px_auto] items-center gap-3 text-sm">
                <span className="rounded bg-white/10 px-2 py-1 text-center font-mono font-bold text-white">{flow.origin_code || flow.origin_name.slice(0, 3)}</span>
                <span className="relative h-2 overflow-hidden rounded-full bg-white/10">
                  <span className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${Math.max(7, (flow.value / max) * 100)}%`, backgroundColor: color }} />
                </span>
                <span className="rounded bg-white/10 px-2 py-1 text-center font-mono font-bold text-white">{flow.target_code || flow.target_name.slice(0, 3)}</span>
                <span className="font-mono text-xs text-haze">{formatPercent(flow.value)}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ApplicationLayerSecurityPanel({
  geography,
  mode,
  scopeLabel,
  controls,
  overview,
  onModeChange,
}: {
  geography: NonNullable<RadarDashboard["attack_geography"]>;
  mode: AttackGeoTab;
  scopeLabel: string;
  controls?: ReactNode;
  overview?: ReactNode;
  onModeChange: (mode: AttackGeoTab) => void;
}) {
  return (
    <Panel eyebrow="Application layer security" title={`Application Layer Security / ${scopeLabel}`}>
      <div className="grid gap-4 lg:grid-cols-[230px_minmax(0,1fr)] 2xl:grid-cols-[260px_minmax(0,1fr)]">
        {overview ? <div className="min-w-0">{overview}</div> : null}
        <div className="min-w-0">
          <WorldAttackMap
            mode={mode}
            origins={geography.origins}
            targets={geography.targets}
            flows={geography.flows}
            flowMode={geography.flow_mode}
            flowScopeNote={geography.flow_scope_note}
            controls={controls}
            onModeChange={onModeChange}
          />
        </div>
      </div>
      <p className="mt-4 rounded-md border border-white/10 bg-black/20 px-4 py-3 text-sm leading-6 text-haze">
        Attack flow data is aggregated Cloudflare Radar Layer 7 geography. It is not live traffic against this portfolio website.
      </p>
    </Panel>
  );
}

function AttackFlowBars({ data }: { data: AttackFlowPoint[] }) {
  const max = Math.max(...data.map((point) => point.value), 1);

  if (!data.length) {
    return (
      <div className="flex min-h-[260px] items-center justify-center rounded-lg border border-white/10 bg-black/20 text-sm text-haze">
        Attack flow data unavailable.
      </div>
    );
  }

  return (
    <div className="grid gap-3 rounded-lg border border-white/10 bg-black/20 p-4">
      {data.map((flow, index) => (
        <div key={`${flow.origin_code}-${flow.target_code}-${index}`} className="grid gap-2">
          <div className="flex flex-col gap-2 text-sm sm:flex-row sm:items-center sm:justify-between">
            <span className="flex min-w-0 flex-wrap items-center gap-2 text-white">
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded border border-trace/30 bg-trace/10 font-mono text-[11px] text-trace">
                {flow.rank || index + 1}
              </span>
              <span className="truncate">
                {flow.origin_name}
                {flow.origin_code ? <span className="ml-2 font-mono text-xs uppercase text-haze">{flow.origin_code}</span> : null}
              </span>
              <ArrowRight className="text-signal" size={16} />
              <span className="truncate">
                {flow.target_name}
                {flow.target_code ? <span className="ml-2 font-mono text-xs uppercase text-haze">{flow.target_code}</span> : null}
              </span>
            </span>
            <span className="font-mono text-xs text-haze">{formatCompact(flow.value)}%</span>
          </div>
          <div className="h-3 overflow-hidden rounded-full bg-white/10">
            <div className="h-full rounded-full bg-gradient-to-r from-trace via-signal to-cyan-300" style={{ width: `${Math.max(5, (flow.value / max) * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function SignalOverviewPanel({
  data,
  severity,
  severityClass,
}: {
  data: RadarDashboard;
  severity: string;
  severityClass: string;
}) {
  return (
    <aside className="grid gap-3">
      <div className={`rounded-lg border p-3 ${severityClass}`}>
        <p className="font-mono text-[11px] uppercase">Signal severity</p>
        <p className="mt-1 text-2xl font-semibold text-white">{severity}</p>
        <p className="mt-2 text-xs leading-5 text-haze">Aggregated Layer 7 trend movement and attack context.</p>
      </div>

      <section className="rounded-lg border border-white/10 bg-black/20 p-3">
        <p className="font-mono text-[11px] uppercase text-signal">Mitigation mix</p>
        <h3 className="mt-1 text-sm font-semibold text-white">Application attack type split</h3>
        <div className="mt-3">
          <DonutChart data={data.layer7_mitigation_mix || []} centerLabel="Lead attack" compact />
        </div>
      </section>

      <section className="rounded-lg border border-white/10 bg-black/20 p-3">
        <p className="font-mono text-[11px] uppercase text-signal">Traffic classification</p>
        <h3 className="mt-1 text-sm font-semibold text-white">Bot vs human split</h3>
        <div className="mt-3">
          <DonutChart data={data.bot_human} centerLabel="Bot share" compact />
        </div>
      </section>
    </aside>
  );
}

function Panel({ title, eyebrow, children }: { title: string; eyebrow: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5 md:p-6">
      <p className="font-mono text-xs uppercase text-signal">{eyebrow}</p>
      <h2 className="mt-2 text-2xl font-semibold text-white">{title}</h2>
      <div className="mt-5">{children}</div>
    </section>
  );
}

export function GlobalThreatDashboardPage() {
  const [data, setData] = useState<RadarDashboard | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [range, setRange] = useState<RangeKey>("24h");
  const [attackGeoTab, setAttackGeoTab] = useState<AttackGeoTab>("origins");
  const [scopeKey, setScopeKey] = useState<RadarScopeKey>("worldwide");
  const [scopeQuery, setScopeQuery] = useState("");
  const [scopeOpen, setScopeOpen] = useState(false);
  const [selectedPoint, setSelectedPoint] = useState<number | null>(null);
  const [selectedHttpPoint, setSelectedHttpPoint] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const params = new URLSearchParams({
      range,
      scope: scopeKey,
      scopeLabel: selectedScope(scopeKey).label,
    });

    setLoading(true);
    setError("");

    fetch(`/api/radar-dashboard?${params.toString()}`, {
      cache: "no-store",
      headers: {
        Accept: "application/json",
      },
    })
      .then((response) => readJson<RadarDashboard>(response))
      .then((dashboard) => {
        if (!cancelled) setData(dashboard);
      })
      .catch(() => {
        if (!cancelled) setError("Threat data temporarily unavailable.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [range, scopeKey]);

  const activeTrend = data?.layer7_trend || [];
  const activeTrendPoint = selectedPoint !== null ? activeTrend[selectedPoint] : lastItem(activeTrend);
  const attackGeography = data?.attack_geography || { origins: [], targets: [], flows: [] };
  const scope = selectedScope(scopeKey);
  const ScopeIcon = scope.icon;
  const scopeGroups = groupedScopeOptions(scopeQuery);
  const insights = data ? buildAnalystInsights(data) : [];
  const severity =
    Math.abs(trendDelta(data?.layer7_trend || []) || 0) >= 20
      ? "Elevated"
      : Math.abs(trendDelta(data?.layer7_trend || []) || 0) >= 8
        ? "Watch"
        : "Normal";
  const severityClass =
    severity === "Elevated"
      ? "border-trace/40 bg-trace/10 text-trace"
      : severity === "Watch"
        ? "border-volt/40 bg-volt/10 text-volt"
        : "border-cyan-300/35 bg-cyan-400/10 text-cyan-100";
  const dashboardControls = (
    <div className="grid gap-3 rounded-md border border-white/10 bg-black/25 p-3 lg:grid-cols-[minmax(220px,1fr)_auto] lg:items-end">
      <div className="relative">
        <p className="mb-2 font-mono text-[11px] uppercase text-haze">Radar scope</p>
        <button
          type="button"
          onClick={() => setScopeOpen((open) => !open)}
          className="flex w-full items-center justify-between gap-3 rounded-md border border-signal/35 bg-black/35 px-3 py-2.5 text-left text-white transition hover:border-signal/70"
        >
          <span className="flex min-w-0 items-center gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-signal/30 bg-signal/10 text-signal">
              <ScopeIcon size={17} />
            </span>
            <span className="min-w-0">
              <span className="block truncate text-sm font-semibold">{scope.label}</span>
              <span className="mt-0.5 block truncate font-mono text-[11px] uppercase text-haze">{scope.meta}</span>
            </span>
          </span>
          <ChevronDown className={`shrink-0 text-signal transition ${scopeOpen ? "rotate-180" : ""}`} size={18} />
        </button>

        {scopeOpen && (
          <div className="absolute left-0 right-0 top-full z-30 mt-2 overflow-hidden rounded-lg border border-white/15 bg-[#0b0b0b] shadow-[0_18px_60px_rgba(0,0,0,0.7)]">
            <label className="relative block border-b border-white/10">
              <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-haze" size={16} />
              <input
                value={scopeQuery}
                onChange={(event) => setScopeQuery(event.target.value)}
                className="w-full bg-white/[0.04] py-3 pl-10 pr-3 text-sm text-white outline-none placeholder:text-haze/50 focus:bg-signal/10"
                placeholder="Search continents, countries, ASNs"
              />
            </label>
            <div className="max-h-80 overflow-y-auto py-2">
              {scopeGroups.map(({ group, options, total }) =>
                options.length > 0 ? (
                  <div key={group}>
                    <div className="sticky top-0 z-10 flex items-center gap-2 bg-white/[0.08] px-4 py-2 font-mono text-[11px] uppercase text-haze">
                      {group}
                      <span className="rounded-full bg-white/15 px-2 py-0.5 text-white">{total}</span>
                    </div>
                    {options.map((option) => {
                      const Icon = option.icon;

                      return (
                        <button
                          key={option.key}
                          type="button"
                          onClick={() => {
                            setScopeKey(option.key);
                            setScopeOpen(false);
                            setScopeQuery("");
                            setSelectedPoint(null);
                            setSelectedHttpPoint(null);
                          }}
                          className={`flex w-full items-center gap-3 px-4 py-3 text-left text-sm transition hover:bg-white/10 ${
                            option.key === scopeKey ? "bg-signal/15 text-signal" : "text-white"
                          }`}
                        >
                          <Icon size={16} className="shrink-0" />
                          <span className="min-w-0">
                            <span className="block truncate font-semibold">{option.label}</span>
                            <span className="mt-0.5 block truncate font-mono text-[11px] uppercase text-haze">{option.meta}</span>
                          </span>
                        </button>
                      );
                    })}
                  </div>
                ) : null,
              )}
            </div>
          </div>
        )}
      </div>

      <div>
        <p className="mb-2 font-mono text-[11px] uppercase text-haze">Time range</p>
        <div className="grid grid-cols-3 gap-2 lg:min-w-56">
          {rangeOptions.map((option) => (
            <button
              key={option.key}
              type="button"
              onClick={() => {
                setRange(option.key);
                setSelectedPoint(null);
                setSelectedHttpPoint(null);
              }}
              className={`rounded-md border px-4 py-2 text-sm font-semibold transition ${
                range === option.key ? "border-signal/70 bg-signal text-obsidian" : "border-white/10 bg-black/20 text-haze hover:border-signal/40 hover:text-white"
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );

  return (
    <div className="radar-dashboard relative min-h-screen px-5 py-6">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_12%,rgba(252,238,10,0.14),transparent_28%),radial-gradient(circle_at_84%_18%,rgba(255,42,61,0.12),transparent_24%)]" aria-hidden="true" />
      <nav className="relative z-10 mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 rounded-lg border border-white/10 bg-obsidian/80 px-4 py-3">
        <a href="/" className="inline-flex items-center gap-2 text-sm font-semibold uppercase text-white transition hover:text-signal">
          <ArrowLeft size={16} />
          Home
        </a>
        <span className="font-mono text-xs uppercase text-signal">Global threat dashboard</span>
      </nav>

      <div className="relative z-10 mx-auto grid max-w-7xl gap-5 py-6 md:py-8 2xl:gap-6 2xl:py-10">
        <header className="rounded-lg border border-white/10 bg-obsidian/80 p-4 md:p-5 2xl:p-6">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="font-mono text-xs uppercase text-signal">Application-layer attack telemetry</p>
              <h1 className="mt-2 max-w-4xl text-3xl font-semibold leading-tight text-white md:text-4xl 2xl:text-5xl">
                Global Threat Dashboard.
              </h1>
              <p className="mt-3 max-w-3xl text-base leading-7 text-haze">
                A view of Layer 7 attack volume, mitigation mix, source countries, target countries, and attack flows.
              </p>
            </div>
            <div className="rounded-md border border-signal/25 bg-signal/10 px-3 py-2 text-xs leading-5 text-haze lg:max-w-xs">
              <div className="mb-1 flex items-center gap-2 font-mono text-[11px] uppercase text-signal">
                <ShieldAlert size={16} />
                Aggregated signal only
              </div>
              This dashboard uses aggregated Cloudflare Radar data, not individual live attack events.
            </div>
          </div>
        </header>

        <div className="grid gap-6">
            {loading && (
              <div className="grid min-h-[360px] place-items-center rounded-lg border border-white/10 bg-white/[0.04] p-8 text-center">
                <div>
                  <Loader2 className="mx-auto animate-spin text-signal" size={34} />
                  <p className="mt-4 font-mono text-xs uppercase text-signal">Fetching Radar telemetry</p>
                  <p className="mt-2 text-haze">Building the dashboard from Cloudflare Radar.</p>
                </div>
              </div>
            )}

            {!loading && error && (
              <div className="rounded-lg border border-trace/40 bg-trace/10 p-6 text-trace shadow-trace">
                <div className="flex items-center gap-3">
                  <AlertTriangle size={22} />
                  <div>
                    <p className="font-mono text-xs uppercase">Radar provider unavailable</p>
                    <h2 className="mt-1 text-2xl font-semibold text-white">Threat data temporarily unavailable.</h2>
                  </div>
                </div>
              </div>
            )}

            {!loading && data && (
              <>
                {data.warnings.length > 0 && (
                  <div className="rounded-lg border border-volt/35 bg-volt/10 p-4 text-sm leading-6 text-haze">
                    <div className="mb-2 flex items-center gap-2 font-mono text-xs uppercase text-volt">
                      <AlertTriangle size={16} />
                      Partial Radar data
                    </div>
                    {data.warnings.join(" ")}
                  </div>
                )}

                <ApplicationLayerSecurityPanel
                  geography={attackGeography}
                  mode={attackGeoTab}
                  scopeLabel={data.filters?.scope_label || scope.label}
                  controls={dashboardControls}
                  overview={<SignalOverviewPanel data={data} severity={severity} severityClass={severityClass} />}
                  onModeChange={setAttackGeoTab}
                />

                <Panel eyebrow="Layer 7 attack volume" title={`Application attack trend / ${data.filters?.scope_label || scope.label}`}>
                  <LineChart data={activeTrend} tone="trace" compact selectedIndex={selectedPoint ?? Math.max(activeTrend.length - 1, 0)} onSelect={setSelectedPoint} />
                  <div className="mt-4 rounded-md border border-white/10 bg-black/20 p-4">
                    <p className="font-mono text-xs uppercase text-signal">Selected point</p>
                    <div className="mt-3 grid gap-3 sm:grid-cols-3">
                      <div>
                        <p className="font-mono text-[11px] uppercase text-haze">Metric</p>
                        <p className="mt-1 font-semibold text-white">Layer 7 attacks</p>
                      </div>
                      <div>
                        <p className="font-mono text-[11px] uppercase text-haze">Time</p>
                        <p className="mt-1 font-semibold text-white">{formatTime(activeTrendPoint?.timestamp)}</p>
                      </div>
                      <div>
                        <p className="font-mono text-[11px] uppercase text-haze">Index</p>
                        <p className="mt-1 font-semibold text-white">{formatCompact(activeTrendPoint?.value)}</p>
                      </div>
                    </div>
                  </div>
                </Panel>

                <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
                  <div className="mb-4 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                    <BarChart3 size={16} />
                    Analyst insights
                  </div>
                  <ul className="grid gap-2 md:grid-cols-2">
                    {insights.map((insight) => (
                      <li key={insight} className="leading-7 text-haze">
                        {insight}
                      </li>
                    ))}
                  </ul>
                </section>

                <details className="group rounded-lg border border-white/10 bg-white/[0.04] p-5">
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-3">
                    <span>
                      <span className="block font-mono text-xs uppercase text-signal">Baseline context</span>
                      <span className="mt-1 block text-xl font-semibold text-white">HTTP traffic background / {data.filters?.scope_label || scope.label}</span>
                    </span>
                    <ChevronDown className="shrink-0 text-signal transition group-open:rotate-180" size={20} />
                  </summary>
                  <div className="mt-5 grid gap-5 2xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]">
                    <div className="rounded-lg border border-white/10 bg-black/20 p-4">
                      <p className="mb-3 font-mono text-xs uppercase text-signal">All HTTP trend</p>
                      <LineChart
                        data={data.http_trend}
                        tone="signal"
                        compact
                        selectedIndex={selectedHttpPoint ?? Math.max((data.http_trend || []).length - 1, 0)}
                        onSelect={setSelectedHttpPoint}
                      />
                    </div>
                    <div className="rounded-lg border border-white/10 bg-black/20 p-4">
                      <p className="mb-3 font-mono text-xs uppercase text-signal">Top traffic locations</p>
                      <LocationBars data={data.top_locations} />
                    </div>
                  </div>
                </details>
              </>
            )}
          </div>
      </div>
    </div>
  );
}
