import {
  geoArea,
  geoCentroid,
  geoEquirectangular,
  geoPath,
  type GeoProjection,
} from "d3-geo";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import {
  AlertTriangle,
  ArrowLeft,
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
import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from "react";

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

type SourceAsPoint = {
  rank?: number;
  asn: string;
  as_number?: number | null;
  name: string;
  label: string;
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
  source_as_distribution?: {
    rows: SourceAsPoint[];
    scope_label: string;
    range_label: string;
    source: string;
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
type MapPan = {
  x: number;
  y: number;
};
type MapDragState = {
  pointerId: number;
  startX: number;
  startY: number;
  panX: number;
  panY: number;
};

const mapWidth = 1500;
const mapHeight = 1000;
const minMapZoom = 1.5;
const defaultMapZoom = 1.5;
const maxMapZoom = 3.5;
const mapZoomStep = 0.5;
const effectiveMapZoomFor = (zoom: number) => zoom;
const maxValidCountryArea = Math.PI * 2;
const continentNames: Record<string, string> = {
  AF: "Africa",
  AS: "Asia",
  EU: "Europe",
  NA: "North America",
  OC: "Oceania",
  SA: "South America",
};

function reverseLinearRing<T>(ring: T[]) {
  return [...ring].reverse();
}

function reverseWorldGeometry(geometry: Geometry): Geometry {
  switch (geometry.type) {
    case "Polygon":
      return {
        ...geometry,
        coordinates: geometry.coordinates.map(reverseLinearRing),
      };
    case "MultiPolygon":
      return {
        ...geometry,
        coordinates: geometry.coordinates.map((polygon) => polygon.map(reverseLinearRing)),
      };
    case "GeometryCollection":
      return {
        ...geometry,
        geometries: geometry.geometries.map(reverseWorldGeometry),
      };
    default:
      return geometry;
  }
}

function normalizeWorldFeature(feature: WorldFeature): WorldFeature {
  // Some small territories can be wound as the spherical complement, which d3
  // renders as a whole-world country fill. Flip only impossible country areas.
  return geoArea(feature) > maxValidCountryArea
    ? {
        ...feature,
        geometry: reverseWorldGeometry(feature.geometry),
      }
    : feature;
}
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
  const topSourceAs = data.source_as_distribution?.rows?.[0];
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

  if (topSourceAs) {
    insights.push(`Top source AS in the Layer 7 distribution: ${topSourceAs.asn} ${topSourceAs.name} at ${formatPercent(topSourceAs.value)}.`);
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

function clampMapPan(pan: MapPan, zoom: number): MapPan {
  const maxX = Math.max(0, (mapWidth * zoom - mapWidth) / 2);
  const maxY = Math.max(0, (mapHeight * zoom - mapHeight) / 2);

  return {
    x: Math.min(maxX, Math.max(-maxX, pan.x)),
    y: Math.min(maxY, Math.max(-maxY, pan.y)),
  };
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

type SourceAsTreemapCell = SourceAsPoint & {
  x: number;
  y: number;
  width: number;
  height: number;
  color: string;
};

function sourceAsDisplayName(row: SourceAsPoint) {
  return `${row.asn} ${row.name}`.trim();
}

function layoutTreemapRows(rows: SourceAsPoint[], x: number, y: number, width: number, height: number, depth = 0): SourceAsTreemapCell[] {
  if (!rows.length) return [];
  if (rows.length === 1) {
    return [{ ...rows[0], x, y, width, height, color: attackPalette[depth % attackPalette.length] }];
  }

  const total = rows.reduce((sum, row) => sum + Math.max(row.value, 0), 0) || 1;
  let cursor = 0;
  let splitIndex = 1;

  for (let index = 0; index < rows.length - 1; index += 1) {
    cursor += Math.max(rows[index].value, 0);
    splitIndex = index + 1;
    if (cursor >= total / 2) break;
  }

  const first = rows.slice(0, splitIndex);
  const second = rows.slice(splitIndex);
  const firstTotal = first.reduce((sum, row) => sum + Math.max(row.value, 0), 0);
  const ratio = Math.min(0.82, Math.max(0.18, firstTotal / total));

  if (width >= height) {
    const firstWidth = width * ratio;
    return [...layoutTreemapRows(first, x, y, firstWidth, height, depth), ...layoutTreemapRows(second, x + firstWidth, y, width - firstWidth, height, depth + 1)];
  }

  const firstHeight = height * ratio;
  return [...layoutTreemapRows(first, x, y, width, firstHeight, depth), ...layoutTreemapRows(second, x, y + firstHeight, width, height - firstHeight, depth + 1)];
}

function sourceAsTreemapCells(rows: SourceAsPoint[]) {
  const visible = rows.slice(0, 20);
  const hidden = rows.slice(20);
  const hiddenTotal = hidden.reduce((sum, row) => sum + row.value, 0);
  const treemapRows =
    hiddenTotal > 0
      ? [
          ...visible,
          {
            rank: visible.length + 1,
            asn: "Other",
            name: `${hidden.length} smaller source ASes`,
            label: "Other source ASes",
            value: Number(hiddenTotal.toFixed(2)),
          },
        ]
      : visible;

  return layoutTreemapRows(treemapRows, 0, 0, 100, 100);
}

function SourceAsDistributionPanel({ data, scopeLabel }: { data?: RadarDashboard["source_as_distribution"]; scopeLabel: string }) {
  const rows = data?.rows || [];
  const cells = sourceAsTreemapCells(rows);
  const maxValue = Math.max(...rows.map((row) => row.value), 1);
  const topRows = rows.slice(0, 6);

  return (
    <Panel eyebrow="Source AS distribution" title={`Application layer DDoS source AS distribution / ${scopeLabel}`}>
      <div className="mb-4 flex flex-col gap-3 text-sm leading-6 text-haze lg:flex-row lg:items-center lg:justify-between">
        <p>Share of application-layer attack source autonomous systems from Cloudflare Radar.</p>
        <a
          href="https://radar.cloudflare.com/reports"
          target="_blank"
          rel="noreferrer"
          className="inline-flex w-fit items-center rounded-md border border-signal/30 bg-signal/10 px-3 py-2 font-mono text-xs uppercase text-signal transition hover:border-signal/70 hover:bg-signal/15"
        >
          Read latest DDoS report
        </a>
      </div>

      {!rows.length ? (
        <div className="grid min-h-[260px] place-items-center rounded-lg border border-white/10 bg-black/25 p-6 text-center text-haze">
          <div>
            <Network className="mx-auto text-signal" size={28} />
            <p className="mt-3 font-semibold text-white">Source AS distribution unavailable.</p>
            <p className="mt-2 text-sm">Radar did not return source AS rows for this scope and time range.</p>
          </div>
        </div>
      ) : (
        <div className="grid gap-4 2xl:grid-cols-[minmax(0,1.35fr)_360px]">
          <div className="rounded-lg border border-white/10 bg-black/30 p-3">
            <div className="relative h-[420px] overflow-hidden rounded-md border border-white/10 bg-[#07100d] shadow-[inset_0_0_55px_rgba(103,232,249,0.06)]">
              {cells.map((cell, index) => {
                const compact = cell.width < 13 || cell.height < 12;
                const tiny = cell.width < 8 || cell.height < 8;

                return (
                  <button
                    key={`${cell.asn}-${cell.name}-${index}`}
                    type="button"
                    className="absolute overflow-hidden border border-black/70 p-2 text-left transition hover:z-10 hover:scale-[1.015] hover:border-signal/60 focus:z-10 focus:outline-none focus:ring-2 focus:ring-signal"
                    style={{
                      left: `${cell.x}%`,
                      top: `${cell.y}%`,
                      width: `${cell.width}%`,
                      height: `${cell.height}%`,
                      background: `linear-gradient(135deg, ${cell.color}d9, rgba(213,255,218,0.68))`,
                      color: "#020403",
                    }}
                    title={`${sourceAsDisplayName(cell)}: ${formatPercent(cell.value)}`}
                  >
                    {!tiny && (
                      <span className="flex h-full flex-col justify-center">
                        <span className={`block font-semibold leading-tight ${compact ? "text-xs" : "text-lg"}`}>{cell.asn}</span>
                        {!compact && <span className="mt-1 line-clamp-2 text-xs font-medium leading-tight">{cell.name}</span>}
                        <span className={`mt-1 font-mono font-semibold ${compact ? "text-[10px]" : "text-xs"}`}>{formatPercent(cell.value)}</span>
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
            <div className="mt-3 grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 font-mono text-xs text-haze">
              <span>0%</span>
              <span className="h-3 rounded-full bg-gradient-to-r from-[#dff8db] via-[#67e8f9] to-[#0f4c93]" />
              <span>{formatPercent(maxValue)}</span>
            </div>
          </div>

          <div className="grid content-start gap-2 rounded-lg border border-white/10 bg-black/25 p-4">
            <p className="font-mono text-xs uppercase text-signal">Top source ASes</p>
            {topRows.map((row, index) => (
              <div key={`${row.asn}-${row.name}`} className="grid gap-2 rounded-md border border-white/10 bg-white/[0.035] px-3 py-2">
                <div className="flex items-start justify-between gap-3">
                  <span className="min-w-0">
                    <span className="block font-semibold text-white">{row.asn}</span>
                    <span className="mt-0.5 block truncate text-xs text-haze">{row.name}</span>
                  </span>
                  <span className="font-mono text-xs text-haze">{formatPercent(row.value)}</span>
                </div>
                <span className="h-1.5 overflow-hidden rounded-full bg-white/10">
                  <span className="block h-full rounded-full" style={{ width: `${Math.max(5, (row.value / maxValue) * 100)}%`, backgroundColor: attackPalette[index % attackPalette.length] }} />
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Panel>
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
  const normalizedFeatures = useMemo(() => features.map(normalizeWorldFeature), [features]);
  const reducedMotion = useReducedMotionPreference();
  const [selectedSignal, setSelectedSignal] = useState<GraphSignal | null>(null);
  const [mapZoom, setMapZoom] = useState(defaultMapZoom);
  const [mapPan, setMapPan] = useState<MapPan>({ x: 0, y: 0 });
  const [isDraggingMap, setIsDraggingMap] = useState(false);
  const mapDragRef = useRef<MapDragState | null>(null);
  const featureCollection = useMemo<WorldFeatureCollection>(
    () => ({ type: "FeatureCollection", features: normalizedFeatures }) as WorldFeatureCollection,
    [normalizedFeatures],
  );
  const projection = useMemo(() => {
    const base = geoEquirectangular().precision(0.1);
    if (!normalizedFeatures.length) return base.scale(232).translate([mapWidth / 2, mapHeight / 2]);
    return base.fitExtent([[42, 132], [mapWidth - 42, mapHeight - 132]], featureCollection as never);
  }, [featureCollection, normalizedFeatures.length]);
  const pathGenerator = useMemo(() => geoPath(projection), [projection]);
  const countryPaths = useMemo(
    () =>
      normalizedFeatures
        .map((feature, index) => ({
          id: `${feature.id || feature.properties?.name || "country"}-${index}`,
          name: feature.properties?.name,
          path: pathGenerator(feature as never),
        }))
        .filter((item): item is { id: string; name: string | undefined; path: string } => typeof item.path === "string" && item.path.length > 0),
    [normalizedFeatures, pathGenerator],
  );
  const featureLookup = useMemo(() => buildFeatureLookup(normalizedFeatures), [normalizedFeatures]);
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
  const edgeOpacity = mode === "flows" ? 0.86 : 0.42;
  const effectiveMapZoom = effectiveMapZoomFor(mapZoom);
  const zoomOffsetX = (mapWidth - mapWidth * effectiveMapZoom) / 2;
  const zoomOffsetY = (mapHeight - mapHeight * effectiveMapZoom) / 2;
  const mapTransform = `translate(${zoomOffsetX + mapPan.x} ${zoomOffsetY + mapPan.y}) scale(${effectiveMapZoom})`;
  const showCompactCodes = effectiveMapZoom >= 1.65;
  const zoomedMarkerOuterRadius = 5.5 / effectiveMapZoom;
  const zoomedMarkerInnerRadius = 2.55 / effectiveMapZoom;
  const zoomedUnconnectedOuterRadius = 4 / effectiveMapZoom;
  const zoomedUnconnectedInnerRadius = 1.9 / effectiveMapZoom;
  const zoomedMarkerStroke = 1.8 / effectiveMapZoom;
  const zoomedPacketRadius = (width: number) => Math.max(2.1, Math.min(4.4, width / 3.2)) / effectiveMapZoom;
  const zoomedEdgeWidth = (width: number) => Math.max(1.85, width * 1.08) / Math.sqrt(effectiveMapZoom);
  const zoomedEdgeHaloWidth = (width: number) => Math.max(4.2, width * 1.85) / Math.sqrt(effectiveMapZoom);
  const zoomLabel = `${mapZoom.toFixed(mapZoom % 1 === 0 ? 0 : 1)}x`;
  const zoomIn = () =>
    setMapZoom((current) => {
      const next = Math.min(maxMapZoom, Number((current + mapZoomStep).toFixed(2)));
      setMapPan((pan) => clampMapPan(pan, effectiveMapZoomFor(next)));
      return next;
    });
  const zoomOut = () =>
    setMapZoom((current) => {
      const next = Math.max(minMapZoom, Number((current - mapZoomStep).toFixed(2)));
      setMapPan((pan) => clampMapPan(pan, effectiveMapZoomFor(next)));
      return next;
    });
  const resetZoom = () => {
    setMapZoom(defaultMapZoom);
    setMapPan({ x: 0, y: 0 });
  };
  const isMapReset = mapZoom === defaultMapZoom && mapPan.x === 0 && mapPan.y === 0;
  const svgPointFromPointer = (event: ReactPointerEvent<SVGSVGElement>) => {
    const point = event.currentTarget.createSVGPoint();
    const matrix = event.currentTarget.getScreenCTM();
    point.x = event.clientX;
    point.y = event.clientY;

    if (!matrix) return { x: point.x, y: point.y };
    const transformed = point.matrixTransform(matrix.inverse());
    return { x: transformed.x, y: transformed.y };
  };
  const handleMapPointerDown = (event: ReactPointerEvent<SVGSVGElement>) => {
    if (event.button !== 0) return;
    const point = svgPointFromPointer(event);
    mapDragRef.current = {
      pointerId: event.pointerId,
      startX: point.x,
      startY: point.y,
      panX: mapPan.x,
      panY: mapPan.y,
    };
    setIsDraggingMap(true);
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const handleMapPointerMove = (event: ReactPointerEvent<SVGSVGElement>) => {
    const drag = mapDragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    const point = svgPointFromPointer(event);
    setMapPan(
      clampMapPan(
        {
          x: drag.panX + point.x - drag.startX,
          y: drag.panY + point.y - drag.startY,
        },
        effectiveMapZoom,
      ),
    );
  };
  const stopMapDrag = (event: ReactPointerEvent<SVGSVGElement>) => {
    const drag = mapDragRef.current;
    if (drag?.pointerId === event.pointerId && event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    mapDragRef.current = null;
    setIsDraggingMap(false);
  };

  useEffect(() => {
    setSelectedSignal(null);
  }, [mode, origins, targets, flows]);

  useEffect(() => {
    setMapZoom(defaultMapZoom);
    setMapPan({ x: 0, y: 0 });
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
        <div className="relative overflow-hidden rounded-md border border-white/10 bg-[#020304] shadow-[inset_0_0_0_1px_rgba(252,238,10,0.03),0_18px_70px_rgba(0,0,0,0.35)]">
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
              disabled={isMapReset}
              className="grid h-9 w-9 place-items-center text-haze transition hover:bg-white/10 hover:text-white disabled:cursor-not-allowed disabled:opacity-35"
              aria-label="Reset map zoom and position"
            >
              <RotateCcw size={14} />
            </button>
          </div>
          <svg
            viewBox={`0 0 ${mapWidth} ${mapHeight}`}
            className={`h-[310px] w-full touch-none select-none sm:h-[360px] lg:h-[420px] 2xl:h-[480px] ${isDraggingMap ? "cursor-grabbing" : "cursor-grab"}`}
            preserveAspectRatio="xMidYMid meet"
            role="img"
            aria-label="World map showing Layer 7 attack source and target flows"
            onPointerDown={handleMapPointerDown}
            onPointerMove={handleMapPointerMove}
            onPointerUp={stopMapDrag}
            onPointerCancel={stopMapDrag}
            onPointerLeave={(event) => {
              if (mapDragRef.current) stopMapDrag(event);
            }}
          >
            <defs>
              <linearGradient id="world-map-ocean" x1="0" x2="1" y1="0" y2="1">
                <stop offset="0%" stopColor="#000000" />
                <stop offset="52%" stopColor="#010303" />
                <stop offset="100%" stopColor="#000000" />
              </linearGradient>
              <linearGradient id="world-land-fill" x1="0" x2="1" y1="0" y2="1">
                <stop offset="0%" stopColor="#8f9796" />
                <stop offset="54%" stopColor="#7d8584" />
                <stop offset="100%" stopColor="#697170" />
              </linearGradient>
              <radialGradient id="world-map-glow" cx="50%" cy="50%" r="72%">
                <stop offset="0%" stopColor="#fcee0a" stopOpacity="0.018" />
                <stop offset="45%" stopColor="#67e8f9" stopOpacity="0.02" />
                <stop offset="100%" stopColor="#050608" stopOpacity="0" />
              </radialGradient>
              <filter id="world-marker-glow">
                <feDropShadow dx="0" dy="0" stdDeviation="4.2" floodColor="rgba(252,238,10,0.38)" />
                <feDropShadow dx="0" dy="0" stdDeviation="5.5" floodColor="rgba(103,232,249,0.38)" />
              </filter>
            </defs>
            <rect width={mapWidth} height={mapHeight} fill="url(#world-map-ocean)" />
            <rect width={mapWidth} height={mapHeight} fill="url(#world-map-glow)" />
            {[0, 1, 2, 3, 4, 5].map((line) => (
              <line key={`map-h-${line}`} x1="34" x2={mapWidth - 34} y1={130 + line * 118} y2={130 + line * 118} stroke="rgba(252,238,10,0.018)" strokeDasharray="3 12" />
            ))}
            {[0, 1, 2, 3, 4, 5, 6, 7].map((line) => (
              <line key={`map-v-${line}`} x1={82 + line * 190} x2={82 + line * 190} y1="46" y2={mapHeight - 46} stroke="rgba(103,232,249,0.016)" strokeDasharray="3 12" />
            ))}

            <g transform={mapTransform}>
              {countryPaths.length ? (
                <g>
                  {countryPaths.map((country) => (
                    <path
                      key={country.id}
                      d={country.path}
                      fill="url(#world-land-fill)"
                      fillRule="evenodd"
                      fillOpacity="0.98"
                      stroke="rgba(0,0,0,0.78)"
                      strokeWidth={Math.max(0.44, 0.95 / Math.sqrt(effectiveMapZoom))}
                    >
                      <title>{country.name}</title>
                    </path>
                  ))}
                </g>
              ) : (
                <text x={mapWidth / 2} y={mapHeight / 2} fill="#d7c99e" fontSize="14" textAnchor="middle">
                  Loading world map...
                </text>
              )}
              {countryPaths.length ? (
                <g pointerEvents="none">
                  {countryPaths.map((country) => (
                    <path
                      key={`border-${country.id}`}
                      d={country.path}
                      fill="none"
                      clipRule="evenodd"
                      stroke="rgba(0,0,0,0.68)"
                      strokeWidth={Math.max(0.62, 1.35 / Math.sqrt(effectiveMapZoom))}
                      strokeLinejoin="round"
                      strokeLinecap="round"
                    />
                  ))}
                </g>
              ) : null}

              {edges.map((edge) => (
                <path
                  key={`${edge.id}-halo`}
                  d={edge.path}
                  fill="none"
                  stroke={edge.color}
                  strokeLinecap="round"
                  strokeOpacity={mode === "flows" ? 0.2 : 0.12}
                  strokeWidth={zoomedEdgeHaloWidth(edge.width)}
                  filter="url(#world-marker-glow)"
                  pointerEvents="none"
                />
              ))}
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
                  filter={mode === "flows" ? "url(#world-marker-glow)" : undefined}
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
                edges.slice(0, 10).map((edge, index) => (
                  <circle key={`${edge.id}-packet`} r={zoomedPacketRadius(edge.width)} fill={edge.color} opacity={mode === "flows" ? "0.95" : "0.45"} filter="url(#world-marker-glow)">
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

                <SourceAsDistributionPanel data={data.source_as_distribution} scopeLabel={data.filters?.scope_label || scope.label} />

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
