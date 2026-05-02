import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  BarChart3,
  ChevronDown,
  Clipboard,
  Download,
  Globe2,
  Loader2,
  MapPin,
  Network,
  Radar,
  Search,
  ShieldAlert,
  Zap,
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
  value: number;
};

type AttackLocationPoint = {
  rank?: number;
  code?: string;
  name: string;
  value: number;
};

type AttackFlowPoint = {
  rank?: number;
  origin_code?: string;
  origin_name: string;
  target_code?: string;
  target_name: string;
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

type GeoJsonGeometry = {
  type: "Polygon" | "MultiPolygon";
  coordinates: number[][][] | number[][][][];
};

type GeoJsonFeature = {
  type: "Feature";
  geometry?: GeoJsonGeometry | null;
};

type GeoJsonCollection = {
  type: "FeatureCollection";
  features: GeoJsonFeature[];
};

const rangeOptions: Array<{ key: RangeKey; label: string }> = [
  { key: "24h", label: "24h" },
  { key: "7d", label: "7d" },
  { key: "30d", label: "30d" },
];

const attackGeoTabs: Array<{ key: AttackGeoTab; label: string }> = [
  { key: "origins", label: "Attack Origins" },
  { key: "targets", label: "Targeted Countries" },
  { key: "flows", label: "Origin -> Target Flows" },
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
    insights.push(`Top Layer 7 attack origin: ${topOrigin.name} at ${formatCompact(topOrigin.value)}% of observed attack origin share.`);
  }

  if (topTarget) {
    insights.push(`Most targeted country: ${topTarget.name} at ${formatCompact(topTarget.value)}% of observed target share.`);
  }

  if (topFlow) {
    insights.push(`Strongest country attack flow: ${topFlow.origin_name} -> ${topFlow.target_name} at ${formatCompact(topFlow.value)}%.`);
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
  selectedIndex,
  onSelect,
}: {
  data: TrendPoint[];
  tone?: "signal" | "trace";
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
      <svg viewBox={`0 0 ${width} ${height}`} className="h-60 w-full overflow-visible" role="img" aria-label="Radar time series chart">
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

function DonutChart({ data, centerLabel = "Top share" }: { data: SplitPoint[]; centerLabel?: string }) {
  const rows = data.length ? data.slice(0, 4) : [{ label: "Unavailable", value: 100 }];
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
    <div className="grid gap-5 rounded-lg border border-white/10 bg-black/20 p-4">
      <div
        className="relative mx-auto h-48 w-48 rounded-full"
        style={{
          background: `conic-gradient(${gradient})`,
          boxShadow: "0 0 38px rgba(252,238,10,0.12)",
        }}
      >
        <div className="absolute inset-5 grid place-items-center rounded-full border border-white/10 bg-obsidian text-center">
          <span className="font-mono text-xs uppercase text-haze">{centerLabel}</span>
          <span className="text-3xl font-semibold text-white">{formatPercent(lead.value)}</span>
        </div>
      </div>
      <div className="grid gap-3">
        {rows.map((row, index) => (
          <div key={row.label} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 rounded-md border border-white/10 bg-white/[0.035] px-4 py-3">
            <span className="flex min-w-0 items-center gap-3 text-sm leading-5 text-haze">
              <span className="h-3 w-3 shrink-0 rounded-full" style={{ backgroundColor: attackPalette[index % attackPalette.length] }} />
              <span className="min-w-0 break-words">{row.label}</span>
            </span>
            <span className="font-mono text-sm font-semibold text-white">{formatPercent(row.value)}</span>
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
            <span className="truncate text-white">
              {location.name}
              {location.code ? <span className="ml-2 font-mono text-xs uppercase text-haze">{location.code}</span> : null}
            </span>
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

const mapSize = { width: 920, height: 430 };

const countryGeo: Record<string, { lat: number; lon: number }> = {
  AR: { lat: -34.6, lon: -58.4 },
  AU: { lat: -35.3, lon: 149.1 },
  BE: { lat: 50.9, lon: 4.4 },
  BR: { lat: -15.8, lon: -47.9 },
  CA: { lat: 45.4, lon: -75.7 },
  CL: { lat: -33.4, lon: -70.7 },
  CN: { lat: 39.9, lon: 116.4 },
  CO: { lat: 4.7, lon: -74.1 },
  DE: { lat: 52.5, lon: 13.4 },
  EG: { lat: 30.0, lon: 31.2 },
  ES: { lat: 40.4, lon: -3.7 },
  FR: { lat: 48.9, lon: 2.4 },
  GB: { lat: 51.5, lon: -0.1 },
  HK: { lat: 22.3, lon: 114.2 },
  ID: { lat: -6.2, lon: 106.8 },
  IN: { lat: 28.6, lon: 77.2 },
  IR: { lat: 35.7, lon: 51.4 },
  IT: { lat: 41.9, lon: 12.5 },
  JP: { lat: 35.7, lon: 139.7 },
  KE: { lat: -1.3, lon: 36.8 },
  KR: { lat: 37.6, lon: 126.9 },
  MX: { lat: 19.4, lon: -99.1 },
  MY: { lat: 3.1, lon: 101.7 },
  NG: { lat: 9.1, lon: 7.5 },
  NL: { lat: 52.4, lon: 4.9 },
  NZ: { lat: -41.3, lon: 174.8 },
  PE: { lat: -12.0, lon: -77.0 },
  PH: { lat: 14.6, lon: 121.0 },
  PK: { lat: 33.7, lon: 73.1 },
  RU: { lat: 55.8, lon: 37.6 },
  SA: { lat: 24.7, lon: 46.7 },
  SG: { lat: 1.35, lon: 103.8 },
  TH: { lat: 13.8, lon: 100.5 },
  TR: { lat: 39.9, lon: 32.9 },
  US: { lat: 38.9, lon: -77.0 },
  VN: { lat: 21.0, lon: 105.8 },
  ZA: { lat: -25.7, lon: 28.2 },
};

const worldLandPaths = [
  "M72 142 C112 92 187 76 260 104 C285 116 310 137 339 133 C320 156 298 178 260 181 C228 184 218 204 203 224 C172 220 160 197 130 190 C104 183 84 165 72 142Z",
  "M302 220 C338 227 367 263 352 305 C337 350 319 393 287 397 C263 361 244 320 253 281 C260 250 275 227 302 220Z",
  "M421 127 C453 103 500 110 524 134 C506 151 470 160 433 151 C404 145 397 135 421 127Z",
  "M466 177 C516 184 552 232 544 294 C538 355 497 373 460 318 C434 278 430 224 466 177Z",
  "M516 127 C592 82 705 83 791 125 C838 148 869 190 846 226 C771 227 692 214 630 238 C585 226 552 203 513 196 C499 166 491 146 516 127Z",
  "M650 238 C696 237 749 266 768 304 C731 322 690 309 651 281Z",
  "M705 307 C758 290 820 316 845 355 C801 384 739 378 699 342Z",
  "M333 64 C374 43 421 53 433 87 C402 114 352 104 325 85Z",
];

let cachedWorldPaths: string[] | null = null;

function projectGeo(lat: number, lon: number) {
  return {
    x: ((lon + 180) / 360) * mapSize.width,
    y: ((85 - lat) / 170) * mapSize.height,
  };
}

function ringPath(ring: number[][]) {
  return ring
    .map((coordinate, index) => {
      const [lon, lat] = coordinate;
      const { x, y } = projectGeo(lat, lon);
      return `${index === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(" ")
    .concat(" Z");
}

function geometryPath(geometry: GeoJsonGeometry) {
  if (geometry.type === "Polygon") {
    return (geometry.coordinates as number[][][]).map(ringPath).join(" ");
  }

  if (geometry.type === "MultiPolygon") {
    return (geometry.coordinates as number[][][][]).flatMap((polygon) => polygon.map(ringPath)).join(" ");
  }

  return "";
}

function useWorldMapPaths() {
  const [paths, setPaths] = useState<string[]>(() => cachedWorldPaths || []);

  useEffect(() => {
    if (cachedWorldPaths) return;

    let cancelled = false;

    fetch("/world-countries.geojson", { cache: "force-cache" })
      .then((response) => (response.ok ? response.json() : Promise.reject(new Error("Map unavailable"))))
      .then((geojson: GeoJsonCollection) => {
        const generated = geojson.features
          .map((feature) => (feature.geometry ? geometryPath(feature.geometry) : ""))
          .filter(Boolean);

        if (!cancelled && generated.length) {
          cachedWorldPaths = generated;
          setPaths(generated);
        }
      })
      .catch(() => {
        if (!cancelled) setPaths([]);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return paths.length ? paths : worldLandPaths;
}

function mapPoint(code?: string, index = 0) {
  if (code && countryGeo[code]) {
    return projectGeo(countryGeo[code].lat, countryGeo[code].lon);
  }

  return { x: 115 + (index % 6) * 130, y: 120 + Math.floor(index / 6) * 70 };
}

function AttackLocationBars({ data, emptyLabel }: { data: AttackLocationPoint[]; emptyLabel: string }) {
  const max = Math.max(...data.map((point) => point.value), 1);

  if (!data.length) {
    return (
      <div className="flex min-h-[260px] items-center justify-center rounded-lg border border-white/10 bg-black/20 text-sm text-haze">
        {emptyLabel}
      </div>
    );
  }

  return (
    <div className="grid gap-3 rounded-lg border border-white/10 bg-black/20 p-4">
      {data.map((country, index) => (
        <div key={`${country.code}-${country.name}-${index}`} className="grid gap-2">
          <div className="flex items-center justify-between gap-3 text-sm">
            <span className="flex min-w-0 items-center gap-3">
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded border border-signal/30 bg-signal/10 font-mono text-[11px] text-signal">
                {country.rank || index + 1}
              </span>
              <span className="truncate text-white">
                {country.name}
                {country.code ? <span className="ml-2 font-mono text-xs uppercase text-haze">{country.code}</span> : null}
              </span>
            </span>
            <span className="font-mono text-xs text-haze">{formatCompact(country.value)}%</span>
          </div>
          <div className="h-3 overflow-hidden rounded-full bg-white/10">
            <div className="h-full rounded-full bg-gradient-to-r from-trace via-volt to-signal" style={{ width: `${Math.max(5, (country.value / max) * 100)}%` }} />
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

function AttackWorldMap({
  mode,
  origins,
  targets,
  flows,
  onModeChange,
}: {
  mode: AttackGeoTab;
  origins: AttackLocationPoint[];
  targets: AttackLocationPoint[];
  flows: AttackFlowPoint[];
  onModeChange: (mode: AttackGeoTab) => void;
}) {
  const points = mode === "targets" ? targets : origins;
  const mapPoints = mode === "flows" ? flowEndpointPoints(flows) : points;
  const maxValue = Math.max(...mapPoints.map((point) => point.value), ...flows.map((flow) => flow.value), 1);
  const mapTitle = mode === "targets" ? "Top attacks by target location" : mode === "flows" ? "Top attack country flows" : "Top attacks by source location";
  const worldPaths = useWorldMapPaths();

  return (
    <div className="overflow-hidden rounded-lg border border-white/10 bg-[#07090b] p-4">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="font-mono text-xs uppercase text-signal">{mapTitle}</p>
          <p className="mt-1 text-sm text-haze">Aggregated Layer 7 Radar geography</p>
        </div>
        <div className="flex items-center gap-2">
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
              {tab.key === "origins" ? "Source" : tab.key === "targets" ? "Target" : "Flow"}
            </button>
          ))}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <svg viewBox={`0 0 ${mapSize.width} ${mapSize.height}`} className="h-[360px] w-full rounded-md bg-black/45 md:h-[520px] xl:h-[560px]" role="img" aria-label="Projected world map showing Radar attack geography">
          <defs>
            <radialGradient id="map-radar-glow" cx="50%" cy="44%" r="70%">
              <stop offset="0%" stopColor="#67e8f9" stopOpacity="0.16" />
              <stop offset="100%" stopColor="#67e8f9" stopOpacity="0" />
            </radialGradient>
            <linearGradient id="attack-line" x1="0" x2="1">
              <stop offset="0%" stopColor="#f97316" stopOpacity="0.18" />
              <stop offset="50%" stopColor="#67e8f9" stopOpacity="0.58" />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.28" />
            </linearGradient>
          </defs>

          <rect width={mapSize.width} height={mapSize.height} fill="url(#map-radar-glow)" />
          {[0, 1, 2, 3, 4, 5].map((line) => (
            <line key={`v-${line}`} x1={100 + line * 140} x2={100 + line * 140} y1="44" y2="386" stroke="rgba(255,255,255,0.06)" strokeDasharray="4 10" />
          ))}
          {[0, 1, 2, 3, 4].map((line) => (
            <line key={`h-${line}`} x1="42" x2="880" y1={64 + line * 72} y2={64 + line * 72} stroke="rgba(255,255,255,0.06)" strokeDasharray="4 10" />
          ))}
          {[180, 260, 340].map((radius) => (
            <circle key={radius} cx="460" cy="210" r={radius} fill="none" stroke="rgba(103,232,249,0.05)" strokeWidth="1" />
          ))}

          <g>
            {worldPaths.map((shape, index) => (
              <path key={`${shape.slice(0, 16)}-${index}`} d={shape} fill="rgba(151,232,241,0.7)" stroke="rgba(0,0,0,0.42)" strokeWidth="0.55" />
            ))}
          </g>

          {mode === "flows" &&
            flows.slice(0, 8).map((flow, index) => {
              const start = mapPoint(flow.origin_code, index);
              const end = mapPoint(flow.target_code, index + 3);
              const curveY = Math.max(32, Math.min(start.y, end.y) - 54 - (index % 4) * 10);
              const width = Math.max(1.3, Math.min(6.5, (flow.value / maxValue) * 6.5));
              const samePoint = Math.abs(start.x - end.x) < 3 && Math.abs(start.y - end.y) < 3;
              const d = samePoint
                ? `M ${start.x} ${start.y} C ${start.x - 64} ${start.y - 58}, ${start.x + 64} ${start.y - 58}, ${end.x} ${end.y}`
                : `M ${start.x} ${start.y} C ${(start.x + end.x) / 2} ${curveY}, ${(start.x + end.x) / 2} ${curveY}, ${end.x} ${end.y}`;

              return (
                <path
                  key={`${flow.origin_code}-${flow.target_code}-${index}`}
                  d={d}
                  fill="none"
                  stroke={attackPalette[index % attackPalette.length]}
                  strokeWidth={width}
                  strokeLinecap="round"
                  strokeOpacity="0.55"
                  strokeDasharray="8 10"
                >
                  <animate attributeName="stroke-dashoffset" values="36;0" dur={`${5 + index * 0.4}s`} repeatCount="indefinite" />
                </path>
              );
            })}

          {mapPoints.map((point, index) => {
            const coords = mapPoint(point.code, index);
            const color = attackPalette[index % attackPalette.length];
            const radius = Math.max(5.5, Math.min(16, 5.5 + (point.value / maxValue) * 13));

            return (
              <g key={`${point.code}-${point.name}-${index}`}>
                <circle cx={coords.x} cy={coords.y} r={radius + 7} fill={color} opacity="0.08">
                  <animate attributeName="opacity" values="0.08;0.2;0.08" dur="3.2s" repeatCount="indefinite" />
                </circle>
                <circle cx={coords.x} cy={coords.y} r={radius + 3} fill="#050608" stroke={color} strokeWidth="2.5" />
                <circle cx={coords.x} cy={coords.y} r={Math.max(3, radius * 0.34)} fill={color} />
                <text x={coords.x + radius + 8} y={coords.y + 5} fill="#ffffff" fontSize="12" fontWeight="800">
                  {point.code || point.name}
                </text>
                <title>{`${point.name}: ${formatPercent(point.value)}`}</title>
              </g>
            );
          })}
        </svg>

        <div className="grid gap-4">
          <AttackFlowRibbon flows={flows} />
          <LocationRankList title={mode === "targets" ? "Top targets" : "Top sources"} data={mode === "targets" ? targets : origins} />
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
  onModeChange,
}: {
  geography: { origins: AttackLocationPoint[]; targets: AttackLocationPoint[]; flows: AttackFlowPoint[] };
  mode: AttackGeoTab;
  scopeLabel: string;
  onModeChange: (mode: AttackGeoTab) => void;
}) {
  return (
    <Panel eyebrow="Application layer security" title={`Application Layer Security / ${scopeLabel}`}>
      <AttackWorldMap mode={mode} origins={geography.origins} targets={geography.targets} flows={geography.flows} onModeChange={onModeChange} />
      <p className="mt-4 rounded-md border border-white/10 bg-black/20 px-4 py-3 text-sm leading-6 text-haze">
        Attack geography is aggregated Cloudflare Radar Layer 7 data. It is not a live attack map for this portfolio website.
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

function SummaryCard({
  icon: Icon,
  label,
  value,
  body,
  tone = "signal",
}: {
  icon: typeof Radar;
  label: string;
  value: string;
  body: string;
  tone?: "signal" | "trace" | "cyan";
}) {
  const toneClass =
    tone === "trace"
      ? "border-trace/30 bg-trace/10 text-trace"
      : tone === "cyan"
        ? "border-cyan-300/30 bg-cyan-400/10 text-cyan-100"
        : "border-signal/30 bg-signal/10 text-signal";

  return (
    <div className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <div className={`mb-5 inline-flex h-11 w-11 items-center justify-center rounded-lg border ${toneClass}`}>
        <Icon size={20} />
      </div>
      <p className="font-mono text-xs uppercase text-haze">{label}</p>
      <p className="mt-2 text-3xl font-semibold text-white">{value}</p>
      <p className="mt-3 text-sm leading-6 text-haze">{body}</p>
    </div>
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
  const [copyStatus, setCopyStatus] = useState("");

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

  const latestAttackValue = useMemo(() => {
    const latest = data?.layer7_trend ? lastItem(data.layer7_trend) : undefined;
    return latest?.value ?? null;
  }, [data]);
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

  const analystSummary = data
    ? [
        "Global Threat Dashboard analyst summary",
        `Range: ${data.filters?.range_label || range}`,
        `Scope: ${data.filters?.scope_label || scope.label}`,
        `Application attack insight: ${data.summary.application_attack_insight}`,
        ...insights.map((insight) => `- ${insight}`),
      ].join("\n")
    : "";

  const copySummary = async () => {
    if (!analystSummary) return;
    await navigator.clipboard.writeText(analystSummary);
    setCopyStatus("Copied");
    window.setTimeout(() => setCopyStatus(""), 1800);
  };

  const downloadJson = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `cloudflare-radar-attacks-${range}-${scopeKey.replace(":", "-")}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

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

      <div className="relative z-10 mx-auto grid max-w-7xl gap-6 py-10 md:py-12">
        <header className="rounded-lg border border-white/10 bg-obsidian/80 p-6 md:p-8">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="font-mono text-xs uppercase text-signal">Cloudflare Radar / application-layer attack telemetry</p>
              <h1 className="mt-3 max-w-4xl text-4xl font-semibold leading-tight text-white md:text-6xl">
                Global Threat Dashboard.
              </h1>
              <p className="mt-5 max-w-3xl text-base leading-7 text-haze md:text-lg">
                A SOC-style view of Layer 7 attack volume, mitigation mix, source countries, target countries, and attack flows from Cloudflare Radar.
              </p>
            </div>
            <div className="rounded-lg border border-signal/25 bg-signal/10 p-4 text-sm leading-6 text-haze lg:max-w-sm">
              <div className="mb-2 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                <ShieldAlert size={16} />
                Aggregated signal only
              </div>
              This dashboard uses aggregated Cloudflare Radar data, not individual live attack events.
            </div>
          </div>
        </header>

        <div className="grid gap-6 lg:grid-cols-[300px_minmax(0,1fr)] lg:items-start">
          <aside className="rounded-lg border border-white/10 bg-white/[0.04] p-5 lg:sticky lg:top-6">
            <div className="mb-5 flex items-center gap-2 font-mono text-xs uppercase text-signal">
              <Radar size={16} />
              Dashboard controls
            </div>

            <div className="grid gap-5">
              <div className="relative">
                <p className="mb-3 font-mono text-xs uppercase text-haze">Radar scope</p>
                <button
                  type="button"
                  onClick={() => setScopeOpen((open) => !open)}
                  className="flex w-full items-center justify-between gap-3 rounded-lg border border-signal/35 bg-black/25 px-4 py-3 text-left text-white transition hover:border-signal/70"
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
                <p className="mb-3 font-mono text-xs uppercase text-haze">Time range</p>
                <div className="grid grid-cols-3 gap-2 lg:grid-cols-1">
                  {rangeOptions.map((option) => (
                    <button
                      key={option.key}
                      type="button"
                      onClick={() => {
                        setRange(option.key);
                        setSelectedPoint(null);
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

              <div>
                <p className="mb-3 font-mono text-xs uppercase text-haze">Attack geography</p>
                <div className="grid gap-2">
                  {attackGeoTabs.map((tab) => (
                    <button
                      key={tab.key}
                      type="button"
                      onClick={() => setAttackGeoTab(tab.key)}
                      className={`rounded-md border px-4 py-2 text-left text-sm font-semibold transition ${
                        attackGeoTab === tab.key ? "border-signal/70 bg-signal text-obsidian" : "border-white/10 bg-black/20 text-haze hover:border-signal/40 hover:text-white"
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid gap-2 border-t border-white/10 pt-5">
                <button
                  type="button"
                  onClick={copySummary}
                  disabled={!data}
                  className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-white/10 bg-black/20 px-4 text-sm font-semibold text-white transition hover:border-signal/45 hover:text-signal disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Clipboard size={16} />
                  {copyStatus || "Copy summary"}
                </button>
                <button
                  type="button"
                  onClick={downloadJson}
                  disabled={!data}
                  className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-white/10 bg-black/20 px-4 text-sm font-semibold text-white transition hover:border-signal/45 hover:text-signal disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Download size={16} />
                  Download JSON
                </button>
              </div>
            </div>
          </aside>

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

                <ApplicationLayerSecurityPanel geography={attackGeography} mode={attackGeoTab} scopeLabel={data.filters?.scope_label || scope.label} onModeChange={setAttackGeoTab} />

                <div className="grid gap-6 xl:grid-cols-[minmax(0,1.35fr)_minmax(340px,0.65fr)]">
                  <Panel eyebrow="Layer 7 attack volume" title={`Application attack trend / ${data.filters?.scope_label || scope.label}`}>
                    <LineChart data={activeTrend} tone="trace" selectedIndex={selectedPoint ?? Math.max(activeTrend.length - 1, 0)} onSelect={setSelectedPoint} />
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

                  <Panel eyebrow="Mitigation mix" title="Application attack type split">
                    <DonutChart data={data.layer7_mitigation_mix || []} centerLabel="Lead attack" />
                  </Panel>
                </div>

                <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <SummaryCard icon={ShieldAlert} label="Application attacks" value={formatCompact(latestAttackValue)} body={data.summary.application_attack_insight} tone="trace" />
                  <SummaryCard icon={MapPin} label="Top attack origin" value={attackGeography.origins[0]?.code || "N/A"} body={attackGeography.origins[0] ? `${attackGeography.origins[0].name} leads source locations at ${formatPercent(attackGeography.origins[0].value)}.` : "Origin country data unavailable."} tone="cyan" />
                  <SummaryCard icon={Globe2} label="Top target" value={attackGeography.targets[0]?.code || "N/A"} body={attackGeography.targets[0] ? `${attackGeography.targets[0].name} leads target locations at ${formatPercent(attackGeography.targets[0].value)}.` : "Target country data unavailable."} />
                  <SummaryCard icon={Activity} label="Last updated" value={formatTime(data.summary.last_updated)} body="Timestamp from Cloudflare Radar metadata for the newest dataset used." />
                </section>

                <section className="grid gap-4 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
                  <div className={`rounded-lg border p-5 ${severityClass}`}>
                    <p className="font-mono text-xs uppercase">Global signal severity</p>
                    <h2 className="mt-2 text-3xl font-semibold text-white">{severity}</h2>
                    <p className="mt-3 text-sm leading-6 text-haze">
                      This is an analyst-style signal based on aggregated Radar Layer 7 trend movement and application-layer attack context. It does not indicate attacks against this portfolio.
                    </p>
                  </div>

                  <div className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
                    <div className="mb-4 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                      <BarChart3 size={16} />
                      Analyst insights
                    </div>
                    <ul className="grid gap-2">
                      {insights.map((insight) => (
                        <li key={insight} className="leading-7 text-haze">
                          {insight}
                        </li>
                      ))}
                    </ul>
                  </div>
                </section>

                <section className="grid gap-4 md:grid-cols-3">
                  {[
                    [Globe2, "Global scope", "Radar aggregates activity from Cloudflare's global network rather than this individual portfolio site."],
                    [Radar, "Security context", "Useful for showing internet-wide application-layer attack patterns, source countries, targets, and flow telemetry."],
                    [Zap, "Cached edge view", "Successful dashboard responses are cached briefly to keep the public page fast and token usage low."],
                  ].map(([Icon, title, body]) => (
                    <div key={String(title)} className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
                      <Icon className="text-signal" size={20} />
                      <h3 className="mt-4 text-lg font-semibold text-white">{String(title)}</h3>
                      <p className="mt-2 text-sm leading-6 text-haze">{String(body)}</p>
                    </div>
                  ))}
                </section>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
