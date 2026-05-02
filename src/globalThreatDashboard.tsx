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
import { motion } from "framer-motion";
import { useEffect, useMemo, useState } from "react";

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

const fadeUp = {
  hidden: { opacity: 0, y: 24 },
  visible: { opacity: 1, y: 0 },
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
    <div className="grid gap-5 rounded-lg border border-white/10 bg-black/20 p-5 sm:grid-cols-[180px_minmax(0,1fr)] sm:items-center">
      <div
        className="relative mx-auto h-44 w-44 rounded-full"
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
          <div key={row.label} className="flex items-center justify-between gap-4 rounded-md border border-white/10 bg-white/[0.035] px-4 py-3">
            <span className="flex items-center gap-3 text-sm text-haze">
              <span className="h-3 w-3 rounded-full" style={{ backgroundColor: attackPalette[index % attackPalette.length] }} />
              {row.label}
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

const countryCoordinates: Record<string, { x: number; y: number }> = {
  US: { x: 190, y: 178 },
  CA: { x: 182, y: 108 },
  BR: { x: 300, y: 306 },
  GB: { x: 431, y: 145 },
  FR: { x: 443, y: 171 },
  DE: { x: 465, y: 158 },
  NL: { x: 455, y: 151 },
  BE: { x: 452, y: 162 },
  ES: { x: 424, y: 194 },
  IT: { x: 475, y: 197 },
  NG: { x: 468, y: 260 },
  ZA: { x: 506, y: 360 },
  CN: { x: 680, y: 195 },
  IN: { x: 623, y: 243 },
  ID: { x: 706, y: 305 },
  JP: { x: 760, y: 191 },
  SG: { x: 688, y: 288 },
  MY: { x: 678, y: 280 },
  HK: { x: 697, y: 221 },
  VN: { x: 681, y: 248 },
  AU: { x: 744, y: 354 },
};

function mapPoint(code?: string, index = 0) {
  return code && countryCoordinates[code] ? countryCoordinates[code] : { x: 90 + (index % 6) * 118, y: 110 + Math.floor(index / 6) * 60 };
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

function AttackWorldMap({ mode, origins, targets, flows }: { mode: AttackGeoTab; origins: AttackLocationPoint[]; targets: AttackLocationPoint[]; flows: AttackFlowPoint[] }) {
  const points = mode === "targets" ? targets : origins;
  const maxValue = Math.max(...points.map((point) => point.value), ...flows.map((flow) => flow.value), 1);
  const mapTitle = mode === "targets" ? "Top attacks by target location" : mode === "flows" ? "Top attack country flows" : "Top attacks by source location";

  return (
    <div className="overflow-hidden rounded-lg border border-white/10 bg-[#07090b] p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="font-mono text-xs uppercase text-signal">{mapTitle}</p>
          <p className="mt-1 text-sm text-haze">Aggregated Layer 7 Radar geography</p>
        </div>
        <span className="rounded-md border border-white/10 bg-white/[0.04] px-3 py-1.5 font-mono text-xs uppercase text-haze">
          {mode === "origins" ? "Source" : mode === "targets" ? "Target" : "Flow"}
        </span>
      </div>

      <svg viewBox="0 0 900 440" className="h-[360px] w-full rounded-md bg-black/45" role="img" aria-label="World attack geography map">
        <defs>
          <filter id="map-glow">
            <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="rgba(103,232,249,0.35)" />
          </filter>
          <linearGradient id="attack-line" x1="0" x2="1">
            <stop offset="0%" stopColor="#fcee0a" stopOpacity="0.1" />
            <stop offset="50%" stopColor="#67e8f9" stopOpacity="0.45" />
            <stop offset="100%" stopColor="#ff2a3d" stopOpacity="0.2" />
          </linearGradient>
        </defs>

        {[0, 1, 2, 3, 4, 5].map((line) => (
          <line key={`v-${line}`} x1={80 + line * 140} x2={80 + line * 140} y1="54" y2="390" stroke="rgba(255,255,255,0.055)" strokeDasharray="4 9" />
        ))}
        {[0, 1, 2, 3].map((line) => (
          <line key={`h-${line}`} x1="35" x2="865" y1={90 + line * 82} y2={90 + line * 82} stroke="rgba(255,255,255,0.055)" strokeDasharray="4 9" />
        ))}

        <path d="M90 118 C130 72 214 80 254 126 C237 160 176 169 124 154 C92 147 74 139 90 118Z" fill="rgba(176,235,244,0.8)" stroke="rgba(255,255,255,0.18)" />
        <path d="M265 247 C310 236 355 278 339 331 C323 382 293 407 271 363 C256 331 232 283 265 247Z" fill="rgba(176,235,244,0.72)" stroke="rgba(255,255,255,0.15)" />
        <path d="M412 120 C464 97 523 116 535 165 C497 189 422 184 385 155 C380 139 391 128 412 120Z" fill="rgba(176,235,244,0.78)" stroke="rgba(255,255,255,0.17)" />
        <path d="M468 205 C521 193 561 241 542 310 C527 363 485 353 464 303 C448 265 428 222 468 205Z" fill="rgba(176,235,244,0.72)" stroke="rgba(255,255,255,0.15)" />
        <path d="M545 139 C650 78 782 110 815 183 C740 220 630 211 548 177 C522 166 518 152 545 139Z" fill="rgba(176,235,244,0.8)" stroke="rgba(255,255,255,0.18)" />
        <path d="M660 274 C710 255 773 276 800 336 C758 374 686 364 654 317 C642 300 644 284 660 274Z" fill="rgba(176,235,244,0.72)" stroke="rgba(255,255,255,0.15)" />
        <path d="M381 78 C408 53 453 58 466 91 C446 114 397 111 373 94 C367 86 371 81 381 78Z" fill="rgba(176,235,244,0.45)" stroke="rgba(255,255,255,0.12)" />

        {mode === "flows" &&
          flows.map((flow, index) => {
            const start = mapPoint(flow.origin_code, index);
            const end = mapPoint(flow.target_code, index + 3);
            const curveY = Math.min(start.y, end.y) - 70 - index * 5;
            const width = Math.max(1.2, Math.min(8, (flow.value / maxValue) * 8));

            return (
              <path
                key={`${flow.origin_code}-${flow.target_code}-${index}`}
                d={`M ${start.x} ${start.y} C ${start.x + 100} ${curveY}, ${end.x - 100} ${curveY}, ${end.x} ${end.y}`}
                fill="none"
                stroke="url(#attack-line)"
                strokeWidth={width}
                strokeLinecap="round"
              />
            );
          })}

        {(mode === "flows" ? flows.flatMap((flow, index) => [
          { code: flow.origin_code, name: flow.origin_name, value: flow.value, kind: "source", index },
          { code: flow.target_code, name: flow.target_name, value: flow.value, kind: "target", index: index + flows.length },
        ]) : points.map((point, index) => ({ ...point, kind: mode, index }))).map((point, index) => {
          const coords = mapPoint(point.code, point.index || index);
          const color = attackPalette[index % attackPalette.length];
          const radius = Math.max(6, Math.min(18, 6 + (point.value / maxValue) * 18));

          return (
            <g key={`${point.code}-${point.name}-${index}`} filter="url(#map-glow)">
              <circle cx={coords.x} cy={coords.y} r={radius + 4} fill="none" stroke={color} strokeOpacity="0.24" strokeWidth="2" />
              <circle cx={coords.x} cy={coords.y} r={radius} fill="#07090b" stroke={color} strokeWidth="4" />
              <text x={coords.x + radius + 7} y={coords.y + 4} fill="#ffffff" fontSize="12" fontWeight="700">
                {point.code || point.name}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function AttackFlowDiagram({ data }: { data: AttackFlowPoint[] }) {
  const max = Math.max(...data.map((point) => point.value), 1);

  if (!data.length) {
    return (
      <div className="flex min-h-[360px] items-center justify-center rounded-lg border border-white/10 bg-black/20 text-sm text-haze">
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
      <svg viewBox="0 0 420 410" className="h-[360px] w-full" role="img" aria-label="Layer 7 attack flow diagram">
        {data.map((flow, index) => {
          const y = 40 + index * 42;
          const thickness = Math.max(3, Math.min(34, (flow.value / max) * 34));
          const color = attackPalette[index % attackPalette.length];

          return (
            <g key={`${flow.origin_code}-${flow.target_code}-${index}`}>
              <path
                d={`M 74 ${y} C 165 ${y}, 245 ${y + (index % 2 === 0 ? 26 : -22)}, 344 ${y}`}
                fill="none"
                stroke={color}
                strokeOpacity="0.5"
                strokeWidth={thickness}
                strokeLinecap="round"
              />
              <rect x="12" y={y - 15} width="74" height="30" rx="4" fill="rgba(255,255,255,0.08)" />
              <rect x="334" y={y - 15} width="74" height="30" rx="4" fill="rgba(255,255,255,0.08)" />
              <text x="22" y={y + 5} fill="#ffffff" fontSize="13" fontWeight="700">
                {flow.origin_code || flow.origin_name.slice(0, 3)}
              </text>
              <text x="374" y={y + 5} fill="#ffffff" fontSize="13" fontWeight="700" textAnchor="middle">
                {flow.target_code || flow.target_name.slice(0, 3)}
              </text>
              <text x="210" y={y - Math.max(12, thickness / 2)} fill="#d7c99e" fontSize="11" textAnchor="middle">
                {formatPercent(flow.value)}
              </text>
            </g>
          );
        })}
        <text x="18" y="396" fill="#67e8f9" fontSize="12" fontWeight="700">
          Source
        </text>
        <text x="370" y="396" fill="#67e8f9" fontSize="12" fontWeight="700" textAnchor="middle">
          Target
        </text>
      </svg>
    </div>
  );
}

function ApplicationLayerSecurityPanel({
  geography,
  mode,
  scopeLabel,
}: {
  geography: { origins: AttackLocationPoint[]; targets: AttackLocationPoint[]; flows: AttackFlowPoint[] };
  mode: AttackGeoTab;
  scopeLabel: string;
}) {
  return (
    <Panel eyebrow="Application layer security" title={`Attack geography / ${scopeLabel}`}>
      <div className="grid gap-5 2xl:grid-cols-[minmax(0,1.35fr)_minmax(360px,0.65fr)]">
        <AttackWorldMap mode={mode} origins={geography.origins} targets={geography.targets} flows={geography.flows} />
        <AttackFlowDiagram data={geography.flows} />
      </div>
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
    <div className="rounded-lg border border-white/10 bg-white/[0.04] p-5 backdrop-blur-xl">
      <div className={`mb-5 inline-flex h-11 w-11 items-center justify-center rounded-lg border ${toneClass}`}>
        <Icon size={20} />
      </div>
      <p className="font-mono text-xs uppercase text-haze">{label}</p>
      <p className="mt-2 text-3xl font-semibold text-white">{value}</p>
      <p className="mt-3 text-sm leading-6 text-haze">{body}</p>
    </div>
  );
}

function Panel({ title, eyebrow, children }: { title: string; eyebrow: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5 shadow-glow backdrop-blur-xl md:p-6">
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
    <div className="relative min-h-screen px-5 py-6">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_12%,rgba(252,238,10,0.14),transparent_28%),radial-gradient(circle_at_84%_18%,rgba(255,42,61,0.12),transparent_24%)]" aria-hidden="true" />
      <nav className="relative z-10 mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 rounded-lg border border-white/10 bg-obsidian/70 px-4 py-3 backdrop-blur-xl">
        <a href="/" className="glitch-control inline-flex items-center gap-2 text-sm font-semibold uppercase text-white">
          <ArrowLeft size={16} />
          Home
        </a>
        <span className="font-mono text-xs uppercase text-signal">Global threat dashboard</span>
      </nav>

      <div className="relative z-10 mx-auto grid max-w-7xl gap-6 py-10 md:py-12">
        <motion.header initial="hidden" animate="visible" variants={fadeUp} transition={{ duration: 0.55 }} className="rounded-lg border border-white/10 bg-obsidian/75 p-6 shadow-glow backdrop-blur-xl md:p-8">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="font-mono text-xs uppercase text-signal">Cloudflare Radar / application-layer attack telemetry</p>
              <h1 className="micro-glitch-heading mt-3 max-w-4xl text-4xl font-semibold leading-tight text-white md:text-6xl" data-text="Global Threat Dashboard.">
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
        </motion.header>

        <div className="grid gap-6 lg:grid-cols-[300px_minmax(0,1fr)] lg:items-start">
          <aside className="rounded-lg border border-white/10 bg-white/[0.04] p-5 shadow-glow backdrop-blur-xl lg:sticky lg:top-6">
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
                  className="glitch-control flex w-full items-center justify-between gap-3 rounded-lg border border-signal/35 bg-black/25 px-4 py-3 text-left text-white shadow-[0_0_24px_rgba(252,238,10,0.1)] transition hover:border-signal/70"
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
                      className={`glitch-control rounded-md border px-4 py-2 text-sm font-semibold transition ${
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
                      className={`glitch-control rounded-md border px-4 py-2 text-left text-sm font-semibold transition ${
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
                  className="glitch-control inline-flex h-10 items-center justify-center gap-2 rounded-md border border-white/10 bg-black/20 px-4 text-sm font-semibold text-white transition hover:border-signal/45 hover:text-signal disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Clipboard size={16} />
                  {copyStatus || "Copy summary"}
                </button>
                <button
                  type="button"
                  onClick={downloadJson}
                  disabled={!data}
                  className="glitch-control inline-flex h-10 items-center justify-center gap-2 rounded-md border border-white/10 bg-black/20 px-4 text-sm font-semibold text-white transition hover:border-signal/45 hover:text-signal disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Download size={16} />
                  Download JSON
                </button>
              </div>
            </div>
          </aside>

          <div className="grid gap-6">
            {loading && (
              <div className="grid min-h-[360px] place-items-center rounded-lg border border-white/10 bg-white/[0.04] p-8 text-center shadow-glow backdrop-blur-xl">
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

                <ApplicationLayerSecurityPanel geography={attackGeography} mode={attackGeoTab} scopeLabel={data.filters?.scope_label || scope.label} />

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

                <motion.section initial="hidden" animate="visible" variants={fadeUp} transition={{ duration: 0.55, delay: 0.08 }} className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <SummaryCard icon={ShieldAlert} label="Application attacks" value={formatCompact(latestAttackValue)} body={data.summary.application_attack_insight} tone="trace" />
                  <SummaryCard icon={MapPin} label="Top attack origin" value={attackGeography.origins[0]?.code || "N/A"} body={attackGeography.origins[0] ? `${attackGeography.origins[0].name} leads source locations at ${formatPercent(attackGeography.origins[0].value)}.` : "Origin country data unavailable."} tone="cyan" />
                  <SummaryCard icon={Globe2} label="Top target" value={attackGeography.targets[0]?.code || "N/A"} body={attackGeography.targets[0] ? `${attackGeography.targets[0].name} leads target locations at ${formatPercent(attackGeography.targets[0].value)}.` : "Target country data unavailable."} />
                  <SummaryCard icon={Activity} label="Last updated" value={formatTime(data.summary.last_updated)} body="Timestamp from Cloudflare Radar metadata for the newest dataset used." />
                </motion.section>

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
