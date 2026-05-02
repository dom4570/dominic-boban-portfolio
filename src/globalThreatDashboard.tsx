import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  BarChart3,
  Bot,
  Clipboard,
  Download,
  Globe2,
  Loader2,
  Radar,
  ShieldAlert,
  Users,
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
  };
  note: string;
};

type RangeKey = "24h" | "7d" | "30d";
type MetricKey = "http" | "layer7";
type LocationTrafficKey = "all" | "bot" | "human";
type AttackGeoTab = "origins" | "targets" | "flows";

const rangeOptions: Array<{ key: RangeKey; label: string }> = [
  { key: "24h", label: "24h" },
  { key: "7d", label: "7d" },
  { key: "30d", label: "30d" },
];

const metricOptions: Array<{ key: MetricKey; label: string; tone: "signal" | "trace" }> = [
  { key: "http", label: "HTTP requests", tone: "signal" },
  { key: "layer7", label: "Layer 7 attacks", tone: "trace" },
];

const locationTrafficOptions: Array<{ key: LocationTrafficKey; label: string }> = [
  { key: "all", label: "All traffic" },
  { key: "bot", label: "Bot traffic" },
  { key: "human", label: "Human traffic" },
];

const attackGeoTabs: Array<{ key: AttackGeoTab; label: string }> = [
  { key: "origins", label: "Attack Origins" },
  { key: "targets", label: "Targeted Countries" },
  { key: "flows", label: "Origin -> Target Flows" },
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
  const botPercent = data.summary.bot_percent || 0;
  const httpPeak = peakPoint(data.http_trend);
  const layer7Peak = peakPoint(data.layer7_trend);
  const layer7Delta = trendDelta(data.layer7_trend);
  const topLocation = data.top_locations[0];
  const topOrigin = data.attack_geography?.origins?.[0];
  const topTarget = data.attack_geography?.targets?.[0];
  const topFlow = data.attack_geography?.flows?.[0];

  if (botPercent >= 35) {
    insights.push(`Bot traffic is elevated at ${formatPercent(botPercent)}, so automated activity is a major part of the global HTTP mix.`);
  } else {
    insights.push(`Human traffic is currently dominant, with bots at ${formatPercent(botPercent)} of the global HTTP mix.`);
  }

  if (httpPeak) {
    insights.push(`HTTP request pressure peaked around ${formatTime(httpPeak.timestamp)} with an index value of ${formatCompact(httpPeak.value)}.`);
  }

  if (layer7Peak) {
    insights.push(`Layer 7 activity peaked around ${formatTime(layer7Peak.timestamp)} with an index value of ${formatCompact(layer7Peak.value)}.`);
  }

  if (layer7Delta !== null) {
    const direction = layer7Delta >= 0 ? "up" : "down";
    insights.push(`The latest Layer 7 point is ${direction} ${Math.abs(layer7Delta).toFixed(1)}% compared with the previous point.`);
  }

  if (topLocation) {
    insights.push(`${topLocation.name} leads the selected location view with ${formatCompact(topLocation.value)}% share.`);
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
        <path d={`${path} L ${width - padding} ${height - padding} L ${padding} ${height - padding} Z`} fill={`url(#line-fill-${tone})`} />
        <path d={path} fill="none" stroke={stroke} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" filter={`url(#line-glow-${tone})`} />
        {data.map((point, index) => {
          const { x, y } = chartPoint(point, index);
          const selected = selectedIndex === index;

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
      </svg>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-xs text-haze">
        <span>{formatTime(data[0]?.timestamp)}</span>
        <span className="font-mono uppercase text-white/70">Latest index: {formatCompact(latest)}</span>
        <span>{formatTime(lastItem(data)?.timestamp)}</span>
      </div>
    </div>
  );
}

function DonutChart({ data }: { data: SplitPoint[] }) {
  const bot = data.find((point) => point.label.toLowerCase() === "bot")?.value || 0;
  const human = data.find((point) => point.label.toLowerCase() === "human")?.value || 0;
  const total = bot + human || 1;
  const botDegrees = (bot / total) * 360;

  return (
    <div className="grid gap-5 rounded-lg border border-white/10 bg-black/20 p-5 sm:grid-cols-[180px_minmax(0,1fr)] sm:items-center">
      <div
        className="relative mx-auto h-44 w-44 rounded-full"
        style={{
          background: `conic-gradient(#fcee0a 0deg ${botDegrees}deg, #67e8f9 ${botDegrees}deg 360deg)`,
          boxShadow: "0 0 38px rgba(252,238,10,0.12)",
        }}
      >
        <div className="absolute inset-5 grid place-items-center rounded-full border border-white/10 bg-obsidian text-center">
          <span className="font-mono text-xs uppercase text-haze">Bot share</span>
          <span className="text-3xl font-semibold text-white">{formatPercent(bot)}</span>
        </div>
      </div>
      <div className="grid gap-3">
        {[
          ["Bot", bot, "bg-signal"],
          ["Human", human, "bg-cyan-300"],
        ].map(([label, value, swatch]) => (
          <div key={label} className="flex items-center justify-between gap-4 rounded-md border border-white/10 bg-white/[0.035] px-4 py-3">
            <span className="flex items-center gap-3 text-sm text-haze">
              <span className={`h-3 w-3 rounded-full ${swatch}`} />
              {label} traffic
            </span>
            <span className="font-mono text-sm font-semibold text-white">{formatPercent(Number(value))}</span>
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
  const [metric, setMetric] = useState<MetricKey>("http");
  const [locationTraffic, setLocationTraffic] = useState<LocationTrafficKey>("all");
  const [attackGeoTab, setAttackGeoTab] = useState<AttackGeoTab>("origins");
  const [selectedPoint, setSelectedPoint] = useState<number | null>(null);
  const [copyStatus, setCopyStatus] = useState("");

  useEffect(() => {
    let cancelled = false;
    const params = new URLSearchParams({
      range,
      traffic: locationTraffic,
    });

    setLoading(true);
    setError("");

    fetch(`/api/radar-dashboard?${params.toString()}`, {
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
  }, [range, locationTraffic]);

  const latestAttackValue = useMemo(() => {
    const latest = data?.layer7_trend ? lastItem(data.layer7_trend) : undefined;
    return latest?.value ?? null;
  }, [data]);
  const activeMetric = metricOptions.find((option) => option.key === metric) || metricOptions[0];
  const activeTrend = metric === "http" ? data?.http_trend || [] : data?.layer7_trend || [];
  const activeTrendPoint = selectedPoint !== null ? activeTrend[selectedPoint] : lastItem(activeTrend);
  const attackGeography = data?.attack_geography || { origins: [], targets: [], flows: [] };
  const insights = data ? buildAnalystInsights(data) : [];
  const severity =
    (data?.summary.bot_percent || 0) >= 40 || Math.abs(trendDelta(data?.layer7_trend || []) || 0) >= 20
      ? "Elevated"
      : (data?.summary.bot_percent || 0) >= 30
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
        `Bot traffic: ${formatPercent(data.summary.bot_percent)}`,
        `Human traffic: ${formatPercent(data.summary.human_percent)}`,
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
    link.download = `cloudflare-radar-${range}-${locationTraffic}.json`;
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
              <p className="font-mono text-xs uppercase text-signal">Cloudflare Radar / aggregated internet telemetry</p>
              <h1 className="micro-glitch-heading mt-3 max-w-4xl text-4xl font-semibold leading-tight text-white md:text-6xl" data-text="Global Threat Dashboard.">
                Global Threat Dashboard.
              </h1>
              <p className="mt-5 max-w-3xl text-base leading-7 text-haze md:text-lg">
                A SOC-style view of global HTTP traffic, bot activity, application-layer attack patterns, and top internet locations from Cloudflare Radar.
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

        <section className="grid gap-4 rounded-lg border border-white/10 bg-white/[0.04] p-5 shadow-glow backdrop-blur-xl lg:grid-cols-[1fr_1fr_1fr_auto] lg:items-end">
          <div>
            <p className="mb-3 font-mono text-xs uppercase text-signal">Time range</p>
            <div className="flex flex-wrap gap-2">
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
            <p className="mb-3 font-mono text-xs uppercase text-signal">Graph metric</p>
            <div className="flex flex-wrap gap-2">
              {metricOptions.map((option) => (
                <button
                  key={option.key}
                  type="button"
                  onClick={() => {
                    setMetric(option.key);
                    setSelectedPoint(null);
                  }}
                  className={`glitch-control rounded-md border px-4 py-2 text-sm font-semibold transition ${
                    metric === option.key ? "border-signal/70 bg-signal text-obsidian" : "border-white/10 bg-black/20 text-haze hover:border-signal/40 hover:text-white"
                  }`}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <p className="mb-3 font-mono text-xs uppercase text-signal">Location filter</p>
            <div className="flex flex-wrap gap-2">
              {locationTrafficOptions.map((option) => (
                <button
                  key={option.key}
                  type="button"
                  onClick={() => setLocationTraffic(option.key)}
                  className={`glitch-control rounded-md border px-4 py-2 text-sm font-semibold transition ${
                    locationTraffic === option.key ? "border-signal/70 bg-signal text-obsidian" : "border-white/10 bg-black/20 text-haze hover:border-signal/40 hover:text-white"
                  }`}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap gap-2">
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
              JSON
            </button>
          </div>
        </section>

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
            <motion.section initial="hidden" animate="visible" variants={fadeUp} transition={{ duration: 0.55, delay: 0.08 }} className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <SummaryCard icon={Bot} label="Bot traffic" value={formatPercent(data.summary.bot_percent)} body="Likely automated HTTP traffic share over the selected global Radar window." />
              <SummaryCard icon={Users} label="Human traffic" value={formatPercent(data.summary.human_percent)} body="Likely human HTTP traffic share for the same global period." tone="cyan" />
              <SummaryCard icon={ShieldAlert} label="Application attacks" value={formatCompact(latestAttackValue)} body={data.summary.application_attack_insight} tone="trace" />
              <SummaryCard icon={Activity} label="Last updated" value={formatTime(data.summary.last_updated)} body="Timestamp from Cloudflare Radar metadata for the newest dataset used." />
            </motion.section>

            {data.warnings.length > 0 && (
              <div className="rounded-lg border border-volt/35 bg-volt/10 p-4 text-sm leading-6 text-haze">
                <div className="mb-2 flex items-center gap-2 font-mono text-xs uppercase text-volt">
                  <AlertTriangle size={16} />
                  Partial Radar data
                </div>
                {data.warnings.join(" ")}
              </div>
            )}

            <section className="grid gap-4 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
              <div className={`rounded-lg border p-5 ${severityClass}`}>
                <p className="font-mono text-xs uppercase">Global signal severity</p>
                <h2 className="mt-2 text-3xl font-semibold text-white">{severity}</h2>
                <p className="mt-3 text-sm leading-6 text-haze">
                  This is an analyst-style signal based on aggregated Radar bot share and Layer 7 trend movement. It does not indicate attacks against this portfolio.
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

            <div className="grid gap-6 xl:grid-cols-[minmax(0,1.3fr)_minmax(340px,0.7fr)]">
              <Panel eyebrow="Interactive trend analysis" title={activeMetric.label}>
                <LineChart data={activeTrend} tone={activeMetric.tone} selectedIndex={selectedPoint ?? Math.max(activeTrend.length - 1, 0)} onSelect={setSelectedPoint} />
                <div className="mt-4 rounded-md border border-white/10 bg-black/20 p-4">
                  <p className="font-mono text-xs uppercase text-signal">Selected point</p>
                  <div className="mt-3 grid gap-3 sm:grid-cols-3">
                    <div>
                      <p className="font-mono text-[11px] uppercase text-haze">Metric</p>
                      <p className="mt-1 font-semibold text-white">{activeMetric.label}</p>
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

              <Panel eyebrow="Bot split" title="Bot vs human traffic">
                <DonutChart data={data.bot_human} />
              </Panel>
            </div>

            <div className="grid gap-6 xl:grid-cols-[minmax(340px,0.8fr)_minmax(0,1.2fr)]">
              <Panel eyebrow="Top locations" title={`${locationTrafficOptions.find((option) => option.key === locationTraffic)?.label || "All traffic"} by location`}>
                <LocationBars data={data.top_locations} />
              </Panel>

              <Panel eyebrow="Layer 7 activity" title="Application attack trend">
                <LineChart data={data.layer7_trend} tone="trace" />
              </Panel>
            </div>

            <Panel eyebrow="Layer 7 attack geography" title="Country attack map">
              <div className="mb-5 flex flex-wrap gap-2">
                {attackGeoTabs.map((tab) => (
                  <button
                    key={tab.key}
                    type="button"
                    onClick={() => setAttackGeoTab(tab.key)}
                    className={`glitch-control rounded-md border px-4 py-2 text-sm font-semibold transition ${
                      attackGeoTab === tab.key ? "border-signal/70 bg-signal text-obsidian" : "border-white/10 bg-black/20 text-haze hover:border-signal/40 hover:text-white"
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {attackGeoTab === "origins" && <AttackLocationBars data={attackGeography.origins} emptyLabel="Attack origin country data unavailable." />}
              {attackGeoTab === "targets" && <AttackLocationBars data={attackGeography.targets} emptyLabel="Target country data unavailable." />}
              {attackGeoTab === "flows" && <AttackFlowBars data={attackGeography.flows} />}

              <p className="mt-4 rounded-md border border-white/10 bg-black/20 px-4 py-3 text-sm leading-6 text-haze">
                Country attack geography is aggregated Cloudflare Radar Layer 7 data. It is not a live attack map for this portfolio website.
              </p>
            </Panel>

            <section className="grid gap-4 md:grid-cols-3">
              {[
                [Globe2, "Global scope", "Radar aggregates activity from Cloudflare's global network rather than this individual portfolio site."],
                [Radar, "Security context", "Useful for showing internet-wide patterns across bots, HTTP traffic, and application attack telemetry."],
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
  );
}
