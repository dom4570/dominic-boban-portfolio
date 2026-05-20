import "leaflet/dist/leaflet.css";

import L from "leaflet";
import {
  AlertTriangle,
  ArrowLeft,
  Globe2,
  Loader2,
  MapPin,
  Radar,
  RotateCcw,
  ShieldAlert,
} from "lucide-react";
import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";

type ThreatPoint = {
  id: string;
  rank: number;
  ip: string;
  latitude: number;
  longitude: number;
  city: string;
  region: string;
  country: string;
  country_code: string;
  abuse_confidence_score: number;
  last_reported_at: string;
  asn: string;
  as_name: string;
  isp: string;
  org: string;
  hosting: boolean;
  proxy: boolean;
  mobile: boolean;
  source: string;
  ip_intelligence?: IpIntelligenceSummary;
  abuseipdb_intelligence?: AbuseIpdbSummary;
};

type ThreatOriginResponse = {
  mode: "live" | "fallback";
  cache_status: "fresh" | "cached" | "stale" | "fallback";
  generated_at: string;
  cache_expires_at: string | null;
  next_refresh_at: string | null;
  source: string;
  points: ThreatPoint[];
  warnings: string[];
};

type SpamhausDataset = {
  code: number;
  dataset: string;
  label: string;
  explanation: string;
  url: string;
};

type IpIntelligenceSummary = {
  status: SpamhausDetail["status"];
  listing_count: number;
  codes: number[];
  datasets: Array<Pick<SpamhausDataset, "code" | "dataset" | "label">>;
  generated_at: string;
  cache_status: SpamhausDetail["cache_status"];
};

type AbuseIpdbCategory = {
  id: number;
  label: string;
  count?: number;
};

type AbuseIpdbReport = {
  reported_at: string;
  reporter_country_code: string;
  reporter_country_name: string;
  comment: string;
  categories: AbuseIpdbCategory[];
};

type AbuseIpdbSummary = {
  provider: "abuseipdb";
  status: "reported" | "not_reported" | "unavailable" | "not_configured";
  abuse_confidence_score: number;
  total_reports: number;
  num_distinct_users: number;
  max_age_in_days: number;
  usage_type: string;
  isp: string;
  domain: string;
  country_code: string;
  country_name: string;
  is_tor: boolean;
  is_whitelisted: boolean | null;
  last_reported_at: string;
  top_categories: AbuseIpdbCategory[];
  generated_at: string;
  cache_status: "fresh" | "cached";
};

type SpamhausHistory = {
  status: "found" | "not_found" | "unavailable";
  events?: SpamhausHistoryEvent[];
  warnings: string[];
};

type SpamhausHistoryEvent = {
  dataset?: string;
  listed_at?: string;
  removed_at?: string;
  valid_until_at?: string;
  seen_at?: string;
  detection?: string;
  heuristic?: string;
  botname?: string;
  source_ip?: string;
  source_port?: number | null;
  destination_ip?: string;
  destination_port?: number | null;
  protocol?: string;
};

type SpamhausDetail = {
  ip: string;
  status: "listed" | "not_listed" | "unavailable" | "not_configured";
  listing_count: number;
  codes: number[];
  datasets: SpamhausDataset[];
  generated_at: string;
  cache_status: "fresh" | "cached";
  cache_expires_at: string;
  warnings: string[];
  history?: SpamhausHistory | null;
};

type AbuseIpdbDetail = AbuseIpdbSummary & {
  ip: string;
  recent_report_total: number;
  recent_reports: AbuseIpdbReport[];
  report_window_days: number;
  reports_status: "not_loaded" | "found" | "not_found" | "unavailable";
  cache_expires_at: string;
  warnings: string[];
};

const MAX_DAILY_POINTS = 50;

function readJson<T>(response: Response): Promise<T> {
  return response.json().then((body) => {
    if (!response.ok) {
      throw new Error(body?.message || "Threat origin data is temporarily unavailable.");
    }

    return body as T;
  });
}

function formatDate(value: string | null | undefined) {
  if (!value || value === "Demo data") return value || "Unknown";
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

function formatNumber(value: number | null | undefined) {
  return new Intl.NumberFormat("en-GB").format(Math.max(0, Number(value) || 0));
}

function formatLocation(point: ThreatPoint) {
  const city = point.city && point.city !== "Unknown city" ? point.city : "";
  const country = point.country || point.country_code || "Unknown";

  return [city, country].filter(Boolean).join(", ");
}

function formatEndpoint(ip: string | undefined, port: number | null | undefined) {
  if (!ip && !port) return "";
  if (!ip && port) return `port ${port}`;
  return [ip, port ? `:${port}` : ""].filter(Boolean).join("");
}

function cacheStatusLabel(status: ThreatOriginResponse["cache_status"] | undefined) {
  if (status === "fresh") return "Fresh daily snapshot";
  if (status === "cached") return "Cached daily snapshot";
  if (status === "stale") return "Stale daily snapshot";
  if (status === "fallback") return "Demo fallback";
  return "Loading";
}

function rankTone(rank: number) {
  if (rank <= 10) return "#ff2a3d";
  if (rank <= 25) return "#fcee0a";
  return "#22d3ee";
}

function markerSize(rank: number) {
  if (rank <= 10) return 20;
  if (rank <= 25) return 16;
  return 13;
}

const NO_INTELLIGENCE_DATA = "No additional intelligence data is available at the moment.";

function createThreatMarkerIcon(point: ThreatPoint, selected: boolean) {
  const color = rankTone(point.rank || MAX_DAILY_POINTS);
  const sizeValue = markerSize(point.rank || MAX_DAILY_POINTS);
  const selectedClass = selected ? " threat-pulse-marker--selected" : "";

  return L.divIcon({
    className: "",
    html: `<span class="threat-pulse-marker${selectedClass}" style="--marker-color:${color};--marker-size:${sizeValue}px"></span>`,
    iconAnchor: [sizeValue / 2, sizeValue / 2],
    iconSize: [sizeValue, sizeValue],
  });
}

function IntelligenceSummary({
  ip,
  loadingFull,
  summary,
}: {
  ip: string;
  loadingFull: boolean;
  summary: IpIntelligenceSummary;
}) {
  if (summary.status === "listed") {
    return (
      <div>
        <p className="text-sm font-semibold text-white">
          {ip} has {summary.listing_count} intelligence {summary.listing_count === 1 ? "listing" : "listings"}.
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          {summary.datasets.map((dataset) => (
            <span
              key={`${dataset.code}-${dataset.dataset}`}
              className="rounded-md border border-signal/30 bg-signal/10 px-2 py-1 font-mono text-[10px] uppercase text-signal"
            >
              {dataset.dataset} / Code {dataset.code}
            </span>
          ))}
        </div>
        {loadingFull ? <p className="mt-3 text-xs leading-5 text-haze">Loading full dataset context...</p> : null}
      </div>
    );
  }

  if (summary.status === "not_listed") {
    return (
      <p className="text-sm leading-6 text-haze">
        {loadingFull ? "No current IP Data listing found. Checking additional context..." : NO_INTELLIGENCE_DATA}
      </p>
    );
  }

  return (
    <p className="text-sm leading-6 text-haze">
      {summary.status === "not_configured" ? "IP intelligence is not configured yet." : "IP intelligence is unavailable right now."}
    </p>
  );
}

function StatBlock({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-white/10 bg-black/25 p-4">
      <p className="font-mono text-[11px] uppercase text-haze">{label}</p>
      <p className="mt-2 break-words text-xl font-semibold leading-tight text-white">{value}</p>
    </div>
  );
}

function EmptyMapState({ loading, error }: { loading: boolean; error: string }) {
  return (
    <div className="absolute inset-0 z-[500] grid place-items-center bg-obsidian/80 px-6 text-center backdrop-blur-sm">
      {loading ? (
        <div>
          <Loader2 className="mx-auto animate-spin text-signal" size={34} />
          <p className="mt-4 font-mono text-xs uppercase text-signal">Fetching source locations</p>
          <p className="mt-2 text-sm text-haze">Querying the server-side AbuseIPDB map endpoint.</p>
        </div>
      ) : (
        <div>
          <AlertTriangle className="mx-auto text-trace" size={34} />
          <p className="mt-4 font-mono text-xs uppercase text-trace">Map data unavailable</p>
          <p className="mt-2 max-w-sm text-sm leading-6 text-haze">{error || "No usable coordinates were returned."}</p>
        </div>
      )}
    </div>
  );
}

function historyConnection(event: SpamhausHistoryEvent) {
  return [
    formatEndpoint(event.source_ip, event.source_port),
    formatEndpoint(event.destination_ip, event.destination_port),
  ].filter(Boolean);
}

function HistoricalEventDetail({ event }: { event: SpamhausHistoryEvent }) {
  const connection = historyConnection(event);

  return (
    <div className="mt-3 rounded-md border border-white/10 bg-white/[0.04] p-3">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="font-mono text-[10px] uppercase text-haze">Newest event</span>
        {event.dataset ? (
          <span className="rounded-md bg-signal px-2 py-1 font-mono text-[10px] font-semibold uppercase text-obsidian">
            {event.dataset}
          </span>
        ) : null}
      </div>
      <div className="grid gap-2 text-xs leading-5 text-haze md:grid-cols-2">
        {event.listed_at ? (
          <p>
            <span className="text-white">Date listed:</span> {formatDate(event.listed_at)}
          </p>
        ) : null}
        {event.removed_at || event.valid_until_at ? (
          <p>
            <span className="text-white">{event.removed_at ? "Date removed:" : "Valid until:"}</span>{" "}
            {formatDate(event.removed_at || event.valid_until_at)}
          </p>
        ) : null}
        {event.seen_at ? (
          <p>
            <span className="text-white">Most recent detection:</span> {formatDate(event.seen_at)}
          </p>
        ) : null}
        {connection.length ? (
          <p>
            <span className="text-white">Connection:</span> {connection.join(" -> ")}
            {event.protocol ? ` (${event.protocol})` : ""}
          </p>
        ) : null}
      </div>
      {event.detection ? <p className="mt-3 text-sm leading-6 text-white">{event.detection}</p> : null}
      {event.botname || event.heuristic ? (
        <p className="mt-2 text-xs leading-5 text-haze">
          {[event.botname ? `Bot: ${event.botname}` : "", event.heuristic ? `Heuristic: ${event.heuristic}` : ""].filter(Boolean).join(" / ")}
        </p>
      ) : null}
    </div>
  );
}

function HistoricalListing({ history }: { history: SpamhausHistory | null | undefined }) {
  if (!history) return null;

  if (history.status === "not_found") {
    return (
      <div className="mt-4 rounded-md border border-white/10 bg-white/[0.03] p-3">
        <p className="font-mono text-[10px] uppercase text-haze">Historical listings</p>
        <p className="mt-2 text-xs leading-5 text-haze">{NO_INTELLIGENCE_DATA}</p>
      </div>
    );
  }

  if (history.status === "unavailable") {
    return (
      <div className="mt-4 rounded-md border border-volt/20 bg-volt/10 p-3">
        <p className="font-mono text-[10px] uppercase text-volt">Historical listings unavailable</p>
        {history.warnings?.length ? <p className="mt-2 text-xs leading-5 text-haze">{history.warnings.join(" ")}</p> : null}
      </div>
    );
  }

  const events = history.events || [];
  const newest = events[0];

  if (!newest) {
    return (
      <div className="mt-4 rounded-md border border-white/10 bg-white/[0.03] p-3">
        <p className="font-mono text-[10px] uppercase text-haze">Historical listings</p>
        <p className="mt-2 text-xs leading-5 text-haze">{NO_INTELLIGENCE_DATA}</p>
      </div>
    );
  }

  return (
    <div className="mt-4 rounded-md border border-white/10 bg-white/[0.03] p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono text-[10px] uppercase text-haze">Historical listings</p>
        <span className="rounded-md border border-white/10 bg-black/25 px-2 py-1 font-mono text-[10px] uppercase text-haze">
          Last {events.length}
        </span>
      </div>
      <HistoricalEventDetail event={newest} />
    </div>
  );
}

function ProviderPanel({ children, title }: { children: ReactNode; title: string }) {
  return (
    <div className="rounded-md border border-white/10 bg-white/[0.035] p-3">
      <p className="font-mono text-[10px] uppercase text-signal">{title}</p>
      <div className="mt-3">{children}</div>
    </div>
  );
}

function AbuseCategoryBadges({ categories }: { categories: AbuseIpdbCategory[] }) {
  if (!categories.length) return null;

  return (
    <div className="mt-3 flex flex-wrap gap-2">
      {categories.map((category) => (
        <span
          key={`${category.id}-${category.label}`}
          className="rounded-md border border-cyan-300/25 bg-cyan-300/10 px-2 py-1 font-mono text-[10px] uppercase text-cyan-100"
        >
          {category.label}
          {category.count ? ` x${category.count}` : ""}
        </span>
      ))}
    </div>
  );
}

function AbuseIpdbIntelligence({
  detail,
  loading,
  selectedIp,
  summary,
}: {
  detail: AbuseIpdbDetail | null;
  loading: boolean;
  selectedIp: string;
  summary: AbuseIpdbSummary | null;
}) {
  const payload = detail || summary;
  if (!payload || payload.status !== "reported" || payload.total_reports <= 0) {
    return null;
  }

  const topCategories = detail?.top_categories?.length ? detail.top_categories : payload.top_categories || [];

  return (
    <ProviderPanel title="AbuseIPDB reports">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-white">
            {selectedIp} has {formatNumber(payload.total_reports)} reports from {formatNumber(payload.num_distinct_users)} distinct sources.
          </p>
          <p className="mt-1 text-xs leading-5 text-haze">
            Third-party reports about this source IP over the last {payload.max_age_in_days} days, not direct telemetry from this portfolio.
          </p>
        </div>
        <span className="rounded-md border border-white/10 bg-black/30 px-2 py-1 font-mono text-[10px] uppercase text-haze">
          {payload.cache_status}
        </span>
      </div>

      <div className="mt-3 grid gap-2 md:grid-cols-3">
        <div className="rounded-md border border-white/10 bg-black/20 p-3">
          <p className="font-mono text-[10px] uppercase text-haze">Report count</p>
          <p className="mt-1 text-lg font-semibold text-white">{formatNumber(payload.total_reports)}</p>
        </div>
        <div className="rounded-md border border-white/10 bg-black/20 p-3">
          <p className="font-mono text-[10px] uppercase text-haze">Reporters</p>
          <p className="mt-1 text-lg font-semibold text-white">{formatNumber(payload.num_distinct_users)}</p>
        </div>
        <div className="rounded-md border border-white/10 bg-black/20 p-3">
          <p className="font-mono text-[10px] uppercase text-haze">Last report</p>
          <p className="mt-1 text-sm font-semibold text-white">{formatDate(payload.last_reported_at)}</p>
        </div>
      </div>

      <div className="mt-3 grid gap-2 text-xs leading-5 text-haze md:grid-cols-2">
        {payload.usage_type ? (
          <p>
            <span className="text-white">Usage:</span> {payload.usage_type}
          </p>
        ) : null}
        {payload.isp || payload.domain ? (
          <p>
            <span className="text-white">Network:</span> {[payload.isp, payload.domain].filter(Boolean).join(" / ")}
          </p>
        ) : null}
        {payload.country_name || payload.country_code ? (
          <p>
            <span className="text-white">Country:</span> {payload.country_name || payload.country_code}
          </p>
        ) : null}
        {payload.is_tor || payload.is_whitelisted !== null ? (
          <p>
            <span className="text-white">Flags:</span>{" "}
            {[payload.is_tor ? "Tor" : "", payload.is_whitelisted === true ? "Whitelisted" : ""].filter(Boolean).join(", ") || "None returned"}
          </p>
        ) : null}
      </div>

      <AbuseCategoryBadges categories={topCategories} />

    </ProviderPanel>
  );
}

function SpamhausIntelligence({
  detail,
  loading,
  selectedIp,
  summary,
}: {
  detail: SpamhausDetail | null;
  loading: boolean;
  selectedIp: string;
  summary: IpIntelligenceSummary | null;
}) {
  if (detail?.status === "listed") {
    return (
      <ProviderPanel title="Spamhaus listings">
        <p className="text-sm font-semibold text-white">
          {detail.ip} has {detail.listing_count} intelligence {detail.listing_count === 1 ? "listing" : "listings"}.
        </p>
        <div className="mt-3 grid gap-2 lg:grid-cols-3">
          {detail.datasets.map((dataset) => (
            <div key={`${dataset.code}-${dataset.dataset}`} className="rounded-md border border-white/10 bg-white/[0.04] p-3">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <span className="rounded-md bg-signal px-2 py-1 font-mono text-[10px] font-semibold uppercase text-obsidian">
                  {dataset.dataset}
                </span>
                <span className="font-mono text-[10px] uppercase text-haze">Code {dataset.code}</span>
              </div>
              <p className="text-sm font-semibold text-white">{dataset.label}</p>
              <p className="mt-1 text-xs leading-5 text-haze">{dataset.explanation}</p>
            </div>
          ))}
        </div>
        <HistoricalListing history={detail.history} />
      </ProviderPanel>
    );
  }

  if (detail?.status === "not_listed" && (detail.history?.status === "found" || detail.history?.status === "unavailable")) {
    return (
      <ProviderPanel title="Spamhaus listings">
        <p className="text-sm leading-6 text-haze">No current IP Data listing found.</p>
        <HistoricalListing history={detail.history} />
      </ProviderPanel>
    );
  }

  if (summary?.status === "listed") {
    return (
      <ProviderPanel title="Spamhaus listings">
        <IntelligenceSummary ip={selectedIp} loadingFull={loading} summary={summary} />
      </ProviderPanel>
    );
  }

  return null;
}

function IpIntelligence({
  abuseDetail,
  abuseError,
  abuseLoading,
  abuseSummary,
  detail,
  error,
  loading,
  selectedIp,
  summary,
}: {
  abuseDetail: AbuseIpdbDetail | null;
  abuseError: string;
  abuseLoading: boolean;
  abuseSummary: AbuseIpdbSummary | null;
  detail: SpamhausDetail | null;
  error: string;
  loading: boolean;
  selectedIp: string;
  summary: IpIntelligenceSummary | null;
}) {
  const spamhausContent = (
    <SpamhausIntelligence detail={detail} loading={loading} selectedIp={selectedIp} summary={summary} />
  );
  const abuseContent = (
    <AbuseIpdbIntelligence detail={abuseDetail} loading={abuseLoading} selectedIp={selectedIp} summary={abuseSummary} />
  );
  const hasSpamhausContent = Boolean(
    detail?.status === "listed" ||
      summary?.status === "listed" ||
      (detail?.status === "not_listed" && (detail.history?.status === "found" || detail.history?.status === "unavailable")),
  );
  const hasAbuseContent = Boolean((abuseDetail || abuseSummary)?.status === "reported" && (abuseDetail || abuseSummary)?.total_reports);
  const isChecking = loading || abuseLoading;

  return (
    <div className="rounded-lg border border-white/10 bg-black/25 p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <p className="font-mono text-[11px] uppercase text-signal">IP Intelligence</p>
        {detail?.cache_status || summary?.cache_status || abuseDetail?.cache_status || abuseSummary?.cache_status ? (
          <span className="rounded-md border border-white/10 bg-black/30 px-2 py-1 font-mono text-[10px] uppercase text-haze">
            {detail?.cache_status || summary?.cache_status || abuseDetail?.cache_status || abuseSummary?.cache_status}
          </span>
        ) : null}
      </div>

      {!selectedIp ? (
        <p className="text-sm leading-6 text-haze">Select a source to check IP intelligence.</p>
      ) : hasSpamhausContent || hasAbuseContent ? (
        <div className="grid gap-3">
          {abuseContent}
          {spamhausContent}
        </div>
      ) : isChecking ? (
        <div className="flex items-center gap-2 text-sm text-haze">
          <Loader2 className="animate-spin text-signal" size={15} />
          Checking IP intelligence...
        </div>
      ) : (
        <p className="text-sm leading-6 text-haze">{NO_INTELLIGENCE_DATA}</p>
      )}

      {detail?.warnings?.length ? (
        <p className="mt-3 text-xs leading-5 text-volt">{detail.warnings.join(" ")}</p>
      ) : null}
      {error && !hasSpamhausContent ? <p className="mt-3 text-xs leading-5 text-trace">{error}</p> : null}
      {abuseDetail?.warnings?.length ? (
        <p className="mt-3 text-xs leading-5 text-volt">{abuseDetail.warnings.join(" ")}</p>
      ) : null}
      {abuseError && !hasAbuseContent ? <p className="mt-3 text-xs leading-5 text-trace">{abuseError}</p> : null}
    </div>
  );
}

export function LiveThreatMapPage() {
  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const markerLayerRef = useRef<L.LayerGroup | null>(null);
  const markerRefs = useRef(new Map<string, L.Marker>());
  const fittedPointsSignatureRef = useRef("");
  const spamhausCacheRef = useRef(new Map<string, SpamhausDetail>());
  const abuseIpdbCacheRef = useRef(new Map<string, AbuseIpdbDetail>());
  const [data, setData] = useState<ThreatOriginResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [spamhausDetail, setSpamhausDetail] = useState<SpamhausDetail | null>(null);
  const [spamhausLoading, setSpamhausLoading] = useState(false);
  const [spamhausError, setSpamhausError] = useState("");
  const [abuseIpdbDetail, setAbuseIpdbDetail] = useState<AbuseIpdbDetail | null>(null);
  const [abuseIpdbLoading, setAbuseIpdbLoading] = useState(false);
  const [abuseIpdbError, setAbuseIpdbError] = useState("");
  const [mapReady, setMapReady] = useState(false);

  const points = data?.points || [];
  const selectedPoint = points.find((point) => point.id === selectedId) || points[0] || null;
  const countryCount = useMemo(() => new Set(points.map((point) => point.country_code || point.country).filter(Boolean)).size, [points]);
  const refreshCycle = data?.mode === "live" ? "24h" : "Demo";
  const nextRefresh = data?.next_refresh_at ? formatDate(data.next_refresh_at) : "Not scheduled";

  const loadThreatOrigins = () => {
    setLoading(true);
    setError("");

    fetch("/api/abuse-origin-map", {
      cache: "no-store",
      headers: {
        Accept: "application/json",
      },
    })
      .then((response) => readJson<ThreatOriginResponse>(response))
      .then((payload) => {
        setData(payload);
        setSelectedId(payload.points[0]?.id || "");
      })
      .catch((loadError) => {
        setError(loadError instanceof Error ? loadError.message : "Threat origin data is temporarily unavailable.");
        setData(null);
        setSelectedId("");
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadThreatOrigins();
  }, []);

  useEffect(() => {
    if (!selectedPoint?.ip) {
      setSpamhausDetail(null);
      setSpamhausError("");
      setSpamhausLoading(false);
      return;
    }

    if (data?.mode !== "live") {
      setSpamhausDetail({
        ip: selectedPoint.ip,
        status: "unavailable",
        listing_count: 0,
        codes: [],
        datasets: [],
        generated_at: new Date().toISOString(),
        cache_status: "fresh",
        cache_expires_at: "",
        warnings: ["IP intelligence is available after the live daily AbuseIPDB map loads."],
      });
      setSpamhausError("");
      setSpamhausLoading(false);
      return;
    }

    const cachedDetail = spamhausCacheRef.current.get(selectedPoint.ip);
    if (cachedDetail) {
      setSpamhausDetail(cachedDetail);
      setSpamhausError("");
      setSpamhausLoading(false);
      return;
    }

    const controller = new AbortController();
    setSpamhausLoading(true);
    setSpamhausError("");
    setSpamhausDetail(null);

    fetch(`/api/spamhaus-ip-detail?ip=${encodeURIComponent(selectedPoint.ip)}`, {
      headers: {
        Accept: "application/json",
      },
      signal: controller.signal,
    })
      .then((response) => readJson<SpamhausDetail>(response))
      .then((payload) => {
        spamhausCacheRef.current.set(selectedPoint.ip, payload);
        setSpamhausDetail(payload);
      })
      .catch((loadError) => {
        if (loadError instanceof DOMException && loadError.name === "AbortError") return;
        setSpamhausError(loadError instanceof Error ? loadError.message : "IP intelligence is temporarily unavailable.");
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setSpamhausLoading(false);
        }
      });

    return () => controller.abort();
  }, [data?.mode, selectedPoint?.ip]);

  useEffect(() => {
    if (!selectedPoint?.ip) {
      setAbuseIpdbDetail(null);
      setAbuseIpdbError("");
      setAbuseIpdbLoading(false);
      return;
    }

    if (data?.mode !== "live") {
      setAbuseIpdbDetail(null);
      setAbuseIpdbError("");
      setAbuseIpdbLoading(false);
      return;
    }

    const cachedDetail = abuseIpdbCacheRef.current.get(selectedPoint.ip);
    if (cachedDetail) {
      setAbuseIpdbDetail(cachedDetail);
      setAbuseIpdbError("");
      setAbuseIpdbLoading(false);
      return;
    }

    const controller = new AbortController();
    setAbuseIpdbLoading(true);
    setAbuseIpdbError("");
    setAbuseIpdbDetail(null);

    fetch(`/api/abuseipdb-ip-detail?ip=${encodeURIComponent(selectedPoint.ip)}`, {
      headers: {
        Accept: "application/json",
      },
      signal: controller.signal,
    })
      .then((response) => readJson<AbuseIpdbDetail>(response))
      .then((payload) => {
        abuseIpdbCacheRef.current.set(selectedPoint.ip, payload);
        setAbuseIpdbDetail(payload);
      })
      .catch((loadError) => {
        if (loadError instanceof DOMException && loadError.name === "AbortError") return;
        setAbuseIpdbError(loadError instanceof Error ? loadError.message : "AbuseIPDB intelligence is temporarily unavailable.");
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setAbuseIpdbLoading(false);
        }
      });

    return () => controller.abort();
  }, [data?.mode, selectedPoint?.ip]);

  useEffect(() => {
    let createdMap: L.Map | null = null;

    if (!mapContainerRef.current || mapRef.current) return undefined;

    const map = L.map(mapContainerRef.current, {
      attributionControl: true,
      minZoom: 2,
      maxZoom: 8,
      scrollWheelZoom: true,
      worldCopyJump: true,
      zoomControl: false,
    }).setView([20, 0], 2);
    createdMap = map;

    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
      maxZoom: 8,
      subdomains: "abcd",
    }).addTo(map);
    L.control.zoom({ position: "bottomright" }).addTo(map);

    markerLayerRef.current = L.layerGroup().addTo(map);
    mapRef.current = map;
    setMapReady(true);
    window.setTimeout(() => map.invalidateSize(), 80);

    return () => {
      markerRefs.current.clear();
      markerLayerRef.current = null;
      const map = mapRef.current || createdMap;
      mapRef.current = null;
      map?.remove();
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    const markerLayer = markerLayerRef.current;
    if (!mapReady || !map || !markerLayer) return;

    markerLayer.clearLayers();
    markerRefs.current.clear();

    if (!points.length) {
      fittedPointsSignatureRef.current = "";
      return;
    }

    const bounds = L.latLngBounds([]);
    const pointsSignature = points.map((point) => `${point.id}:${point.latitude}:${point.longitude}`).join("|");

    points.forEach((point) => {
      const tooltip = document.createElement("div");
      tooltip.className = "threat-map-tooltip__content";

      const tooltipIp = document.createElement("div");
      tooltipIp.className = "threat-map-tooltip__ip";
      tooltipIp.textContent = point.ip;

      const tooltipLocation = document.createElement("div");
      tooltipLocation.className = "threat-map-tooltip__location";
      tooltipLocation.textContent = formatLocation(point);

      const tooltipMeta = document.createElement("div");
      tooltipMeta.className = "threat-map-tooltip__grid";
      tooltipMeta.append(
        Object.assign(document.createElement("span"), { textContent: "Daily rank" }),
        Object.assign(document.createElement("strong"), { textContent: `#${point.rank || "?"}` }),
        Object.assign(document.createElement("span"), { textContent: "Last report" }),
        Object.assign(document.createElement("strong"), { textContent: formatDate(point.last_reported_at) }),
      );

      tooltip.append(tooltipIp, tooltipLocation, tooltipMeta);

      const marker = L.marker([point.latitude, point.longitude], {
        icon: createThreatMarkerIcon(point, selectedPoint?.id === point.id),
        title: `${point.ip} / ${formatLocation(point)}`,
        zIndexOffset: selectedPoint?.id === point.id ? 1000 : point.rank ? MAX_DAILY_POINTS - point.rank : 0,
      })
        .on("click", () => setSelectedId(point.id));

      marker.bindTooltip(tooltip, {
        className: "threat-map-tooltip",
        direction: "top",
        offset: [0, -8],
      });

      marker.addTo(markerLayer);
      markerRefs.current.set(point.id, marker);
      bounds.extend([point.latitude, point.longitude]);
    });

    if (bounds.isValid() && fittedPointsSignatureRef.current !== pointsSignature) {
      map.fitBounds(bounds.pad(0.18), {
        animate: false,
        maxZoom: points.length === 1 ? 4 : 3,
      });
      fittedPointsSignatureRef.current = pointsSignature;
    }
  }, [mapReady, points, selectedPoint?.id]);

  const focusPoint = (point: ThreatPoint) => {
    setSelectedId(point.id);
    mapRef.current?.setView([point.latitude, point.longitude], Math.max(mapRef.current.getZoom(), 4), { animate: true });
  };

  return (
    <div className="live-threat-map-page relative min-h-screen px-5 py-6">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(252,238,10,0.13),transparent_25%),radial-gradient(circle_at_82%_16%,rgba(34,211,238,0.12),transparent_24%),linear-gradient(180deg,rgba(5,7,13,0.52),#05070d_82%)]" aria-hidden="true" />

      <nav className="relative z-10 mx-auto flex max-w-[1720px] flex-wrap items-center justify-between gap-3 rounded-lg border border-white/10 bg-obsidian/82 px-4 py-3 backdrop-blur-xl">
        <a href="/" className="inline-flex items-center gap-2 text-sm font-semibold uppercase text-white transition hover:text-signal">
          <ArrowLeft size={16} />
          Home
        </a>
        <span className="inline-flex items-center gap-2 rounded-md border border-signal/25 bg-signal/10 px-3 py-2 font-mono text-xs uppercase text-signal">
          <Radar size={15} />
          Daily Top 50
        </span>
      </nav>

      <div className="relative z-10 mx-auto grid max-w-[1720px] gap-5 py-6 md:py-8">
        <header className="rounded-lg border border-white/10 bg-obsidian/82 p-5 shadow-glow backdrop-blur-xl md:p-6">
          <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_360px] lg:items-end">
            <div>
              <p className="font-mono text-xs uppercase text-signal">Daily Top 50 AbuseIPDB sources</p>
              <h1 className="mt-2 max-w-4xl text-3xl font-semibold leading-tight text-white md:text-5xl">
                Daily Top 50 Threat Origin Map.
              </h1>
              <p className="mt-4 max-w-3xl text-base leading-8 text-haze">
                Smaller source markers show approximate geo-IP locations from the daily cached AbuseIPDB blacklist snapshot. It represents reported abusive source locations, not live attack volume.
              </p>
            </div>
            <div className={`rounded-lg border p-4 ${data?.mode === "live" ? "border-signal/35 bg-signal/10" : "border-volt/35 bg-volt/10"}`}>
              <div className={`mb-2 flex items-center gap-2 font-mono text-[11px] uppercase ${data?.mode === "live" ? "text-signal" : "text-volt"}`}>
                <ShieldAlert size={16} />
                {cacheStatusLabel(data?.cache_status)}
              </div>
              <div className="grid gap-2 text-sm leading-6 text-haze">
                <p>Refreshes every 24 hours.</p>
                <p>Last updated {formatDate(data?.generated_at)}.</p>
                <p>Next refresh {nextRefresh}.</p>
              </div>
            </div>
          </div>
        </header>

        {data?.warnings?.length ? (
          <div className="rounded-lg border border-volt/35 bg-volt/10 p-4 text-sm leading-6 text-haze">
            <div className="mb-2 flex items-center gap-2 font-mono text-xs uppercase text-volt">
              <AlertTriangle size={16} />
              Provider note
            </div>
            {data.warnings.join(" ")}
          </div>
        ) : null}

        <section className="grid gap-5">
          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
            <div>
              <div className="overflow-hidden rounded-lg border border-white/10 bg-white/[0.04]">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-4 py-3">
                  <div className="flex items-center gap-2 font-mono text-xs uppercase text-signal">
                    <Globe2 size={16} />
                    Daily source marker layer
                  </div>
                  <button
                    type="button"
                    onClick={loadThreatOrigins}
                    disabled={loading}
                    className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-white/10 bg-black/25 px-3 text-sm font-medium text-white transition hover:border-signal/45 hover:text-signal disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {loading ? <Loader2 className="animate-spin" size={15} /> : <RotateCcw size={15} />}
                    Reload cache
                  </button>
                </div>
                <div className="relative">
                  <div ref={mapContainerRef} className="threat-origin-map h-[58vh] min-h-[420px] w-full" aria-label="Reported abusive IP source map" />
                  {(loading || (!points.length && error)) && <EmptyMapState loading={loading} error={error} />}
                </div>
              </div>
            </div>

            <aside className="grid content-start gap-4">
              <div className="grid grid-cols-2 gap-3">
                <StatBlock label="Mapped IPs" value={String(points.length)} />
                <StatBlock label="Countries" value={String(countryCount)} />
                <StatBlock label="Refresh cycle" value={refreshCycle} />
                <StatBlock label="Next refresh" value={nextRefresh} />
              </div>

              {selectedPoint ? (
                <div className="rounded-lg border border-signal/25 bg-signal/10 p-4">
                  <div className="mb-3 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                    <MapPin size={16} />
                    Selected source
                  </div>
                  <h2 className="text-xl font-semibold text-white">{selectedPoint.ip}</h2>
                  <p className="mt-2 leading-6 text-haze">{formatLocation(selectedPoint)}</p>
                  <div className="mt-4 grid gap-3 text-sm">
                    <div className="flex justify-between gap-4">
                      <span className="text-haze">Daily rank</span>
                      <strong className="text-white">#{selectedPoint.rank || "?"}</strong>
                    </div>
                    <div className="flex justify-between gap-4">
                      <span className="text-haze">Last report</span>
                      <strong className="text-right text-white">{formatDate(selectedPoint.last_reported_at)}</strong>
                    </div>
                    <div>
                      <span className="text-haze">Network</span>
                      <p className="mt-1 text-white">{selectedPoint.as_name || selectedPoint.org || selectedPoint.isp || "Unknown network"}</p>
                    </div>
                  </div>
                </div>
              ) : null}
            </aside>
          </div>

          <IpIntelligence
            abuseDetail={abuseIpdbDetail}
            abuseError={abuseIpdbError}
            abuseLoading={abuseIpdbLoading}
            abuseSummary={selectedPoint?.abuseipdb_intelligence || null}
            detail={spamhausDetail}
            error={spamhausError}
            loading={spamhausLoading}
            selectedIp={selectedPoint?.ip || ""}
            summary={selectedPoint?.ip_intelligence || null}
          />

          <div className="rounded-lg border border-white/10 bg-white/[0.04] p-4">
            <div className="mb-3 flex items-center justify-between gap-3">
              <p className="font-mono text-xs uppercase text-signal">Daily Top 50 ranking</p>
              <span className="rounded-md border border-white/10 bg-black/25 px-2 py-1 font-mono text-[11px] uppercase text-haze">
                {data?.cache_status || "loading"}
              </span>
            </div>
            <div className="max-h-[360px] overflow-y-auto pr-1">
              <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
                {points
                  .slice()
                  .sort((left, right) => (left.rank || MAX_DAILY_POINTS) - (right.rank || MAX_DAILY_POINTS))
                  .map((point) => (
                    <button
                      key={point.id}
                      type="button"
                      onClick={() => focusPoint(point)}
                      className={`min-h-[82px] rounded-md border p-3 text-left transition ${
                        selectedPoint?.id === point.id
                          ? "border-signal/55 bg-signal/10"
                          : "border-white/10 bg-black/20 hover:border-signal/35 hover:bg-white/[0.06]"
                      }`}
                    >
                      <span className="flex h-full items-center justify-between gap-3">
                        <span className="min-w-0">
                          <span className="block truncate text-sm font-semibold text-white">{point.ip}</span>
                          <span className="mt-1 block truncate text-xs text-haze">{formatLocation(point)}</span>
                        </span>
                        <span className="shrink-0 rounded-md px-2 py-1 text-sm font-semibold text-obsidian" style={{ backgroundColor: rankTone(point.rank || MAX_DAILY_POINTS) }}>
                          #{point.rank || "?"}
                        </span>
                      </span>
                    </button>
                  ))}
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
