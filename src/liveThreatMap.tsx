import "leaflet/dist/leaflet.css";

import L from "leaflet";
import {
  AlertTriangle,
  ArrowLeft,
  BarChart3,
  Bug,
  Globe2,
  Loader2,
  MapPin,
  Network,
  Radar,
  RotateCcw,
  ShieldAlert,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

type ThreatPoint = {
  id: string;
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
  usage_type?: string;
};

type ThreatOriginResponse = {
  mode: "live" | "fallback";
  generated_at: string;
  source: string;
  points: ThreatPoint[];
  warnings: string[];
};

type ThreatCategory = {
  id: number;
  label: string;
  count?: number;
};

type ThreatReport = {
  id: string;
  reported_at: string;
  comment: string;
  categories: ThreatCategory[];
};

type ThreatDetailResponse = {
  mode: "live" | "unavailable";
  ip: string;
  generated_at: string;
  available: boolean;
  total_reports: number | null;
  distinct_reporters: number | null;
  usage_type: string;
  domain: string;
  hostnames: string[];
  categories: ThreatCategory[];
  recent_reports: ThreatReport[];
  warnings: string[];
};

type BarRow = {
  label: string;
  value: number;
  meta?: string;
};

function escapeHtml(value: unknown) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => {
    const entities: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    };

    return entities[character] || character;
  });
}

function readJson<T>(response: Response): Promise<T> {
  return response.json().then((body) => {
    if (!response.ok) {
      throw new Error(body?.message || "Threat origin data is temporarily unavailable.");
    }

    return body as T;
  });
}

function formatDate(value: string) {
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

function formatLocation(point: ThreatPoint) {
  const city = point.city && point.city !== "Unknown city" ? point.city : "";
  const country = point.country || point.country_code || "Unknown";

  return [city, country].filter(Boolean).join(", ");
}

function countryKey(point: ThreatPoint) {
  return point.country_code || point.country || "unknown";
}

function countryLabel(point: ThreatPoint) {
  return point.country_code ? `${point.country} (${point.country_code})` : point.country || "Unknown";
}

function networkLabel(point: ThreatPoint) {
  return point.as_name || point.org || point.isp || point.asn || "Unknown network";
}

function markerTone(point: ThreatPoint) {
  if (point.proxy) return "#ff2a3d";
  if (point.hosting) return "#fcee0a";
  if (point.mobile) return "#22d3ee";
  return "#8aff80";
}

function markerSize(point: ThreatPoint) {
  if (point.proxy || point.hosting) return 24;
  return 19;
}

function dateSortValue(value: string) {
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? time : 0;
}

function tooltipHtml(point: ThreatPoint) {
  const flags = [
    point.hosting ? "Hosting" : "",
    point.proxy ? "Proxy/VPN" : "",
    point.mobile ? "Mobile" : "",
  ].filter(Boolean);

  return `
    <div class="threat-map-tooltip__content">
      <div class="threat-map-tooltip__ip">${escapeHtml(point.ip)}</div>
      <div class="threat-map-tooltip__location">${escapeHtml(formatLocation(point))}</div>
      <div class="threat-map-tooltip__grid">
        <span>Last report</span><strong>${escapeHtml(formatDate(point.last_reported_at))}</strong>
        <span>Network</span><strong>${escapeHtml(networkLabel(point))}</strong>
        <span>Action</span><strong>Click to inspect reports</strong>
      </div>
      ${flags.length ? `<div class="threat-map-tooltip__flags">${flags.map((flag) => `<span>${escapeHtml(flag)}</span>`).join("")}</div>` : ""}
    </div>
  `;
}

function countRows<T>(items: T[], getKey: (item: T) => string, getMeta?: (item: T) => string): BarRow[] {
  const counts = new Map<string, BarRow>();

  items.forEach((item) => {
    const label = getKey(item).trim() || "Unknown";
    const existing = counts.get(label) || { label, value: 0, meta: getMeta?.(item) };
    existing.value += 1;
    counts.set(label, existing);
  });

  return Array.from(counts.values()).sort((left, right) => right.value - left.value || left.label.localeCompare(right.label));
}

function flagRows(points: ThreatPoint[]): BarRow[] {
  const rows = [
    { label: "Hosting", value: points.filter((point) => point.hosting).length },
    { label: "Proxy/VPN", value: points.filter((point) => point.proxy).length },
    { label: "Mobile", value: points.filter((point) => point.mobile).length },
    { label: "Other", value: points.filter((point) => !point.hosting && !point.proxy && !point.mobile).length },
  ];

  return rows.filter((row) => row.value > 0);
}

function StatBlock({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-white/10 bg-black/25 p-4">
      <p className="font-mono text-[11px] uppercase text-haze">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-white">{value}</p>
    </div>
  );
}

function BarList({ rows, limit = 5 }: { rows: BarRow[]; limit?: number }) {
  const visibleRows = rows.slice(0, limit);
  const maxValue = Math.max(...visibleRows.map((row) => row.value), 1);

  if (!visibleRows.length) {
    return <p className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-haze">No mapped rows for this country.</p>;
  }

  return (
    <div className="grid gap-2">
      {visibleRows.map((row) => (
        <div key={`${row.label}-${row.meta || ""}`} className="rounded-md border border-white/10 bg-black/20 p-3">
          <div className="mb-2 flex items-center justify-between gap-3 text-sm">
            <span className="min-w-0 truncate font-medium text-white">{row.label}</span>
            <span className="shrink-0 font-mono text-xs text-signal">{row.value}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-white/10">
            <span className="block h-full rounded-full bg-signal" style={{ width: `${Math.max(8, (row.value / maxValue) * 100)}%` }} />
          </div>
          {row.meta ? <p className="mt-2 truncate text-xs text-haze">{row.meta}</p> : null}
        </div>
      ))}
    </div>
  );
}

function CategoryChips({ categories }: { categories: ThreatCategory[] }) {
  if (!categories.length) {
    return <p className="text-sm leading-6 text-haze">No attack categories returned for the recent verbose reports.</p>;
  }

  return (
    <div className="flex flex-wrap gap-2">
      {categories.map((category) => (
        <span key={`${category.id}-${category.label}`} className="rounded-md border border-trace/30 bg-trace/10 px-2.5 py-1.5 text-xs font-medium text-cyan-100">
          {category.label}
          {typeof category.count === "number" ? ` x${category.count}` : ""}
        </span>
      ))}
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

export function LiveThreatMapPage() {
  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const layerRef = useRef<L.LayerGroup | null>(null);
  const markerRefs = useRef(new Map<string, L.Marker>());
  const [data, setData] = useState<ThreatOriginResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [selectedCountryKey, setSelectedCountryKey] = useState("");
  const [detailsByIp, setDetailsByIp] = useState<Record<string, ThreatDetailResponse>>({});
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");

  const points = data?.points || [];
  const selectedPoint = points.find((point) => point.id === selectedId) || points[0] || null;
  const canLoadDetail = data?.mode === "live" && selectedPoint?.source === "abuseipdb_blacklist";
  const selectedDetail = selectedPoint && canLoadDetail ? detailsByIp[selectedPoint.ip] : undefined;
  const countryCount = useMemo(() => new Set(points.map((point) => countryKey(point)).filter(Boolean)).size, [points]);
  const networkCount = useMemo(() => new Set(points.map(networkLabel).filter((label) => label !== "Unknown network")).size, [points]);
  const flaggedSourceCount = useMemo(() => points.filter((point) => point.hosting || point.proxy || point.mobile).length, [points]);
  const countryRows = useMemo(
    () =>
      countRows(
        points,
        (point) => countryLabel(point),
        (point) => countryKey(point),
      ),
    [points],
  );
  const selectedCountryPoints = useMemo(() => points.filter((point) => countryKey(point) === selectedCountryKey), [points, selectedCountryKey]);
  const selectedCountryLabel = selectedCountryPoints[0] ? countryLabel(selectedCountryPoints[0]) : selectedPoint ? countryLabel(selectedPoint) : "No country selected";
  const cityRows = useMemo(() => countRows(selectedCountryPoints, (point) => point.city || point.region || "Unknown city"), [selectedCountryPoints]);
  const networkRows = useMemo(() => countRows(selectedCountryPoints, networkLabel), [selectedCountryPoints]);
  const selectedCountryFlagRows = useMemo(() => flagRows(selectedCountryPoints), [selectedCountryPoints]);

  const selectPoint = (point: ThreatPoint, focusMap = true) => {
    setSelectedId(point.id);
    setSelectedCountryKey(countryKey(point));

    if (focusMap) {
      mapRef.current?.setView([point.latitude, point.longitude], Math.max(mapRef.current.getZoom(), 4), { animate: true });
      markerRefs.current.get(point.id)?.openTooltip();
    }
  };

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
        setSelectedCountryKey(payload.points[0] ? countryKey(payload.points[0]) : "");
      })
      .catch((loadError) => {
        setError(loadError instanceof Error ? loadError.message : "Threat origin data is temporarily unavailable.");
        setData(null);
        setSelectedId("");
        setSelectedCountryKey("");
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadThreatOrigins();
  }, []);

  useEffect(() => {
    if (!selectedPoint || !canLoadDetail || detailsByIp[selectedPoint.ip]) {
      setDetailLoading(false);
      setDetailError("");
      return;
    }

    const controller = new AbortController();
    setDetailLoading(true);
    setDetailError("");

    fetch(`/api/abuse-origin-detail?ip=${encodeURIComponent(selectedPoint.ip)}`, {
      cache: "no-store",
      headers: {
        Accept: "application/json",
      },
      signal: controller.signal,
    })
      .then((response) => readJson<ThreatDetailResponse>(response))
      .then((payload) => {
        setDetailsByIp((existing) => ({
          ...existing,
          [selectedPoint.ip]: payload,
        }));
      })
      .catch((detailLoadError) => {
        if (controller.signal.aborted) return;
        setDetailError(detailLoadError instanceof Error ? detailLoadError.message : "Threat detail is temporarily unavailable.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setDetailLoading(false);
      });

    return () => controller.abort();
  }, [canLoadDetail, detailsByIp, selectedPoint]);

  useEffect(() => {
    if (!mapContainerRef.current || mapRef.current) return;

    const map = L.map(mapContainerRef.current, {
      attributionControl: true,
      minZoom: 2,
      maxZoom: 8,
      scrollWheelZoom: true,
      worldCopyJump: true,
      zoomControl: false,
    }).setView([20, 0], 2);

    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
      maxZoom: 8,
      subdomains: "abcd",
    }).addTo(map);
    L.control.zoom({ position: "bottomright" }).addTo(map);

    layerRef.current = L.layerGroup().addTo(map);
    mapRef.current = map;
    window.setTimeout(() => map.invalidateSize(), 80);

    return () => {
      markerRefs.current.clear();
      layerRef.current = null;
      mapRef.current = null;
      map.remove();
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    const layer = layerRef.current;
    if (!map || !layer) return;

    layer.clearLayers();
    markerRefs.current.clear();

    if (!points.length) return;

    const bounds = L.latLngBounds([]);

    points.forEach((point) => {
      const color = markerTone(point);
      const size = markerSize(point);
      const icon = L.divIcon({
        className: "",
        html: `<span class="threat-pulse-marker" style="--marker-color:${color};--marker-size:${size}px"></span>`,
        iconAnchor: [size / 2, size / 2],
        iconSize: [size, size],
      });
      const marker = L.marker([point.latitude, point.longitude], {
        icon,
        title: `${point.ip} / ${formatLocation(point)}`,
      })
        .bindTooltip(tooltipHtml(point), {
          className: "threat-map-tooltip",
          direction: "top",
          offset: [0, -10],
          opacity: 0.98,
        })
        .on("click", () => selectPoint(point, false));

      marker.addTo(layer);
      markerRefs.current.set(point.id, marker);
      bounds.extend([point.latitude, point.longitude]);
    });

    if (bounds.isValid()) {
      map.fitBounds(bounds.pad(0.18), {
        animate: false,
        maxZoom: points.length === 1 ? 4 : 3,
      });
    }
  }, [points]);

  return (
    <div className="live-threat-map-page relative min-h-screen px-5 py-6">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(252,238,10,0.13),transparent_25%),radial-gradient(circle_at_82%_16%,rgba(34,211,238,0.12),transparent_24%),linear-gradient(180deg,rgba(5,7,13,0.52),#05070d_82%)]" aria-hidden="true" />

      <nav className="relative z-10 mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 rounded-lg border border-white/10 bg-obsidian/82 px-4 py-3 backdrop-blur-xl">
        <a href="/" className="inline-flex items-center gap-2 text-sm font-semibold uppercase text-white transition hover:text-signal">
          <ArrowLeft size={16} />
          Home
        </a>
        <span className="inline-flex items-center gap-2 rounded-md border border-signal/25 bg-signal/10 px-3 py-2 font-mono text-xs uppercase text-signal">
          <Radar size={15} />
          AbuseIPDB source map
        </span>
      </nav>

      <div className="relative z-10 mx-auto grid max-w-7xl gap-5 py-6 md:py-8">
        <header className="rounded-lg border border-white/10 bg-obsidian/82 p-5 shadow-glow backdrop-blur-xl md:p-6">
          <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_320px] lg:items-end">
            <div>
              <p className="font-mono text-xs uppercase text-signal">Reported abusive IP geolocation</p>
              <h1 className="mt-2 max-w-4xl text-3xl font-semibold leading-tight text-white md:text-5xl">
                Live Threat Origin Map.
              </h1>
              <p className="mt-4 max-w-3xl text-base leading-8 text-haze">
                Pulsing points show approximate source locations for recently reported abusive IPs. Selecting a point fetches AbuseIPDB report categories for that IP only.
              </p>
            </div>
            <div className={`rounded-lg border p-4 ${data?.mode === "live" ? "border-signal/35 bg-signal/10" : "border-volt/35 bg-volt/10"}`}>
              <div className={`mb-2 flex items-center gap-2 font-mono text-[11px] uppercase ${data?.mode === "live" ? "text-signal" : "text-volt"}`}>
                <ShieldAlert size={16} />
                {data?.mode === "live" ? "Live provider data" : loading ? "Checking provider" : "Demo fallback"}
              </div>
              <p className="text-sm leading-6 text-haze">
                Generated {data?.generated_at ? formatDate(data.generated_at) : "after provider response"}.
              </p>
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

        <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_400px]">
          <div className="grid gap-5">
            <div className="overflow-hidden rounded-lg border border-white/10 bg-white/[0.04]">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-4 py-3">
                <div className="flex items-center gap-2 font-mono text-xs uppercase text-signal">
                  <Globe2 size={16} />
                  Source geolocation layer
                </div>
                <button
                  type="button"
                  onClick={loadThreatOrigins}
                  disabled={loading}
                  className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-white/10 bg-black/25 px-3 text-sm font-medium text-white transition hover:border-signal/45 hover:text-signal disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {loading ? <Loader2 className="animate-spin" size={15} /> : <RotateCcw size={15} />}
                  Refresh
                </button>
              </div>
              <div className="relative">
                <div ref={mapContainerRef} className="threat-origin-map h-[62vh] min-h-[430px] w-full" aria-label="Reported abusive IP source map" />
                {(loading || (!points.length && error)) && <EmptyMapState loading={loading} error={error} />}
              </div>
            </div>

            <div className="grid gap-4 rounded-lg border border-white/10 bg-white/[0.04] p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="mb-2 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                    <BarChart3 size={16} />
                    Country drilldown
                  </div>
                  <h2 className="text-2xl font-semibold text-white">{selectedCountryLabel}</h2>
                  <p className="mt-2 text-sm leading-6 text-haze">Breakdown is based only on the current mapped AbuseIPDB sample.</p>
                </div>
                <span className="rounded-md border border-white/10 bg-black/25 px-3 py-2 font-mono text-xs uppercase text-haze">
                  {selectedCountryPoints.length} mapped IPs
                </span>
              </div>

              <div className="grid gap-4 lg:grid-cols-3">
                <div>
                  <p className="mb-3 font-mono text-[11px] uppercase text-haze">Cities / locations</p>
                  <BarList rows={cityRows} />
                </div>
                <div>
                  <p className="mb-3 font-mono text-[11px] uppercase text-haze">Networks</p>
                  <BarList rows={networkRows} />
                </div>
                <div>
                  <p className="mb-3 font-mono text-[11px] uppercase text-haze">Infrastructure flags</p>
                  <BarList rows={selectedCountryFlagRows} />
                </div>
              </div>

              <div>
                <p className="mb-3 font-mono text-[11px] uppercase text-haze">IPs in selected country</p>
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {selectedCountryPoints.map((point) => (
                    <button
                      key={point.id}
                      type="button"
                      onClick={() => selectPoint(point)}
                      className={`rounded-md border p-3 text-left transition ${
                        selectedPoint?.id === point.id ? "border-signal/55 bg-signal/10" : "border-white/10 bg-black/20 hover:border-signal/35 hover:bg-white/[0.06]"
                      }`}
                    >
                      <span className="block truncate text-sm font-semibold text-white">{point.ip}</span>
                      <span className="mt-1 block truncate text-xs text-haze">{networkLabel(point)}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <aside className="grid content-start gap-4">
            <div className="grid grid-cols-2 gap-3">
              <StatBlock label="Mapped IPs" value={String(points.length)} />
              <StatBlock label="Countries" value={String(countryCount)} />
              <StatBlock label="Networks" value={String(networkCount)} />
              <StatBlock label="Flagged infra" value={String(flaggedSourceCount)} />
            </div>

            {selectedPoint ? (
              <div className="rounded-lg border border-signal/25 bg-signal/10 p-4">
                <div className="mb-3 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                  <Bug size={16} />
                  Selected source detail
                </div>
                <h2 className="text-xl font-semibold text-white">{selectedPoint.ip}</h2>
                <p className="mt-2 leading-6 text-haze">{formatLocation(selectedPoint)}</p>
                <div className="mt-4 grid gap-3 text-sm">
                  <div className="flex justify-between gap-4">
                    <span className="text-haze">Last report</span>
                    <strong className="text-right text-white">{formatDate(selectedPoint.last_reported_at)}</strong>
                  </div>
                  <div>
                    <span className="text-haze">Network</span>
                    <p className="mt-1 text-white">{networkLabel(selectedPoint)}</p>
                  </div>
                  <div>
                    <span className="text-haze">Usage type</span>
                    <p className="mt-1 text-white">{selectedDetail?.usage_type || selectedPoint.usage_type || "Unknown"}</p>
                  </div>
                </div>

                <div className="mt-5 grid grid-cols-2 gap-3">
                  <StatBlock label="Reports" value={detailLoading && !selectedDetail ? "..." : selectedDetail?.total_reports !== null && selectedDetail?.total_reports !== undefined ? String(selectedDetail.total_reports) : "N/A"} />
                  <StatBlock label="Reporters" value={detailLoading && !selectedDetail ? "..." : selectedDetail?.distinct_reporters !== null && selectedDetail?.distinct_reporters !== undefined ? String(selectedDetail.distinct_reporters) : "N/A"} />
                </div>

                <div className="mt-5">
                  <p className="mb-3 font-mono text-[11px] uppercase text-haze">Reported attack categories</p>
                  {!canLoadDetail ? (
                    <p className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm leading-6 text-haze">
                      Live report detail is unavailable while demo fallback points are shown.
                    </p>
                  ) : detailLoading && !selectedDetail ? (
                    <p className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-haze">Loading AbuseIPDB detail...</p>
                  ) : (
                    <CategoryChips categories={selectedDetail?.categories || []} />
                  )}
                </div>

                {selectedDetail?.domain || selectedDetail?.hostnames?.length ? (
                  <div className="mt-5 rounded-md border border-white/10 bg-black/20 p-3 text-sm">
                    {selectedDetail.domain ? <p className="text-haze">Domain: <span className="text-white">{selectedDetail.domain}</span></p> : null}
                    {selectedDetail.hostnames.length ? <p className="mt-2 text-haze">Hostnames: <span className="text-white">{selectedDetail.hostnames.join(", ")}</span></p> : null}
                  </div>
                ) : null}

                {detailError ? (
                  <p className="mt-4 rounded-md border border-volt/35 bg-volt/10 px-3 py-2 text-sm leading-6 text-haze">{detailError}</p>
                ) : null}
                {selectedDetail?.warnings?.length ? (
                  <p className="mt-4 rounded-md border border-volt/35 bg-volt/10 px-3 py-2 text-sm leading-6 text-haze">{selectedDetail.warnings.join(" ")}</p>
                ) : null}
              </div>
            ) : null}

            <div className="rounded-lg border border-white/10 bg-white/[0.04] p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <p className="font-mono text-xs uppercase text-signal">Recent mapped sources</p>
                <span className="rounded-md border border-white/10 bg-black/25 px-2 py-1 font-mono text-[11px] uppercase text-haze">
                  {data?.mode || "loading"}
                </span>
              </div>
              <div className="max-h-[370px] space-y-2 overflow-y-auto pr-1">
                {points
                  .slice()
                  .sort((left, right) => dateSortValue(right.last_reported_at) - dateSortValue(left.last_reported_at))
                  .slice(0, 18)
                  .map((point) => (
                    <button
                      key={point.id}
                      type="button"
                      onClick={() => selectPoint(point)}
                      className={`w-full rounded-md border p-3 text-left transition ${
                        selectedPoint?.id === point.id
                          ? "border-signal/55 bg-signal/10"
                          : "border-white/10 bg-black/20 hover:border-signal/35 hover:bg-white/[0.06]"
                      }`}
                    >
                      <span className="flex items-center justify-between gap-3">
                        <span className="min-w-0">
                          <span className="block truncate text-sm font-semibold text-white">{point.ip}</span>
                          <span className="mt-1 block truncate text-xs text-haze">{formatLocation(point)}</span>
                        </span>
                        <span className="shrink-0 rounded-md border border-white/10 bg-black/25 px-2 py-1 font-mono text-[11px] uppercase text-haze">
                          {point.country_code || "IP"}
                        </span>
                      </span>
                    </button>
                  ))}
              </div>
            </div>

            <div className="rounded-lg border border-white/10 bg-white/[0.04] p-4">
              <div className="mb-3 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                <Network size={16} />
                Recent report evidence
              </div>
              {detailLoading && !selectedDetail ? (
                <p className="rounded-md border border-white/10 bg-black/20 px-3 py-2 text-sm text-haze">Loading recent report evidence...</p>
              ) : selectedDetail?.recent_reports?.length ? (
                <div className="grid gap-3">
                  {selectedDetail.recent_reports.slice(0, 4).map((report) => (
                    <article key={report.id} className="rounded-md border border-white/10 bg-black/20 p-3">
                      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono text-[11px] uppercase text-haze">{formatDate(report.reported_at)}</span>
                      </div>
                      <CategoryChips categories={report.categories} />
                      {report.comment ? <p className="mt-3 text-sm leading-6 text-haze">{report.comment}</p> : null}
                    </article>
                  ))}
                </div>
              ) : (
                <p className="text-sm leading-6 text-haze">Select a live IP to load recent AbuseIPDB report evidence.</p>
              )}
            </div>
          </aside>
        </section>
      </div>
    </div>
  );
}
