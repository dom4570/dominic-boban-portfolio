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
  virustotal_intelligence?: VirusTotalSummary;
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

type MitreTechnique = {
  id: string;
  tactic: string;
  technique: string;
};

type MitreMatch = {
  technique_id: string;
  source: "abuseipdb" | "spamhaus" | "virustotal";
  evidence: string;
  evidence_title?: string;
  evidence_summary?: string;
  raw_evidence?: string;
  meaning?: string;
  matched_field: string;
  confidence: "high" | "medium";
  pattern_label: string;
  evidence_score?: number;
  source_count?: number;
  signals?: string[];
  service?: string;
  port?: number | null;
  confidence_reason?: string;
  analyst_summary?: string;
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
  mitre_techniques?: MitreTechnique[];
  mitre_matches?: MitreMatch[];
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
  mitre_techniques?: MitreTechnique[];
  mitre_matches?: MitreMatch[];
};

type VirusTotalSummary = {
  provider: "virustotal";
  status: "found" | "not_found" | "unavailable" | "not_configured";
  vendor_malicious: number;
  vendor_suspicious: number;
  vendor_harmless: number;
  vendor_undetected: number;
  vendor_timeout: number;
  vendor_total: number;
  reputation: number;
  community_harmless: number;
  community_malicious: number;
  asn: string;
  as_owner: string;
  country: string;
  tags?: string[];
  threat_labels?: string[];
  detection_names?: string[];
  last_analysis_date: string;
  permalink: string;
  generated_at: string;
  cache_status: "fresh" | "cached";
};

type VirusTotalDetail = VirusTotalSummary & {
  ip: string;
  cache_expires_at: string;
  warnings: string[];
  mitre_techniques?: MitreTechnique[];
  mitre_matches?: MitreMatch[];
};

type VirusTotalPrewarmResponse = {
  status: string;
  attempted: number;
  cached: number;
  remaining: number;
  next_run_at: string;
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

function formatSignedNumber(value: number | null | undefined) {
  const number = Number(value);
  return new Intl.NumberFormat("en-GB").format(Number.isFinite(number) ? number : 0);
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
    <div className="mt-2 rounded-md border border-white/10 bg-white/[0.04] p-2.5">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="font-mono text-[10px] uppercase text-haze">Newest event</span>
        {event.dataset ? (
          <span className="rounded-md bg-signal px-2 py-1 font-mono text-[10px] font-semibold uppercase text-obsidian">
            {event.dataset}
          </span>
        ) : null}
      </div>
      <div className="flex flex-wrap gap-2">
        {event.listed_at ? (
          <SignalFact label="Date listed" value={formatDate(event.listed_at)} />
        ) : null}
        {event.removed_at || event.valid_until_at ? (
          <SignalFact label={event.removed_at ? "Date removed" : "Valid until"} value={formatDate(event.removed_at || event.valid_until_at)} />
        ) : null}
        {event.seen_at ? (
          <SignalFact label="Most recent detection" value={formatDate(event.seen_at)} />
        ) : null}
        {connection.length ? (
          <SignalFact label="Connection" value={`${connection.join(" -> ")}${event.protocol ? ` (${event.protocol})` : ""}`} />
        ) : null}
      </div>
      {event.detection ? <p className="mt-2 text-sm leading-6 text-white">{event.detection}</p> : null}
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
      <div className="mt-3 rounded-md border border-white/10 bg-white/[0.03] p-2.5">
        <p className="font-mono text-[10px] uppercase text-haze">Historical listings</p>
        <p className="mt-2 text-xs leading-5 text-haze">{NO_INTELLIGENCE_DATA}</p>
      </div>
    );
  }

  if (history.status === "unavailable") {
    return (
      <div className="mt-3 rounded-md border border-volt/20 bg-volt/10 p-2.5">
        <p className="font-mono text-[10px] uppercase text-volt">Historical listings unavailable</p>
        {history.warnings?.length ? <p className="mt-2 text-xs leading-5 text-haze">{history.warnings.join(" ")}</p> : null}
      </div>
    );
  }

  const events = history.events || [];
  const newest = events[0];

  if (!newest) {
    return (
      <div className="mt-3 rounded-md border border-white/10 bg-white/[0.03] p-2.5">
        <p className="font-mono text-[10px] uppercase text-haze">Historical listings</p>
        <p className="mt-2 text-xs leading-5 text-haze">{NO_INTELLIGENCE_DATA}</p>
      </div>
    );
  }

  return (
    <div className="mt-3 rounded-md border border-white/10 bg-white/[0.03] p-2.5">
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

function SourceBadge({ label, title }: { label: string; title: string }) {
  return (
    <span
      className="rounded-md border border-white/10 bg-black/25 px-2 py-1 font-mono text-[10px] uppercase text-haze"
      title={title}
    >
      {label}
    </span>
  );
}

function useOutsideDismiss<T extends HTMLElement>(active: boolean, onDismiss: () => void) {
  const ref = useRef<T | null>(null);

  useEffect(() => {
    if (!active) return undefined;

    const handlePointerStart = (event: MouseEvent | TouchEvent) => {
      const target = event.target;
      if (target instanceof Node && ref.current && !ref.current.contains(target)) {
        onDismiss();
      }
    };

    document.addEventListener("mousedown", handlePointerStart);
    document.addEventListener("touchstart", handlePointerStart);

    return () => {
      document.removeEventListener("mousedown", handlePointerStart);
      document.removeEventListener("touchstart", handlePointerStart);
    };
  }, [active, onDismiss]);

  return ref;
}

function SignalSection({
  children,
  className = "",
  source,
  sourceTitle,
  title,
}: {
  children: ReactNode;
  className?: string;
  source: string;
  sourceTitle: string;
  title: string;
}) {
  return (
    <section className={`rounded-lg border border-white/10 bg-black/20 p-3 ${className}`}>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono text-[10px] uppercase text-signal">{title}</p>
        <SourceBadge label={source} title={sourceTitle} />
      </div>
      {children}
    </section>
  );
}

function SignalMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-[132px] flex-1 rounded-md border border-white/10 bg-white/[0.035] px-3 py-2">
      <p className="font-mono text-[10px] uppercase text-haze">{label}</p>
      <p className="mt-1 break-words text-lg font-semibold leading-tight text-white">{value}</p>
    </div>
  );
}

function SignalFact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <span className="inline-flex max-w-full items-center gap-1 rounded-md border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-xs leading-5 text-haze">
      <span className="shrink-0 text-white">{label}:</span>
      <span className="min-w-0 break-words">{value}</span>
    </span>
  );
}

function AbuseCategoryBadges({ categories }: { categories: AbuseIpdbCategory[] }) {
  if (!categories.length) return null;

  return (
    <div className="mt-2 flex flex-wrap gap-2">
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

function mergeMitreTechniques(...groups: Array<MitreTechnique[] | null | undefined>) {
  const deduped = new Map<string, MitreTechnique>();

  groups.flatMap((group) => group || []).forEach((technique) => {
    if (technique?.id && !deduped.has(technique.id)) {
      deduped.set(technique.id, technique);
    }
  });

  return [...deduped.values()].sort((left, right) => left.id.localeCompare(right.id));
}

function mergeMitreMatches(...groups: Array<MitreMatch[] | null | undefined>) {
  const deduped = new Map<string, MitreMatch>();

  groups.flatMap((group) => group || []).forEach((match) => {
    if (!match?.technique_id) return;

    const key = [
      match.technique_id,
      match.source,
      match.matched_field,
      match.pattern_label,
      match.evidence,
    ].join(":");

    if (!deduped.has(key)) {
      deduped.set(key, match);
    }
  });

  return [...deduped.values()];
}

const MITRE_TACTIC_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

function tacticOrder(tactic: string) {
  const index = MITRE_TACTIC_ORDER.findIndex((item) => item.toLowerCase() === tactic.toLowerCase());
  return index === -1 ? MITRE_TACTIC_ORDER.length : index;
}

function mitreSourceBadge(match: MitreMatch) {
  if (match.source === "virustotal") {
    return {
      label: "Reputation",
      title: "Source: VirusTotal cached reputation evidence",
    };
  }

  if (match.source === "abuseipdb") {
    return {
      label: "Activity",
      title: "Source: AbuseIPDB evidence",
    };
  }

  return {
    label: "Listing",
    title: "Source: Spamhaus evidence",
  };
}

function mitreMatchScore(match: MitreMatch) {
  return Math.max(0, Math.min(100, Number(match.evidence_score) || (match.confidence === "high" ? 72 : 54)));
}

function mitreTechniqueStats(matches: MitreMatch[]) {
  const scores = matches.map(mitreMatchScore);
  const maxScore = scores.length ? Math.max(...scores) : 0;
  const sources = new Set(matches.map((match) => match.source).filter(Boolean));
  const services = [...new Set(matches.map((match) => match.service).filter(Boolean))];
  const ports = [...new Set(matches.map((match) => match.port).filter((port): port is number => typeof port === "number"))];
  const confidence: "Strong" | "Likely" | "Context" = maxScore >= 76 || sources.size >= 2 ? "Strong" : maxScore >= 58 ? "Likely" : "Context";

  return {
    maxScore,
    confidence,
    sourceCount: sources.size || Math.max(1, matches.length ? 1 : 0),
    services,
    ports,
  };
}

function mitreNodeClasses(confidence: "Strong" | "Likely" | "Context", isActive: boolean) {
  if (isActive) return "border-signal/70 bg-signal/15 shadow-[0_0_22px_rgba(250,255,0,0.14)]";
  if (confidence === "Strong") return "border-trace/40 bg-trace/10 hover:border-trace/70 hover:bg-trace/15";
  if (confidence === "Likely") return "border-cyan-300/30 bg-cyan-300/10 hover:border-cyan-300/55 hover:bg-cyan-300/15";
  return "border-white/15 bg-white/[0.03] hover:border-white/30";
}

function MitreBehaviorGraph({ matches, techniques }: { matches: MitreMatch[]; techniques: MitreTechnique[] }) {
  const [selectedId, setSelectedId] = useState("");
  const containerRef = useOutsideDismiss<HTMLDivElement>(Boolean(selectedId), () => setSelectedId(""));
  const scoredMatches = matches.filter((match) => mitreMatchScore(match) >= 50 || match.confidence === "high");
  const explainableIds = new Set(scoredMatches.map((match) => match.technique_id).filter(Boolean));
  const sortedTechniques = techniques.filter((technique) => explainableIds.has(technique.id)).sort((left, right) => {
    const order = tacticOrder(left.tactic) - tacticOrder(right.tactic);
    return order || left.id.localeCompare(right.id);
  });

  if (!sortedTechniques.length) return null;

  const activeId = sortedTechniques.some((technique) => technique.id === selectedId) ? selectedId : "";
  const activeTechnique = sortedTechniques.find((technique) => technique.id === activeId) || null;
  const matchesByTechnique = new Map<string, MitreMatch[]>();

  scoredMatches.forEach((match) => {
    if (!match.technique_id) return;
    const nextMatches = [...(matchesByTechnique.get(match.technique_id) || []), match].sort((left, right) => mitreMatchScore(right) - mitreMatchScore(left));
    matchesByTechnique.set(match.technique_id, nextMatches);
  });

  const tacticGroups = sortedTechniques.reduce<Array<{ tactic: string; techniques: MitreTechnique[] }>>((groups, technique) => {
    const existing = groups.find((group) => group.tactic === technique.tactic);
    if (existing) {
      existing.techniques.push(technique);
    } else {
      groups.push({ tactic: technique.tactic, techniques: [technique] });
    }
    return groups;
  }, []);

  const activeMatches = matchesByTechnique.get(activeTechnique?.id || "") || [];
  const activeStats = activeTechnique ? mitreTechniqueStats(activeMatches) : null;

  return (
    <div ref={containerRef} className="rounded-md border border-cyan-300/20 bg-cyan-300/10 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono text-[10px] uppercase text-cyan-100">ATT&CK Behavior Graph</p>
        <SourceBadge label="Framework" title="Source: MITRE ATT&CK Enterprise technique catalog" />
      </div>
      <p className="mt-2 text-xs leading-5 text-haze">
        Mapped from third-party source-IP evidence, not confirmed telemetry against this portfolio.
      </p>

      <div className="mt-3 overflow-x-auto pb-1">
        <div className="flex min-w-max items-stretch gap-3">
          {tacticGroups.map((group, groupIndex) => {
            const visibleTechniques = group.techniques.slice(0, 2);
            const hiddenCount = Math.max(0, group.techniques.length - visibleTechniques.length);

            return (
              <div key={group.tactic} className="relative min-w-[190px] rounded-lg border border-cyan-300/15 bg-black/25 p-2.5">
                {groupIndex < tacticGroups.length - 1 ? (
                  <span className="pointer-events-none absolute left-full top-1/2 hidden h-px w-3 bg-cyan-300/30 sm:block" />
                ) : null}
                <p className="mb-2 font-mono text-[10px] uppercase text-haze">{group.tactic}</p>
                <div className="grid gap-2">
                  {visibleTechniques.map((technique) => {
                    const isActive = technique.id === activeId;
                    const techniqueMatches = matchesByTechnique.get(technique.id) || [];
                    const stats = mitreTechniqueStats(techniqueMatches);

                    return (
                      <button
                        key={technique.id}
                        type="button"
                        className={`rounded-md border px-2.5 py-2 text-left transition ${mitreNodeClasses(stats.confidence, isActive)}`}
                        aria-expanded={isActive}
                        onClick={() => setSelectedId(isActive ? "" : technique.id)}
                      >
                        <span className="font-mono text-[10px] uppercase text-cyan-100">{technique.id}</span>
                        <span className="mt-1 block text-sm font-semibold leading-tight text-white">{technique.technique}</span>
                        <span className="mt-1 flex flex-wrap gap-1.5 font-mono text-[9px] uppercase text-haze">
                          <span>{stats.confidence}</span>
                          <span>{stats.sourceCount} src</span>
                          <span>{stats.maxScore}/100</span>
                        </span>
                      </button>
                    );
                  })}
                  {hiddenCount ? (
                    <span className="rounded-md border border-white/10 bg-white/[0.03] px-2.5 py-2 font-mono text-[10px] uppercase text-haze">
                      +{hiddenCount} more
                    </span>
                  ) : null}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {activeTechnique ? (
        <div className="mt-3 rounded-md border border-white/10 bg-black/25 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md border border-cyan-300/30 bg-cyan-300/10 px-2 py-1 font-mono text-[10px] uppercase text-cyan-100">
              {activeTechnique.id}
            </span>
            <span className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 font-mono text-[10px] uppercase text-haze">
              {activeTechnique.tactic}
            </span>
            <span className="text-sm font-semibold text-white">{activeTechnique.technique}</span>
            {activeStats ? (
              <>
                <span className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 font-mono text-[10px] uppercase text-haze">
                  {activeStats.confidence}
                </span>
                <span className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 font-mono text-[10px] uppercase text-haze">
                  {activeStats.sourceCount} source {activeStats.sourceCount === 1 ? "signal" : "signals"}
                </span>
                <span className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 font-mono text-[10px] uppercase text-haze">
                  {activeStats.maxScore}/100
                </span>
              </>
            ) : null}
          </div>

          {activeMatches.length ? (
            <div className="mt-2 grid gap-2 md:grid-cols-2">
              {activeMatches.slice(0, 4).map((match, index) => (
                <div
                  key={`${match.technique_id}-${match.source}-${match.matched_field}-${index}`}
                  className="rounded-md border border-white/10 bg-white/[0.03] p-2.5"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[10px] uppercase text-signal">{match.evidence_title || match.pattern_label}</span>
                    <SourceBadge {...mitreSourceBadge(match)} />
                    <span className="rounded-md border border-white/10 bg-black/20 px-2 py-1 font-mono text-[10px] uppercase text-haze">
                      {match.confidence}
                    </span>
                    <span className="rounded-md border border-white/10 bg-black/20 px-2 py-1 font-mono text-[10px] uppercase text-haze">
                      {mitreMatchScore(match)}/100
                    </span>
                  </div>
                  <div className="mt-2 grid gap-2 text-xs leading-5 text-haze">
                    <p>
                      <span className="text-white">Why this mapped:</span> {match.analyst_summary || match.meaning || "This evidence matched a deterministic ATT&CK behavior rule."}
                    </p>
                    <p>
                      <span className="text-white">Evidence used:</span> {match.evidence_summary || match.evidence}
                    </p>
                    {match.service || match.port || match.confidence_reason ? (
                      <p>
                        <span className="text-white">Context:</span>{" "}
                        {[match.service, match.port ? `port ${match.port}` : "", match.confidence_reason].filter(Boolean).join(" / ")}
                      </p>
                    ) : null}
                    {match.signals?.length ? (
                      <div className="flex flex-wrap gap-1.5">
                        {match.signals.slice(0, 6).map((signal) => (
                          <span key={signal} className="rounded border border-cyan-300/20 bg-cyan-300/10 px-1.5 py-0.5 font-mono text-[9px] uppercase text-cyan-100">
                            {signal.replace(/_/g, " ")}
                          </span>
                        ))}
                      </div>
                    ) : null}
                    {match.raw_evidence && match.raw_evidence !== match.evidence_summary ? (
                      <p className="break-words rounded-md border border-white/10 bg-black/20 p-2 font-mono text-[10px] leading-5 text-haze">
                        {match.raw_evidence}
                      </p>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="mt-2 text-xs leading-5 text-haze">
              No explainable evidence was returned for this technique.
            </p>
          )}
        </div>
      ) : null}
    </div>
  );
}

type EvidenceDataset = Pick<SpamhausDataset, "code" | "dataset" | "label">;

type IntelligenceAssessment = {
  activity: string;
  conclusion: string;
  corroboration: string;
  confidence: "Strong" | "Likely" | "Context";
  confidenceScore: number;
  primaryTechniqueId?: string;
  service?: string;
  port?: number | null;
  scope: string;
  secondarySignals: string[];
  supportingSignals: string[];
  limitations: string[];
  evidenceCards: Array<{
    label: string;
    value: string;
    detail: string;
  }>;
};

type IntelScore = {
  score: number;
  severity: "Low" | "Elevated" | "High" | "Critical";
};

type ThreatProfileBadge = {
  id: string;
  label: string;
  confidence: "Strong" | "Likely" | "Context";
  evidence: string;
  sourceCount: number;
  tone: "red" | "purple" | "cyan" | "amber" | "zinc";
  priority: number;
  kind: "finding" | "context";
  score?: number;
  snippets?: string[];
};

function abusePayload(detail: AbuseIpdbDetail | null, summary: AbuseIpdbSummary | null) {
  const payload = detail || summary;
  return payload?.status === "reported" && payload.total_reports > 0 ? payload : null;
}

function abuseCategories(detail: AbuseIpdbDetail | null, summary: AbuseIpdbSummary | null) {
  const payload = abusePayload(detail, summary);
  return detail?.top_categories?.length ? detail.top_categories : payload?.top_categories || [];
}

function categorySet(categories: AbuseIpdbCategory[]) {
  return new Set(categories.map((category) => category.label.toLowerCase()));
}

function spamhausDatasets(detail: SpamhausDetail | null, summary: IpIntelligenceSummary | null): EvidenceDataset[] {
  if (detail?.status === "listed") return detail.datasets;
  if (summary?.status === "listed") return summary.datasets;
  return [];
}

function spamhausListingCount(detail: SpamhausDetail | null, summary: IpIntelligenceSummary | null) {
  if (detail?.status === "listed") return detail.listing_count;
  if (summary?.status === "listed") return summary.listing_count;
  return 0;
}

function newestHistoryEvent(detail: SpamhausDetail | null) {
  return detail?.history?.status === "found" ? detail.history.events?.[0] || null : null;
}

function virusTotalPayload(detail: VirusTotalDetail | null, summary: VirusTotalSummary | null) {
  const payload = detail || summary;
  return payload?.status === "found" ? payload : null;
}

function virusTotalRatio(payload: VirusTotalSummary | VirusTotalDetail | null) {
  if (!payload || payload.vendor_total <= 0) return "";
  return `${formatNumber(payload.vendor_malicious)}/${formatNumber(payload.vendor_total)}`;
}

function hasVirusTotalDetections(payload: VirusTotalSummary | VirusTotalDetail | null) {
  return Boolean(payload && (payload.vendor_malicious > 0 || payload.vendor_suspicious > 0));
}

function cleanProfileEvidence(value: string) {
  return value.replace(/\s+/g, " ").trim().slice(0, 180);
}

function uniqueProfileValues(values: Array<string | undefined | null>) {
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];
}

function confidenceRank(confidence: ThreatProfileBadge["confidence"]) {
  if (confidence === "Strong") return 3;
  if (confidence === "Likely") return 2;
  return 1;
}

function addProfile(profiles: Map<string, ThreatProfileBadge>, next: ThreatProfileBadge) {
  const existing = profiles.get(next.id);
  if (!existing || next.priority > existing.priority || confidenceRank(next.confidence) > confidenceRank(existing.confidence)) {
    profiles.set(next.id, next);
  }
}

function profileToneClasses(tone: ThreatProfileBadge["tone"]) {
  if (tone === "red") return "border-l-trace bg-trace/10 text-trace";
  if (tone === "purple") return "border-l-purple-400 bg-purple-400/10 text-purple-200";
  if (tone === "cyan") return "border-l-cyan-300 bg-cyan-300/10 text-cyan-100";
  if (tone === "amber") return "border-l-volt bg-volt/10 text-volt";
  return "border-l-white/25 bg-white/[0.035] text-haze";
}

function hasDataset(datasets: EvidenceDataset[], names: string[]) {
  return datasets.some((dataset) => names.some((name) => dataset.dataset.toLowerCase().includes(name.toLowerCase())));
}

function matchesForTechnique(matches: MitreMatch[], techniqueId: string) {
  return matches
    .filter((match) => match.technique_id === techniqueId)
    .sort((left, right) => mitreMatchScore(right) - mitreMatchScore(left));
}

function sourceCountFromMatches(matches: MitreMatch[]) {
  return new Set(matches.map((match) => match.source).filter(Boolean)).size || (matches.length ? 1 : 0);
}

function profileConfidenceFromMatches(matches: MitreMatch[]) {
  const bestScore = Math.max(0, ...matches.map(mitreMatchScore));
  const sourceCount = sourceCountFromMatches(matches);
  if (bestScore >= 76 || sourceCount >= 2) return "Strong";
  if (bestScore >= 56 || matches.length) return "Likely";
  return "Context";
}

function profileSnippetsFromMatches(matches: MitreMatch[]) {
  return uniqueProfileValues(
    matches.flatMap((match) => [
      match.analyst_summary,
      match.confidence_reason,
      match.raw_evidence,
    ]),
  ).slice(0, 3);
}

function addTechniqueProfile(
  profiles: Map<string, ThreatProfileBadge>,
  matches: MitreMatch[],
  techniqueId: string,
  profile: Pick<ThreatProfileBadge, "id" | "label" | "tone" | "priority">,
  fallbackEvidence = "",
) {
  const techniqueMatches = matchesForTechnique(matches, techniqueId);
  if (!techniqueMatches.length && !fallbackEvidence) return;

  const sourceCount = sourceCountFromMatches(techniqueMatches) || 1;
  const bestScore = Math.max(0, ...techniqueMatches.map(mitreMatchScore));
  const confidence = techniqueMatches.length ? profileConfidenceFromMatches(techniqueMatches) : "Likely";
  const evidence = techniqueMatches.length
    ? `${profile.label} is supported by ${sourceCount} source ${sourceCount === 1 ? "signal" : "signals"} with a top evidence score of ${bestScore || "n/a"}/100.`
    : fallbackEvidence;

  addProfile(profiles, {
    ...profile,
    confidence,
    evidence,
    sourceCount,
    kind: "finding",
    score: bestScore || undefined,
    snippets: profileSnippetsFromMatches(techniqueMatches),
  });
}

function deriveThreatProfiles({
  abuse,
  categories,
  datasets,
  historyEvent,
  matches,
  point,
  virusTotal,
}: {
  abuse: AbuseIpdbSummary | AbuseIpdbDetail | null;
  categories: AbuseIpdbCategory[];
  datasets: EvidenceDataset[];
  historyEvent: SpamhausHistoryEvent | null;
  matches: MitreMatch[];
  point: ThreatPoint | null;
  virusTotal: VirusTotalSummary | VirusTotalDetail | null;
}) {
  const profiles = new Map<string, ThreatProfileBadge>();
  const categoryLabels = categorySet(categories);
  const networkText = cleanProfileEvidence([
    point?.as_name,
    point?.isp,
    point?.org,
    abuse?.usage_type,
    abuse?.isp,
    abuse?.domain,
    virusTotal?.asn ? `AS${virusTotal.asn}` : "",
    virusTotal?.as_owner,
  ].filter(Boolean).join(" "));
  const behaviorText = cleanProfileEvidence([
    ...categories.map((category) => category.label),
    ...matches.flatMap((match) => [match.pattern_label, match.evidence, match.evidence_summary || "", match.raw_evidence || ""]),
    ...(virusTotal?.tags || []),
    ...(virusTotal?.threat_labels || []),
    ...(virusTotal?.detection_names || []),
    historyEvent?.detection,
    historyEvent?.heuristic,
    historyEvent?.botname,
  ].filter(Boolean).join(" "));

  const hasHostedInfra = Boolean(point?.hosting) || /hosting|vps|data center|datacenter|cloud|dedicated|servers|ovh|digitalocean|linode|amazon|aws|azure|google|vultr|hetzner|leaseweb|transit/i.test(networkText);
  const hasAnonymizedRelay = Boolean(point?.proxy || abuse?.is_tor) || /tor|tor-exit|vpn|proxy|nordvpn|expressvpn|proton|mullvad|surfshark|hide-my-ip/i.test(networkText);
  const hasMobileNetwork = Boolean(point?.mobile) || /mobile|cellular|wireless|carrier/i.test(networkText);

  if (hasHostedInfra) {
    addProfile(profiles, {
      id: "hosted-infrastructure",
      label: "Hosted Infrastructure",
      confidence: "Context",
      evidence: `Network or usage fields indicate cloud, hosting, VPS, data-center, or transit infrastructure. ${networkText}`,
      sourceCount: [point?.hosting, abuse?.usage_type, virusTotal?.as_owner].filter(Boolean).length || 1,
      tone: "red",
      priority: 55,
      kind: "context",
    });
  } else if (hasAnonymizedRelay) {
    addProfile(profiles, {
      id: "anonymized-relay",
      label: "Anonymized Relay",
      confidence: "Context",
      evidence: `Proxy, Tor, VPN, or relay indicators are present in the selected IP metadata. ${networkText}`,
      sourceCount: [point?.proxy, abuse?.is_tor, networkText].filter(Boolean).length || 1,
      tone: "purple",
      priority: 52,
      kind: "context",
    });
  } else if (hasMobileNetwork) {
    addProfile(profiles, {
      id: "mobile-carrier",
      label: "Mobile/Carrier Network",
      confidence: "Context",
      evidence: `Geo-IP or network metadata indicates mobile, carrier, or wireless infrastructure. ${networkText}`,
      sourceCount: 1,
      tone: "zinc",
      priority: 35,
      kind: "context",
    });
  } else if (networkText) {
    addProfile(profiles, {
      id: "residential-corporate",
      label: "Residential/Corporate Network",
      confidence: "Context",
      evidence: `No hosting, proxy, or mobile indicator dominated the network metadata. ${networkText}`,
      sourceCount: 1,
      tone: "zinc",
      priority: 20,
      kind: "context",
    });
  }

  const hasMatch = (id: string) => matches.some((match) => match.technique_id === id);
  const hasDatasetSignal = (names: string[]) => hasDataset(datasets, names);

  addTechniqueProfile(
    profiles,
    matches,
    "T1110",
    { id: "credential-attack", label: "Credential Attack Source", tone: "red", priority: 95 },
    categoryLabels.has("brute-force") || categoryLabels.has("ssh") ? "Activity categories indicate brute-force or SSH behavior." : "",
  );

  addTechniqueProfile(
    profiles,
    matches,
    "T1595",
    { id: "recon-scanner", label: "Recon Scanner", tone: "cyan", priority: 90 },
    categoryLabels.has("port scan") || /scan|probe|scanner|recon/i.test(behaviorText) ? "Selected evidence references scanning, probing, or reconnaissance behavior." : "",
  );

  addTechniqueProfile(
    profiles,
    matches,
    "T1190",
    { id: "web-exploit-probe", label: "Web Exploit Probe", tone: "amber", priority: 88 },
    categoryLabels.has("sql injection") || categoryLabels.has("web app attack") ? "Activity categories indicate SQL injection or public-facing web application exploit behavior." : "",
  );

  addTechniqueProfile(
    profiles,
    matches,
    "T1071",
    { id: "c2-labeled", label: "C2-Labeled Infrastructure", tone: "purple", priority: 86 },
    /c2|c&c|command and control|botnet controller/i.test(behaviorText) ? "Selected evidence explicitly references C2 or command-and-control behavior." : "",
  );

  addTechniqueProfile(
    profiles,
    matches,
    "T1566",
    { id: "phishing-infrastructure", label: "Phishing Infrastructure", tone: "amber", priority: 84 },
    categoryLabels.has("phishing") || /phishing/i.test(behaviorText) ? "Selected evidence references phishing behavior." : "",
  );

  addTechniqueProfile(
    profiles,
    matches,
    "T1498",
    { id: "dos-source", label: "DoS Source", tone: "red", priority: 82 },
    categoryLabels.has("ddos attack") || /ddos|denial of service|flood|ping of death/i.test(behaviorText) ? "Selected evidence references denial-of-service behavior." : "",
  );

  if (hasDatasetSignal(["XBL", "CBL"]) || categoryLabels.has("exploited host") || /mirai|mozi|tsunami|kaiten|bashlite|gafgyt|botnet|infected|trojan/i.test(behaviorText)) {
    addProfile(profiles, {
      id: "compromised-host",
      label: "Possible Compromised Host",
      confidence: hasMatch("T1110") || hasMatch("T1190") || hasMatch("T1071") ? "Likely" : "Context",
      evidence: "Matched exploited-host, XBL/CBL, botnet family, infected-host, or malware-related reputation context. This does not create an ATT&CK behavior node by itself.",
      sourceCount: [hasDatasetSignal(["XBL", "CBL"]), categoryLabels.has("exploited host"), /botnet|infected|trojan/i.test(behaviorText)].filter(Boolean).length || 1,
      tone: "purple",
      priority: 80,
      kind: "context",
    });
  }

  return [...profiles.values()].sort((left, right) => {
    if (left.kind !== right.kind) return left.kind === "finding" ? -1 : 1;
    if (left.confidence !== right.confidence) return confidenceRank(right.confidence) - confidenceRank(left.confidence);
    return right.priority - left.priority;
  });
}

function datasetScore(datasets: EvidenceDataset[]) {
  return Math.min(
    20,
    datasets.reduce((score, dataset) => {
      const label = dataset.dataset.toUpperCase();
      if (label.includes("PBL")) return score;
      if (label.includes("DROP") || label.includes("SBL")) return score + 8;
      if (label.includes("XBL") || label.includes("CBL")) return score + 7;
      if (label.includes("CSS") || label.includes("AUTHBL")) return score + 5;
      return score + 3;
    }, 0),
  );
}

function freshnessScore(abuse: AbuseIpdbSummary | AbuseIpdbDetail | null, event: SpamhausHistoryEvent | null, virusTotal: VirusTotalSummary | VirusTotalDetail | null) {
  const dates = [abuse?.last_reported_at, event?.seen_at, event?.listed_at, virusTotal?.last_analysis_date]
    .map((value) => new Date(value || 0).getTime())
    .filter((value) => Number.isFinite(value) && value > 0);

  if (!dates.length) return 0;

  const ageDays = (Date.now() - Math.max(...dates)) / (24 * 60 * 60 * 1000);
  if (ageDays <= 1) return 10;
  if (ageDays <= 3) return 8;
  if (ageDays <= 7) return 6;
  if (ageDays <= 30) return 3;
  return 1;
}

function deriveIntelScore({
  abuse,
  datasets,
  historyEvent,
  virusTotal,
}: {
  abuse: AbuseIpdbSummary | AbuseIpdbDetail | null;
  datasets: EvidenceDataset[];
  historyEvent: SpamhausHistoryEvent | null;
  virusTotal: VirusTotalSummary | VirusTotalDetail | null;
}): IntelScore {
  const reportScore = abuse?.total_reports ? Math.min(25, (Math.log10(abuse.total_reports + 1) / 5) * 25) : 0;
  const reporterScore = abuse?.num_distinct_users ? Math.min(20, (Math.log10(abuse.num_distinct_users + 1) / 3) * 20) : 0;
  const vendorRatio = virusTotal?.vendor_total
    ? (virusTotal.vendor_malicious + virusTotal.vendor_suspicious * 0.5) / virusTotal.vendor_total
    : 0;
  const vendorScore = Math.min(25, (vendorRatio / 0.3) * 25);
  const score = Math.round(
    Math.min(100, reportScore + reporterScore + vendorScore + datasetScore(datasets) + freshnessScore(abuse, historyEvent, virusTotal)),
  );

  return {
    score,
    severity: score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 30 ? "Elevated" : "Low",
  };
}

function intelSeverityClasses(severity: IntelScore["severity"]) {
  if (severity === "Critical") {
    return {
      card: "border-trace/50 bg-trace/10 text-trace shadow-trace",
      pill: "border-trace/55 bg-trace/15 text-trace",
    };
  }

  if (severity === "High") {
    return {
      card: "border-trace/40 bg-trace/10 text-trace",
      pill: "border-trace/45 bg-trace/15 text-trace",
    };
  }

  if (severity === "Elevated") {
    return {
      card: "border-volt/40 bg-volt/10 text-volt",
      pill: "border-volt/45 bg-volt/15 text-volt",
    };
  }

  return {
    card: "border-cyan-300/35 bg-cyan-400/10 text-cyan-100",
    pill: "border-cyan-300/45 bg-cyan-400/15 text-cyan-100",
  };
}

function hasSshBruteforceHistory(event: SpamhausHistoryEvent | null) {
  if (!event) return false;
  const text = [event.detection, event.heuristic, event.botname, event.protocol].filter(Boolean).join(" ").toLowerCase();
  const usesPort22 = event.source_port === 22 || event.destination_port === 22;
  return usesPort22 && (text.includes("bruteforce") || text.includes("brute force") || text.includes("ssh"));
}

function assessmentConfidence(score: number): IntelligenceAssessment["confidence"] {
  if (score >= 76) return "Strong";
  if (score >= 52) return "Likely";
  return "Context";
}

function assessmentSourceText(count: number) {
  return `${count} source ${count === 1 ? "signal" : "signals"}`;
}

function latestEvidenceDate(abuse: AbuseIpdbSummary | AbuseIpdbDetail | null, event: SpamhausHistoryEvent | null, virusTotal: VirusTotalSummary | VirusTotalDetail | null) {
  const dates = [abuse?.last_reported_at, event?.seen_at, event?.listed_at, virusTotal?.last_analysis_date]
    .map((value) => ({ value, time: new Date(value || 0).getTime() }))
    .filter((entry): entry is { value: string; time: number } => Boolean(entry.value) && Number.isFinite(entry.time) && entry.time > 0);

  return dates.sort((left, right) => right.time - left.time)[0]?.value || "";
}

function matchServiceText(match: MitreMatch | null) {
  if (!match) return "";
  return [match.service, match.port ? `port ${match.port}` : ""].filter(Boolean).join(" / ");
}

function bestMatchForTechnique(matches: MitreMatch[], techniqueId: string) {
  return matchesForTechnique(matches, techniqueId)[0] || null;
}

function assessmentTechniqueConfig(techniqueId: string, match: MitreMatch | null) {
  const service = match?.service || "";
  const port = match?.port || null;

  if (techniqueId === "T1110") {
    if (service === "SSH" || port === 22) {
      return {
        activity: "SSH brute-force source",
        conclusion: "This IP is most strongly associated with SSH credential attack behavior.",
      };
    }

    if (service === "RDP" || port === 3389) {
      return {
        activity: "RDP brute-force source",
        conclusion: "This IP is most strongly associated with Remote Desktop credential attack behavior.",
      };
    }

    return {
      activity: "Credential attack source",
      conclusion: "This IP is most strongly associated with repeated authentication or brute-force behavior.",
    };
  }

  if (techniqueId === "T1595") {
    return {
      activity: "Recon scanning source",
      conclusion: "This IP is most strongly associated with probing or scanning network services.",
    };
  }

  if (techniqueId === "T1190") {
    return {
      activity: "Web exploit probe",
      conclusion: "This IP is most strongly associated with public-facing application exploit probing.",
    };
  }

  if (techniqueId === "T1566") {
    return {
      activity: "Phishing infrastructure signal",
      conclusion: "This IP is associated with phishing-related third-party evidence.",
    };
  }

  if (techniqueId === "T1498") {
    return {
      activity: "Denial-of-service source",
      conclusion: "This IP is associated with denial-of-service or flooding behavior.",
    };
  }

  if (techniqueId === "T1071") {
    return {
      activity: "C2-labeled infrastructure",
      conclusion: "This IP has explicit command-and-control labeling in third-party evidence.",
    };
  }

  return {
    activity: "Mapped behavior source",
    conclusion: "This IP has a mapped third-party behavior signal.",
  };
}

function deriveAssessment({
  abuse,
  categories,
  datasets,
  historyEvent,
  intelScore,
  listingCount,
  matches,
  point,
  profiles,
  virusTotal,
}: {
  abuse: AbuseIpdbSummary | AbuseIpdbDetail | null;
  categories: AbuseIpdbCategory[];
  datasets: EvidenceDataset[];
  historyEvent: SpamhausHistoryEvent | null;
  intelScore: IntelScore;
  listingCount: number;
  matches: MitreMatch[];
  point: ThreatPoint | null;
  profiles: ThreatProfileBadge[];
  virusTotal: VirusTotalSummary | VirusTotalDetail | null;
}): IntelligenceAssessment {
  const labels = categorySet(categories);
  const hasAbuseReports = Boolean(abuse?.total_reports);
  const hasSpamhausListings = listingCount > 0;
  const hasVirusTotalSignal = hasVirusTotalDetections(virusTotal);
  const hasBruteforceSsh = (labels.has("brute-force") && labels.has("ssh")) || hasSshBruteforceHistory(historyEvent);
  const hasPortScan = labels.has("port scan");
  const hasXbl = hasDataset(datasets, ["XBL", "CBL"]);
  const hasAbusiveInfrastructure = hasDataset(datasets, ["SBL", "DROP"]);
  const hasPolicyContext = hasDataset(datasets, ["PBL"]);
  const isHosted = Boolean(point?.hosting) || Boolean(abuse?.usage_type && /data center|hosting|transit|cloud/i.test(abuse.usage_type));
  const hostingContext = isHosted ? " from hosting infrastructure" : "";
  const secondarySignals = [];
  const latest = latestEvidenceDate(abuse, historyEvent, virusTotal);
  const behaviorOrder = ["T1110", "T1595", "T1190", "T1566", "T1498", "T1071"];
  const profileFindingBoost = profiles.some((profile) => profile.kind === "finding" && profile.confidence === "Strong") ? 4 : profiles.some((profile) => profile.kind === "finding") ? 2 : 0;
  const intelBoost = intelScore.severity === "Critical" ? 6 : intelScore.severity === "High" ? 4 : intelScore.severity === "Elevated" ? 2 : 0;
  const behaviorCandidates = behaviorOrder
    .map((techniqueId, order) => {
      const techniqueMatches = matchesForTechnique(matches, techniqueId);
      const bestMatch = techniqueMatches[0] || null;
      if (!bestMatch) return null;

      const sourceCount = sourceCountFromMatches(techniqueMatches);
      const baseScore = mitreMatchScore(bestMatch);
      const confidenceScore = Math.min(100, Math.round(baseScore + Math.max(0, sourceCount - 1) * 8 + profileFindingBoost + intelBoost));

      return {
        techniqueId,
        order,
        bestMatch,
        confidenceScore,
        sourceCount,
        service: bestMatch.service || "",
        port: bestMatch.port || null,
      };
    })
    .filter((candidate): candidate is NonNullable<typeof candidate> => Boolean(candidate))
    .sort((left, right) => right.confidenceScore - left.confidenceScore || left.order - right.order);

  const primary = behaviorCandidates[0] || null;
  const corroborationSources = [
    hasAbuseReports ? "activity reports" : "",
    hasSpamhausListings ? "listing data" : "",
    hasVirusTotalSignal ? "vendor reputation" : "",
  ].filter(Boolean);
  const corroboration = corroborationSources.length > 1
    ? `Confirmed by ${corroborationSources.join(", ").replace(/, ([^,]*)$/, " and $1")}.`
    : corroborationSources.length === 1
      ? `Supported by ${corroborationSources[0]}.`
      : "Supported by third-party reputation data.";
  const limitations = [
    "Reported source-IP evidence, not telemetry against this portfolio.",
    "Verdict is deterministic from cached third-party data.",
  ];

  if (primary) {
    const verdict = assessmentTechniqueConfig(primary.techniqueId, primary.bestMatch);

    if (hasPortScan && primary.techniqueId !== "T1595") secondarySignals.push("Port scanning also reported");
    if (hasBruteforceSsh && primary.techniqueId !== "T1110") secondarySignals.push("Credential attack behavior also reported");
    if (hasXbl) secondarySignals.push("Possible exploited or infected host");
    if (hasAbusiveInfrastructure) secondarySignals.push("Known abusive infrastructure/listed netblock");
    if (hasPolicyContext) secondarySignals.push("Policy/listing context also present");
    if (hasVirusTotalSignal) secondarySignals.push("Vendor detections present");

    const serviceText = matchServiceText(primary.bestMatch);
    const evidenceCards = [
      {
        label: "Primary evidence",
        value: primary.techniqueId,
        detail: primary.bestMatch.analyst_summary || primary.bestMatch.meaning || primary.bestMatch.evidence_summary || "Mapped from explainable behavior evidence.",
      },
      {
        label: "Source agreement",
        value: assessmentSourceText(primary.sourceCount),
        detail: primary.bestMatch.confidence_reason || "Evidence strength is based on provider source, specificity, and matched behavior signals.",
      },
      serviceText
        ? {
            label: "Service context",
            value: serviceText,
            detail: "Service and port context make the behavior mapping more specific.",
          }
        : null,
      latest
        ? {
            label: "Latest signal",
            value: formatDate(latest),
            detail: "Newest activity, listing, or reputation timestamp available for this selected source.",
          }
        : null,
    ].filter((card): card is IntelligenceAssessment["evidenceCards"][number] => Boolean(card));

    return {
      activity: verdict.activity,
      conclusion: `${verdict.conclusion}${hostingContext && !verdict.conclusion.includes("hosting") ? hostingContext : ""}${hasSpamhausListings ? ", with listing data indicating broader abuse reputation." : "."}`.replace(/\.\./g, "."),
      corroboration,
      confidence: assessmentConfidence(primary.confidenceScore),
      confidenceScore: primary.confidenceScore,
      primaryTechniqueId: primary.techniqueId,
      service: primary.service,
      port: primary.port,
      scope: limitations[0],
      secondarySignals,
      supportingSignals: uniqueProfileValues([
        ...secondarySignals,
        ...profiles.slice(0, 4).map((profile) => profile.label),
      ]).slice(0, 6),
      limitations,
      evidenceCards,
    };
  }

  let activity = "Reported abusive source";
  let conclusion = "This IP has third-party abuse intelligence, but the available evidence does not identify a single dominant behavior.";
  let contextScore = Math.max(28, Math.min(72, intelScore.score));

  if (hasXbl) {
    activity = "Possible compromised host";
    conclusion = "Listing data indicates this IP may be an exploited or infected host, but no concrete ATT&CK behavior was returned.";
    contextScore = Math.max(contextScore, 48);
  } else if (hasAbusiveInfrastructure) {
    activity = "Known abusive infrastructure";
    conclusion = "Listing data links this IP or netblock to abusive infrastructure, without a concrete behavior verdict.";
    contextScore = Math.max(contextScore, 48);
  } else if (hasAbuseReports) {
    activity = "Repeatedly reported abuse source";
    conclusion = `Activity reporting indicates repeated abusive activity from this source IP${hostingContext}, but no dominant behavior mapping was returned.`;
    contextScore = Math.max(contextScore, abuse?.total_reports && abuse.total_reports > 1000 ? 58 : 46);
  } else if (hasSpamhausListings) {
    activity = "Listed abuse source";
    conclusion = "This source IP appears in abuse reputation datasets, but the available evidence remains contextual.";
    contextScore = Math.max(contextScore, 42);
  } else if (hasVirusTotalSignal) {
    activity = "Vendor-flagged suspicious source";
    conclusion = "Vendor reputation flags this source IP, but no dominant activity signal is available.";
    contextScore = Math.max(contextScore, 42);
  }

  if (hasPortScan) secondarySignals.push("Port scanning category present");
  if (hasBruteforceSsh) secondarySignals.push("Credential attack category present");
  if (hasXbl) secondarySignals.push("Possible exploited or infected host");
  if (hasAbusiveInfrastructure) secondarySignals.push("Known abusive infrastructure/listed netblock");
  if (hasPolicyContext) secondarySignals.push("Policy/listing context also present");
  if (hasVirusTotalSignal) secondarySignals.push("Vendor detections present");

  return {
    activity,
    conclusion,
    corroboration,
    confidence: assessmentConfidence(contextScore),
    confidenceScore: contextScore,
    scope: limitations[0],
    secondarySignals,
    supportingSignals: uniqueProfileValues([
      ...secondarySignals,
      ...profiles.slice(0, 4).map((profile) => profile.label),
    ]).slice(0, 6),
    limitations,
    evidenceCards: [
      {
        label: "Verdict basis",
        value: activity,
        detail: "No high-confidence ATT&CK behavior node was returned, so the verdict stays at reputation/context level.",
      },
      hasAbuseReports
        ? {
            label: "Activity volume",
            value: `${formatNumber(abuse?.total_reports)} reports`,
            detail: `${formatNumber(abuse?.num_distinct_users)} distinct reporters over the configured AbuseIPDB window.`,
          }
        : null,
      hasSpamhausListings
        ? {
            label: "Listing context",
            value: `${formatNumber(listingCount)} listings`,
            detail: datasets.map((dataset) => `${dataset.dataset} / code ${dataset.code}`).join(", ") || "Listing summary returned for this source IP.",
          }
        : null,
      hasVirusTotalSignal
        ? {
            label: "Vendor reputation",
            value: virusTotalRatio(virusTotal) || "Flagged",
            detail: "Vendor reputation is treated as supporting context unless explicit behavior labels are present.",
          }
        : null,
    ].filter((card): card is IntelligenceAssessment["evidenceCards"][number] => Boolean(card)),
  };
}

function AssessmentPanel({ assessment }: { assessment: IntelligenceAssessment }) {
  const confidenceClasses = profileToneClasses(
    assessment.confidence === "Strong" ? "red" : assessment.confidence === "Likely" ? "amber" : "zinc",
  );

  return (
    <div className="rounded-md border border-signal/25 bg-signal/10 p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[10px] uppercase text-signal">Analyst Verdict</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <h3 className="text-xl font-semibold text-white">{assessment.activity}</h3>
            {assessment.primaryTechniqueId ? (
              <span className="rounded-md border border-cyan-300/25 bg-cyan-300/10 px-2 py-1 font-mono text-[10px] uppercase text-cyan-100">
                {assessment.primaryTechniqueId}
              </span>
            ) : null}
          </div>
        </div>
        <div className={`rounded-md border px-2.5 py-1.5 text-right ${confidenceClasses}`}>
          <p className="font-mono text-[9px] uppercase text-haze">Confidence</p>
          <p className="font-mono text-[11px] uppercase text-white">
            {assessment.confidence} · {assessment.confidenceScore}/100
          </p>
        </div>
      </div>

      <p className="mt-2 text-sm leading-6 text-white">{assessment.conclusion}</p>

      {assessment.evidenceCards.length ? (
        <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-4">
          {assessment.evidenceCards.slice(0, 4).map((card) => (
            <div key={`${card.label}-${card.value}`} className="rounded-md border border-white/10 bg-black/25 p-2.5">
              <p className="font-mono text-[9px] uppercase text-haze">{card.label}</p>
              <p className="mt-1 text-sm font-semibold text-white">{card.value}</p>
              <p className="mt-1 text-xs leading-5 text-haze">{card.detail}</p>
            </div>
          ))}
        </div>
      ) : null}

      <div className="mt-3 flex flex-wrap gap-2">
        {assessment.supportingSignals.length ? assessment.supportingSignals.map((signal) => (
          <span key={signal} className="rounded-md border border-white/10 bg-white/[0.04] px-2 py-1 font-mono text-[10px] uppercase text-haze">
            {signal}
          </span>
        )) : (
          <span className="rounded-md border border-white/10 bg-white/[0.04] px-2 py-1 font-mono text-[10px] uppercase text-haze">
            No secondary signal highlighted
          </span>
        )}
      </div>

      <div className="mt-3 grid gap-2 text-xs leading-5 text-haze lg:grid-cols-2">
        <p>
          <span className="text-white">Corroboration:</span> {assessment.corroboration}
        </p>
        <p>
          <span className="text-white">Limits:</span> {assessment.limitations.join(" ")}
        </p>
      </div>
    </div>
  );
}

function ThreatProfileStrip({ profiles }: { profiles: ThreatProfileBadge[] }) {
  const [activeId, setActiveId] = useState("");
  const containerRef = useOutsideDismiss<HTMLDivElement>(Boolean(activeId), () => setActiveId(""));

  if (!profiles.length) return null;

  const findings = profiles.filter((profile) => profile.kind === "finding").slice(0, 3);
  const contextProfiles = profiles.filter((profile) => profile.kind === "context").slice(0, 6);
  const overflowContextCount = Math.max(0, profiles.filter((profile) => profile.kind === "context").length - contextProfiles.length);
  const activeProfile = profiles.find((profile) => profile.id === activeId);

  return (
    <div ref={containerRef} className="rounded-md border border-white/10 bg-white/[0.03] p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono text-[10px] uppercase text-signal">Analyst Profile</p>
        <SourceBadge label="Derived" title="Generated from selected-IP activity, reputation, listing, and network evidence." />
      </div>

      {findings.length ? (
        <div className="grid gap-2 lg:grid-cols-3">
          {findings.map((profile) => (
            <button
              key={profile.id}
              type="button"
              aria-expanded={activeId === profile.id}
              className={`rounded-md border border-white/10 border-l-2 p-2.5 text-left transition hover:border-white/25 ${profileToneClasses(profile.tone)}`}
              onClick={() => setActiveId(activeId === profile.id ? "" : profile.id)}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-[10px] uppercase">{profile.label}</span>
                <span className="rounded border border-white/10 bg-black/20 px-1.5 py-0.5 font-mono text-[9px] uppercase text-haze">
                  {profile.confidence}
                </span>
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5 font-mono text-[9px] uppercase text-haze">
                <span>{profile.sourceCount} src</span>
                {profile.score ? <span>{profile.score}/100</span> : null}
              </div>
            </button>
          ))}
        </div>
      ) : null}

      {contextProfiles.length ? (
        <div className={`${findings.length ? "mt-3" : ""} flex flex-wrap gap-2`}>
          {contextProfiles.map((profile) => (
            <button
              key={profile.id}
              type="button"
              aria-expanded={activeId === profile.id}
              className={`inline-flex max-w-full items-center gap-2 rounded-md border border-white/10 border-l-2 px-2.5 py-1.5 font-mono text-[10px] uppercase ${profileToneClasses(profile.tone)}`}
              onClick={() => setActiveId(activeId === profile.id ? "" : profile.id)}
            >
              <span className="truncate">{profile.label}</span>
              <span className="rounded border border-white/10 bg-black/20 px-1.5 py-0.5 text-[9px] text-haze">{profile.confidence}</span>
            </button>
          ))}
          {overflowContextCount ? (
            <span className="inline-flex items-center rounded-md border border-white/10 bg-white/[0.03] px-2.5 py-1.5 font-mono text-[10px] uppercase text-haze">
              +{overflowContextCount} context
            </span>
          ) : null}
        </div>
      ) : null}

      {!findings.length && contextProfiles.length ? (
        <p className="mt-2 text-xs leading-5 text-haze">
          Context is available, but no strong behavior mapping was returned for this source.
        </p>
      ) : null}

      {activeProfile ? (
        <div className="mt-3 rounded-md border border-white/10 bg-black/25 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`rounded-md border border-white/10 border-l-2 px-2 py-1 font-mono text-[10px] uppercase ${profileToneClasses(activeProfile.tone)}`}>
              {activeProfile.label}
            </span>
            <span className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 font-mono text-[10px] uppercase text-haze">
              {activeProfile.confidence}
            </span>
            <span className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 font-mono text-[10px] uppercase text-haze">
              {activeProfile.sourceCount} source {activeProfile.sourceCount === 1 ? "signal" : "signals"}
            </span>
            {activeProfile.score ? (
              <span className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 font-mono text-[10px] uppercase text-haze">
                {activeProfile.score}/100
              </span>
            ) : null}
          </div>
          <p className="mt-2 text-xs leading-5 text-haze">
            <span className="text-white">Why this appeared:</span> {activeProfile.evidence}
          </p>
          {activeProfile.snippets?.length ? (
            <div className="mt-2 grid gap-2">
              {activeProfile.snippets.map((snippet) => (
                <p key={snippet} className="break-words rounded-md border border-white/10 bg-black/20 p-2 font-mono text-[10px] leading-5 text-haze">
                  {snippet}
                </p>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function IntelligenceSignalsPanel({
  abuse,
  categories,
  datasets,
  history,
  historyEvent,
  listingCount,
  virusTotal,
}: {
  abuse: AbuseIpdbSummary | AbuseIpdbDetail | null;
  categories: AbuseIpdbCategory[];
  datasets: EvidenceDataset[];
  history: SpamhausHistory | null | undefined;
  historyEvent: SpamhausHistoryEvent | null;
  listingCount: number;
  virusTotal: VirusTotalSummary | VirusTotalDetail | null;
}) {
  const hasListingSignals = Boolean(listingCount || history?.status === "found" || history?.status === "unavailable");
  const score = deriveIntelScore({ abuse, datasets, historyEvent, virusTotal });
  const severityClasses = intelSeverityClasses(score.severity);

  if (!abuse && !virusTotal && !hasListingSignals) return null;

  return (
    <div className="rounded-md border border-white/10 bg-white/[0.035] p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono text-[10px] uppercase text-signal">Intelligence Signals</p>
        <span className="rounded-md border border-white/10 bg-black/25 px-2 py-1 font-mono text-[10px] uppercase text-haze">
          Evidence dashboard
        </span>
      </div>

      <div className={`mt-2 rounded-lg border px-3 py-2.5 ${severityClasses.card}`}>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] uppercase">Intel Score</span>
            <span className="text-2xl font-semibold leading-none text-white tabular-nums">
              {score.score}
              <span className="text-lg text-haze">/100</span>
            </span>
            <span className={`inline-flex rounded-md border px-3 py-1.5 font-mono text-[10px] font-semibold uppercase ${severityClasses.pill}`}>
              {score.severity}
            </span>
          </div>
          <p className="max-w-2xl text-xs leading-5 text-haze sm:text-right">
            Combined third-party reputation, activity, listing, and freshness signals for this source IP.
          </p>
        </div>
      </div>

      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        {abuse ? (
          <SignalSection source="Activity data" sourceTitle="Source: AbuseIPDB reports" title="Activity Signals">
            <div className="flex flex-wrap gap-2">
              <SignalMetric label="Reports" value={formatNumber(abuse.total_reports)} />
              <SignalMetric label="Reporters" value={formatNumber(abuse.num_distinct_users)} />
              <SignalMetric label="Latest report" value={formatDate(abuse.last_reported_at)} />
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              {abuse.usage_type ? (
                <SignalFact label="Usage" value={abuse.usage_type} />
              ) : null}
              {abuse.isp || abuse.domain ? (
                <SignalFact label="Network" value={[abuse.isp, abuse.domain].filter(Boolean).join(" / ")} />
              ) : null}
              {abuse.country_name || abuse.country_code ? (
                <SignalFact label="Country" value={abuse.country_name || abuse.country_code} />
              ) : null}
              {abuse.is_tor || abuse.is_whitelisted !== null ? (
                <SignalFact
                  label="Flags"
                  value={[abuse.is_tor ? "Tor" : "", abuse.is_whitelisted === true ? "Whitelisted" : ""].filter(Boolean).join(", ") || "None returned"}
                />
              ) : null}
            </div>
            <AbuseCategoryBadges categories={categories} />
          </SignalSection>
        ) : null}

        {virusTotal ? (
          <SignalSection source="Reputation data" sourceTitle="Source: VirusTotal vendor reputation" title="Reputation Signals">
            <div className="flex flex-wrap gap-2">
              <SignalMetric label="Vendor detections" value={virusTotalRatio(virusTotal) || "None returned"} />
              <SignalMetric label="Latest analysis" value={formatDate(virusTotal.last_analysis_date)} />
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              <SignalFact label="Malicious" value={formatNumber(virusTotal.vendor_malicious)} />
              <SignalFact label="Suspicious" value={formatNumber(virusTotal.vendor_suspicious)} />
              <SignalFact label="Harmless" value={formatNumber(virusTotal.vendor_harmless)} />
              <SignalFact label="Undetected" value={formatNumber(virusTotal.vendor_undetected)} />
              <SignalFact label="Reputation" value={formatSignedNumber(virusTotal.reputation)} />
              <SignalFact
                label="Community"
                value={`${formatNumber(virusTotal.community_malicious)} malicious / ${formatNumber(virusTotal.community_harmless)} harmless votes`}
              />
              {virusTotal.asn || virusTotal.as_owner ? (
                <SignalFact label="Network" value={[virusTotal.asn ? `AS${virusTotal.asn}` : "", virusTotal.as_owner].filter(Boolean).join(" / ")} />
              ) : null}
              {virusTotal.country ? (
                <SignalFact label="Country" value={virusTotal.country} />
              ) : null}
            </div>
            {virusTotal.permalink ? (
              <a
                className="mt-2 inline-flex rounded-md border border-signal/25 bg-signal/10 px-2 py-1 font-mono text-[10px] uppercase text-signal transition hover:border-signal/60"
                href={virusTotal.permalink}
                target="_blank"
                rel="noreferrer"
              >
                View external reputation report
              </a>
            ) : null}
          </SignalSection>
        ) : null}

        {hasListingSignals ? (
          <SignalSection className="lg:col-span-2" source="Listing data" sourceTitle="Source: Spamhaus listings and historical intelligence" title="Listing Signals">
            {listingCount ? (
              <div>
                <p className="text-sm font-semibold text-white">
                  {listingCount} current reputation {listingCount === 1 ? "listing" : "listings"}.
                </p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {datasets.map((dataset) => (
                    <span
                      key={`${dataset.code}-${dataset.dataset}`}
                      className="rounded-md border border-signal/30 bg-signal/10 px-2 py-1 font-mono text-[10px] uppercase text-signal"
                      title={dataset.label}
                    >
                      {dataset.dataset} / Code {dataset.code}
                    </span>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-sm leading-6 text-haze">No current reputation listing found.</p>
            )}
            <HistoricalListing history={history} />
          </SignalSection>
        ) : null}
      </div>
    </div>
  );
}

function IpIntelligence({
  abuseDetail,
  abuseError,
  abuseLoading,
  abuseSummary,
  detail,
  error,
  loading,
  selectedPoint,
  selectedIp,
  summary,
  virusTotalDetail,
  virusTotalError,
  virusTotalLoading,
  virusTotalSummary,
}: {
  abuseDetail: AbuseIpdbDetail | null;
  abuseError: string;
  abuseLoading: boolean;
  abuseSummary: AbuseIpdbSummary | null;
  detail: SpamhausDetail | null;
  error: string;
  loading: boolean;
  selectedPoint: ThreatPoint | null;
  selectedIp: string;
  summary: IpIntelligenceSummary | null;
  virusTotalDetail: VirusTotalDetail | null;
  virusTotalError: string;
  virusTotalLoading: boolean;
  virusTotalSummary: VirusTotalSummary | null;
}) {
  const abuse = abusePayload(abuseDetail, abuseSummary);
  const categories = abuseCategories(abuseDetail, abuseSummary);
  const datasets = spamhausDatasets(detail, summary);
  const listingCount = spamhausListingCount(detail, summary);
  const history = detail?.history;
  const historyEvent = newestHistoryEvent(detail);
  const virusTotal = virusTotalPayload(virusTotalDetail, virusTotalSummary);
  const hasSpamhausContent = Boolean(
    listingCount ||
      history?.status === "found" ||
      history?.status === "unavailable",
  );
  const hasAbuseContent = Boolean(abuse);
  const hasVirusTotalContent = Boolean(virusTotal);
  const mitreTechniques = mergeMitreTechniques(abuseDetail?.mitre_techniques, detail?.mitre_techniques, virusTotalDetail?.mitre_techniques);
  const mitreMatches = mergeMitreMatches(abuseDetail?.mitre_matches, detail?.mitre_matches, virusTotalDetail?.mitre_matches);
  const threatProfiles = deriveThreatProfiles({
    abuse,
    categories,
    datasets,
    historyEvent,
    matches: mitreMatches,
    point: selectedPoint,
    virusTotal,
  });
  const intelScore = deriveIntelScore({ abuse, datasets, historyEvent, virusTotal });
  const assessment = hasSpamhausContent || hasAbuseContent || hasVirusTotalContent
    ? deriveAssessment({
        abuse,
        categories,
        datasets,
        historyEvent,
        intelScore,
        listingCount,
        matches: mitreMatches,
        point: selectedPoint,
        profiles: threatProfiles,
        virusTotal,
      })
    : null;
  const isChecking = loading || abuseLoading || virusTotalLoading;

  return (
    <div className="rounded-lg border border-white/10 bg-black/25 p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <p className="font-mono text-[11px] uppercase text-signal">IP Intelligence</p>
        {detail?.cache_status || summary?.cache_status || abuseDetail?.cache_status || abuseSummary?.cache_status || virusTotalDetail?.cache_status || virusTotalSummary?.cache_status ? (
          <span className="rounded-md border border-white/10 bg-black/30 px-2 py-1 font-mono text-[10px] uppercase text-haze">
            {detail?.cache_status || summary?.cache_status || abuseDetail?.cache_status || abuseSummary?.cache_status || virusTotalDetail?.cache_status || virusTotalSummary?.cache_status}
          </span>
        ) : null}
      </div>

      {!selectedIp ? (
        <p className="text-sm leading-6 text-haze">Select a source to check IP intelligence.</p>
      ) : assessment ? (
        <div className="grid gap-3">
          <AssessmentPanel assessment={assessment} />
          <ThreatProfileStrip profiles={threatProfiles} />
          <MitreBehaviorGraph matches={mitreMatches} techniques={mitreTechniques} />
          <IntelligenceSignalsPanel
            abuse={abuse}
            categories={categories}
            datasets={datasets}
            history={history}
            historyEvent={historyEvent}
            listingCount={listingCount}
            virusTotal={virusTotal}
          />
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
      {virusTotalDetail?.warnings?.length ? (
        <p className="mt-3 text-xs leading-5 text-volt">{virusTotalDetail.warnings.join(" ")}</p>
      ) : null}
      {virusTotalError && !hasVirusTotalContent ? <p className="mt-3 text-xs leading-5 text-trace">{virusTotalError}</p> : null}
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
  const virusTotalCacheRef = useRef(new Map<string, VirusTotalDetail>());
  const [data, setData] = useState<ThreatOriginResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [warmupStatus, setWarmupStatus] = useState<VirusTotalPrewarmResponse | null>(null);
  const [warmupLoading, setWarmupLoading] = useState(false);
  const [warmupError, setWarmupError] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [spamhausDetail, setSpamhausDetail] = useState<SpamhausDetail | null>(null);
  const [spamhausLoading, setSpamhausLoading] = useState(false);
  const [spamhausError, setSpamhausError] = useState("");
  const [abuseIpdbDetail, setAbuseIpdbDetail] = useState<AbuseIpdbDetail | null>(null);
  const [abuseIpdbLoading, setAbuseIpdbLoading] = useState(false);
  const [abuseIpdbError, setAbuseIpdbError] = useState("");
  const [virusTotalDetail, setVirusTotalDetail] = useState<VirusTotalDetail | null>(null);
  const [virusTotalLoading, setVirusTotalLoading] = useState(false);
  const [virusTotalError, setVirusTotalError] = useState("");
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
        setSelectedId((currentId) => (payload.points.some((point) => point.id === currentId) ? currentId : payload.points[0]?.id || ""));
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

  const warmReputationCache = () => {
    if (data?.mode !== "live" || warmupLoading) {
      return;
    }

    setWarmupLoading(true);
    setWarmupError("");

    fetch("/api/virustotal-prewarm", {
      method: "POST",
      headers: {
        Accept: "application/json",
      },
    })
      .then((response) => readJson<VirusTotalPrewarmResponse>(response))
      .then((payload) => {
        setWarmupStatus(payload);
        if (payload.cached > 0 || payload.remaining <= 0 || payload.status === "complete") {
          loadThreatOrigins();
        }
      })
      .catch((loadError) => {
        setWarmupError(loadError instanceof Error ? loadError.message : "Reputation cache warmup is temporarily unavailable.");
      })
      .finally(() => setWarmupLoading(false));
  };

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
    if (!selectedPoint?.ip) {
      setVirusTotalDetail(null);
      setVirusTotalError("");
      setVirusTotalLoading(false);
      return;
    }

    if (data?.mode !== "live") {
      setVirusTotalDetail(null);
      setVirusTotalError("");
      setVirusTotalLoading(false);
      return;
    }

    const cachedDetail = virusTotalCacheRef.current.get(selectedPoint.ip);
    if (cachedDetail) {
      setVirusTotalDetail(cachedDetail);
      setVirusTotalError("");
      setVirusTotalLoading(false);
      return;
    }

    const controller = new AbortController();
    setVirusTotalLoading(true);
    setVirusTotalError("");
    setVirusTotalDetail(null);

    fetch(`/api/virustotal-ip-detail?ip=${encodeURIComponent(selectedPoint.ip)}`, {
      headers: {
        Accept: "application/json",
      },
      signal: controller.signal,
    })
      .then((response) => readJson<VirusTotalDetail>(response))
      .then((payload) => {
        virusTotalCacheRef.current.set(selectedPoint.ip, payload);
        setVirusTotalDetail(payload);
      })
      .catch((loadError) => {
        if (loadError instanceof DOMException && loadError.name === "AbortError") return;
        setVirusTotalError(loadError instanceof Error ? loadError.message : "VirusTotal intelligence is temporarily unavailable.");
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setVirusTotalLoading(false);
        }
      });

    return () => controller.abort();
  }, [data?.mode, selectedPoint?.ip]);

  useEffect(() => {
    if (data?.mode !== "live" || !points.length) {
      return;
    }

    let stopped = false;
    let intervalId = 0;

    const warmVirusTotalCache = () => {
      fetch("/api/virustotal-prewarm", {
        method: "POST",
        headers: {
          Accept: "application/json",
        },
      })
        .then((response) => readJson<{ status: string; remaining: number }>(response))
        .then((payload) => {
          if (!stopped && (payload.remaining <= 0 || payload.status === "complete" || payload.status === "empty" || payload.status === "not_configured")) {
            window.clearInterval(intervalId);
          }
        })
        .catch(() => {
          // Silent best-effort warmup; selected-IP lookup can still retry and show warnings.
        });
    };

    warmVirusTotalCache();
    intervalId = window.setInterval(warmVirusTotalCache, 60_000);

    return () => {
      stopped = true;
      window.clearInterval(intervalId);
    };
  }, [data?.generated_at, data?.mode, points.length]);

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
          <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_340px] xl:grid-cols-[minmax(0,1fr)_380px] 2xl:grid-cols-[minmax(0,1fr)_420px]">
            <div>
              <div className="overflow-hidden rounded-lg border border-white/10 bg-white/[0.04]">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-4 py-3">
                  <div className="flex items-center gap-2 font-mono text-xs uppercase text-signal">
                    <Globe2 size={16} />
                    Daily source marker layer
                  </div>
                  <div className="flex flex-wrap items-center justify-end gap-2">
                    <button
                      type="button"
                      onClick={warmReputationCache}
                      disabled={data?.mode !== "live" || warmupLoading}
                      className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-cyan-300/20 bg-cyan-300/10 px-3 text-sm font-medium text-cyan-100 transition hover:border-cyan-300/45 hover:text-cyan-50 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {warmupLoading ? <Loader2 className="animate-spin" size={15} /> : <Radar size={15} />}
                      Warm intel cache
                    </button>
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
                </div>
                {(warmupStatus || warmupError) && (
                  <div className="border-b border-white/10 bg-black/20 px-4 py-2 text-xs leading-5 text-haze">
                    {warmupError ? (
                      <span className="text-trace">{warmupError}</span>
                    ) : warmupStatus ? (
                      <span>
                        Reputation warmup: {warmupStatus.status}. Cached {warmupStatus.cached} this run, {warmupStatus.remaining} remaining
                        {warmupStatus.next_run_at ? `; next batch after ${formatDate(warmupStatus.next_run_at)}` : ""}.
                        {warmupStatus.warnings?.length ? ` ${warmupStatus.warnings.join(" ")}` : ""}
                      </span>
                    ) : null}
                  </div>
                )}
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
            selectedPoint={selectedPoint}
            selectedIp={selectedPoint?.ip || ""}
            summary={selectedPoint?.ip_intelligence || null}
            virusTotalDetail={virusTotalDetail}
            virusTotalError={virusTotalError}
            virusTotalLoading={virusTotalLoading}
            virusTotalSummary={selectedPoint?.virustotal_intelligence || null}
          />

          <div className="rounded-lg border border-white/10 bg-white/[0.04] p-4">
            <div className="mb-3 flex items-center justify-between gap-3">
              <p className="font-mono text-xs uppercase text-signal">Daily Top 50 ranking</p>
              <span className="rounded-md border border-white/10 bg-black/25 px-2 py-1 font-mono text-[11px] uppercase text-haze">
                {data?.cache_status || "loading"}
              </span>
            </div>
            <div className="max-h-[360px] overflow-y-auto pr-1">
              <div className="grid gap-2 md:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
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
