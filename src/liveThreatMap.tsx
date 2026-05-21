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
  last_analysis_date: string;
  permalink: string;
  generated_at: string;
  cache_status: "fresh" | "cached";
};

type VirusTotalDetail = VirusTotalSummary & {
  ip: string;
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

function SignalSection({
  children,
  source,
  sourceTitle,
  title,
}: {
  children: ReactNode;
  source: string;
  sourceTitle: string;
  title: string;
}) {
  return (
    <section className="border-t border-white/10 py-3 first:border-t-0 first:pt-0 last:pb-0">
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
    <div className="min-w-[142px] rounded-md border border-white/10 bg-black/20 px-3 py-2">
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

type EvidenceDataset = Pick<SpamhausDataset, "code" | "dataset" | "label">;

type IntelligenceAssessment = {
  activity: string;
  conclusion: string;
  corroboration: string;
  freshness: string;
  scope: string;
  chips: string[];
  secondarySignals: string[];
};

type IntelScore = {
  score: number;
  severity: "Low" | "Elevated" | "High" | "Critical";
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

function hasDataset(datasets: EvidenceDataset[], names: string[]) {
  return datasets.some((dataset) => names.some((name) => dataset.dataset.toLowerCase().includes(name.toLowerCase())));
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

function latestSeen(
  abuse: AbuseIpdbSummary | AbuseIpdbDetail | null,
  event: SpamhausHistoryEvent | null,
  virusTotal: VirusTotalSummary | VirusTotalDetail | null,
) {
  const candidates = [abuse?.last_reported_at, event?.seen_at, event?.listed_at, virusTotal?.last_analysis_date].filter(Boolean) as string[];
  const latest = candidates
    .map((value) => ({ value, time: new Date(value).getTime() }))
    .filter((entry) => Number.isFinite(entry.time))
    .sort((left, right) => right.time - left.time)[0]?.value;

  return latest ? formatDate(latest) : "Unknown";
}

function deriveAssessment({
  abuse,
  categories,
  datasets,
  historyEvent,
  listingCount,
  virusTotal,
}: {
  abuse: AbuseIpdbSummary | AbuseIpdbDetail | null;
  categories: AbuseIpdbCategory[];
  datasets: EvidenceDataset[];
  historyEvent: SpamhausHistoryEvent | null;
  listingCount: number;
  virusTotal: VirusTotalSummary | VirusTotalDetail | null;
}): IntelligenceAssessment {
  const labels = categorySet(categories);
  const hasAbuseReports = Boolean(abuse?.total_reports);
  const hasSpamhausListings = listingCount > 0;
  const hasVirusTotalSignal = hasVirusTotalDetections(virusTotal);
  const hasVirusTotalData = Boolean(virusTotal);
  const hasBruteforceSsh = (labels.has("brute-force") && labels.has("ssh")) || hasSshBruteforceHistory(historyEvent);
  const hasPortScan = labels.has("port scan");
  const hasXbl = hasDataset(datasets, ["XBL", "CBL"]);
  const hasAbusiveInfrastructure = hasDataset(datasets, ["SBL", "DROP"]);
  const hasPolicyContext = hasDataset(datasets, ["PBL"]);
  const hostingContext = abuse?.usage_type && /data center|hosting|transit|cloud/i.test(abuse.usage_type) ? " from hosting infrastructure" : "";
  const secondarySignals = [];

  let activity = "Reported abusive source";
  let conclusion = "This IP has third-party abuse intelligence, but the available evidence does not identify a single dominant activity.";

  if (hasBruteforceSsh) {
    activity = "SSH brute-force source";
    conclusion = `This IP is most strongly associated with SSH brute-force activity${hostingContext}.`;
  } else if (hasPortScan) {
    activity = "Port scanning source";
    conclusion = `This IP is most strongly associated with port scanning activity${hostingContext}.`;
  } else if (hasXbl) {
    activity = "Possible exploited or infected host";
    conclusion = "Listing data indicates this IP may be an exploited or infected host.";
  } else if (hasAbusiveInfrastructure) {
    activity = "Known abusive infrastructure";
    conclusion = "Listing data links this IP or netblock to abusive infrastructure.";
  } else if (hasAbuseReports) {
    activity = "Repeatedly reported abuse source";
    conclusion = `Activity reporting indicates repeated abusive activity from this source IP${hostingContext}.`;
  } else if (hasSpamhausListings) {
    activity = "Listed abuse source";
    conclusion = "This source IP appears in abuse reputation datasets.";
  } else if (hasVirusTotalSignal) {
    activity = "Vendor-flagged suspicious source";
    conclusion = "Vendor reputation flags this source IP, but no dominant activity signal is available.";
  }

  if (hasPortScan && activity !== "Port scanning source") secondarySignals.push("Port scanning also reported");
  if (hasXbl && activity !== "Possible exploited or infected host") secondarySignals.push("Possible exploited or infected host");
  if (hasAbusiveInfrastructure && activity !== "Known abusive infrastructure") secondarySignals.push("Known abusive infrastructure/listed netblock");
  if (hasPolicyContext) secondarySignals.push("Policy/listing context also present");
  if (hasVirusTotalSignal && activity !== "Vendor-flagged suspicious source") secondarySignals.push("Vendor detections present");

  if (hasSpamhausListings && hasAbuseReports && !conclusion.includes("listing data")) {
    conclusion = `${conclusion.replace(/\.$/, "")}, with listing data indicating broader abuse reputation.`;
  }

  const corroborationSources = [
    hasAbuseReports ? "activity reports" : "",
    hasSpamhausListings ? "listing data" : "",
    hasVirusTotalSignal ? "vendor reputation" : "",
  ].filter(Boolean);
  const freshness = latestSeen(abuse, historyEvent, virusTotal);

  return {
    activity,
    conclusion,
    corroboration: corroborationSources.length > 1
      ? `Confirmed by ${corroborationSources.join(", ").replace(/, ([^,]*)$/, " and $1")}.`
      : corroborationSources.length === 1
        ? `Supported by ${corroborationSources[0]}.`
        : "Supported by third-party reputation data.",
    freshness,
    scope: "Reported source IP activity, not traffic against this portfolio.",
    chips: [
      hasAbuseReports ? `${formatNumber(abuse?.total_reports)} reports` : "",
      hasAbuseReports ? `${formatNumber(abuse?.num_distinct_users)} reporters` : "",
      hasSpamhausListings ? `${listingCount} ${listingCount === 1 ? "listing" : "listings"}` : "",
      hasVirusTotalData && virusTotalRatio(virusTotal) ? `${virusTotalRatio(virusTotal)} vendors` : "",
      `Last seen ${freshness}`,
    ].filter(Boolean),
    secondarySignals,
  };
}

function AssessmentPanel({ assessment }: { assessment: IntelligenceAssessment }) {
  return (
    <div className="rounded-md border border-signal/25 bg-signal/10 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[10px] uppercase text-signal">Assessment</p>
          <h3 className="mt-2 text-xl font-semibold text-white">{assessment.activity}</h3>
        </div>
        <span className="rounded-md border border-white/10 bg-black/25 px-2 py-1 font-mono text-[10px] uppercase text-haze">
          Freshness {assessment.freshness}
        </span>
      </div>
      <p className="mt-3 text-sm leading-6 text-white">{assessment.conclusion}</p>
      <div className="mt-3 grid gap-2 text-xs leading-5 text-haze md:grid-cols-3">
        <p>
          <span className="text-white">Corroboration:</span> {assessment.corroboration}
        </p>
        <p>
          <span className="text-white">Scope:</span> {assessment.scope}
        </p>
        <p>
          <span className="text-white">Secondary:</span> {assessment.secondarySignals.join(", ") || "No secondary signal highlighted"}
        </p>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {assessment.chips.map((chip) => (
          <span key={chip} className="rounded-md border border-signal/25 bg-black/25 px-2 py-1 font-mono text-[10px] uppercase text-signal">
            {chip}
          </span>
        ))}
      </div>
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
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[10px] uppercase text-signal">Intelligence Signals</p>
          <p className="mt-1.5 max-w-3xl text-sm leading-6 text-haze">
            Intel Score reflects combined third-party reputation, activity, listing, and freshness signals for this source IP.
          </p>
        </div>
        <div className={`w-full rounded-lg border p-3 text-center sm:w-[158px] ${severityClasses.card}`}>
          <p className="font-mono text-[10px] uppercase">Intel Score</p>
          <p className="mt-1 text-3xl font-semibold leading-none text-white tabular-nums">
            {score.score}
            <span className="text-xl text-haze">/100</span>
          </p>
          <span className={`mt-2 inline-flex rounded-md border px-3 py-1.5 font-mono text-[10px] font-semibold uppercase ${severityClasses.pill}`}>
            {score.severity}
          </span>
        </div>
      </div>

      <div className="mt-3">
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
          <SignalSection source="Listing data" sourceTitle="Source: Spamhaus listings and historical intelligence" title="Listing Signals">
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
  const assessment = hasSpamhausContent || hasAbuseContent || hasVirusTotalContent
    ? deriveAssessment({ abuse, categories, datasets, historyEvent, listingCount, virusTotal })
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
