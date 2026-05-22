import { resolveMitreTechniques } from "./mitre-attack.js";

const THREAT_PATTERNS = [
  {
    id: "ssh-bruteforce-combined",
    regex: /\b(?:ssh|sshd|ssh2|port\s*22)\b[\s\S]{0,180}\b(?:brute[-\s]?force|bruteforce|failed password|authentication failure)|\b(?:brute[-\s]?force|bruteforce|failed password|authentication failure)\b[\s\S]{0,180}\b(?:ssh|sshd|ssh2|port\s*22)\b/i,
    techniqueId: "T1110",
    techniqueName: "Brute Force",
    tactic: "Credential Access",
    sourceTypes: ["abuseipdb", "spamhaus"],
    priority: 100,
    confidence: "high",
    evidenceLabel: "SSH brute-force signal",
    mergeKey: "bruteforce",
  },
  {
    id: "bruteforce-generic",
    regex: /\b(?:brute[-\s]?force|bruteforce|failed password|authentication brute[-\s]?force|stolen credential|authbl)\b/i,
    techniqueId: "T1110",
    techniqueName: "Brute Force",
    tactic: "Credential Access",
    sourceTypes: ["abuseipdb", "spamhaus"],
    priority: 90,
    confidence: "high",
    evidenceLabel: "Brute-force signal",
    mergeKey: "bruteforce",
  },
  {
    id: "active-scanning",
    regex: /\b(?:port scan|active scan|scan(?:ning|ned)?|scanner|probe|probing|reconnaissance)\b/i,
    techniqueId: "T1595",
    techniqueName: "Active Scanning",
    tactic: "Reconnaissance",
    sourceTypes: ["abuseipdb", "spamhaus"],
    priority: 80,
    confidence: "high",
    evidenceLabel: "Scanning signal",
    mergeKey: "scanning",
  },
  {
    id: "network-denial-of-service",
    regex: /\b(?:ddos|dos attack|denial of service|ping of death|flood(?:ing)?)\b/i,
    techniqueId: "T1498",
    techniqueName: "Network Denial of Service",
    tactic: "Impact",
    sourceTypes: ["abuseipdb", "spamhaus"],
    priority: 75,
    confidence: "high",
    evidenceLabel: "Denial-of-service signal",
    mergeKey: "denial-of-service",
  },
  {
    id: "public-app-exploit",
    regex: /\b(?:sql injection|web app attack|public[-\s]?facing|cve-\d{4}-\d+|citrix|netscaler|rce|remote code execution|apache struts|log4shell|wordpress|joomla|drupal)\b/i,
    techniqueId: "T1190",
    techniqueName: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    sourceTypes: ["abuseipdb", "spamhaus"],
    priority: 70,
    confidence: "high",
    evidenceLabel: "Public-facing application exploit signal",
    mergeKey: "public-app-exploit",
  },
  {
    id: "phishing",
    regex: /\bphishing\b/i,
    techniqueId: "T1566",
    techniqueName: "Phishing",
    tactic: "Initial Access",
    sourceTypes: ["abuseipdb", "spamhaus"],
    priority: 65,
    confidence: "high",
    evidenceLabel: "Phishing signal",
    mergeKey: "phishing",
  },
];

function cleanEvidence(value, maxLength = 180) {
  return String(value || "")
    .replace(/[^\w .,:()#+&/:?@'"[\]-]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function addEvidence(fields, source, matchedField, value) {
  const evidence = cleanEvidence(value);
  if (!evidence) return;

  fields.push({
    source,
    matched_field: matchedField,
    evidence,
    normalized: evidence.toLowerCase(),
  });
}

function numberOrNull(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function abuseCategoryEvidence(category) {
  const id = numberOrNull(category?.id);
  return [
    id ? `category ${id}` : "",
    category?.label || "",
    category?.count ? `count ${category.count}` : "",
  ].filter(Boolean).join(" ");
}

export function normalizeAbuseIpdbEvidence(payload) {
  const fields = [];

  for (const category of Array.isArray(payload?.top_categories) ? payload.top_categories : []) {
    addEvidence(fields, "abuseipdb", "top_categories", abuseCategoryEvidence(category));
  }

  for (const report of Array.isArray(payload?.recent_reports) ? payload.recent_reports : []) {
    addEvidence(fields, "abuseipdb", "recent_report.comment", report?.comment);

    for (const category of Array.isArray(report?.categories) ? report.categories : []) {
      addEvidence(fields, "abuseipdb", "recent_report.categories", abuseCategoryEvidence(category));
    }
  }

  return fields;
}

function spamhausDatasetEvidence(dataset) {
  return [
    dataset?.code ? `code ${dataset.code}` : "",
    dataset?.dataset || "",
    dataset?.label || "",
  ].filter(Boolean).join(" ");
}

function spamhausEventEvidence(event) {
  const ports = [
    event?.source_port ? `source port ${event.source_port}` : "",
    event?.destination_port ? `destination port ${event.destination_port}` : "",
  ].filter(Boolean).join(" ");

  const connection = [
    event?.source_ip || "",
    event?.destination_ip ? `to ${event.destination_ip}` : "",
    ports,
    event?.protocol || "",
  ].filter(Boolean).join(" ");

  return [
    event?.dataset || "",
    connection,
    event?.detection || "",
    event?.heuristic ? `heuristic ${event.heuristic}` : "",
    event?.botname ? `bot ${event.botname}` : "",
  ].filter(Boolean).join(" ");
}

export function normalizeSpamhausEvidence(payload) {
  const fields = [];

  for (const dataset of Array.isArray(payload?.datasets) ? payload.datasets : []) {
    addEvidence(fields, "spamhaus", "datasets", spamhausDatasetEvidence(dataset));
  }

  for (const event of Array.isArray(payload?.history?.events) ? payload.history.events : []) {
    addEvidence(fields, "spamhaus", "history.events", spamhausEventEvidence(event));
  }

  return fields;
}

function compareMatches(left, right) {
  if (left.priority !== right.priority) return right.priority - left.priority;
  if (left.confidence !== right.confidence) return left.confidence === "high" ? -1 : 1;
  return left.technique_id.localeCompare(right.technique_id);
}

export function matchThreatPatterns(fields, sourceType) {
  const matchesByMergeKey = new Map();

  for (const field of Array.isArray(fields) ? fields : []) {
    if (!field?.normalized || field.source !== sourceType) continue;

    for (const pattern of THREAT_PATTERNS) {
      if (!pattern.sourceTypes.includes(sourceType)) continue;

      const match = pattern.regex.exec(field.normalized);
      if (!match) continue;

      const key = `${pattern.techniqueId}:${pattern.mergeKey || pattern.id}`;
      const nextMatch = {
        technique_id: pattern.techniqueId,
        source: sourceType,
        evidence: field.evidence,
        matched_field: field.matched_field,
        confidence: pattern.confidence,
        pattern_label: pattern.evidenceLabel,
        priority: pattern.priority,
      };
      const existing = matchesByMergeKey.get(key);

      if (!existing || compareMatches(nextMatch, existing) < 0) {
        matchesByMergeKey.set(key, nextMatch);
      }
    }
  }

  return [...matchesByMergeKey.values()].sort(compareMatches);
}

export async function addMitrePatternAnalysis(payload, sourceType, normalizeEvidence) {
  try {
    const matches = matchThreatPatterns(normalizeEvidence(payload), sourceType);
    const techniques = await resolveMitreTechniques(matches.map((match) => match.technique_id));
    const resolvedIds = new Set(techniques.map((technique) => technique.id));

    return {
      ...payload,
      mitre_techniques: techniques,
      mitre_matches: matches
        .filter((match) => resolvedIds.has(match.technique_id))
        .map(({ priority, ...match }) => match),
    };
  } catch {
    return {
      ...payload,
      mitre_techniques: [],
      mitre_matches: [],
    };
  }
}
