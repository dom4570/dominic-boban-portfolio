import { resolveMitreTechniques } from "./mitre-attack.js";

const THREAT_PATTERNS = [
  {
    id: "ssh-bruteforce-combined",
    regex: /\b(?:ssh|sshd|ssh2|port\s*22)\b[\s\S]{0,180}\b(?:brute[-\s]?force|bruteforce|failed password|authentication failure)|\b(?:brute[-\s]?force|bruteforce|failed password|authentication failure)\b[\s\S]{0,180}\b(?:ssh|sshd|ssh2|port\s*22)\b/i,
    techniqueId: "T1110",
    techniqueName: "Brute Force",
    tactic: "Credential Access",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    priority: 100,
    confidence: "high",
    evidenceLabel: "SSH brute-force signal",
    meaning: "This maps to Credential Access because the evidence references SSH authentication failures, port 22 activity, or brute-force login behavior.",
    mergeKey: "bruteforce",
  },
  {
    id: "bruteforce-generic",
    regex: /\b(?:brute[-\s]?force|bruteforce|failed password|authentication brute[-\s]?force|stolen credential|authbl)\b/i,
    techniqueId: "T1110",
    techniqueName: "Brute Force",
    tactic: "Credential Access",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    priority: 90,
    confidence: "high",
    evidenceLabel: "Brute-force signal",
    meaning: "This maps to Credential Access because the evidence references repeated authentication attempts or brute-force login behavior.",
    mergeKey: "bruteforce",
  },
  {
    id: "active-scanning",
    regex: /\b(?:port scan|active scan|scan(?:ning|ned)?|scanner|probe|probing|reconnaissance)\b/i,
    techniqueId: "T1595",
    techniqueName: "Active Scanning",
    tactic: "Reconnaissance",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    priority: 80,
    confidence: "high",
    evidenceLabel: "Scanning signal",
    meaning: "This maps to Reconnaissance because the evidence references scanning, probing, or port-scan behavior.",
    mergeKey: "scanning",
  },
  {
    id: "network-denial-of-service",
    regex: /\b(?:ddos|dos attack|denial of service|ping of death|flood(?:ing)?)\b/i,
    techniqueId: "T1498",
    techniqueName: "Network Denial of Service",
    tactic: "Impact",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    priority: 75,
    confidence: "high",
    evidenceLabel: "Denial-of-service signal",
    meaning: "This maps to Impact because the evidence references denial-of-service, DDoS, flooding, or ping-of-death behavior.",
    mergeKey: "denial-of-service",
  },
  {
    id: "public-app-exploit",
    regex: /\b(?:sql injection|web app attack|public[-\s]?facing|cve-\d{4}-\d+|citrix|netscaler|rce|remote code execution|apache struts|log4shell|wordpress|joomla|drupal)\b/i,
    techniqueId: "T1190",
    techniqueName: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    priority: 70,
    confidence: "high",
    evidenceLabel: "Public-facing application exploit signal",
    meaning: "This maps to Initial Access because the evidence references SQL injection, public-facing application exploitation, CVE text, Citrix/Netscaler, RCE, or web app attack behavior.",
    mergeKey: "public-app-exploit",
  },
  {
    id: "phishing",
    regex: /\bphishing\b/i,
    techniqueId: "T1566",
    techniqueName: "Phishing",
    tactic: "Initial Access",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    priority: 65,
    confidence: "high",
    evidenceLabel: "Phishing signal",
    meaning: "This maps to Initial Access because the evidence references phishing behavior.",
    mergeKey: "phishing",
  },
  {
    id: "command-and-control",
    regex: /\b(?:c2|c&c|command[-\s]?and[-\s]?control|botnet controller)\b/i,
    techniqueId: "T1071",
    techniqueName: "Application Layer Protocol",
    tactic: "Command and Control",
    sourceTypes: ["spamhaus", "virustotal"],
    priority: 60,
    confidence: "medium",
    evidenceLabel: "Command-and-control signal",
    meaning: "This maps to Command and Control because the evidence explicitly references C2, command-and-control, or botnet controller behavior.",
    mergeKey: "command-and-control",
  },
];

function cleanEvidence(value, maxLength = 180) {
  return String(value || "")
    .replace(/[^\w .,:()#+&/:?@'"[\]-]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function addEvidence(fields, source, matchedField, value, metadata = {}) {
  const evidence = cleanEvidence(value, 240);
  if (!evidence) return;

  fields.push({
    source,
    matched_field: matchedField,
    evidence,
    evidence_title: cleanEvidence(metadata.title || evidence, 140),
    evidence_summary: cleanEvidence(metadata.summary || "", 280),
    raw_evidence: cleanEvidence(metadata.rawEvidence || value, 320),
    normalized: evidence.toLowerCase(),
  });
}

function numberOrNull(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function abuseCategoryEvidence(category) {
  const id = numberOrNull(category?.id);
  const label = cleanEvidence(category?.label || (id ? `Category ${id}` : "AbuseIPDB category"), 80);
  const count = numberOrNull(category?.count);

  return {
    value: [label, id ? `category ${id}` : ""].filter(Boolean).join(" "),
    title: `AbuseIPDB category: ${label}`,
    summary: count
      ? `${label} appeared in ${count} of the latest AbuseIPDB report examples loaded for this selected IP.`
      : `AbuseIPDB labels this selected IP with the ${label}${id ? ` category ${id}` : " category"}.`,
    rawEvidence: [id ? `Category ${id}` : "", label, count ? `sample count ${count}` : ""].filter(Boolean).join(": "),
  };
}

export function normalizeAbuseIpdbEvidence(payload) {
  const fields = [];

  for (const category of Array.isArray(payload?.top_categories) ? payload.top_categories : []) {
    const evidence = abuseCategoryEvidence(category);
    addEvidence(fields, "abuseipdb", "top_categories", evidence.value, evidence);
  }

  for (const report of Array.isArray(payload?.recent_reports) ? payload.recent_reports : []) {
    addEvidence(fields, "abuseipdb", "recent_report.comment", report?.comment, {
      title: "Reporter log snippet",
      summary: "A recent AbuseIPDB report comment included text matching this ATT&CK behavior.",
      rawEvidence: report?.comment,
    });

    for (const category of Array.isArray(report?.categories) ? report.categories : []) {
      const evidence = abuseCategoryEvidence(category);
      addEvidence(fields, "abuseipdb", "recent_report.categories", evidence.value, evidence);
    }
  }

  return fields;
}

function spamhausDatasetEvidence(dataset) {
  const datasetName = cleanEvidence(dataset?.dataset || "Spamhaus listing", 80);
  const label = cleanEvidence(dataset?.label || datasetName, 120);
  const code = numberOrNull(dataset?.code);

  return {
    value: [datasetName, label, code ? `code ${code}` : ""].filter(Boolean).join(" "),
    title: `Current listing: ${datasetName}`,
    summary: `${label}${code ? ` returned code ${code}` : ""}. Dataset-only listings are used only when they describe a concrete behavior signal.`,
    rawEvidence: [datasetName, label, code ? `code ${code}` : ""].filter(Boolean).join(" / "),
  };
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

  const dataset = cleanEvidence(event?.dataset || "historical listing", 60);
  const detection = cleanEvidence(event?.detection || "historical detection", 120);
  const heuristic = cleanEvidence(event?.heuristic || "", 60);
  const botname = cleanEvidence(event?.botname || "", 80);
  const protocol = cleanEvidence(event?.protocol || "", 20);
  const port = event?.destination_port || event?.source_port || null;
  const value = [
    event?.dataset || "",
    connection,
    event?.detection || "",
    event?.heuristic ? `heuristic ${event.heuristic}` : "",
    event?.botname ? `bot ${event.botname}` : "",
  ].filter(Boolean).join(" ");

  return {
    value,
    title: "Historical listing event",
    summary: [
      `Spamhaus historical intelligence recorded ${dataset} activity`,
      port ? `on port ${port}` : "",
      protocol ? `using ${protocol}` : "",
      heuristic ? `with heuristic ${heuristic}` : "",
      botname ? `and bot label ${botname}` : "",
    ].filter(Boolean).join(" ") + ".",
    rawEvidence: [dataset, connection, detection, heuristic ? `heuristic ${heuristic}` : "", botname ? `bot ${botname}` : ""].filter(Boolean).join(" "),
  };
}

export function normalizeSpamhausEvidence(payload) {
  const fields = [];

  for (const dataset of Array.isArray(payload?.datasets) ? payload.datasets : []) {
    const evidence = spamhausDatasetEvidence(dataset);
    addEvidence(fields, "spamhaus", "datasets", evidence.value, evidence);
  }

  for (const event of Array.isArray(payload?.history?.events) ? payload.history.events : []) {
    const evidence = spamhausEventEvidence(event);
    addEvidence(fields, "spamhaus", "history.events", evidence.value, evidence);
  }

  return fields;
}

export function normalizeVirusTotalEvidence(payload) {
  const fields = [];

  for (const tag of Array.isArray(payload?.tags) ? payload.tags : []) {
    addEvidence(fields, "virustotal", "tags", tag, {
      title: "VirusTotal tag",
      summary: "VirusTotal returned this IP tag in the cached reputation report.",
      rawEvidence: tag,
    });
  }

  for (const label of Array.isArray(payload?.threat_labels) ? payload.threat_labels : []) {
    addEvidence(fields, "virustotal", "threat_labels", label, {
      title: "VirusTotal threat label",
      summary: "VirusTotal returned this behavior or threat label in the cached IP report.",
      rawEvidence: label,
    });
  }

  for (const detection of Array.isArray(payload?.detection_names) ? payload.detection_names : []) {
    addEvidence(fields, "virustotal", "detection_names", detection, {
      title: "Vendor detection text",
      summary: "A VirusTotal vendor result included behavior text matching this ATT&CK mapping.",
      rawEvidence: detection,
    });
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
        evidence_title: field.evidence_title || pattern.evidenceLabel,
        evidence_summary: field.evidence_summary || "Evidence from this source matched the ATT&CK behavior pattern.",
        raw_evidence: field.raw_evidence || field.evidence,
        meaning: pattern.meaning,
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
