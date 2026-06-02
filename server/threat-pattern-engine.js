import { resolveMitreTechniques } from "./mitre-attack.js";

const SOURCE_LABELS = {
  abuseipdb: "Activity",
  spamhaus: "Listing",
  virustotal: "Reputation",
};

const THREAT_PATTERNS = [
  {
    id: "ssh-bruteforce",
    techniqueId: "T1110",
    techniqueName: "Brute Force",
    tactic: "Credential Access",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    required: [{ any: ["bruteforce", "auth_failure"] }, { any: ["ssh", "port_22"] }],
    boosts: ["failed_password", "port_22", "ssh"],
    priority: 100,
    minScore: 58,
    highScore: 74,
    evidenceLabel: "SSH brute-force signal",
    meaning: "This maps to Credential Access because the evidence references SSH authentication failures, port 22 activity, or brute-force login behavior.",
    summary: "SSH brute-force behavior mapped from third-party source-IP evidence.",
    mergeKey: "bruteforce",
  },
  {
    id: "rdp-bruteforce",
    techniqueId: "T1110",
    techniqueName: "Brute Force",
    tactic: "Credential Access",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    required: [{ any: ["bruteforce", "auth_failure"] }, { any: ["rdp", "port_3389"] }],
    boosts: ["port_3389", "rdp"],
    priority: 96,
    minScore: 58,
    highScore: 74,
    evidenceLabel: "RDP brute-force signal",
    meaning: "This maps to Credential Access because the evidence references Remote Desktop authentication or brute-force behavior.",
    summary: "RDP brute-force behavior mapped from third-party source-IP evidence.",
    mergeKey: "bruteforce",
  },
  {
    id: "bruteforce-generic",
    techniqueId: "T1110",
    techniqueName: "Brute Force",
    tactic: "Credential Access",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    required: [{ any: ["bruteforce", "auth_failure", "failed_password"] }],
    boosts: ["ssh", "port_22", "rdp", "port_3389"],
    priority: 82,
    minScore: 62,
    highScore: 78,
    evidenceLabel: "Brute-force signal",
    meaning: "This maps to Credential Access because the evidence references repeated authentication attempts or brute-force login behavior.",
    summary: "Brute-force behavior mapped from third-party source-IP evidence.",
    mergeKey: "bruteforce",
  },
  {
    id: "active-scanning",
    techniqueId: "T1595",
    techniqueName: "Active Scanning",
    tactic: "Reconnaissance",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    required: [{ any: ["port_scan", "scanning", "probing"] }],
    boosts: ["port_scan", "cve", "web_probe"],
    priority: 80,
    minScore: 54,
    highScore: 70,
    evidenceLabel: "Scanning signal",
    meaning: "This maps to Reconnaissance because the evidence references scanning, probing, or port-scan behavior.",
    summary: "Scanning or probing behavior mapped from third-party source-IP evidence.",
    mergeKey: "scanning",
  },
  {
    id: "network-denial-of-service",
    techniqueId: "T1498",
    techniqueName: "Network Denial of Service",
    tactic: "Impact",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    required: [{ any: ["dos", "ddos", "flood"] }],
    boosts: ["ddos", "flood"],
    priority: 75,
    minScore: 56,
    highScore: 72,
    evidenceLabel: "Denial-of-service signal",
    meaning: "This maps to Impact because the evidence references denial-of-service, DDoS, flooding, or ping-of-death behavior.",
    summary: "Denial-of-service behavior mapped from third-party source-IP evidence.",
    mergeKey: "denial-of-service",
  },
  {
    id: "public-app-exploit",
    techniqueId: "T1190",
    techniqueName: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    required: [{ any: ["sql_injection", "web_exploit", "cve", "rce", "citrix_netscaler"] }],
    boosts: ["sql_injection", "cve", "rce", "citrix_netscaler"],
    priority: 70,
    minScore: 58,
    highScore: 72,
    evidenceLabel: "Public-facing application exploit signal",
    meaning: "This maps to Initial Access because the evidence references SQL injection, public-facing application exploitation, CVE text, Citrix/Netscaler, RCE, or web app attack behavior.",
    summary: "Public-facing application exploit behavior mapped from third-party source-IP evidence.",
    mergeKey: "public-app-exploit",
  },
  {
    id: "phishing",
    techniqueId: "T1566",
    techniqueName: "Phishing",
    tactic: "Initial Access",
    sourceTypes: ["abuseipdb", "spamhaus", "virustotal"],
    required: [{ any: ["phishing"] }],
    boosts: ["credential_theft"],
    priority: 65,
    minScore: 52,
    highScore: 68,
    evidenceLabel: "Phishing signal",
    meaning: "This maps to Initial Access because the evidence references phishing behavior.",
    summary: "Phishing behavior mapped from third-party source-IP evidence.",
    mergeKey: "phishing",
  },
  {
    id: "command-and-control",
    techniqueId: "T1071",
    techniqueName: "Application Layer Protocol",
    tactic: "Command and Control",
    sourceTypes: ["spamhaus", "virustotal"],
    required: [{ any: ["c2", "command_control"] }],
    boosts: ["botnet_controller"],
    priority: 60,
    minScore: 64,
    highScore: 78,
    evidenceLabel: "Command-and-control signal",
    meaning: "This maps to Command and Control because the evidence explicitly references C2, command-and-control, or botnet controller behavior.",
    summary: "Command-and-control behavior mapped from explicit third-party evidence.",
    mergeKey: "command-and-control",
  },
];

const ABUSE_CATEGORY_MEANINGS = new Map([
  [1, "DNS compromise reports indicate abuse involving unauthorized or malicious changes to DNS infrastructure."],
  [2, "DNS poisoning reports indicate attempts to misdirect traffic by corrupting DNS resolution."],
  [3, "Fraud order reports indicate the IP was associated with suspicious or fraudulent transaction activity."],
  [4, "DDoS reports indicate denial-of-service traffic intended to disrupt network or application availability."],
  [5, "FTP brute-force reports indicate repeated login attempts against FTP services."],
  [6, "Ping of Death reports indicate malformed or oversized ICMP traffic associated with denial-of-service behavior."],
  [7, "Phishing reports indicate the IP was associated with credential-theft or social-engineering infrastructure."],
  [8, "Fraud VoIP reports indicate suspicious or abusive voice-over-IP activity."],
  [9, "Open Proxy reports indicate the IP may relay traffic for other users and hide the original source."],
  [10, "Web Spam reports indicate unwanted or abusive web-posted content."],
  [11, "Email Spam reports indicate unwanted or abusive email-sending behavior."],
  [12, "Blog Spam reports indicate unwanted or abusive blog/comment-posted content."],
  [13, "VPN reports indicate the IP was observed as VPN infrastructure or anonymized network access."],
  [14, "Port Scan reports indicate probing or scanning of network services, usually reconnaissance before other activity."],
  [15, "Hacking reports indicate unauthorized access attempts or other compromise-oriented behavior."],
  [16, "SQL Injection reports indicate attempts to abuse database-backed web applications through SQL input."],
  [17, "Spoofing reports indicate traffic or identity manipulation intended to impersonate another source."],
  [18, "Brute-Force reports indicate repeated authentication attempts against accounts or services."],
  [19, "Bad Web Bot reports indicate automated web activity considered abusive or unwanted."],
  [20, "Exploited Host reports indicate the IP may belong to a compromised or malware-affected machine."],
  [21, "Web App Attack reports indicate attempts to exploit public-facing web application behavior."],
  [22, "SSH reports indicate activity involving Secure Shell services, often login attempts on port 22."],
  [23, "IoT Targeted reports indicate activity aimed at internet-connected devices such as cameras, routers, or DVRs."],
]);

function cleanEvidence(value, maxLength = 180) {
  return String(value || "")
    .replace(/[^\w .,:()#+&/:?@'"[\]-]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function numberOrNull(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function extractPorts(text) {
  const ports = [];
  const patterns = [
    /\b(?:source|destination)?\s*port\s*(\d{1,5})\b/gi,
    /(?:^|[\s/:])(\d{2,5})\s*\((?:tcp|udp)\)/gi,
  ];

  for (const pattern of patterns) {
    let match = pattern.exec(text);
    while (match) {
      const port = Number(match[1]);
      if (Number.isInteger(port) && port > 0 && port <= 65535) ports.push(port);
      match = pattern.exec(text);
    }
  }

  return unique(ports);
}

function extractProtocol(text) {
  const match = /\b(tcp|udp|icmp|http|https|ssh|rdp)\b/i.exec(text);
  return match ? match[1].toUpperCase() : "";
}

function signalDefinitions(text, ports) {
  const hasPort = (port) => ports.includes(port) || new RegExp(`\\bport\\s*${port}\\b`, "i").test(text);
  const checks = [
    ["ssh", /\b(?:ssh|sshd|ssh2)\b/i.test(text) || hasPort(22)],
    ["port_22", hasPort(22)],
    ["rdp", /\b(?:rdp|remote desktop)\b/i.test(text) || hasPort(3389)],
    ["port_3389", hasPort(3389)],
    ["bruteforce", /\b(?:brute[-\s]?force|bruteforce|password spraying|spraying|dictionary attack|credential stuffing|login attempts?|authbl)\b/i.test(text)],
    ["auth_failure", /\b(?:failed password|authentication failure|invalid login|login failure|pam_unix|sshd:auth)\b/i.test(text)],
    ["failed_password", /\bfailed password\b/i.test(text)],
    ["port_scan", /\bport scan\b/i.test(text)],
    ["scanning", /\b(?:active scan|scan(?:ning|ned)?|scanner|masscan|zmap|nmap)\b/i.test(text)],
    ["probing", /\b(?:probe|probing|reconnaissance|dirbuster|nikto|acunetix|wp-admin)\b/i.test(text)],
    ["web_probe", /\b(?:wp-admin|wp-login|nikto|acunetix|dirbuster|wordpress|joomla|drupal)\b/i.test(text)],
    ["sql_injection", /\b(?:sql injection|sqli|sqlmap)\b/i.test(text)],
    ["web_exploit", /\b(?:web app attack|public[-\s]?facing application|apache struts|log4shell|wordpress|joomla|drupal)\b/i.test(text)],
    ["cve", /\bcve-\d{4}-\d+\b/i.test(text)],
    ["rce", /\b(?:rce|remote code execution)\b/i.test(text)],
    ["citrix_netscaler", /\b(?:citrix|netscaler)\b/i.test(text)],
    ["phishing", /\bphishing\b/i.test(text)],
    ["credential_theft", /\b(?:credential theft|credential[-\s]?theft|credential leak|credentials leak)\b/i.test(text)],
    ["dos", /\b(?:dos attack|denial of service|ping of death)\b/i.test(text)],
    ["ddos", /\bddos\b/i.test(text)],
    ["flood", /\b(?:flood|syn flood|udp flood|udp-amplify)\b/i.test(text)],
    ["c2", /\b(?:c2|c&c)\b/i.test(text)],
    ["command_control", /\bcommand[-\s]?and[-\s]?control\b/i.test(text)],
    ["botnet_controller", /\bbotnet controller\b/i.test(text)],
    ["compromised_context", /\b(?:xbl|cbl|exploited host|infected|trojan|malware|botnet|mirai|mozi|tsunami|kaiten|bashlite|gafgyt)\b/i.test(text)],
  ];

  return checks.filter(([, matched]) => matched).map(([signal]) => signal);
}

function deriveService(signals, ports) {
  if (signals.includes("ssh") || ports.includes(22)) return "SSH";
  if (signals.includes("rdp") || ports.includes(3389)) return "RDP";
  if (signals.includes("sql_injection") || signals.includes("web_exploit") || signals.includes("web_probe")) return "Web application";
  if (signals.includes("phishing")) return "Phishing infrastructure";
  if (signals.includes("ddos") || signals.includes("dos")) return "Network availability";
  return "";
}

function addEvidence(fields, source, matchedField, value, metadata = {}) {
  const evidence = cleanEvidence(value, 240);
  if (!evidence) return;

  const rawEvidence = cleanEvidence(metadata.rawEvidence || value, 360);
  const normalized = [evidence, metadata.summary || "", rawEvidence].filter(Boolean).join(" ").toLowerCase();
  const ports = unique([...(metadata.ports || []), ...extractPorts(normalized)]);
  const signals = unique([...(metadata.signals || []), ...signalDefinitions(normalized, ports)]);
  const service = metadata.service || deriveService(signals, ports);

  fields.push({
    source,
    matched_field: matchedField,
    evidence,
    evidence_title: cleanEvidence(metadata.title || evidence, 140),
    evidence_summary: cleanEvidence(metadata.summary || "", 300),
    raw_evidence: rawEvidence,
    normalized,
    category_id: metadata.categoryId || "",
    category_label: cleanEvidence(metadata.categoryLabel || "", 80),
    timestamp: cleanEvidence(metadata.timestamp || "", 80),
    protocol: cleanEvidence(metadata.protocol || extractProtocol(normalized), 20),
    ports,
    service,
    signals,
  });
}

function categoryIdFromValue(category) {
  return numberOrNull(category?.id || category);
}

function categoryIdsFromReport(report) {
  return (Array.isArray(report?.categories) ? report.categories : [])
    .map(categoryIdFromValue)
    .filter(Boolean);
}

function abuseCategorySamples(reports) {
  const samples = new Map();

  for (const report of Array.isArray(reports) ? reports : []) {
    const sample = {
      reported_at: cleanEvidence(report?.reported_at || report?.reportedAt || "", 80),
      reporter_country: cleanEvidence(report?.reporter_country_name || report?.reporterCountryName || report?.reporter_country_code || report?.reporterCountryCode || "", 80),
      comment: cleanEvidence(report?.comment || "", 260),
    };

    for (const id of categoryIdsFromReport(report)) {
      if (!samples.has(id)) samples.set(id, sample);
    }
  }

  return samples;
}

function categorySignals(id, label) {
  const normalized = `${label}`.toLowerCase();
  const signals = [];
  if (id === 4 || id === 6 || /ddos|ping of death/i.test(normalized)) signals.push("dos", id === 4 ? "ddos" : "");
  if (id === 7 || /phishing/i.test(normalized)) signals.push("phishing");
  if (id === 14 || /port scan/i.test(normalized)) signals.push("port_scan", "scanning");
  if (id === 16 || /sql injection/i.test(normalized)) signals.push("sql_injection");
  if (id === 18 || /brute-force|brute force/i.test(normalized)) signals.push("bruteforce");
  if (id === 21 || /web app attack/i.test(normalized)) signals.push("web_exploit");
  if (id === 22 || /\bssh\b/i.test(normalized)) signals.push("ssh", "port_22");
  if (id === 20 || /exploited host/i.test(normalized)) signals.push("compromised_context");
  return unique(signals);
}

function abuseCategoryEvidence(category, sample = null) {
  const id = numberOrNull(category?.id);
  const label = cleanEvidence(category?.label || (id ? `Category ${id}` : "AbuseIPDB category"), 80);
  const count = numberOrNull(category?.count);
  const meaning = ABUSE_CATEGORY_MEANINGS.get(id) || `${label} is an AbuseIPDB report category returned for this selected IP.`;
  const countText = count
    ? `Seen in ${count} of the latest AbuseIPDB report examples loaded for this selected IP.`
    : "Returned as an AbuseIPDB category for this selected IP.";
  const sampleParts = sample
    ? [
        "Representative recent report",
        sample.reported_at ? `at ${sample.reported_at}` : "",
        sample.reporter_country ? `from ${sample.reporter_country}` : "",
        sample.comment ? "included a comment snippet shown below." : "was tagged with this category.",
      ].filter(Boolean).join(" ") + "."
    : "";
  const summary = [id ? `Category ID ${id}: ${label}.` : `${label}.`, countText, sampleParts, meaning].filter(Boolean).join(" ");

  return {
    value: [label, id ? `category ${id}` : ""].filter(Boolean).join(" "),
    title: `AbuseIPDB category: ${label}`,
    summary,
    rawEvidence: sample?.comment || summary,
    categoryId: id,
    categoryLabel: label,
    timestamp: sample?.reported_at || "",
    signals: categorySignals(id, label),
  };
}

export function normalizeAbuseIpdbEvidence(payload) {
  const fields = [];
  const reports = Array.isArray(payload?.recent_reports) ? payload.recent_reports : [];
  const categorySamples = abuseCategorySamples(reports);

  for (const category of Array.isArray(payload?.top_categories) ? payload.top_categories : []) {
    const evidence = abuseCategoryEvidence(category, categorySamples.get(categoryIdFromValue(category)) || null);
    addEvidence(fields, "abuseipdb", "top_categories", evidence.value, evidence);
  }

  for (const report of reports) {
    addEvidence(fields, "abuseipdb", "recent_report.comment", report?.comment, {
      title: "Reporter log snippet",
      summary: "A recent AbuseIPDB report comment included behavior text matching this ATT&CK mapping.",
      rawEvidence: report?.comment,
      timestamp: report?.reported_at || report?.reportedAt || "",
    });

    for (const category of Array.isArray(report?.categories) ? report.categories : []) {
      const evidence = abuseCategoryEvidence(category, {
        reported_at: report?.reported_at || report?.reportedAt || "",
        reporter_country: report?.reporter_country_name || report?.reporterCountryName || report?.reporter_country_code || report?.reporterCountryCode || "",
        comment: report?.comment || "",
      });
      addEvidence(fields, "abuseipdb", "recent_report.categories", evidence.value, evidence);
    }
  }

  return fields;
}

function spamhausDatasetEvidence(dataset) {
  const datasetName = cleanEvidence(dataset?.dataset || "Spamhaus listing", 80);
  const label = cleanEvidence(dataset?.label || datasetName, 120);
  const code = numberOrNull(dataset?.code);
  const contextSignals = /\b(?:xbl|cbl)\b/i.test(datasetName) ? ["compromised_context"] : [];

  return {
    value: [datasetName, label, code ? `code ${code}` : ""].filter(Boolean).join(" "),
    title: `Current listing: ${datasetName}`,
    summary: `${label}${code ? ` returned code ${code}` : ""}. Dataset-only listings are treated as reputation context unless concrete behavior evidence is also present.`,
    rawEvidence: [datasetName, label, code ? `code ${code}` : ""].filter(Boolean).join(" / "),
    signals: contextSignals,
  };
}

function spamhausEventEvidence(event) {
  const ports = [event?.source_port, event?.destination_port].map(numberOrNull).filter(Boolean);
  const portText = [
    event?.source_port ? `source port ${event.source_port}` : "",
    event?.destination_port ? `destination port ${event.destination_port}` : "",
  ].filter(Boolean).join(" ");
  const connection = [event?.source_ip || "", event?.destination_ip ? `to ${event.destination_ip}` : "", portText, event?.protocol || ""].filter(Boolean).join(" ");
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
    timestamp: event?.seen_at || event?.listed_at || "",
    ports,
    protocol,
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
      timestamp: payload?.last_analysis_date || "",
    });
  }

  for (const label of Array.isArray(payload?.threat_labels) ? payload.threat_labels : []) {
    addEvidence(fields, "virustotal", "threat_labels", label, {
      title: "VirusTotal threat label",
      summary: "VirusTotal returned this behavior or threat label in the cached IP report.",
      rawEvidence: label,
      timestamp: payload?.last_analysis_date || "",
    });
  }

  for (const detection of Array.isArray(payload?.detection_names) ? payload.detection_names : []) {
    addEvidence(fields, "virustotal", "detection_names", detection, {
      title: "Vendor detection text",
      summary: "A VirusTotal vendor result included behavior text matching this ATT&CK mapping.",
      rawEvidence: detection,
      timestamp: payload?.last_analysis_date || "",
    });
  }

  return fields;
}

function fieldSpecificity(field) {
  if (field.matched_field === "history.events") return 26;
  if (field.matched_field === "recent_report.comment") return 24;
  if (field.matched_field === "detection_names") return 20;
  if (field.matched_field === "threat_labels") return 18;
  if (field.matched_field.includes("categories") || field.matched_field === "top_categories") return 14;
  if (field.matched_field === "tags") return 12;
  if (field.matched_field === "datasets") return 4;
  return 10;
}

function recencyScore(fields) {
  const timestamps = fields
    .map((field) => new Date(field.timestamp || 0).getTime())
    .filter((value) => Number.isFinite(value) && value > 0);
  if (!timestamps.length) return 0;

  const ageDays = (Date.now() - Math.max(...timestamps)) / (24 * 60 * 60 * 1000);
  if (ageDays <= 1) return 8;
  if (ageDays <= 3) return 6;
  if (ageDays <= 7) return 4;
  if (ageDays <= 30) return 2;
  return 1;
}

function sourceWeight(sourceType) {
  if (sourceType === "abuseipdb") return 8;
  if (sourceType === "spamhaus") return 8;
  return 6;
}

function hasRequiredSignals(pattern, signalSet) {
  return pattern.required.every((group) => group.any.some((signal) => signalSet.has(signal)));
}

function relevantFields(pattern, fields) {
  const relevantSignals = new Set([
    ...pattern.required.flatMap((group) => group.any),
    ...(pattern.boosts || []),
  ]);

  return fields.filter((field) => field.signals?.some((signal) => relevantSignals.has(signal)));
}

function bestEvidenceField(fields) {
  return [...fields].sort((left, right) => {
    const specificity = fieldSpecificity(right) - fieldSpecificity(left);
    if (specificity) return specificity;
    return (right.signals?.length || 0) - (left.signals?.length || 0);
  })[0];
}

function confidenceFromScore(score, pattern) {
  return score >= pattern.highScore ? "high" : "medium";
}

function analystSummary(pattern, service, port, sourceType) {
  const sourceLabel = SOURCE_LABELS[sourceType] || sourceType;
  const serviceText = service ? `${service} ` : "";
  const portText = port ? ` on port ${port}` : "";
  return `${serviceText}${pattern.summary}${portText ? ` (${portText.trim()})` : ""} Source: ${sourceLabel}.`;
}

function confidenceReason(score, fields, signals, sourceType) {
  const highSpecificity = fields.some((field) => fieldSpecificity(field) >= 20);
  const signalText = signals.slice(0, 4).join(", ") || "behavior";
  const sourceLabel = SOURCE_LABELS[sourceType] || sourceType;
  const parts = [
    `Score ${score}/100`,
    highSpecificity ? "high-specificity evidence" : "category or reputation evidence",
    `${signals.length} signal${signals.length === 1 ? "" : "s"}: ${signalText}`,
    `${sourceLabel} source`,
  ];
  return parts.join("; ") + ".";
}

function compareMatches(left, right) {
  if (left.evidence_score !== right.evidence_score) return right.evidence_score - left.evidence_score;
  if (left.priority !== right.priority) return right.priority - left.priority;
  if (left.confidence !== right.confidence) return left.confidence === "high" ? -1 : 1;
  return left.technique_id.localeCompare(right.technique_id);
}

export function matchThreatPatterns(fields, sourceType) {
  const sourceFields = (Array.isArray(fields) ? fields : []).filter((field) => field?.source === sourceType);
  const matchesByMergeKey = new Map();

  for (const pattern of THREAT_PATTERNS) {
    if (!pattern.sourceTypes.includes(sourceType)) continue;

    const candidates = relevantFields(pattern, sourceFields);
    if (!candidates.length) continue;

    const signals = unique(candidates.flatMap((field) => field.signals || []));
    const signalSet = new Set(signals);
    if (!hasRequiredSignals(pattern, signalSet)) continue;

    const specificity = Math.max(...candidates.map(fieldSpecificity), 0);
    const requiredScore = pattern.required.length * 18;
    const boostScore = (pattern.boosts || []).filter((signal) => signalSet.has(signal)).length * 5;
    const evidenceScore = Math.min(100, Math.round(24 + requiredScore + boostScore + specificity + sourceWeight(sourceType) + recencyScore(candidates)));
    const hasStrongEvidence = specificity >= 20 || signals.length >= 2;
    if (evidenceScore < pattern.minScore && !hasStrongEvidence) continue;

    const evidenceField = bestEvidenceField(candidates);
    const ports = unique(candidates.flatMap((field) => field.ports || []));
    const service = deriveService(signals, ports) || evidenceField?.service || "";
    const port = ports.find((candidatePort) => (service === "SSH" && candidatePort === 22) || (service === "RDP" && candidatePort === 3389)) || ports[0] || null;
    const key = `${pattern.techniqueId}:${pattern.mergeKey || pattern.id}`;
    const nextMatch = {
      technique_id: pattern.techniqueId,
      source: sourceType,
      evidence: evidenceField?.evidence || pattern.evidenceLabel,
      evidence_title: evidenceField?.evidence_title || pattern.evidenceLabel,
      evidence_summary: evidenceField?.evidence_summary || "Evidence from this source matched the ATT&CK behavior pattern.",
      raw_evidence: evidenceField?.raw_evidence || evidenceField?.evidence || pattern.evidenceLabel,
      meaning: pattern.meaning,
      matched_field: evidenceField?.matched_field || "",
      confidence: confidenceFromScore(evidenceScore, pattern),
      pattern_label: pattern.evidenceLabel,
      evidence_score: evidenceScore,
      source_count: 1,
      signals,
      service,
      port,
      confidence_reason: confidenceReason(evidenceScore, candidates, signals, sourceType),
      analyst_summary: analystSummary(pattern, service, port, sourceType),
      priority: pattern.priority,
    };
    const existing = matchesByMergeKey.get(key);
    if (!existing || compareMatches(nextMatch, existing) < 0) {
      matchesByMergeKey.set(key, nextMatch);
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
