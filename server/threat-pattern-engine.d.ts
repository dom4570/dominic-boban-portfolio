export type MitreMatch = {
  technique_id: string;
  source: "abuseipdb" | "spamhaus" | "virustotal";
  evidence: string;
  evidence_title: string;
  evidence_summary: string;
  raw_evidence: string;
  meaning: string;
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

export function normalizeAbuseIpdbEvidence(payload: unknown): Array<Record<string, string>>;

export function normalizeSpamhausEvidence(payload: unknown): Array<Record<string, string>>;

export function normalizeVirusTotalEvidence(payload: unknown): Array<Record<string, string>>;

export function matchThreatPatterns(
  fields: Array<Record<string, string>>,
  sourceType: "abuseipdb" | "spamhaus" | "virustotal",
): MitreMatch[];

export function addMitrePatternAnalysis<T>(
  payload: T,
  sourceType: "abuseipdb" | "spamhaus" | "virustotal",
  normalizeEvidence: (payload: T) => Array<Record<string, string>>,
): Promise<T & { mitre_techniques: Array<{ id: string; tactic: string; technique: string }>; mitre_matches: MitreMatch[] }>;
