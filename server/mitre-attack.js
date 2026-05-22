const MITRE_ENTERPRISE_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const CACHE_TTL_SECONDS = Math.floor(CACHE_TTL_MS / 1000);
const CACHE_SCHEMA_VERSION = 1;
const LOCAL_CACHE_FILE = ".cache/mitre-attack-techniques.json";
const EDGE_CACHE_URL = "https://portfolio-cache.local/mitre-attack/enterprise-techniques";

const tacticNames = new Map([
  ["reconnaissance", "Reconnaissance"],
  ["resource-development", "Resource Development"],
  ["initial-access", "Initial Access"],
  ["execution", "Execution"],
  ["persistence", "Persistence"],
  ["privilege-escalation", "Privilege Escalation"],
  ["defense-evasion", "Defense Evasion"],
  ["credential-access", "Credential Access"],
  ["discovery", "Discovery"],
  ["lateral-movement", "Lateral Movement"],
  ["collection", "Collection"],
  ["command-and-control", "Command and Control"],
  ["exfiltration", "Exfiltration"],
  ["impact", "Impact"],
]);

let memoryCatalog = null;
let memoryCatalogUntil = 0;
let pendingCatalog = null;

function cleanString(value, fallback = "", maxLength = 180) {
  return String(value || fallback)
    .replace(/[^\w .,:()#+&/-]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function isNodeRuntime() {
  return typeof process !== "undefined" && Boolean(process.versions?.node);
}

function timeoutSignal(timeoutMs) {
  if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
    return AbortSignal.timeout(timeoutMs);
  }

  const controller = new AbortController();
  setTimeout(() => controller.abort(), timeoutMs);
  return controller.signal;
}

function expiresAtFromNow() {
  return new Date(Date.now() + CACHE_TTL_MS).toISOString();
}

function cacheExpiryTime(payload) {
  const expiry = new Date(payload?.cache_expires_at || 0).getTime();
  return Number.isFinite(expiry) ? expiry : 0;
}

function isCatalogPayloadUsable(payload, now = Date.now()) {
  return (
    payload?.cache_schema_version === CACHE_SCHEMA_VERSION &&
    Array.isArray(payload.techniques) &&
    cacheExpiryTime(payload) > now
  );
}

function edgeCacheRequest() {
  return new Request(EDGE_CACHE_URL, { method: "GET" });
}

async function readEdgeCache() {
  if (!globalThis.caches?.default) {
    return null;
  }

  const response = await globalThis.caches.default.match(edgeCacheRequest()).catch(() => null);
  if (!response?.ok) {
    return null;
  }

  const payload = await response.json().catch(() => null);
  return isCatalogPayloadUsable(payload) ? payload : null;
}

async function writeEdgeCache(payload) {
  if (!globalThis.caches?.default || !isCatalogPayloadUsable(payload)) {
    return;
  }

  const response = new Response(JSON.stringify(payload), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": `public, max-age=${CACHE_TTL_SECONDS}`,
    },
  });

  await globalThis.caches.default.put(edgeCacheRequest(), response).catch(() => {});
}

async function localCachePath() {
  if (!isNodeRuntime()) {
    return "";
  }

  const path = await import("node:path");
  return path.resolve(process.cwd(), LOCAL_CACHE_FILE);
}

async function readLocalCache() {
  const filePath = await localCachePath();
  if (!filePath) {
    return null;
  }

  try {
    const fs = await import("node:fs/promises");
    const payload = JSON.parse(await fs.readFile(filePath, "utf8"));
    return isCatalogPayloadUsable(payload) ? payload : null;
  } catch {
    return null;
  }
}

async function writeLocalCache(payload) {
  const filePath = await localCachePath();
  if (!filePath || !isCatalogPayloadUsable(payload)) {
    return;
  }

  try {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(payload), "utf8");
  } catch {
    // Local cache is best-effort for development.
  }
}

async function readPersistentCatalog() {
  const payload = (await readEdgeCache()) || (await readLocalCache());
  if (!payload) {
    return null;
  }

  memoryCatalog = payload;
  memoryCatalogUntil = cacheExpiryTime(payload);
  return payload;
}

async function writePersistentCatalog(payload) {
  memoryCatalog = payload;
  memoryCatalogUntil = cacheExpiryTime(payload);
  await Promise.all([writeEdgeCache(payload), writeLocalCache(payload)]);
}

function attackIdFromReferences(references) {
  const reference = (Array.isArray(references) ? references : []).find((entry) => {
    const externalId = cleanString(entry?.external_id, "", 24);
    return entry?.source_name === "mitre-attack" && /^T\d{4}(?:\.\d{3})?$/.test(externalId);
  });

  return cleanString(reference?.external_id, "", 24);
}

function tacticFromPattern(pattern) {
  const phase = (Array.isArray(pattern?.kill_chain_phases) ? pattern.kill_chain_phases : []).find(
    (entry) => entry?.kill_chain_name === "mitre-attack" && entry?.phase_name,
  );
  const phaseName = cleanString(phase?.phase_name, "", 80).toLowerCase();
  return tacticNames.get(phaseName) || cleanString(phase?.phase_name, "Unknown", 80);
}

function normalizeTechnique(pattern) {
  const id = attackIdFromReferences(pattern?.external_references);
  const technique = cleanString(pattern?.name, "", 140);

  if (!id || !technique || pattern?.revoked === true || pattern?.x_mitre_deprecated === true) {
    return null;
  }

  return {
    id,
    tactic: tacticFromPattern(pattern),
    technique,
  };
}

function normalizeCatalog(body) {
  const techniques = (Array.isArray(body?.objects) ? body.objects : [])
    .filter((item) => item?.type === "attack-pattern")
    .map(normalizeTechnique)
    .filter(Boolean)
    .sort((left, right) => left.id.localeCompare(right.id));

  return {
    cache_schema_version: CACHE_SCHEMA_VERSION,
    generated_at: new Date().toISOString(),
    cache_expires_at: expiresAtFromNow(),
    source: MITRE_ENTERPRISE_STIX_URL,
    techniques,
  };
}

async function fetchMitreCatalog() {
  const response = await fetch(MITRE_ENTERPRISE_STIX_URL, {
    headers: {
      Accept: "application/json",
      "User-Agent": "DominicBobanPortfolio/1.0 mitre-attack-mapper",
    },
    signal: timeoutSignal(12000),
  });

  if (!response.ok) {
    throw new Error(`MITRE ATT&CK returned status ${response.status}.`);
  }

  const body = await response.json();
  return normalizeCatalog(body);
}

export async function getMitreTechniqueCatalog() {
  const now = Date.now();
  if (memoryCatalog && memoryCatalogUntil > now) {
    return memoryCatalog.techniques;
  }

  const persistent = await readPersistentCatalog();
  if (persistent) {
    return persistent.techniques;
  }

  if (!pendingCatalog) {
    pendingCatalog = fetchMitreCatalog()
      .then(async (payload) => {
        await writePersistentCatalog(payload);
        return payload;
      })
      .catch(() => ({
        cache_schema_version: CACHE_SCHEMA_VERSION,
        generated_at: new Date().toISOString(),
        cache_expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
        source: MITRE_ENTERPRISE_STIX_URL,
        techniques: [],
      }))
      .finally(() => {
        pendingCatalog = null;
      });
  }

  const payload = await pendingCatalog;
  if (isCatalogPayloadUsable(payload)) {
    memoryCatalog = payload;
    memoryCatalogUntil = cacheExpiryTime(payload);
  }

  return Array.isArray(payload?.techniques) ? payload.techniques : [];
}

export async function resolveMitreTechniques(ids) {
  const requestedIds = [...new Set((Array.isArray(ids) ? ids : []).map((id) => cleanString(id, "", 24)).filter(Boolean))];
  if (!requestedIds.length) {
    return [];
  }

  const catalog = await getMitreTechniqueCatalog();
  if (!catalog.length) {
    return [];
  }

  const byId = new Map(catalog.map((technique) => [technique.id, technique]));
  return requestedIds.map((id) => byId.get(id)).filter(Boolean);
}
