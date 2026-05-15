export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

export function problem(message, status = 400) {
  return json({ success: false, message }, status);
}

export function getDatabase(env) {
  return env.BLOG_DB || null;
}

function decodeAccessJwt(token) {
  if (!token) return null;

  const parts = String(token).split(".");
  if (parts.length < 2) return null;

  try {
    const normalized = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const prefix = `${name}=`;
  const match = cookie
    .split(";")
    .map((value) => value.trim())
    .find((value) => value.startsWith(prefix));

  return match ? decodeURIComponent(match.slice(prefix.length)) : "";
}

function getAccessJwtEmail(request, env) {
  const token =
    request.headers.get("Cf-Access-Jwt-Assertion") ||
    request.headers.get("cf-access-jwt-assertion") ||
    getCookie(request, "CF_Authorization");

  const payload = decodeAccessJwt(token);
  if (!payload) return "";

  const expectedIssuer = String(env.CLOUDFLARE_ACCESS_ISSUER || "https://dominic-boban.cloudflareaccess.com").trim();
  const now = Math.floor(Date.now() / 1000);

  if (expectedIssuer && payload.iss && payload.iss !== expectedIssuer) return "";
  if (payload.exp && Number(payload.exp) <= now) return "";
  if (payload.nbf && Number(payload.nbf) > now + 60) return "";

  return String(payload.email || "").trim().toLowerCase();
}

function isAllowedAdminHost(request, env) {
  const hostname = new URL(request.url).hostname.toLowerCase();
  const allowedHosts = String(env.ADMIN_HOSTS || "www.dominic-boban.com")
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);

  return allowedHosts.includes(hostname);
}

export async function requireAdmin(request, env) {
  const configuredEmail = String(env.ADMIN_EMAIL || "").trim().toLowerCase();
  const requestEmail =
    String(request.headers.get("Cf-Access-Authenticated-User-Email") || "").trim().toLowerCase() ||
    getAccessJwtEmail(request, env);

  if (!configuredEmail) {
    return problem("ADMIN_EMAIL is not configured.", 500);
  }

  if (!isAllowedAdminHost(request, env)) {
    return problem("Admin API is only available on the canonical domain.", 403);
  }

  if (!requestEmail || requestEmail !== configuredEmail) {
    return problem("Cloudflare Access admin authorization required.", 401);
  }

  return null;
}

export function slugify(value) {
  return String(value || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 96);
}

export function normalizeTags(value) {
  const tags = Array.isArray(value) ? value : [];

  return tags
    .map((tag) => String(tag || "").trim())
    .filter(Boolean)
    .slice(0, 12);
}

export function normalizePost(row) {
  if (!row) return null;

  let tags = [];

  try {
    tags = JSON.parse(row.tags_json || "[]");
  } catch {
    tags = [];
  }

  return {
    id: row.id,
    slug: row.slug,
    title: row.title,
    summary: row.summary,
    content_md: row.content_md,
    cover_image_key: row.cover_image_key || null,
    cover_image_url: row.cover_image_key ? `/media/${row.cover_image_key}` : null,
    tags,
    status: row.status,
    created_at: row.created_at,
    updated_at: row.updated_at,
    published_at: row.published_at || null,
  };
}

export async function readPostInput(request) {
  const body = await request.json().catch(() => null);

  if (!body) {
    return { error: "Invalid JSON body." };
  }

  const title = String(body.title || "").trim();
  const summary = String(body.summary || "").trim();
  const contentMd = String(body.content_md || "").trim();
  const slug = slugify(body.slug || title);
  const status = body.status === "published" ? "published" : "draft";
  const coverImageKey = body.cover_image_key ? String(body.cover_image_key).trim() : null;
  const tags = normalizeTags(body.tags);

  if (!title || !summary || !contentMd) {
    return { error: "Title, summary, and Markdown content are required." };
  }

  if (!slug) {
    return { error: "A valid slug is required." };
  }

  return {
    value: {
      title,
      summary,
      content_md: contentMd,
      slug,
      status,
      cover_image_key: coverImageKey,
      tags_json: JSON.stringify(tags),
    },
  };
}
