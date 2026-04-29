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

export function requireAdmin(request, env) {
  const configuredEmail = String(env.ADMIN_EMAIL || "").trim().toLowerCase();
  const requestEmail = String(request.headers.get("Cf-Access-Authenticated-User-Email") || "").trim().toLowerCase();

  if (!configuredEmail) {
    return problem("ADMIN_EMAIL is not configured.", 500);
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
