import { getDatabase, json, normalizePost, problem, readPostInput, requireAdmin } from "../../../../server/blog-utils.js";

export async function onRequestGet({ request, env }) {
  const authError = requireAdmin(request, env);
  if (authError) return authError;

  const database = getDatabase(env);
  if (!database) return problem("BLOG_DB binding is not configured.", 500);

  const result = await database
    .prepare(
      `SELECT id, slug, title, summary, content_md, cover_image_key, tags_json, status, created_at, updated_at, published_at
       FROM posts
       ORDER BY updated_at DESC`,
    )
    .all();

  return json({ posts: (result.results || []).map(normalizePost) });
}

export async function onRequestPost({ request, env }) {
  const authError = requireAdmin(request, env);
  if (authError) return authError;

  const database = getDatabase(env);
  if (!database) return problem("BLOG_DB binding is not configured.", 500);

  const input = await readPostInput(request);
  if (input.error) return problem(input.error, 400);

  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  const publishedAt = input.value.status === "published" ? now : null;

  try {
    await database
      .prepare(
        `INSERT INTO posts (id, slug, title, summary, content_md, cover_image_key, tags_json, status, created_at, updated_at, published_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        id,
        input.value.slug,
        input.value.title,
        input.value.summary,
        input.value.content_md,
        input.value.cover_image_key,
        input.value.tags_json,
        input.value.status,
        now,
        now,
        publishedAt,
      )
      .run();
  } catch {
    return problem("Slug already exists or the post could not be created.", 409);
  }

  const post = await database.prepare("SELECT * FROM posts WHERE id = ?").bind(id).first();
  return json({ post: normalizePost(post) }, 201);
}
