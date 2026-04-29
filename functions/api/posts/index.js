import { getDatabase, json, normalizePost, problem } from "../../../server/blog-utils.js";

export async function onRequestGet({ env }) {
  const database = getDatabase(env);

  if (!database) {
    return problem("BLOG_DB binding is not configured.", 500);
  }

  const result = await database
    .prepare(
      `SELECT id, slug, title, summary, content_md, cover_image_key, tags_json, status, created_at, updated_at, published_at
       FROM posts
       WHERE status = 'published'
       ORDER BY published_at DESC, updated_at DESC`,
    )
    .all();

  return json({ posts: (result.results || []).map(normalizePost) }, 200, {
    "Cache-Control": "public, max-age=60",
  });
}
