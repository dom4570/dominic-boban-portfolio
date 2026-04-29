import { getDatabase, json, normalizePost, problem } from "../../../server/blog-utils.js";

export async function onRequestGet({ env, params }) {
  try {
    const database = getDatabase(env);

    if (!database) {
      return problem("BLOG_DB binding is not configured.", 500);
    }

    const post = await database
      .prepare(
        `SELECT id, slug, title, summary, content_md, cover_image_key, tags_json, status, created_at, updated_at, published_at
         FROM posts
         WHERE slug = ? AND status = 'published'
         LIMIT 1`,
      )
      .bind(params.slug)
      .first();

    if (!post) {
      return problem("Post not found.", 404);
    }

    return json({ post: normalizePost(post) }, 200, {
      "Cache-Control": "public, max-age=60",
    });
  } catch (error) {
    return problem(error instanceof Error ? error.message : "Unable to load post.", 500);
  }
}
