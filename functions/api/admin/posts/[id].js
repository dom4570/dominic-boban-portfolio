import { getDatabase, json, normalizePost, problem, readPostInput, requireAdmin } from "../../../../server/blog-utils.js";

export async function onRequestGet({ request, env, params }) {
  const authError = requireAdmin(request, env);
  if (authError) return authError;

  const database = getDatabase(env);
  if (!database) return problem("BLOG_DB binding is not configured.", 500);

  const post = await database.prepare("SELECT * FROM posts WHERE id = ? LIMIT 1").bind(params.id).first();

  if (!post) return problem("Post not found.", 404);

  return json({ post: normalizePost(post) });
}

export async function onRequestPut({ request, env, params }) {
  const authError = requireAdmin(request, env);
  if (authError) return authError;

  const database = getDatabase(env);
  if (!database) return problem("BLOG_DB binding is not configured.", 500);

  const current = await database.prepare("SELECT * FROM posts WHERE id = ? LIMIT 1").bind(params.id).first();
  if (!current) return problem("Post not found.", 404);

  const input = await readPostInput(request);
  if (input.error) return problem(input.error, 400);

  const now = new Date().toISOString();
  const publishedAt = input.value.status === "published" ? current.published_at || now : null;

  try {
    await database
      .prepare(
        `UPDATE posts
         SET slug = ?, title = ?, summary = ?, content_md = ?, cover_image_key = ?, tags_json = ?, status = ?, updated_at = ?, published_at = ?
         WHERE id = ?`,
      )
      .bind(
        input.value.slug,
        input.value.title,
        input.value.summary,
        input.value.content_md,
        input.value.cover_image_key,
        input.value.tags_json,
        input.value.status,
        now,
        publishedAt,
        params.id,
      )
      .run();
  } catch {
    return problem("Slug already exists or the post could not be updated.", 409);
  }

  const post = await database.prepare("SELECT * FROM posts WHERE id = ?").bind(params.id).first();
  return json({ post: normalizePost(post) });
}

export async function onRequestDelete({ request, env, params }) {
  const authError = requireAdmin(request, env);
  if (authError) return authError;

  const database = getDatabase(env);
  if (!database) return problem("BLOG_DB binding is not configured.", 500);

  await database.prepare("DELETE FROM posts WHERE id = ?").bind(params.id).run();

  return json({ success: true });
}
