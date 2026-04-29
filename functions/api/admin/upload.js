import { json, problem, requireAdmin } from "../../../server/blog-utils.js";

const allowedTypes = new Map([
  ["image/jpeg", "jpg"],
  ["image/png", "png"],
  ["image/webp", "webp"],
  ["image/gif", "gif"],
]);

export async function onRequestPost({ request, env }) {
  const authError = requireAdmin(request, env);
  if (authError) return authError;

  if (!env.BLOG_MEDIA) {
    return problem("BLOG_MEDIA binding is not configured.", 500);
  }

  const form = await request.formData().catch(() => null);
  const image = form?.get("image");

  if (!image || typeof image === "string") {
    return problem("Image file is required.", 400);
  }

  if (!allowedTypes.has(image.type)) {
    return problem("Only JPG, PNG, WEBP, and GIF images are supported.", 400);
  }

  if (image.size > 8 * 1024 * 1024) {
    return problem("Image must be smaller than 8 MB.", 400);
  }

  const now = new Date();
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, "0");
  const extension = allowedTypes.get(image.type);
  const key = `blog/${year}/${month}/${crypto.randomUUID()}.${extension}`;

  await env.BLOG_MEDIA.put(key, await image.arrayBuffer(), {
    httpMetadata: {
      contentType: image.type,
      cacheControl: "public, max-age=31536000, immutable",
    },
  });

  return json({ key, url: `/media/${key}` }, 201);
}
