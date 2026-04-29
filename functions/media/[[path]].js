export async function onRequestGet({ env, params }) {
  if (!env.BLOG_MEDIA) {
    return Response.json({ success: false, message: "BLOG_MEDIA binding is not configured." }, { status: 500 });
  }

  const value = params.path;
  const key = Array.isArray(value) ? value.join("/") : String(value || "");

  if (!key) {
    return Response.json({ success: false, message: "Media key is required." }, { status: 400 });
  }

  const object = await env.BLOG_MEDIA.get(key);

  if (!object) {
    return Response.json({ success: false, message: "Media not found." }, { status: 404 });
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Cache-Control", "public, max-age=31536000, immutable");

  return new Response(object.body, { headers });
}
