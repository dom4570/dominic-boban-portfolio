const SITE_URL = "https://www.dominic-boban.com";

function escapeXml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function formatDate(value) {
  const date = value ? new Date(value) : new Date();
  return Number.isNaN(date.getTime()) ? new Date().toISOString().slice(0, 10) : date.toISOString().slice(0, 10);
}

function renderSitemap(urls) {
  const entries = urls
    .map(
      (url) => `  <url>
    <loc>${escapeXml(url.loc)}</loc>
    <lastmod>${escapeXml(url.lastmod)}</lastmod>
    <changefreq>${escapeXml(url.changefreq)}</changefreq>
    <priority>${escapeXml(url.priority)}</priority>
  </url>`,
    )
    .join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${entries}
</urlset>
`;
}

export async function onRequestGet({ env }) {
  const today = new Date().toISOString().slice(0, 10);
  const urls = [
    {
      loc: `${SITE_URL}/`,
      lastmod: today,
      changefreq: "monthly",
      priority: "1.0",
    },
    {
      loc: `${SITE_URL}/blog`,
      lastmod: today,
      changefreq: "weekly",
      priority: "0.8",
    },
    {
      loc: `${SITE_URL}/email-scanner`,
      lastmod: today,
      changefreq: "monthly",
      priority: "0.7",
    },
  ];

  try {
    if (env.BLOG_DB) {
      const result = await env.BLOG_DB.prepare(
        `SELECT slug, updated_at, published_at
         FROM posts
         WHERE status = 'published'
         ORDER BY published_at DESC`,
      ).all();

      for (const post of result.results || []) {
        if (!post.slug) continue;

        urls.push({
          loc: `${SITE_URL}/blog/${post.slug}`,
          lastmod: formatDate(post.updated_at || post.published_at),
          changefreq: "monthly",
          priority: "0.7",
        });
      }
    }
  } catch {
    // Keep sitemap available even if D1 is temporarily unavailable.
  }

  return new Response(renderSitemap(urls), {
    headers: {
      "Content-Type": "application/xml; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
    },
  });
}
