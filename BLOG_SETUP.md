# Cloudflare Blog Setup

This portfolio now supports a dynamic blog with Cloudflare Pages Functions, D1, R2, and Cloudflare Access.

## Required Cloudflare Resources

Create these in Cloudflare:

- D1 database: `dominic_blog_db`
- R2 bucket: `dominic-blog-media`
- Pages binding: `BLOG_DB` -> the D1 database
- Pages binding: `BLOG_MEDIA` -> the R2 bucket
- Pages environment variable: `ADMIN_EMAIL=dominicboban@dominic-boban.com`

Keep the existing `VITE_WEB3FORMS_ACCESS_KEY` variable for the contact form.

## D1 Schema

Apply `schema.sql` to the D1 database.

Using Wrangler:

```bash
npx wrangler d1 execute dominic_blog_db --remote --file=schema.sql
```

Or use the Cloudflare dashboard D1 query console and paste the contents of `schema.sql`.

## Cloudflare Access

Create a Cloudflare Access application/policy that allows only:

```txt
dominicboban@dominic-boban.com
```

Protect both paths:

```txt
https://www.dominic-boban.com/admin*
https://www.dominic-boban.com/api/admin*
```

The admin UI loads at `/admin`, but the API also needs Access so Cloudflare forwards the authenticated email header.

## Publishing Flow

1. Visit `https://www.dominic-boban.com/admin`.
2. Log in through Cloudflare Access.
3. Create a draft.
4. Upload a cover image or inline image.
5. Preview the Markdown.
6. Publish when ready.

Published posts appear at:

```txt
https://www.dominic-boban.com/blog
https://www.dominic-boban.com/blog/{slug}
```

Drafts never appear publicly.
