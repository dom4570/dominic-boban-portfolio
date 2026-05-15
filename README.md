# Dominic Boban Portfolio

Cybersecurity portfolio deployed on Cloudflare Pages with React, Vite, TypeScript, and Cloudflare Pages Functions.

## Global Threat Dashboard

The `/global-threat-dashboard` page shows aggregated internet and security trends from Cloudflare Radar.
It also includes Layer 7 attack geography for origin countries, targeted countries, and origin-to-target country flows.

Architecture:

```text
Browser -> Cloudflare Pages Function -> Cloudflare Radar API -> Dashboard
```

Runtime configuration:

- Environment variable: `CLOUDFLARE_RADAR_TOKEN`
- Token permission: `Account -> Radar -> Read`
- Secret location: Cloudflare Pages project settings, production environment variables/secrets

Security notes:

- The Radar API token is read only inside `functions/api/radar-dashboard.js`.
- The token is never exposed to frontend code.
- Successful Radar responses are cached briefly at the edge to reduce API usage.
- Radar data is aggregated/anonymized internet trend data, not individual live attack events.

## Live Threat Origin Map

The `/live-threat-map` page shows approximate geo-IP locations for AbuseIPDB-reported abusive IP sources.
It intentionally uses pulsing dots instead of destination lines because AbuseIPDB does not identify victim or target locations.

Runtime configuration:

- Environment variable: `ABUSEIPDB_API_KEY`
- Local dev: set the variable in the terminal before `npm run dev`
- Secret location: Cloudflare Pages project settings, production environment variables/secrets

Security notes:

- The AbuseIPDB key is read only by `/api/abuse-origin-map`.
- The key is never exposed to frontend code.
- If AbuseIPDB or geo-IP lookup is unavailable, the page shows clearly labelled demo fallback points.
