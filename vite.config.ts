import { defineConfig, type Plugin, type ViteDevServer } from "vite";
import react from "@vitejs/plugin-react";
import { handleAbuseOriginMapRequest, handleThreatMapRefreshRequest } from "./server/abuse-origin-map.js";
import { handleAbuseIpdbIpDetailRequest } from "./server/abuseipdb-ip-detail.js";
import { handleSpamhausIpDetailRequest } from "./server/spamhaus-ip-detail.js";
import { handleVirusTotalIpDetailRequest, handleVirusTotalPrewarmRequest } from "./server/virustotal-ip-detail.js";
import { rejectUnauthorizedScheduledRequest, scheduledRefreshAuthorized } from "./server/scheduled-refresh-auth.js";

declare const process: {
  env: Record<string, string | undefined>;
};

type DevRequest = {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
};

type DevResponse = {
  statusCode: number;
  setHeader: (key: string, value: string) => void;
  end: (body?: string | Uint8Array) => void;
};

function localAbuseOriginMapApi(): Plugin {
  return {
    name: "local-abuse-origin-map-api",
    configureServer(server: ViteDevServer) {
      server.middlewares.use("/api/abuse-origin-map", async (req, res) => {
        const devReq = req as unknown as DevRequest;
        const devRes = res as unknown as DevResponse;
        const rawHost = devReq.headers.host;
        const host = (Array.isArray(rawHost) ? rawHost[0] : rawHost) || "127.0.0.1:5173";
        const headers = new Headers();

        for (const [key, value] of Object.entries(devReq.headers)) {
          if (Array.isArray(value)) {
            value.forEach((entry) => headers.append(key, entry));
          } else if (value) {
            headers.set(key, value);
          }
        }

        try {
          const url = new URL(`/api/abuse-origin-map${devReq.url || ""}`, `http://${host}`);
          const response = await handleAbuseOriginMapRequest(
            new Request(url, {
              method: devReq.method || "GET",
              headers,
            }),
            process.env,
          );
          const body = new Uint8Array(await response.arrayBuffer());

          devRes.statusCode = response.status;
          response.headers.forEach((value, key) => devRes.setHeader(key, value));
          devRes.end(body);
        } catch (error) {
          devRes.statusCode = 500;
          devRes.setHeader("Content-Type", "application/json; charset=utf-8");
          const message = error instanceof Error ? error.message : "Local threat origin API failed.";
          devRes.end(JSON.stringify({ message }));
        }
      });

      server.middlewares.use("/api/spamhaus-ip-detail", async (req, res) => {
        const devReq = req as unknown as DevRequest;
        const devRes = res as unknown as DevResponse;
        const rawHost = devReq.headers.host;
        const host = (Array.isArray(rawHost) ? rawHost[0] : rawHost) || "127.0.0.1:5173";
        const headers = new Headers();

        for (const [key, value] of Object.entries(devReq.headers)) {
          if (Array.isArray(value)) {
            value.forEach((entry) => headers.append(key, entry));
          } else if (value) {
            headers.set(key, value);
          }
        }

        try {
          const url = new URL(`/api/spamhaus-ip-detail${devReq.url || ""}`, `http://${host}`);
          const response = await handleSpamhausIpDetailRequest(
            new Request(url, {
              method: devReq.method || "GET",
              headers,
            }),
            process.env,
          );
          const body = new Uint8Array(await response.arrayBuffer());

          devRes.statusCode = response.status;
          response.headers.forEach((value, key) => devRes.setHeader(key, value));
          devRes.end(body);
        } catch (error) {
          devRes.statusCode = 500;
          devRes.setHeader("Content-Type", "application/json; charset=utf-8");
          const message = error instanceof Error ? error.message : "Local Spamhaus detail API failed.";
          devRes.end(JSON.stringify({ message }));
        }
      });

      server.middlewares.use("/api/abuseipdb-ip-detail", async (req, res) => {
        const devReq = req as unknown as DevRequest;
        const devRes = res as unknown as DevResponse;
        const rawHost = devReq.headers.host;
        const host = (Array.isArray(rawHost) ? rawHost[0] : rawHost) || "127.0.0.1:5173";
        const headers = new Headers();

        for (const [key, value] of Object.entries(devReq.headers)) {
          if (Array.isArray(value)) {
            value.forEach((entry) => headers.append(key, entry));
          } else if (value) {
            headers.set(key, value);
          }
        }

        try {
          const url = new URL(`/api/abuseipdb-ip-detail${devReq.url || ""}`, `http://${host}`);
          const response = await handleAbuseIpdbIpDetailRequest(
            new Request(url, {
              method: devReq.method || "GET",
              headers,
            }),
            process.env,
          );
          const body = new Uint8Array(await response.arrayBuffer());

          devRes.statusCode = response.status;
          response.headers.forEach((value, key) => devRes.setHeader(key, value));
          devRes.end(body);
        } catch (error) {
          devRes.statusCode = 500;
          devRes.setHeader("Content-Type", "application/json; charset=utf-8");
          const message = error instanceof Error ? error.message : "Local AbuseIPDB detail API failed.";
          devRes.end(JSON.stringify({ message }));
        }
      });

      server.middlewares.use("/api/virustotal-ip-detail", async (req, res) => {
        const devReq = req as unknown as DevRequest;
        const devRes = res as unknown as DevResponse;
        const rawHost = devReq.headers.host;
        const host = (Array.isArray(rawHost) ? rawHost[0] : rawHost) || "127.0.0.1:5173";
        const headers = new Headers();

        for (const [key, value] of Object.entries(devReq.headers)) {
          if (Array.isArray(value)) {
            value.forEach((entry) => headers.append(key, entry));
          } else if (value) {
            headers.set(key, value);
          }
        }

        try {
          const url = new URL(`/api/virustotal-ip-detail${devReq.url || ""}`, `http://${host}`);
          const response = await handleVirusTotalIpDetailRequest(
            new Request(url, {
              method: devReq.method || "GET",
              headers,
            }),
            process.env,
          );
          const body = new Uint8Array(await response.arrayBuffer());

          devRes.statusCode = response.status;
          response.headers.forEach((value, key) => devRes.setHeader(key, value));
          devRes.end(body);
        } catch (error) {
          devRes.statusCode = 500;
          devRes.setHeader("Content-Type", "application/json; charset=utf-8");
          const message = error instanceof Error ? error.message : "Local VirusTotal detail API failed.";
          devRes.end(JSON.stringify({ message }));
        }
      });

      server.middlewares.use("/api/virustotal-prewarm", async (req, res) => {
        const devReq = req as unknown as DevRequest;
        const devRes = res as unknown as DevResponse;
        const rawHost = devReq.headers.host;
        const host = (Array.isArray(rawHost) ? rawHost[0] : rawHost) || "127.0.0.1:5173";
        const headers = new Headers();

        for (const [key, value] of Object.entries(devReq.headers)) {
          if (Array.isArray(value)) {
            value.forEach((entry) => headers.append(key, entry));
          } else if (value) {
            headers.set(key, value);
          }
        }

        try {
          const url = new URL(`/api/virustotal-prewarm${devReq.url || ""}`, `http://${host}`);
          const response = await handleVirusTotalPrewarmRequest(
            new Request(url, {
              method: devReq.method || "POST",
              headers,
            }),
            process.env,
          );
          const body = new Uint8Array(await response.arrayBuffer());

          devRes.statusCode = response.status;
          response.headers.forEach((value, key) => devRes.setHeader(key, value));
          devRes.end(body);
        } catch (error) {
          devRes.statusCode = 500;
          devRes.setHeader("Content-Type", "application/json; charset=utf-8");
          const message = error instanceof Error ? error.message : "Local VirusTotal prewarm API failed.";
          devRes.end(JSON.stringify({ message }));
        }
      });

      server.middlewares.use("/api/admin/refresh-threat-map", async (req, res) => {
        const devReq = req as unknown as DevRequest;
        const devRes = res as unknown as DevResponse;
        const rawHost = devReq.headers.host;
        const host = (Array.isArray(rawHost) ? rawHost[0] : rawHost) || "127.0.0.1:5173";
        const headers = new Headers();

        for (const [key, value] of Object.entries(devReq.headers)) {
          if (Array.isArray(value)) {
            value.forEach((entry) => headers.append(key, entry));
          } else if (value) {
            headers.set(key, value);
          }
        }

        try {
          const url = new URL(`/api/admin/refresh-threat-map${devReq.url || ""}`, `http://${host}`);
          const request = new Request(url, {
            method: devReq.method || "POST",
            headers,
          });
          const response = scheduledRefreshAuthorized(request, process.env)
            ? await handleThreatMapRefreshRequest(request, process.env)
            : rejectUnauthorizedScheduledRequest(process.env);
          const body = new Uint8Array(await response.arrayBuffer());

          devRes.statusCode = response.status;
          response.headers.forEach((value, key) => devRes.setHeader(key, value));
          devRes.end(body);
        } catch (error) {
          devRes.statusCode = 500;
          devRes.setHeader("Content-Type", "application/json; charset=utf-8");
          const message = error instanceof Error ? error.message : "Local scheduled threat map refresh failed.";
          devRes.end(JSON.stringify({ message }));
        }
      });

      server.middlewares.use("/api/admin/warm-threat-intel", async (req, res) => {
        const devReq = req as unknown as DevRequest;
        const devRes = res as unknown as DevResponse;
        const rawHost = devReq.headers.host;
        const host = (Array.isArray(rawHost) ? rawHost[0] : rawHost) || "127.0.0.1:5173";
        const headers = new Headers();

        for (const [key, value] of Object.entries(devReq.headers)) {
          if (Array.isArray(value)) {
            value.forEach((entry) => headers.append(key, entry));
          } else if (value) {
            headers.set(key, value);
          }
        }

        try {
          const url = new URL(`/api/admin/warm-threat-intel${devReq.url || ""}`, `http://${host}`);
          const request = new Request(url, {
            method: devReq.method || "POST",
            headers,
          });
          const response = scheduledRefreshAuthorized(request, process.env)
            ? await handleVirusTotalPrewarmRequest(request, process.env)
            : rejectUnauthorizedScheduledRequest(process.env);
          const body = new Uint8Array(await response.arrayBuffer());

          devRes.statusCode = response.status;
          response.headers.forEach((value, key) => devRes.setHeader(key, value));
          devRes.end(body);
        } catch (error) {
          devRes.statusCode = 500;
          devRes.setHeader("Content-Type", "application/json; charset=utf-8");
          const message = error instanceof Error ? error.message : "Local scheduled threat intelligence warmup failed.";
          devRes.end(JSON.stringify({ message }));
        }
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), localAbuseOriginMapApi()],
  server: {
    proxy: {
      "/api/radar-dashboard": {
        target: "https://www.dominic-boban.com",
        changeOrigin: true,
        secure: true,
      },
    },
  },
});
