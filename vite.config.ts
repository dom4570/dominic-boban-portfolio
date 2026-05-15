import { defineConfig, type Plugin, type ViteDevServer } from "vite";
import react from "@vitejs/plugin-react";

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

function localAbuseOriginApi(): Plugin {
  return {
    name: "local-abuse-origin-api",
    configureServer(server: ViteDevServer) {
      server.middlewares.use(async (req, res, next) => {
        const devReq = req as unknown as DevRequest;
        const devRes = res as unknown as DevResponse;
        const path = devReq.url?.split("?")[0] || "";
        const isMapRequest = path === "/api/abuse-origin-map";
        const isDetailRequest = path === "/api/abuse-origin-detail";

        if (!isMapRequest && !isDetailRequest) {
          next();
          return;
        }

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
          const { handleAbuseOriginDetailRequest, handleAbuseOriginMapRequest } = await import("./server/abuse-origin-map.js");
          const url = new URL(devReq.url || path, `http://${host}`);
          const handler = isDetailRequest ? handleAbuseOriginDetailRequest : handleAbuseOriginMapRequest;
          const response = await handler(
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
        } catch {
          devRes.statusCode = 500;
          devRes.setHeader("Content-Type", "application/json; charset=utf-8");
          devRes.end(JSON.stringify({ message: "Local threat origin API failed." }));
        }
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), localAbuseOriginApi()],
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
