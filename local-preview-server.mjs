import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { handleAbuseOriginMapRequest } from "./server/abuse-origin-map.js";

const dist = path.join(process.cwd(), "dist");
const mimeTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".txt", "text/plain; charset=utf-8"],
]);

function send(response, status, body, contentType = "text/plain; charset=utf-8") {
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Type": contentType,
  });
  response.end(body);
}

http
  .createServer(async (request, response) => {
    try {
      const url = new URL(request.url || "/", "http://127.0.0.1:5173");

      if (url.pathname === "/api/abuse-origin-map") {
        const apiResponse = await handleAbuseOriginMapRequest(
          new Request(url, { method: request.method || "GET" }),
          process.env,
        );
        const body = Buffer.from(await apiResponse.arrayBuffer());

        response.writeHead(apiResponse.status, Object.fromEntries(apiResponse.headers.entries()));
        response.end(body);
        return;
      }

      let pathname = decodeURIComponent(url.pathname);
      if (pathname === "/" || !path.extname(pathname)) {
        pathname = "/index.html";
      }

      const filePath = path.normalize(path.join(dist, pathname));
      if (!filePath.startsWith(dist)) {
        send(response, 403, "Forbidden");
        return;
      }

      const body = await fs.readFile(filePath).catch(() => fs.readFile(path.join(dist, "index.html")));
      send(response, 200, body, mimeTypes.get(path.extname(filePath)) || "application/octet-stream");
    } catch {
      send(response, 500, "Local server error");
    }
  })
  .listen(5173, "127.0.0.1");
