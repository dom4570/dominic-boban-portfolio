import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
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
