import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { VitePWA } from "vite-plugin-pwa";

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: "autoUpdate",
      includeAssets: ["icon.svg"],
      manifest: {
        name: "CloudCord",
        short_name: "CloudCord",
        description: "Cloudflare-native community chat",
        theme_color: "#11131a",
        background_color: "#090b10",
        display: "standalone",
        start_url: "/",
        icons: [
          {
            src: "/icon.svg",
            sizes: "any",
            type: "image/svg+xml",
            purpose: "any maskable",
          },
        ],
      },
      workbox: {
        navigateFallback: "/index.html",
        runtimeCaching: [
          {
            urlPattern: ({ url }) =>
              url.pathname.startsWith("/api/v1") &&
              url.pathname.endsWith("/messages"),
            handler: "NetworkFirst",
            options: {
              cacheName: "cloudcord-history",
              networkTimeoutSeconds: 3,
              expiration: { maxEntries: 120, maxAgeSeconds: 86_400 },
            },
          },
        ],
      },
    }),
  ],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8787",
      "/health": "http://localhost:8787",
    },
  },
});
