import { defineConfig } from "vitest/config";

export default defineConfig({
  esbuild: { jsx: "automatic" },
  test: { environment: "node", include: ["packages/**/*.test.ts", "apps/web/**/*.test.{ts,tsx}"] },
  resolve: {
    alias: {
      "@contracthunter/core": new URL("./packages/core/src/index.ts", import.meta.url).pathname,
      "@contracthunter/db": new URL("./packages/db/src/index.ts", import.meta.url).pathname,
      "@contracthunter/scanners": new URL("./packages/scanners/src/index.ts", import.meta.url).pathname,
      "@": new URL("./apps/web", import.meta.url).pathname,
    },
  },
});
