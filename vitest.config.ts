import { defineConfig } from "vitest/config";

export default defineConfig({
  esbuild: { jsx: "automatic" },
  test: { environment: "node", include: ["packages/**/*.test.ts", "apps/web/**/*.test.{ts,tsx}"] },
  resolve: {
    alias: [
      { find: "@contracthunter/core/audit-priority-catalog", replacement: new URL("./packages/core/src/audit-priority-catalog.ts", import.meta.url).pathname },
      { find: "@contracthunter/core", replacement: new URL("./packages/core/src/index.ts", import.meta.url).pathname },
      { find: "@contracthunter/db", replacement: new URL("./packages/db/src/index.ts", import.meta.url).pathname },
      { find: "@contracthunter/scanners", replacement: new URL("./packages/scanners/src/index.ts", import.meta.url).pathname },
      { find: "@", replacement: new URL("./apps/web", import.meta.url).pathname },
    ],
  },
});
