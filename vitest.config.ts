import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { environment: "node", include: ["packages/**/*.test.ts"] },
  resolve: {
    alias: {
      "@contracthunter/core": new URL("./packages/core/src/index.ts", import.meta.url).pathname,
      "@contracthunter/db": new URL("./packages/db/src/index.ts", import.meta.url).pathname,
      "@contracthunter/scanners": new URL("./packages/scanners/src/index.ts", import.meta.url).pathname,
    },
  },
});
