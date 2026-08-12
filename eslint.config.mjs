import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

const config = defineConfig([
  ...nextVitals,
  ...nextTypescript,
  globalIgnores(["**/.next/**", "**/node_modules/**", "**/next-env.d.ts", "data/**", "coverage/**"]),
  { rules: { "@next/next/no-html-link-for-pages": "off" } },
]);

export default config;
