import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  output: "standalone",
  transpilePackages: ["@contracthunter/core", "@contracthunter/db", "@contracthunter/scanners"],
  outputFileTracingRoot: path.resolve(import.meta.dirname, "../.."),
  experimental: { useTypeScriptCli: false },
};

export default nextConfig;
