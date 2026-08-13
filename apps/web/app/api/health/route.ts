import { getDatabase } from "@contracthunter/db";
import { runBoundedProcess } from "@contracthunter/scanners";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

async function tool(command: string, args: string[]) {
  try {
    const result = await runBoundedProcess({ command, args, timeoutMs: 10_000, maxOutputBytes: 65_536, env: { NODE_ENV: process.env.NODE_ENV ?? "production", PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin", HOME: "/tmp", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" } });
    const version = `${result.stdout}\n${result.stderr}`.trim().split(/\r?\n/)[0]?.slice(0, 100) || null;
    return { available: result.exitCode === 0, version };
  } catch { return { available: false, version: null }; }
}

export async function GET() {
  try {
    getDatabase().sqlite.prepare("SELECT 1").get();
    const [git, npm, slither, solcSelect] = await Promise.all([tool("git", ["--version"]), tool("npm", ["--version"]), tool("slither", ["--version"]), tool("solc-select", ["--version"])]);
    return NextResponse.json({ status: "ok", service: "contracthunter", version: "0.1.3", database: "connected", tools: { git, npm, slither, solcSelect } });
  } catch {
    return NextResponse.json({ status: "unhealthy", service: "contracthunter", database: "unavailable" }, { status: 503 });
  }
}
