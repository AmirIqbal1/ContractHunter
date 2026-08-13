import { getDatabase } from "@contracthunter/db";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export function GET() {
  try {
    getDatabase().sqlite.prepare("SELECT 1").get();
    return NextResponse.json({ status: "ok", service: "contracthunter", version: "0.1.2", database: "connected" });
  } catch {
    return NextResponse.json({ status: "unhealthy", service: "contracthunter", database: "unavailable" }, { status: 503 });
  }
}
