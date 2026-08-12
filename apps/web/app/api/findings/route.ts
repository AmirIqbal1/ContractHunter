import { findingStatuses, severities } from "@contracthunter/core";
import { getDatabase, listFindings } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { z } from "zod";

const querySchema = z.object({
  scanId: z.string().uuid().optional(),
  severity: z.enum(severities).optional(),
  source: z.string().min(1).max(100).optional(),
  status: z.enum(findingStatuses).optional(),
});

export async function GET(request: Request) {
  const url = new URL(request.url);
  const result = querySchema.safeParse(Object.fromEntries(url.searchParams));
  if (!result.success) return NextResponse.json({ error: "Invalid finding filters." }, { status: 400 });
  return NextResponse.json({ findings: listFindings(getDatabase(), result.data) });
}
