import { NextResponse } from "next/server";
import { publicImpactSession, recreateImpactSession } from "@/lib/impact-lab";
import { getDatabase } from "@contracthunter/db";
import { requestedImpactScan, scopedImpactSession } from "@/lib/impact-api-scope";

export const runtime = "nodejs";
export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  const scanId = requestedImpactScan(request), { id } = await context.params;
  if (!scanId || !/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  if (!scopedImpactSession(getDatabase(), scanId, id)) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  try { return NextResponse.json({ session: publicImpactSession(await recreateImpactSession(id)) }); }
  catch { return NextResponse.json({ error: "Session could not be recreated." }, { status: 400 }); }
}
