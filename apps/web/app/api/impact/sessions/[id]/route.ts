import { NextResponse } from "next/server";
import { getDatabase } from "@contracthunter/db";
import { publicImpactSession, stopImpactSession } from "@/lib/impact-lab";
import { requestedImpactScan, scopedImpactSession } from "@/lib/impact-api-scope";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string }> };
export async function GET(request: Request, context: Context) {
  const { id } = await context.params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ error: "Invalid session ID." }, { status: 400 });
  const scanId = requestedImpactScan(request);
  if (!scanId) return NextResponse.json({ error: "Invalid scan ID." }, { status: 400 });
  const session = scopedImpactSession(getDatabase(), scanId, id);
  return session ? NextResponse.json({ session: publicImpactSession(session) }) : NextResponse.json({ error: "Session not found." }, { status: 404 });
}
export async function DELETE(request: Request, context: Context) {
  const scanId = requestedImpactScan(request), { id } = await context.params;
  if (!scanId || !/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  if (!scopedImpactSession(getDatabase(), scanId, id)) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  try { return NextResponse.json({ session: publicImpactSession(await stopImpactSession(id)) }); }
  catch { return NextResponse.json({ error: "Session could not be stopped." }, { status: 400 }); }
}
