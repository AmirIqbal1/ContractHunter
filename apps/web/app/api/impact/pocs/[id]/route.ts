import { NextResponse } from "next/server";
import { getDatabase } from "@contracthunter/db";
import { publicImpactPoC, requestedImpactScan, scopedImpactPoC } from "@/lib/impact-api-scope";
export const runtime = "nodejs";
type Context = { params: Promise<{ id: string }> };
export async function GET(request: Request, context: Context) {
  const { id } = await context.params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ error: "Invalid PoC ID." }, { status: 400 });
  const scanId = requestedImpactScan(request);
  if (!scanId) return NextResponse.json({ error: "Invalid scan ID." }, { status: 400 });
  const poc = scopedImpactPoC(getDatabase(), scanId, id);
  return poc ? NextResponse.json({ poc: publicImpactPoC(poc) }) : NextResponse.json({ error: "PoC not found." }, { status: 404 });
}
