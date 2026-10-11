import { NextResponse } from "next/server";
import { publicImpactSession, recreateImpactSession } from "@/lib/impact-lab";

export const runtime = "nodejs";
export async function POST(_request: Request, context: { params: Promise<{ id: string }> }) {
  try { return NextResponse.json({ session: publicImpactSession(await recreateImpactSession((await context.params).id)) }); }
  catch { return NextResponse.json({ error: "Session could not be recreated." }, { status: 400 }); }
}
