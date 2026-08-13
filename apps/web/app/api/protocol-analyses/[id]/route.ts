import { getDatabase, getProtocolAnalysis, listInvariants } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const id = idSchema.safeParse((await context.params).id); if (!id.success) return NextResponse.json({ error: "Invalid analysis identifier." }, { status: 400 });
  const analysis = getProtocolAnalysis(getDatabase(), id.data); return analysis ? NextResponse.json({ analysis, invariants: listInvariants(getDatabase(), { scanId: analysis.scanId }, false).filter((item) => item.analysisId === analysis.id) }) : NextResponse.json({ error: "Protocol analysis not found." }, { status: 404 });
}
