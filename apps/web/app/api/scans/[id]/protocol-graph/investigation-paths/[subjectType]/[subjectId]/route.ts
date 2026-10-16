import { investigationSubjectTypes } from "@contracthunter/core";
import { getDatabase, getScan, readStaticProtocolGraph } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";
import { loadInvestigationPaths, type PathSubjectType } from "@/lib/investigation-path-server";

export const runtime = "nodejs";
export async function GET(_request: Request, context: { params: Promise<{ id: string; subjectType: string; subjectId: string }> }) {
  const { id, subjectType, subjectId } = await context.params;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(subjectId).success)
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  if (!investigationSubjectTypes.includes(subjectType as PathSubjectType))
    return NextResponse.json({ error: "Unknown investigation path subject." }, { status: 400 });
  const database = getDatabase();
  if (!getScan(database, id)) return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  try {
    const artifact = readStaticProtocolGraph(database, id);
    if (!artifact)
      return NextResponse.json({ error: "Static protocol graph unavailable for this scan." }, { status: 404 });
    const result = loadInvestigationPaths(database, id, subjectType as PathSubjectType, subjectId, artifact);
    if (!result) return NextResponse.json({ error: "Path subject not found for this scan." }, { status: 404 });
    return NextResponse.json(result);
  } catch {
    return NextResponse.json({ error: "Investigation paths unavailable due to graph integrity or derivation failure." }, { status: 500 });
  }
}
