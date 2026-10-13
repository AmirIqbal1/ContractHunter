import { NextResponse } from "next/server";
import { getDatabase } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { loadImpactOverlay } from "@/lib/impact-overlay-server";

export const runtime = "nodejs";
export async function GET(_request: Request, context: { params: Promise<{ id: string; executionId: string }> }) {
  const { id, executionId } = await context.params;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(executionId).success)
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const overlay = loadImpactOverlay(getDatabase(), id, executionId);
    return overlay ? NextResponse.json(overlay) : NextResponse.json({ error: "Overlay execution not found for this scan." }, { status: 404 });
  } catch {
    return NextResponse.json({ error: "Impact overlay unavailable due to evidence integrity or derivation failure." }, { status: 409 });
  }
}
