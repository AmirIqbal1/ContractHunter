import { NextResponse } from "next/server";
import { getDatabase } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { loadAssetFlow } from "@/lib/asset-flow-server";

export const runtime = "nodejs";
export async function GET(_request: Request, context: { params: Promise<{ id: string; executionId: string }> }) {
  const { id, executionId } = await context.params;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(executionId).success)
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const result = loadAssetFlow(getDatabase(), id, executionId);
    return result ? NextResponse.json(result) :
      NextResponse.json({ error: "Asset accounting execution not found for this scan." }, { status: 404 });
  } catch {
    return NextResponse.json({ error: "Asset accounting unavailable due to evidence integrity or derivation failure." },
      { status: 409 });
  }
}
