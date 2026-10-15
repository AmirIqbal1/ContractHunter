import { NextResponse } from "next/server";
import { getDatabase, readEvidencePackage } from "@contracthunter/db";
import { idSchema } from "@/lib/api";

export const runtime = "nodejs";
export async function GET(_request: Request, context: { params: Promise<{ id: string; packageId: string }> }) {
  const { id, packageId } = await context.params;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(packageId).success)
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const value = readEvidencePackage(getDatabase(), id, packageId);
    return value ? NextResponse.json(value, { headers: { "cache-control": "no-store" } }) :
      NextResponse.json({ error: "Evidence package not found." }, { status: 404 });
  } catch { return NextResponse.json({ error: "Evidence package integrity unavailable." }, { status: 409 }); }
}
