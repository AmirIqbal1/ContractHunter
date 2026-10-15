import { NextResponse } from "next/server";
import { getDatabase } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { finalizeEvidencePackageFromCurrent } from "@/lib/evidence-package-server";

export const runtime = "nodejs";
export async function POST(_request: Request, context: { params: Promise<{ id: string; packageId: string }> }) {
  const { id, packageId } = await context.params;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(packageId).success)
    return NextResponse.json({ error: "Invalid identifier." }, { status: 400 });
  try {
    const value = finalizeEvidencePackageFromCurrent(getDatabase(), id, packageId);
    return NextResponse.json({ packageId: value.packageId, status: value.status,
      manifestHash: value.manifestHash, contentHash: value.contentHash });
  } catch { return NextResponse.json({ error: "Evidence changed or package cannot be finalized." }, { status: 409 }); }
}
