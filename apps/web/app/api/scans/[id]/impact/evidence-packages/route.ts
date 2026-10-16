import { NextResponse } from "next/server";
import { z } from "zod";
import { getDatabase } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { boundedImpactJson } from "@/lib/impact-poc-http";
import { createEvidencePackage } from "@/lib/evidence-package-server";

export const runtime = "nodejs";
const input = z.object({ subjectType: z.enum(["finding", "investigation", "hypothesis"]),
  subjectId: z.string().uuid(), executionId: z.string().uuid().nullable(),
  scenarioRevisionId: z.string().uuid().nullable(), replayRunId: z.string().uuid().nullable() }).strict();
export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  if (!idSchema.safeParse(id).success) return NextResponse.json({ error: "Invalid scan ID." }, { status: 400 });
  try {
    const selection = input.parse(await boundedImpactJson(request, 4096));
    const value = createEvidencePackage(getDatabase(), id, selection);
    return NextResponse.json({ packageId: value.packageId, status: value.status }, { status: 201 });
  } catch { return NextResponse.json({ error: "Evidence selection is invalid or unavailable." }, { status: 409 }); }
}
