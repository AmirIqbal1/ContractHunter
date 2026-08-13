import { investigationStatuses, severities } from "@contracthunter/core";
import { getDatabase, listInvestigations } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { z } from "zod";

const querySchema = z.object({
  scanId: z.string().uuid().optional(),
  severity: z.enum(severities).optional(),
  status: z.enum(investigationStatuses).optional(),
  minimumConfidence: z.coerce.number().int().min(0).max(100).optional(),
  sourceCount: z.coerce.number().int().min(1).optional(),
});

export async function GET(request: Request) {
  const parsed = querySchema.safeParse(Object.fromEntries(new URL(request.url).searchParams));
  if (!parsed.success) return NextResponse.json({ error: "Invalid investigation filters." }, { status: 400 });
  return NextResponse.json({ investigations: listInvestigations(getDatabase(), parsed.data) });
}
