import { invariantCategories, invariantStatuses, invariantTestabilities, severities } from "@contracthunter/core";
import { getDatabase, listInvariants } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { z } from "zod";

const querySchema = z.object({ scanId: z.string().uuid().optional(), category: z.enum(invariantCategories).optional(), severity: z.enum(severities).optional(), status: z.enum(invariantStatuses).optional(), testability: z.enum(invariantTestabilities).optional() });
export async function GET(request: Request) {
  const parsed = querySchema.safeParse(Object.fromEntries(new URL(request.url).searchParams));
  return parsed.success ? NextResponse.json({ invariants: listInvariants(getDatabase(), parsed.data) }) : NextResponse.json({ error: "Invalid invariant filters." }, { status: 400 });
}
