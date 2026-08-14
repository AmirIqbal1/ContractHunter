import { evidenceClasses, hypothesisStatuses, severities } from "@contracthunter/core";
import { getDatabase, listVulnerabilityHypotheses } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { z } from "zod";
const schema = z.object({ scanId: z.string().uuid().optional(), severity: z.enum(severities).optional(), category: z.string().max(100).optional(), reviewerId: z.string().max(100).optional(), status: z.enum(hypothesisStatuses).optional(), minimumConfidence: z.coerce.number().int().min(0).max(85).optional(), evidenceClass: z.enum(evidenceClasses).optional() });
export async function GET(request: Request) { const parsed = schema.safeParse(Object.fromEntries(new URL(request.url).searchParams)); return parsed.success ? NextResponse.json({ hypotheses: listVulnerabilityHypotheses(getDatabase(), parsed.data) }) : NextResponse.json({ error: "Invalid hypothesis filters." }, { status: 400 }); }
