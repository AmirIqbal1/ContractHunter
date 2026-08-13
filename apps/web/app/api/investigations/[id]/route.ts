import { investigationStatuses } from "@contracthunter/core";
import { getDatabase, getInvestigation, listInvestigationFindings, updateInvestigationStatus } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { z } from "zod";
import { idSchema } from "@/lib/api";

const updateSchema = z.object({ status: z.enum(investigationStatuses) }).strict();

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const parsed = idSchema.safeParse((await context.params).id);
  if (!parsed.success) return NextResponse.json({ error: "Invalid investigation identifier." }, { status: 400 });
  const investigation = getInvestigation(getDatabase(), parsed.data);
  return investigation ? NextResponse.json({ investigation, findings: listInvestigationFindings(getDatabase(), parsed.data) }) : NextResponse.json({ error: "Investigation not found." }, { status: 404 });
}

export async function PATCH(request: Request, context: { params: Promise<{ id: string }> }) {
  const id = idSchema.safeParse((await context.params).id);
  if (!id.success) return NextResponse.json({ error: "Invalid investigation identifier." }, { status: 400 });
  const body = updateSchema.safeParse(await request.json().catch(() => null));
  if (!body.success) return NextResponse.json({ error: "Invalid investigation status." }, { status: 400 });
  const investigation = updateInvestigationStatus(getDatabase(), id.data, body.data.status);
  return investigation ? NextResponse.json({ investigation }) : NextResponse.json({ error: "Investigation not found." }, { status: 404 });
}
