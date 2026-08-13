import { getDatabase, getInvariant, updateInvariantStatus } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { z } from "zod";
import { idSchema } from "@/lib/api";

const updateSchema = z.object({ status: z.enum(["proposed", "accepted", "rejected"]) }).strict();
export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const id = idSchema.safeParse((await context.params).id); if (!id.success) return NextResponse.json({ error: "Invalid invariant identifier." }, { status: 400 });
  const invariant = getInvariant(getDatabase(), id.data); return invariant ? NextResponse.json({ invariant }) : NextResponse.json({ error: "Invariant not found." }, { status: 404 });
}
export async function PATCH(request: Request, context: { params: Promise<{ id: string }> }) {
  const id = idSchema.safeParse((await context.params).id); if (!id.success) return NextResponse.json({ error: "Invalid invariant identifier." }, { status: 400 });
  const body = updateSchema.safeParse(await request.json().catch(() => null)); if (!body.success) return NextResponse.json({ error: "Invalid invariant status." }, { status: 400 });
  const invariant = updateInvariantStatus(getDatabase(), id.data, body.data.status); return invariant ? NextResponse.json({ invariant }) : NextResponse.json({ error: "Invariant not found." }, { status: 404 });
}
