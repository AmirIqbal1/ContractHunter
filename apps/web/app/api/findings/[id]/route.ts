import { getDatabase, getFinding } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const parsed = idSchema.safeParse((await context.params).id);
  if (!parsed.success) return NextResponse.json({ error: "Invalid finding identifier." }, { status: 400 });
  const finding = getFinding(getDatabase(), parsed.data);
  return finding ? NextResponse.json({ finding }) : NextResponse.json({ error: "Finding not found." }, { status: 404 });
}
