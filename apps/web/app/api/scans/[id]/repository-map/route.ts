import { getDatabase, getScan, readRepositoryMap } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";

export const runtime = "nodejs";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const parsed = idSchema.safeParse((await context.params).id);
  if (!parsed.success) return NextResponse.json({ error: "Invalid scan identifier." }, { status: 400 });
  const database = getDatabase();
  if (!getScan(database, parsed.data)) return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  const map = readRepositoryMap(database, parsed.data);
  if (!map) return NextResponse.json({ error: "Repository map unavailable for this scan." }, { status: 404 });
  return NextResponse.json(map);
}
