import { getDatabase, getScan, readStaticProtocolGraph } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";

export const runtime = "nodejs";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const parsed = idSchema.safeParse((await context.params).id);
  if (!parsed.success) return NextResponse.json({ error: "Invalid scan identifier." }, { status: 400 });
  const database = getDatabase();
  if (!getScan(database, parsed.data)) return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  try {
    const graph = readStaticProtocolGraph(database, parsed.data);
    if (!graph) return NextResponse.json({ error: "Static protocol graph unavailable for this scan." }, { status: 404 });
    return NextResponse.json(graph);
  } catch {
    return NextResponse.json({ error: "Static protocol graph failed integrity validation." }, { status: 500 });
  }
}
