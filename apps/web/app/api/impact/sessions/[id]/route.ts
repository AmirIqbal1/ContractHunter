import { NextResponse } from "next/server";
import { getDatabase, readImpactForkSession } from "@contracthunter/db";
import { publicImpactSession, stopImpactSession } from "@/lib/impact-lab";

export const runtime = "nodejs";
type Context = { params: Promise<{ id: string }> };
export async function GET(_request: Request, context: Context) {
  const { id } = await context.params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ error: "Invalid session ID." }, { status: 400 });
  const session = readImpactForkSession(getDatabase(), id);
  return session ? NextResponse.json({ session: publicImpactSession(session) }) : NextResponse.json({ error: "Session not found." }, { status: 404 });
}
export async function DELETE(_request: Request, context: Context) {
  try { return NextResponse.json({ session: publicImpactSession(await stopImpactSession((await context.params).id)) }); }
  catch { return NextResponse.json({ error: "Session could not be stopped." }, { status: 400 }); }
}
