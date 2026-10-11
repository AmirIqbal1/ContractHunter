import { NextResponse } from "next/server";
import { getManualPoC } from "@/lib/impact-poc";
export const runtime = "nodejs";
type Context = { params: Promise<{ id: string }> };
export async function GET(_request: Request, context: Context) {
  const { id } = await context.params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ error: "Invalid PoC ID." }, { status: 400 });
  const poc = getManualPoC(id);
  return poc ? NextResponse.json({ poc }) : NextResponse.json({ error: "PoC not found." }, { status: 404 });
}
