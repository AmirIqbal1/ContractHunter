import { NextResponse } from "next/server";
import { getManualPoCExecutionState } from "@/lib/impact-poc";
export const runtime = "nodejs";
type Context = { params: Promise<{ id: string }> };
export async function GET(_request: Request, context: Context) {
  const { id } = await context.params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ error: "Invalid execution ID." }, { status: 400 });
  try {
    const state = getManualPoCExecutionState(id);
    return state ? NextResponse.json({ state }) : NextResponse.json({ error: "Execution not found." }, { status: 404 });
  } catch { return NextResponse.json({ error: "State integrity check failed." }, { status: 409 }); }
}
