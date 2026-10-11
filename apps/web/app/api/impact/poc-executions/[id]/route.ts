import { NextResponse } from "next/server";
import { getManualPoCExecution } from "@/lib/impact-poc";
export const runtime = "nodejs";
type Context = { params: Promise<{ id: string }> };
export async function GET(_request: Request, context: Context) {
  const { id } = await context.params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ error: "Invalid execution ID." }, { status: 400 });
  const execution = getManualPoCExecution(id);
  return execution ? NextResponse.json({ execution }) : NextResponse.json({ error: "Execution not found." }, { status: 404 });
}
