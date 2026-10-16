import { getDatabase, getScan } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";
import { readFunctionExplorer } from "@/lib/function-explorer-server";

export const runtime = "nodejs";
const graphNodeId = /^pn:[a-f0-9]{64}$/;

export async function GET(_request: Request, context: { params: Promise<{
  id: string; contractId: string; functionId: string }> }) {
  const { id, contractId, functionId } = await context.params;
  const scan = idSchema.safeParse(id);
  if (!scan.success || !graphNodeId.test(contractId) || !graphNodeId.test(functionId))
    return NextResponse.json({ error: "Invalid function selector." }, { status: 400 });
  const database = getDatabase();
  if (!getScan(database, scan.data)) return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  try {
    const result = readFunctionExplorer(database, scan.data, contractId, functionId);
    return result ? NextResponse.json(result) : NextResponse.json({ error: "Function unavailable for this scan and contract." },
      { status: 404 });
  } catch {
    return NextResponse.json({ error: "Function analysis failed integrity validation." }, { status: 500 });
  }
}
