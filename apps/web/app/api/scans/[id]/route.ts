import { getCurrentProtocolAnalysis, getDatabase, getScan, listFindings, listInvestigations, listInvariants, listScanScanners } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";

export const runtime = "nodejs";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const parsed = idSchema.safeParse((await context.params).id);
  if (!parsed.success) return NextResponse.json({ error: "Invalid scan identifier." }, { status: 400 });
  const database = getDatabase();
  const scan = getScan(database, parsed.data);
  if (!scan) return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  return NextResponse.json({ scan, scanners: listScanScanners(database, scan.id), investigations: listInvestigations(database, { scanId: scan.id }), protocolAnalysis: getCurrentProtocolAnalysis(database, scan.id), invariants: listInvariants(database, { scanId: scan.id }), findings: listFindings(database, { scanId: scan.id }) });
}
