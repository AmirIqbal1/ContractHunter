import { deriveSecurityView, securityViewTypes, SECURITY_VIEW_LIMITS,
  type SecurityFindingMetadata, type SecurityViewType } from "@contracthunter/core";
import { getDatabase, getFinding, getScan, readStaticProtocolGraph } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";

export const runtime = "nodejs";

export async function GET(_request: Request, context: { params: Promise<{ id: string; view: string }> }) {
  const { id, view } = await context.params;
  const parsed = idSchema.safeParse(id);
  if (!parsed.success) return NextResponse.json({ error: "Invalid scan identifier." }, { status: 400 });
  if (!securityViewTypes.includes(view as SecurityViewType))
    return NextResponse.json({ error: "Unknown security view." }, { status: 400 });
  const database = getDatabase();
  if (!getScan(database, parsed.data)) return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  try {
    const artifact = readStaticProtocolGraph(database, parsed.data);
    if (!artifact) return NextResponse.json({ error: "Static protocol graph unavailable for this scan." }, { status: 404 });
    const metadata: SecurityFindingMetadata[] = [];
    if (view === "findings" || view === "attack-surface") {
      const ids = [...new Set(artifact.findingLinks.map((item) => item.findingId))].sort()
        .slice(0, SECURITY_VIEW_LIMITS.findingMetadata);
      for (const findingId of ids) {
        const finding = getFinding(database, findingId);
        if (finding?.scanId === parsed.data) metadata.push({ id: finding.id,
          detectorId: finding.detectorId?.slice(0, 160) ?? null, title: finding.title.slice(0, 200),
          status: finding.status.slice(0, 80), source: finding.source.slice(0, 80) });
      }
    }
    return NextResponse.json(deriveSecurityView(artifact, view as SecurityViewType, metadata));
  } catch {
    return NextResponse.json({ error: "Security view unavailable due to graph integrity or derivation failure." },
      { status: 500 });
  }
}
