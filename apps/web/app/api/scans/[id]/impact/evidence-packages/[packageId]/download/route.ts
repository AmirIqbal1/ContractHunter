import { canonicalEvidenceJson } from "@contracthunter/core";
import { getDatabase, readEvidencePackage } from "@contracthunter/db";
import { idSchema } from "@/lib/api";

export const runtime = "nodejs";
export async function GET(_request: Request, context: { params: Promise<{ id: string; packageId: string }> }) {
  const { id, packageId } = await context.params;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(packageId).success)
    return new Response("Invalid identifier.", { status: 400 });
  try {
    const value = readEvidencePackage(getDatabase(), id, packageId);
    if (!value || value.status !== "finalized") return new Response("Finalized package not found.", { status: 404 });
    return new Response(`${canonicalEvidenceJson(value)}\n`, { headers: {
      "content-type": "application/json; charset=utf-8", "content-disposition":
        `attachment; filename="contracthunter-evidence-${packageId}.json"`,
      "cache-control": "no-store", "x-content-type-options": "nosniff" } });
  } catch { return new Response("Evidence package integrity unavailable.", { status: 409 }); }
}
