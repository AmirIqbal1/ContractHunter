import { NextResponse } from "next/server";
import { createImpactSession, publicImpactSession } from "@/lib/impact-lab";
import { impactCreateSessionSchema } from "@contracthunter/core";
import { getDatabase } from "@contracthunter/db";
import { impactSubjectInScan, requestedImpactScan } from "@/lib/impact-api-scope";

export const runtime = "nodejs";
async function boundedBody(request: Request): Promise<unknown> {
  if (Number(request.headers.get("content-length") ?? 0) > 16 * 1024 || !request.body) throw new Error("invalid_body");
  const reader = request.body.getReader();
  const parts: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.length;
      if (bytes > 16 * 1024) throw new Error("invalid_body");
      parts.push(part.value);
    }
    return JSON.parse(Buffer.concat(parts).toString("utf8"));
  } finally { await reader.cancel().catch(() => undefined); }
}
export async function POST(request: Request) {
  try {
    const scanId = requestedImpactScan(request);
    if (!scanId) return NextResponse.json({ error: "Invalid scan ID." }, { status: 400 });
    const input = impactCreateSessionSchema.parse(await boundedBody(request));
    if (!impactSubjectInScan(getDatabase(), scanId, input.findingId ?? null, input.hypothesisId ?? null))
      return NextResponse.json({ error: "Subject not found." }, { status: 404 });
    const session = await createImpactSession(input);
    return NextResponse.json({ session: publicImpactSession(session) }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Impact Lab session could not be created." }, { status: 400 });
  }
}
