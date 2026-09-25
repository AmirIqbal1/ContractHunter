import { generateInvariantReplay } from "@/lib/verification/invariant-api";
export const runtime = "nodejs";
export async function POST(request: Request, context: { params: Promise<{ id: string; proposalId: string; runId: string }> }) { return generateInvariantReplay(request, context); }
