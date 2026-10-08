import { NextResponse } from "next/server";
import { getDatabase, getVulnerabilityHypothesis, type DatabaseClient } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { PlanningReuseError, PlanningReuseService } from "./planning-reuse-service";
import { toPublicInvariantProposal } from "./public-invariants";
import { toPublicVerificationPlanAttempt } from "./public-strategy-planning-server";

type RouteContext = { params: Promise<{ id: string; artifactId: string }> };
const MAX_BODY_BYTES = 1_024;

async function bodyless(request: Request): Promise<NextResponse | null> {
  if (new URL(request.url).search) return NextResponse.json({ code: "reuse_request_invalid" }, { status: 400 });
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return NextResponse.json({ code: "reuse_request_too_large" }, { status: 413 });
  if (!request.body) return null;
  const reader = request.body.getReader(); let total = 0;
  while (true) {
    const chunk = await reader.read(); if (chunk.done) break;
    total += chunk.value.byteLength;
    if (total > MAX_BODY_BYTES) { await reader.cancel().catch(() => undefined); return NextResponse.json({ code: "reuse_request_too_large" }, { status: 413 }); }
  }
  return total ? NextResponse.json({ code: "reuse_request_invalid" }, { status: 400 }) : null;
}

async function selected(request: Request, context: RouteContext, database: DatabaseClient) {
  const params = await context.params, id = idSchema.safeParse(params.id), artifactId = idSchema.safeParse(params.artifactId);
  if (!id.success || !artifactId.success) return { response: NextResponse.json({ code: "reuse_request_invalid" }, { status: 400 }) };
  const invalid = await bodyless(request).catch(() => NextResponse.json({ code: "reuse_request_invalid" }, { status: 400 }));
  if (invalid) return { response: invalid };
  if (!getVulnerabilityHypothesis(database, id.data)) return { response: NextResponse.json({ code: "reuse_hypothesis_not_found" }, { status: 404 }) };
  return { id: id.data, artifactId: artifactId.data };
}

function failure(error: unknown) {
  if (error instanceof PlanningReuseError) return NextResponse.json({ code: error.code }, { status: error.code === "reuse_artifact_not_found" ? 404 : 409 });
  return NextResponse.json({ code: "reuse_failed_safely" }, { status: 500 });
}

export async function reuseStructuredPlanningArtifact(request: Request, context: RouteContext, database: DatabaseClient = getDatabase()) {
  const input = await selected(request, context, database);
  if (input.response) return input.response;
  try {
    const row = new PlanningReuseService(database).reuseStructured(input.id!, input.artifactId!);
    return NextResponse.json({ attempt: toPublicVerificationPlanAttempt(row) }, { status: 201 });
  } catch (error) { return failure(error); }
}

export async function reuseInvariantPlanningArtifact(request: Request, context: RouteContext, database: DatabaseClient = getDatabase()) {
  const input = await selected(request, context, database);
  if (input.response) return input.response;
  try {
    const row = new PlanningReuseService(database).reuseInvariant(input.id!, input.artifactId!);
    return NextResponse.json({ proposal: toPublicInvariantProposal(row) }, { status: 201 });
  } catch (error) { return failure(error); }
}
