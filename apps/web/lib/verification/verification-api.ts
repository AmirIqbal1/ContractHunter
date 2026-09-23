import { loadConfig, verificationHarnessPlanSchema, type VerificationPlanGenerationResult } from "@contracthunter/core";
import { getDatabase, getVulnerabilityHypothesis, listHypothesisVerificationRuns, type DatabaseClient } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";
import { createLocalHypothesisVerificationService, HypothesisVerificationRequestError, type HypothesisVerificationService } from "./hypothesis-verification-service";
import { toPublicHypothesisVerificationRun } from "./public-verification";
import { createVerificationPlanGenerationService, VerificationPlanGenerationError, type VerificationPlanGenerationService } from "./verification-plan-generation-service";

const MAX_REQUEST_BYTES = 65_536;
type RouteContext = { params: Promise<{ id: string }> };

function jsonContentType(request: Request): boolean {
  return request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() === "application/json";
}

async function boundedBody(request: Request): Promise<string | null> {
  if (!request.body) return "";
  const reader = request.body.getReader(); const decoder = new TextDecoder(); let total = 0; let body = "";
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) return body + decoder.decode();
    total += chunk.value.byteLength;
    if (total > MAX_REQUEST_BYTES) { await reader.cancel().catch(() => undefined); return null; }
    body += decoder.decode(chunk.value, { stream: true });
  }
}

export async function readVerificationHistory(_request: Request, context: RouteContext, database: DatabaseClient = getDatabase()) {
  const id = idSchema.safeParse((await context.params).id);
  if (!id.success) return NextResponse.json({ error: "Invalid hypothesis identifier." }, { status: 400 });
  if (!getVulnerabilityHypothesis(database, id.data)) return NextResponse.json({ error: "Hypothesis not found." }, { status: 404 });
  const verifications = listHypothesisVerificationRuns(database, id.data).slice(0, 50).map(toPublicHypothesisVerificationRun);
  return NextResponse.json({ verifications });
}

export async function startVerification(
  request: Request,
  context: RouteContext,
  service?: Pick<HypothesisVerificationService, "run">,
) {
  const id = idSchema.safeParse((await context.params).id);
  if (!id.success) return NextResponse.json({ error: "Invalid hypothesis identifier." }, { status: 400 });
  if (!jsonContentType(request)) return NextResponse.json({ error: "Content-Type must be application/json." }, { status: 415 });
  const declaredLength = Number(request.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BYTES) return NextResponse.json({ error: "Verification plan is too large." }, { status: 413 });
  const raw = await boundedBody(request).catch(() => "");
  if (raw === null) return NextResponse.json({ error: "Verification plan is too large." }, { status: 413 });
  let value: unknown;
  try { value = JSON.parse(raw); }
  catch { return NextResponse.json({ error: "Invalid verification plan." }, { status: 400 }); }
  const plan = verificationHarnessPlanSchema.safeParse(value);
  if (!plan.success) return NextResponse.json({ error: "Invalid verification plan." }, { status: 400 });
  if (plan.data.hypothesisId !== id.data) return NextResponse.json({ error: "Verification plan hypothesis does not match the URL." }, { status: 400 });
  try {
    const result = await (service ?? createLocalHypothesisVerificationService()).run(id.data, plan.data);
    if (result.status === "conflict") return NextResponse.json({ error: "An active local verification already exists.", verification: toPublicHypothesisVerificationRun(result.run) }, { status: 409 });
    return NextResponse.json({ status: result.status, verification: toPublicHypothesisVerificationRun(result.run) });
  } catch (error) {
    if (error instanceof HypothesisVerificationRequestError) {
      const status = error.code === "unknown_hypothesis" ? 404 : error.code === "invalid_plan" ? 400 : 409;
      return NextResponse.json({ error: error.message }, { status });
    }
    return NextResponse.json({ error: "Local verification could not be started." }, { status: 500 });
  }
}

export async function generateVerificationPlan(
  request: Request,
  context: RouteContext,
  service?: Pick<VerificationPlanGenerationService, "generate">,
) {
  const id = idSchema.safeParse((await context.params).id);
  if (!id.success) return NextResponse.json({ error: "Invalid hypothesis identifier." }, { status: 400 });
  const declaredLength = Number(request.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BYTES) return NextResponse.json({ error: "Verification plan request is too large." }, { status: 413 });
  const raw = await boundedBody(request).catch(() => null);
  if (raw === null) return NextResponse.json({ error: "Verification plan request is too large." }, { status: 413 });
  if (raw.length > 0) return NextResponse.json({ error: "Verification plan generation does not accept request data." }, { status: 400 });
  if (!service) {
    const config = loadConfig();
    if (!config.AI_ENABLED) return NextResponse.json({ error: "AI verification planning is disabled." }, { status: 409 });
    if (!config.OPENAI_API_KEY) return NextResponse.json({ error: "OpenAI is not configured." }, { status: 409 });
  }
  try {
    const result: VerificationPlanGenerationResult = await (service ?? createVerificationPlanGenerationService()).generate(id.data);
    return NextResponse.json(result);
  } catch (error) {
    if (error instanceof VerificationPlanGenerationError) return NextResponse.json({ error: error.message }, { status: error.code === "unknown_hypothesis" ? 404 : 409 });
    return NextResponse.json({ status: "failed", plan: null, failureCode: "plan_generation_failed" }, { status: 500 });
  }
}
