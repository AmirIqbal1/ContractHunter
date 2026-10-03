import { loadConfig, verificationStrategies } from "@contracthunter/core";
import { assessPersistedHypothesisVerificationStrategies, getDatabase, listVerificationPlanAttempts, type DatabaseClient } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { z } from "zod";
import { idSchema } from "@/lib/api";
import { createInvariantProposalService, InvariantProposalRequestError, type InvariantProposalService } from "./invariant-proposal-service";
import { createVerificationPlanGenerationService, VerificationPlanGenerationError, type VerificationPlanGenerationService } from "./verification-plan-generation-service";
import { toPublicInvariantProposal } from "./public-invariants";
import { toPublicVerificationOptions } from "./public-verification-options";
import { toPublicVerificationPlanAttempt } from "./public-strategy-planning-server";

type RouteContext = { params: Promise<{ id: string; strategy: string }> };
type Services = { database?: DatabaseClient; structured?: Pick<VerificationPlanGenerationService, "generate">; invariant?: Pick<InvariantProposalService, "generate"> };
const MAX_BODY_BYTES = 1_024;

async function bodyless(request: Request): Promise<NextResponse | null> {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return NextResponse.json({ error: "Strategy generation request is too large." }, { status: 413 });
  if (!request.body) return null;
  const reader = request.body.getReader(); let total = 0;
  while (true) {
    const chunk = await reader.read(); if (chunk.done) break;
    total += chunk.value.byteLength;
    if (total > MAX_BODY_BYTES) { await reader.cancel().catch(() => undefined); return NextResponse.json({ error: "Strategy generation request is too large." }, { status: 413 }); }
  }
  return total ? NextResponse.json({ error: "Strategy generation does not accept request data." }, { status: 400 }) : null;
}

export async function generateForSelectedStrategy(request: Request, context: RouteContext, services: Services = {}) {
  const params = await context.params, id = idSchema.safeParse(params.id), strategy = z.enum(verificationStrategies).safeParse(params.strategy);
  if (!id.success || !strategy.success) return NextResponse.json({ error: "Invalid hypothesis or strategy identifier." }, { status: 400 });
  const invalidBody = await bodyless(request).catch(() => NextResponse.json({ error: "Invalid strategy generation request body." }, { status: 400 }));
  if (invalidBody) return invalidBody;
  const database = services.database ?? getDatabase();
  const assessment = assessPersistedHypothesisVerificationStrategies(database, id.data);
  if (!assessment) return NextResponse.json({ error: "Hypothesis not found." }, { status: 404 });
  const option = toPublicVerificationOptions(assessment).find((item) => item.strategy === strategy.data);
  if (!option || option.compatibility !== "compatible") return NextResponse.json({
    code: option?.compatibility === "incompatible" ? "strategy_not_compatible" : "strategy_compatibility_unknown",
    reasons: option?.reasons.map(({ code, requirement }) => ({ code, requirement })) ?? [],
  }, { status: 409 });
  const selectedServiceInjected = strategy.data === "structured-verification" ? !!services.structured : !!services.invariant;
  if (!selectedServiceInjected) {
    const config = loadConfig();
    if (!config.AI_ENABLED || !config.OPENAI_API_KEY) return NextResponse.json({ code: "strategy_generation_unavailable" }, { status: 409 });
  }
  try {
    if (strategy.data === "structured-verification") {
      const result = await (services.structured ?? createVerificationPlanGenerationService(database)).generate(id.data, strategy.data);
      const attempt = listVerificationPlanAttempts(database, id.data).find((item) => item.result === JSON.stringify(result));
      return NextResponse.json({ selectedStrategy: strategy.data, result, attempt: attempt ? toPublicVerificationPlanAttempt(attempt) : null });
    }
    const output = await (services.invariant ?? createInvariantProposalService(database)).generate(id.data, strategy.data);
    return NextResponse.json({ selectedStrategy: strategy.data, proposal: toPublicInvariantProposal(output.proposal) });
  } catch (error) {
    if (error instanceof VerificationPlanGenerationError || error instanceof InvariantProposalRequestError) {
      return NextResponse.json({ code: error.code }, { status: error.code === "unknown_hypothesis" ? 404 : 409 });
    }
    return NextResponse.json({ code: "strategy_generation_failed" }, { status: 500 });
  }
}
