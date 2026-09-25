import { loadConfig } from "@contracthunter/core";
import { getDatabase, getVulnerabilityHypothesis, listExecutableInvariantProposals, listExecutableInvariantRuns, listHypothesisInvariantReplayArtifacts, listHypothesisInvariantReplayRuns, listInvariantEvidenceReviews, type DatabaseClient } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";
import { createLocalExecutableInvariantService, ExecutableInvariantRequestError, type ExecutableInvariantService } from "./executable-invariant-service";
import { createInvariantProposalService, InvariantProposalRequestError, type InvariantProposalService } from "./invariant-proposal-service";
import { createInvariantReplayService, InvariantReplayRequestError, type InvariantReplayService } from "./invariant-replay-service";
import { toPublicInvariantProposal, toPublicInvariantReplayArtifact, toPublicInvariantReplayRun, toPublicInvariantReview, toPublicInvariantRun } from "./public-invariants";

type RouteContext = { params: Promise<{ id: string; proposalId?: string; runId?: string; replayId?: string }> };
const MAX_BODY_BYTES = 1_024;
async function bodyless(request: Request): Promise<NextResponse | null> {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return NextResponse.json({ error: "Invariant request is too large." }, { status: 413 });
  if (!request.body) return null;
  const reader = request.body.getReader(); let total = 0;
  while (true) {
    const chunk = await reader.read(); if (chunk.done) break;
    total += chunk.value.byteLength;
    if (total > MAX_BODY_BYTES) { await reader.cancel().catch(() => undefined); return NextResponse.json({ error: "Invariant request is too large." }, { status: 413 }); }
  }
  return total ? NextResponse.json({ error: "This invariant action does not accept request data." }, { status: 400 }) : null;
}
async function ids(context: RouteContext): Promise<{ id: string; proposalId?: string; runId?: string; replayId?: string } | null> {
  const params = await context.params, id = idSchema.safeParse(params.id);
  const proposal = params.proposalId === undefined ? null : idSchema.safeParse(params.proposalId);
  const run = params.runId === undefined ? null : idSchema.safeParse(params.runId), replay = params.replayId === undefined ? null : idSchema.safeParse(params.replayId);
  return id.success && (!proposal || proposal.success) && (!run || run.success) && (!replay || replay.success) ? { id: id.data, ...(proposal?.success ? { proposalId: proposal.data } : {}), ...(run?.success ? { runId: run.data } : {}), ...(replay?.success ? { replayId: replay.data } : {}) } : null;
}
function errorResponse(error: unknown): NextResponse {
  if (error instanceof InvariantProposalRequestError || error instanceof ExecutableInvariantRequestError || error instanceof InvariantReplayRequestError) return NextResponse.json({ error: error.message }, { status: error.code.startsWith("unknown") ? 404 : 409 });
  return NextResponse.json({ error: "Invariant action failed safely." }, { status: 500 });
}
export async function readInvariantHistory(_request: Request, context: RouteContext, database: DatabaseClient = getDatabase()) {
  const values = await ids(context); if (!values) return NextResponse.json({ error: "Invalid hypothesis identifier." }, { status: 400 });
  if (!getVulnerabilityHypothesis(database, values.id)) return NextResponse.json({ error: "Hypothesis not found." }, { status: 404 });
  const proposals = listExecutableInvariantProposals(database, values.id).slice(0, 50);
  const runs = listExecutableInvariantRuns(database, values.id).slice(0, 50);
  const replays = listHypothesisInvariantReplayArtifacts(database, values.id).slice(0, 50).map(toPublicInvariantReplayArtifact).filter((item) => item !== null), replayRuns = listHypothesisInvariantReplayRuns(database, values.id).slice(0, 50).map(toPublicInvariantReplayRun), reviews = listInvariantEvidenceReviews(database, values.id).slice(0, 50).map(toPublicInvariantReview);
  return NextResponse.json({ proposals: proposals.map(toPublicInvariantProposal), runs: runs.map((run) => toPublicInvariantRun(run, proposals.find((item) => item.planHash === run.planHash)?.id ?? null)), replays, replayRuns, reviews });
}
export async function generateInvariantReplay(request: Request, context: RouteContext, service?: Pick<InvariantReplayService, "generate">) {
  const values = await ids(context); if (!values?.proposalId || !values.runId) return NextResponse.json({ error: "Invalid invariant replay identity." }, { status: 400 });
  const invalidBody = await bodyless(request).catch(() => NextResponse.json({ error: "Invalid invariant request body." }, { status: 400 })); if (invalidBody) return invalidBody;
  try { const artifact = await (service ?? createInvariantReplayService()).generate(values.id, values.proposalId, values.runId); return NextResponse.json({ replay: toPublicInvariantReplayArtifact(artifact) }); } catch (error) { return errorResponse(error); }
}
export async function runInvariantReplay(request: Request, context: RouteContext, service?: Pick<InvariantReplayService, "execute">) {
  const values = await ids(context); if (!values?.replayId) return NextResponse.json({ error: "Invalid replay artifact identifier." }, { status: 400 });
  const invalidBody = await bodyless(request).catch(() => NextResponse.json({ error: "Invalid invariant request body." }, { status: 400 })); if (invalidBody) return invalidBody;
  try { const run = await (service ?? createInvariantReplayService()).execute(values.id, values.replayId); return NextResponse.json({ replayRun: toPublicInvariantReplayRun(run) }); } catch (error) { return errorResponse(error); }
}
export async function reviewInvariantReplay(request: Request, context: RouteContext, service?: Pick<InvariantReplayService, "review">) {
  const values = await ids(context); if (!values?.proposalId || !values.runId || !values.replayId) return NextResponse.json({ error: "Invalid invariant review identity." }, { status: 400 });
  const invalidBody = await bodyless(request).catch(() => NextResponse.json({ error: "Invalid invariant request body." }, { status: 400 })); if (invalidBody) return invalidBody;
  try { const review = (service ?? createInvariantReplayService()).review(values.id, values.proposalId, values.runId, values.replayId); return NextResponse.json({ review: toPublicInvariantReview(review) }); } catch (error) { return errorResponse(error); }
}
export async function generateInvariantProposal(request: Request, context: RouteContext, service?: Pick<InvariantProposalService, "generate">) {
  const values = await ids(context); if (!values) return NextResponse.json({ error: "Invalid hypothesis identifier." }, { status: 400 });
  const invalidBody = await bodyless(request).catch(() => NextResponse.json({ error: "Invalid invariant request body." }, { status: 400 })); if (invalidBody) return invalidBody;
  if (!service) {
    const config = loadConfig();
    if (!config.AI_ENABLED) return NextResponse.json({ error: "AI invariant proposals are disabled." }, { status: 409 });
    if (!config.OPENAI_API_KEY) return NextResponse.json({ error: "OpenAI is not configured." }, { status: 409 });
  }
  try {
    const output = await (service ?? createInvariantProposalService()).generate(values.id);
    return NextResponse.json({ proposal: toPublicInvariantProposal(output.proposal) });
  } catch (error) { return errorResponse(error); }
}
export async function validateInvariantProposal(request: Request, context: RouteContext, service?: Pick<InvariantProposalService, "validate">) {
  const values = await ids(context); if (!values?.proposalId) return NextResponse.json({ error: "Invalid invariant proposal identifier." }, { status: 400 });
  const invalidBody = await bodyless(request).catch(() => NextResponse.json({ error: "Invalid invariant request body." }, { status: 400 })); if (invalidBody) return invalidBody;
  try { const result = await (service ?? createInvariantProposalService()).validate(values.id, values.proposalId); return NextResponse.json({ status: "validated", planHash: result.planHash }); }
  catch (error) { return errorResponse(error); }
}
export async function runInvariantProposal(request: Request, context: RouteContext, proposalService?: Pick<InvariantProposalService, "validate">, executionService?: Pick<ExecutableInvariantService, "run">) {
  const values = await ids(context); if (!values?.proposalId) return NextResponse.json({ error: "Invalid invariant proposal identifier." }, { status: 400 });
  const invalidBody = await bodyless(request).catch(() => NextResponse.json({ error: "Invalid invariant request body." }, { status: 400 })); if (invalidBody) return invalidBody;
  try {
    const validated = await (proposalService ?? createInvariantProposalService()).validate(values.id, values.proposalId);
    const result = await (executionService ?? createLocalExecutableInvariantService()).run(values.id, validated.plan);
    if (result.status === "conflict") return NextResponse.json({ error: "An invariant run is already active.", run: toPublicInvariantRun(result.run, values.proposalId) }, { status: 409 });
    return NextResponse.json({ run: toPublicInvariantRun(result.run, values.proposalId) });
  } catch (error) { return errorResponse(error); }
}
