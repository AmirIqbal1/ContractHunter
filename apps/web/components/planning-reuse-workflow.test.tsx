import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { executableInvariantPlanSchema, invariantPlanHash, verificationHarnessPlanSchema } from "@contracthunter/core";
import { performPlanningReuse } from "@/lib/verification/client-planning-reuse";
import type { PublicInvariantProposal } from "@/lib/verification/public-invariants";
import type { PublicVerificationPlanAttempt } from "@/lib/verification/public-strategy-planning";
import type { PlanningCandidate, PublicVerificationTargetSummary } from "@/lib/verification/verification-target-discovery";
import { LocalInvariantTesting } from "./local-invariant-testing";
import { LocalVerification } from "./local-verification";
import { VerificationTargetSection } from "./verification-target-section";

const hypothesisId = "11111111-1111-4111-8111-111111111111", relatedId = "22222222-2222-4222-8222-222222222222";
const sourceId = "33333333-3333-4333-8333-333333333333", freshId = "44444444-4444-4444-8444-444444444444";
const scanId = "55555555-5555-4555-8555-555555555555", timestamp = "2026-10-08T09:00:00.000Z";
const fingerprint = { schema: "contracthunter-source-closure-fingerprint-v1", sha256: "a".repeat(64), fileCount: 1, totalBytes: 200 };
const candidate = (strategy: PlanningCandidate["strategy"], from = relatedId): PlanningCandidate => ({ artifactId: sourceId,
  artifactType: strategy === "structured-verification" ? "structured-plan" : "invariant-proposal", hypothesisId: from, strategy,
  propertyTargetIds: [], eligibility: "eligible", reasons: ["matching-persisted-validation"], validationState: "validated-at-execution",
  executionHistoryExists: true, sourceClosureFingerprintRecorded: true, createdAt: timestamp });
const target = (item: PlanningCandidate): PublicVerificationTargetSummary => ({ targetId: "f".repeat(64), rootCauseFamily: "arithmetic-order",
  familyLabel: "Arithmetic order", representativeHypothesisId: relatedId, currentHypothesisIsRepresentative: false, relatedHypotheses: [relatedId],
  relatedHypothesisCount: 1, representativeReason: "stable-id-tiebreak", reason: "Exact target", groupingConfidence: "exact",
  strategyReadiness: { compatible: [item.strategy === "legacy-unknown-strategy" ? "structured-verification" : item.strategy], incompatible: [], unknown: [] },
  candidates: [item], candidateCount: 1 });
const structuredPlan = verificationHarnessPlanSchema.parse({ scanId, hypothesisId, resolvedCommit: "a".repeat(40), compilerVersion: "0.8.24",
  primaryContract: "Counter", primarySourcePath: "contracts/Counter.sol", relevantFunctions: ["increment", "count"], sourceFiles: ["contracts/Counter.sol"],
  verificationGoal: "Check a bounded counter transition.", expectedProperty: "Count becomes one.", verificationSteps: ["Deploy and increment."],
  operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "increment" },
    { kind: "read-uint", instanceName: "target", functionName: "count", resultName: "observed" }],
  assertions: [{ id: "count", kind: "uint-eq", actual: "observed", expected: "1", expectedOutcome: "hypothesis-supported", description: "The observed count becomes one." }] });
const structured = (): PublicVerificationPlanAttempt => ({ id: freshId, selectedStrategy: "structured-verification", status: "generated", failureCode: null,
  result: { origin: "reused", status: "generated", plan: structuredPlan, rationale: null, limitations: [], notPlannableReasons: [], failureCode: null },
  origin: "reused", reuseSourceArtifactId: sourceId, reuseTargetId: "f".repeat(64), sourceClosureFingerprint: fingerprint, createdAt: timestamp });
const fuzzPlan = executableInvariantPlanSchema.parse({ schemaVersion: "contracthunter-invariant-plan-v1", mode: "fuzz-property", scanId, hypothesisId,
  resolvedCommit: "a".repeat(40), compilerVersion: "0.8.24", primaryContract: "Counter", primarySourcePath: "contracts/Counter.sol",
  sourceFiles: ["contracts/Counter.sol"], actors: [], setup: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }],
  fuzzAction: { instanceName: "target", functionName: "increment", parameters: [{ name: "value", type: "uint256" }], args: [{ kind: "parameter", name: "value" }] },
  property: { name: "countProperty", observations: [{ kind: "read-uint", instanceName: "target", functionName: "count", resultName: "observed" }],
    assertions: [{ id: "countCheck", kind: "uint-not-eq", actual: "observed", expected: "0" }] } });
const invariant = (strategy: "foundry-fuzz-property" | "foundry-stateful-invariant" | "echidna-stateful-invariant"): PublicInvariantProposal => {
  if (fuzzPlan.mode !== "fuzz-property") throw new Error("Fuzz fixture required.");
  const { fuzzAction, property, ...base } = fuzzPlan;
  const plan = strategy === "foundry-fuzz-property" ? fuzzPlan : executableInvariantPlanSchema.parse({ ...base, mode: "stateful-invariant",
    handlerActions: [{ name: "incrementCounter", instanceName: "target", functionName: "increment", parameters: fuzzAction.parameters, args: fuzzAction.args }],
    properties: [property] });
  return { id: freshId, selectedStrategy: strategy, status: "generated", plan, planHash: invariantPlanHash(plan),
    hypothesisExpectation: "hypothesis-predicts-property-violation", relationRationale: null, rationale: null, limitations: [], notPlannableReasons: [],
    failureCode: null, origin: "reused", reuseSourceArtifactId: sourceId, reuseTargetId: "f".repeat(64), provider: "", model: "", promptVersion: "",
    sourceFileCount: 0, totalSourceBytes: 0, contextTruncated: false, sourceClosureFingerprint: fingerprint, inputTokens: null, outputTokens: null,
    totalTokens: null, estimatedCostUsd: null, durationMs: 0, createdAt: timestamp };
};
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
afterEach(() => vi.restoreAllMocks());

describe("mocked explicit reuse to existing review workflow", () => {
  it("selects a new structured artifact, retains the original history entry, and leaves validation and execution separate", async () => {
    const item = candidate("structured-verification"), old = { ...structured(), id: sourceId, origin: "legacy" as const, reuseSourceArtifactId: null };
    expect(renderToStaticMarkup(<VerificationTargetSection target={target(item)} requestedHypothesisId={hypothesisId} onReuse={() => undefined} />)).toContain("From related hypothesis");
    const fetcher = vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => String(url).includes("/reuse/") ? json({ attempt: structured() }, 201) : json({ target: target(item) }));
    let newAttempt: PublicVerificationPlanAttempt | null = null;
    await performPlanningReuse(hypothesisId, item, { current: null }, { onStart: vi.fn(), onSuccess: (result) => { if ("result" in result.artifact) newAttempt = result.artifact; }, onFailure: vi.fn(), onRefresh: vi.fn(), onFinish: vi.fn() });
    expect(newAttempt).not.toBeNull();
    const html = renderToStaticMarkup(<LocalVerification hypothesisId={hypothesisId} hypothesisStatus="candidate" initialRuns={[]} initialAttempts={[newAttempt!, old]} selectedAttemptId={newAttempt!.id} />);
    expect(html).toContain(freshId); expect(html).toContain(sourceId); expect(html).toContain("Reused planning artifact");
    expect(html).toContain("Pending explicit validation"); expect(html).toContain("Validate plan");
    expect(html).toMatch(/<button[^>]*disabled[^>]*>Verify locally<\/button>/);
    expect(fetcher.mock.calls.map(([url]) => String(url))).toEqual([`/api/hypotheses/${hypothesisId}/verification-target/reuse/structured/${sourceId}`, `/api/hypotheses/${hypothesisId}/verification-target`]);
  });
  it.each(["foundry-fuzz-property", "foundry-stateful-invariant", "echidna-stateful-invariant"] as const)("selects a new %s proposal with pending validation and no inherited run", async (strategy) => {
    const item = candidate(strategy, hypothesisId), old = { ...invariant(strategy), id: sourceId, origin: "legacy" as const, reuseSourceArtifactId: null };
    const fetcher = vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => String(url).includes("/reuse/") ? json({ proposal: invariant(strategy) }, 201) : json({ target: target(item) }));
    let newProposal: PublicInvariantProposal | null = null;
    await performPlanningReuse(hypothesisId, item, { current: null }, { onStart: vi.fn(), onSuccess: (result) => { if ("planHash" in result.artifact) newProposal = result.artifact; }, onFailure: vi.fn(), onRefresh: vi.fn(), onFinish: vi.fn() });
    expect(newProposal).not.toBeNull();
    const html = renderToStaticMarkup(<LocalInvariantTesting hypothesisId={hypothesisId} hypothesisStatus="candidate" initialProposals={[old]} incomingProposal={newProposal} selectedProposalId={newProposal!.id} initialRuns={[]} />);
    expect(html).toContain(freshId); expect(html).toContain(sourceId); expect(html).toContain("Reused planning artifact");
    expect(html).toContain(strategy === "foundry-fuzz-property" ? "fuzz-property" : "stateful-invariant");
    expect(html).toContain("Pending explicit validation"); expect(html).toContain("Execution for this proposal:</strong> Not run");
    expect(html).toContain("Validate proposal"); expect(html).not.toContain("Run with Foundry"); expect(html).not.toContain("Run with Echidna");
    expect(fetcher.mock.calls.map(([url]) => String(url))).toEqual([`/api/hypotheses/${hypothesisId}/verification-target/reuse/invariant/${sourceId}`, `/api/hypotheses/${hypothesisId}/verification-target`]);
  });
  it("shows a stale-on-click rejection, removes its action after refresh, and makes no AI or execution request", async () => {
    const item = candidate("echidna-stateful-invariant"), stale = { ...item, eligibility: "stale" as const, reasons: ["stale-source" as const] };
    const refreshed = { ...target(item), candidates: [stale] };
    const fetcher = vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => String(url).includes("/reuse/") ? json({ code: "reuse_concrete_strategy_incompatible" }, 409) : json({ target: refreshed }));
    let current = target(item), failure = "", created = false;
    await performPlanningReuse(hypothesisId, item, { current: null }, { onStart: vi.fn(), onSuccess: () => { created = true; },
      onFailure: (message) => { failure = message; }, onRefresh: (value) => { if (value) current = value; }, onFinish: vi.fn() });
    const html = renderToStaticMarkup(<VerificationTargetSection target={current} requestedHypothesisId={hypothesisId} onReuse={() => undefined}
      reuseFeedback={{ artifactId: sourceId, message: failure, failed: true }} />);
    expect(created).toBe(false); expect(html).toContain('role="alert"'); expect(html).toContain("concrete compatibility check");
    expect(html).not.toContain(">Reuse plan</button>");
    expect(fetcher.mock.calls.map(([url]) => String(url))).toEqual([`/api/hypotheses/${hypothesisId}/verification-target/reuse/invariant/${sourceId}`, `/api/hypotheses/${hypothesisId}/verification-target`]);
  });
});
