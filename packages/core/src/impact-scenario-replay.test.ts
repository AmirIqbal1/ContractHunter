import { describe, expect, it } from "vitest";
import { deriveScenarioImpact, scenarioContentHash, scenarioParticipantId,
  type ImpactScenario } from "./impact-scenario";
import { deriveReplayIterationAccounting, deriveScenarioReplayResult, replayPlanContentHash,
  replayPlanInputSchema, type ScenarioReplayIteration, type ScenarioReplayPlan,
  type ScenarioReplayRun } from "./impact-scenario-replay";
import type { AssetFlow } from "./asset-flow";

const P = `0x${"1".repeat(40)}`, S = `0x${"2".repeat(40)}`, U = `0x${"3".repeat(40)}`;
const A = `erc20:1:0x${"a".repeat(40)}`, B = `erc1155:1:0x${"b".repeat(40)}:7`;
const NFT = `erc721:1:0x${"c".repeat(40)}:42`;
function flow(executionId: string, hash: string, movements: Array<[string, string, string, string]>): AssetFlow {
  const participants = [P, S, U].map((address) => ({ address, label: "Unmapped address", contractNodeId: null }));
  return { schema: "contracthunter-asset-flow-v1", rulesetVersion: "contracthunter-asset-accounting-v1",
    scanId: "11111111-1111-4111-8111-111111111111", executionId, contentSha256: hash,
    status: "complete-within-evidence", capabilities: { assetAccountingAvailable: true },
    participants, ledgerEntries: movements.map(([assetId, from, to, amount], index) => ({
      id: `ledger-${index}`, assetId, from, to, amount, transactionOrdinal: 0 })),
    attemptedFlows: [], transactions: [{ ordinal: 0, hash: `0x${"f".repeat(64)}`,
      executionCost: { status: "unavailable", gasUsed: "21000", effectiveGasPrice: null, amountWei: null } }],
    reconciliation: [], warnings: [] } as unknown as AssetFlow;
}
const originalId = "22222222-2222-4222-8222-222222222222";
const original = flow(originalId, `sha256:${"a".repeat(64)}`, [[A, P, S, "100"]]);
function scenario(f: AssetFlow): ImpactScenario {
  const content = { scenarioId: "33333333-3333-4333-8333-333333333333", revision: 1, revisionOf: null,
    scanId: f.scanId, executionId: f.executionId,
    subject: { type: "finding" as const, id: "44444444-4444-4444-8444-444444444444" },
    assetFlowContentSha256: f.contentSha256, assetAccountingRulesetVersion: f.rulesetVersion,
    assignments: [{ participantId: scenarioParticipantId(f, P), role: "protocol" as const },
      { participantId: scenarioParticipantId(f, S), role: "scenario-subject" as const }], note: "" };
  return { schema: "contracthunter-impact-scenario-v1", id: "55555555-5555-4555-8555-555555555555",
    ...content, status: "reviewed", createdAt: 1, reviewedAt: 2, rejectedAt: null,
    contentSha256: scenarioContentHash(content) };
}
const review = scenario(original), reference = deriveScenarioImpact(original, review);
function plan(mode: ScenarioReplayPlan["mode"], count = 3): ScenarioReplayPlan {
  const content = { planId: "66666666-6666-4666-8666-666666666666", revision: 1, revisionOf: null,
    scanId: original.scanId, scenarioId: review.scenarioId, scenarioRevisionId: review.id,
    executionId: original.executionId, sessionId: "77777777-7777-4777-8777-777777777777",
    artifactId: "88888888-8888-4888-8888-888888888888", sourceSha256: `sha256:${"b".repeat(64)}`,
    assetFlowContentSha256: original.contentSha256, scenarioContentSha256: review.contentSha256,
    observationPlanSha256: `sha256:${"c".repeat(64)}`, forgeVersion: "forge Version: 1.7.1",
    forgeSha256: "d".repeat(64), chainId: 1, forkBlock: 1, forkBlockHash: `0x${"e".repeat(64)}`,
    targetCodeHashes: {}, runtimeTokenSha256: "f".repeat(64), mode, iterationCount: count };
  return { schema: "contracthunter-scenario-replay-plan-v1", id: "99999999-9999-4999-8999-999999999999",
    ...content, status: "reviewed", createdAt: 1, reviewedAt: 2, rejectedAt: null,
    contentSha256: replayPlanContentHash(content) };
}
function run(status: ScenarioReplayRun["status"] = "completed"): ScenarioReplayRun {
  return { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", planRevisionId: plan("independent-replay").id,
    status, createdAt: 1, startedAt: 2, completedAt: 3, stopReason: null, cancelRequested: false };
}
function item(index: number, amount: string, assetId = A) {
  const f = flow(`00000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
    `sha256:${String(index).repeat(64)}`, [[assetId, P, S, amount]]);
  const accounting = deriveReplayIterationAccounting(original, review, f);
  const iteration: ScenarioReplayIteration = { id: `bbbbbbbb-bbbb-4bbb-8bbb-${String(index).padStart(12, "0")}`,
    runId: run().id, index, status: "completed", executionId: f.executionId,
    startedAt: index, completedAt: index + 1, stopReason: null,
    preSnapshotId: "pre", postSnapshotId: "post", assetFlowContentSha256: f.contentSha256 };
  return { iteration, accounting, assetFlowStatus: f.status };
}
describe("bounded scenario replay accounting", () => {
  it("accepts only two modes and 2–5 integer repetitions", () => {
    for (const count of [1, 6, 2.5]) expect(replayPlanInputSchema.safeParse({ mode: "independent-replay", iterationCount: count }).success).toBe(false);
    expect(replayPlanInputSchema.safeParse({ mode: "cumulative-replay", iterationCount: 5 }).success).toBe(true);
    expect(replayPlanInputSchema.safeParse({ mode: "sweep", iterationCount: 2 }).success).toBe(false);
  });
  it("binds reviewed addresses and refuses stale or draft source roles", () => {
    expect(item(1, "100").accounting.rolePositions.find((row) => row.role === "scenario-subject" &&
      row.transactionOrdinal === null)?.netObservedMovement).toBe("100");
    expect(() => deriveReplayIterationAccounting(original, { ...review, status: "draft" }, original)).toThrow();
    expect(() => deriveReplayIterationAccounting({ ...original, contentSha256: "changed" }, review, original)).toThrow();
  });
  it("reports independent exact reproduction without cumulative movement", () => {
    const p = plan("independent-replay"), values = [item(1, "100"), item(2, "100"), item(3, "100")];
    const result = deriveScenarioReplayResult(p, run(), reference, values);
    expect(result.completedIterations).toBe(3); expect(result.matchingIterations).toBe(3);
    expect(result.repeatability).toBe("reproduced-consistently");
    expect(result.cumulativePositions).toEqual([]);
    expect(deriveScenarioReplayResult(p, run(), reference, values).contentSha256).toBe(result.contentSha256);
  });
  it("shows independent variation without hiding exact iteration amounts", () => {
    const result = deriveScenarioReplayResult(plan("independent-replay"), run(), reference,
      [item(1, "100"), item(2, "90"), item(3, "110")]);
    expect(result.repeatability).toBe("reproduced-with-variation");
    expect(result.iterations.map((entry) => entry.matchedReference)).toEqual([true, false, false]);
    expect(result.iterations[1]?.accounting?.rolePositions.find((row) => row.role === "protocol")?.outgoing).toBe("90");
  });
  it("sums only completed cumulative per-asset facts, not NFT identity or gas", () => {
    const result = deriveScenarioReplayResult(plan("cumulative-replay", 3), run(), reference,
      [item(1, "100"), item(2, "100"), item(3, "100")]);
    expect(result.cumulativePositions.find((row) => row.role === "protocol" && row.assetId === A)?.netObservedMovement).toBe("-300");
    expect(result.cumulativeDirect.find((row) => row.assetId === A && row.direction === "protocol-to-subject")?.amount).toBe("300");
    const nft = deriveScenarioReplayResult(plan("cumulative-replay", 3), run(), reference,
      [item(1, "1", NFT), item(2, "1", NFT), item(3, "1", NFT)]);
    expect(nft.cumulativePositions).toEqual([]); expect(nft.iterations[0]?.accounting?.rolePositions[0]?.assetId).toBe(NFT);
    expect(item(1, "3", B).accounting.rolePositions.some((row) => row.assetId === B && row.incoming === "3")).toBe(true);
  });
  it("retains stop reason and partial evidence without extrapolation", () => {
    const stopped = { ...run("failed"), stopReason: "replay_transaction_outcome_changed" };
    const result = deriveScenarioReplayResult(plan("cumulative-replay", 5), stopped, reference,
      [item(1, "100"), item(2, "100"), item(3, "100"),
        { ...item(4, "0"), iteration: { ...item(4, "0").iteration, status: "reverted" as const,
          stopReason: "replay_transaction_outcome_changed" } }]);
    expect(result.completedIterations).toBe(3); expect(result.stopReason).toBe("replay_transaction_outcome_changed");
    expect(result.cumulativePositions.find((row) => row.role === "protocol")?.outgoing).toBe("300");
    const unavailable = { ...item(1, "100"), accounting: null };
    expect(deriveScenarioReplayResult(plan("independent-replay"), run("failed"), reference, [unavailable]).repeatability).toBe("partial");
  });
});
