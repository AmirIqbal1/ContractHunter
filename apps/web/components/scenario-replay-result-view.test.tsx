import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { type ReplayMovementStep, type ScenarioReplayPlan, type ScenarioReplayResult,
  type ScenarioReplayRun } from "@contracthunter/core";
import { ScenarioReplayResultView, type ReplayIterationEvidence } from "./scenario-replay-result-view";

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: vi.fn() }) }));
const SCAN = "11111111-1111-4111-8111-111111111111", EXEC = "22222222-2222-4222-8222-222222222222";
const SCENARIO = "33333333-3333-4333-8333-333333333333", PLAN = "44444444-4444-4444-8444-444444444444";
const RUN = "55555555-5555-4555-8555-555555555555", TOKEN = `erc20:1:0x${"a".repeat(40)}`;
const NFT = `erc721:1:0x${"b".repeat(40)}:42`;
function fixture(mode: "independent-replay" | "cumulative-replay" = "independent-replay") {
  const plan = { id: PLAN, planId: PLAN, scenarioRevisionId: "revision", mode,
    sourceSha256: "sha256:source", forkBlock: 123, forkBlockHash: "0xfork", chainId: 1,
    forgeVersion: "Forge fixture", forgeSha256: "forgehash", iterationCount: 3,
    assetFlowContentSha256: "e1hash", scenarioContentSha256: "f1hash", contentSha256: "planhash" } as ScenarioReplayPlan;
  const run = { id: RUN, status: "completed", stopReason: null } as ScenarioReplayRun;
  const impact = (index: number) => ({ status: "complete-within-evidence", roles: [],
    rolePositions: [
      { transactionOrdinal: null, role: "scenario-subject", assetId: TOKEN, netObservedMovement: "100", incoming: "100", outgoing: "0" },
      { transactionOrdinal: null, role: "protocol", assetId: TOKEN, netObservedMovement: "-100", incoming: "0", outgoing: "100" },
      { transactionOrdinal: null, role: "scenario-subject", assetId: NFT, netObservedMovement: "1", incoming: "1", outgoing: "0" },
    ], directRoleTransfers: [{ transactionOrdinal: null, direction: "protocol-to-subject", assetId: TOKEN, amount: "100" }],
    reconciliation: [{ observationId: `obs-${index}`, assetId: TOKEN, participant: "0xsubject", kind: "balance",
      before: String((index - 1) * 100), after: String(index * 100), status: "reconciled" }],
    executionCosts: [{ gasUsed: "21000", effectiveGasPrice: null, amountWei: null }],
    warnings: [] });
  const result = { schema: "contracthunter-scenario-replay-result-v1",
    rulesetVersion: "contracthunter-scenario-replay-ruleset-v1", planRevisionId: PLAN, runId: RUN,
    mode, requestedIterations: 3,
    completedIterations: 3, matchingIterations: 3, repeatability: "reproduced-consistently",
    stopReason: null, contentSha256: "resulthash", warnings: [],
    iterations: [1, 2, 3].map((index) => ({ iteration: { id: `iteration-${index}`, index, status: "completed",
      stopReason: null, executionId: `execution-${index}`, assetFlowContentSha256: `flow-${index}` },
      accounting: impact(index), matchedReference: true, variation: [], assetFlowStatus: "complete-within-evidence" })),
    cumulativePositions: mode === "cumulative-replay" ? [{ assetId: TOKEN, role: "scenario-subject",
      incoming: "300", outgoing: "0", netObservedMovement: "300", iterationIndexes: [1, 2, 3] }] : [],
    cumulativeDirect: mode === "cumulative-replay" ? [{ assetId: TOKEN, direction: "protocol-to-subject",
      amount: "300", iterationIndexes: [1, 2, 3] }] : [] } as unknown as ScenarioReplayResult;
  const evidence: ReplayIterationEvidence[] = [1, 2, 3].map((index) => ({ index,
    executionId: `execution-${index}`, executionStatus: "completed", errorCode: null,
    transactionHashes: [`0x${String(index).repeat(64)}`], traceCaptureStatus: "finalized", traceIds: [`trace-${index}`],
    stateCaptureAvailable: true, stateChangeCount: 1, mappedContracts: [], mappedFunctions: [] }));
  const steps: ReplayMovementStep[] = mode === "cumulative-replay" ? [1, 2, 3].map((index) => ({
    iterationIndex: index, assetId: TOKEN, role: "scenario-subject", incoming: "100", outgoing: "0",
    netObservedMovement: "100", cumulativeNetObservedMovement: String(index * 100) })) : [];
  return { plan, run, result, evidence, steps };
}
function render(values = fixture(), result: ScenarioReplayResult | null = values.result,
  forkStatus = "ready") {
  return renderToStaticMarkup(<ScenarioReplayResultView scanId={SCAN} executionId={EXEC} scenarioId={SCENARIO}
    plan={values.plan} run={values.run} result={result} evidence={values.evidence}
    movementSteps={values.steps} subject={{ type: "finding", id: SCENARIO }} forkStatus={forkStatus} />);
}
describe("F2B bounded replay result presentation", () => {
  it("shows independent consistency without cumulative sums or projections", () => {
    const html = render();
    expect(html).toContain("BOUNDED LOCAL REPLAY");
    expect(html).toContain("REPRODUCED CONSISTENTLY");
    expect(html).toContain("3 matched the original reviewed reproduction");
    expect(html).toContain("Independent comparison");
    expect(html).not.toContain("F2A final cumulative positions");
    expect(html).not.toMatch(/remaining repetitions|maximum drain|future projection|USD|GBP/i);
  });
  it("shows exact cumulative progress, separate NFT identity and gas, and equivalent resource table", () => {
    const values = fixture("cumulative-replay"), html = render(values);
    expect(html).toContain("Observed cumulative movement after 3 local repetitions");
    expect(html).toContain("+300");
    expect(html).toContain("token ID 42");
    expect(html).toContain("Observed resource evolution");
    expect(html).toContain("Observed starting value: 0");
    expect(html).toContain("Local execution cost");
    expect(html).toContain("UNAVAILABLE");
    expect(html).toContain("View State Observation");
    expect(html).toContain("View Asset Flow");
    expect(html).toContain("View Observed Execution");
    expect(html).toContain("Static Investigation Path");
  });
  it("keeps stopped, partial and missing evidence explicit", () => {
    const values = fixture("cumulative-replay");
    values.run = { ...values.run, status: "failed", stopReason: "replay_transaction_outcome_changed" };
    values.result = { ...values.result, completedIterations: 2, repeatability: "stopped-after-state-change",
      stopReason: "replay_transaction_outcome_changed", iterations: values.result.iterations.map((item, index) =>
        index === 2 ? { ...item, iteration: { ...item.iteration, status: "reverted",
          stopReason: "replay_transaction_outcome_changed" }, accounting: null, matchedReference: null } : item) };
    const html = render(values);
    expect(html).toContain("2 of 3 completed");
    expect(html).toContain("REPLAY TRANSACTION OUTCOME CHANGED");
    expect(html).toContain("REVERTED");
    expect(html).toContain("UNAVAILABLE");
    expect(html).not.toContain("maximum repetitions = 2");
  });
  it("renders hostile evidence as text and provides bounded historical unavailability", () => {
    const values = fixture();
    values.result = { ...values.result, warnings: ["<script>alert(1)</script>"] };
    const html = render(values);
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(render(values, null)).toContain("Replay accounting unavailable");
  });
  it("keeps infrastructure failure distinct from EVM revert and final-reset failure explicit", () => {
    const values = fixture("cumulative-replay");
    values.run = { ...values.run, status: "failed", stopReason: "replay_final_reset_failed" };
    values.result = { ...values.result, iterations: values.result.iterations.map((item, index) =>
      index === 1 ? { ...item, iteration: { ...item.iteration, status: "reverted" } } :
        index === 2 ? { ...item, iteration: { ...item.iteration, status: "failed", stopReason: "replay_worker_failure" } } : item) };
    values.evidence[2] = { ...values.evidence[2]!, executionStatus: "failed", errorCode: "worker_failed" };
    const html = render(values, values.result, "stopped");
    expect(html).toContain("REVERTED");
    expect(html).toContain("FAILED · EXECUTION FAILED");
    expect(html).toContain("FAILED — fork stopped");
    expect(html).toContain("WORKER FAILED");
  });
  it("uses only canonical mapped IDs for Explorer and Map links", () => {
    const values = fixture();
    values.evidence[0] = { ...values.evidence[0]!, mappedContracts: [
      { address: `0x${"a".repeat(40)}`, contractNodeId: "contract-canonical" }],
    mappedFunctions: [{ contractNodeId: "contract-canonical", functionNodeId: "function-canonical" }] };
    const html = render(values);
    expect(html).toContain("/contracts/contract-canonical");
    expect(html).toContain("/functions/function-canonical");
    expect(html).toContain("/protocol-map?execution=execution-1");
    expect(html).not.toContain("/contracts/Unknown");
  });
  it("shows cancellation and the fixed bound without an automatic continuation", () => {
    const values = fixture();
    values.run = { ...values.run, status: "cancelled", stopReason: "cancel_requested" };
    const html = render(values);
    expect(html).toContain("CANCELLED AFTER ITERATION 3");
    expect(html).toContain("Only 3 requested local repetitions");
    expect(html).not.toContain("Continue until failure");
  });
});
