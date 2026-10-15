import { describe, expect, it } from "vitest";
import { replayMovementSteps } from "./impact-scenario-replay-view";
import type { ScenarioReplayResult } from "./impact-scenario-replay";

const A = `erc20:1:0x${"a".repeat(40)}`, B = `erc1155:1:0x${"b".repeat(40)}:7`;
const NFT = `erc721:1:0x${"c".repeat(40)}:42`;
function fixture(): ScenarioReplayResult {
  const positions = (index: number) => [
    { transactionOrdinal: null, assetId: A, role: "protocol", incoming: "0", outgoing: "100",
      netObservedMovement: "-100" },
    { transactionOrdinal: null, assetId: A, role: "scenario-subject", incoming: "100", outgoing: "0",
      netObservedMovement: "100" },
    { transactionOrdinal: null, assetId: B, role: "scenario-subject", incoming: "3", outgoing: "0",
      netObservedMovement: "3" },
    { transactionOrdinal: null, assetId: NFT, role: "scenario-subject", incoming: "1", outgoing: "0",
      netObservedMovement: "1" },
  ].map((row) => ({ ...row, ledgerEntryIds: [`ledger-${index}`] }));
  return { mode: "cumulative-replay", iterations: [1, 2, 3].map((index) => ({
    iteration: { index, status: "completed", stopReason: null },
    accounting: { rolePositions: positions(index) },
  })), cumulativePositions: [
    { assetId: A, role: "protocol", netObservedMovement: "-300" },
    { assetId: A, role: "scenario-subject", netObservedMovement: "300" },
    { assetId: B, role: "scenario-subject", netObservedMovement: "9" },
  ] } as unknown as ScenarioReplayResult;
}
describe("F2B server-owned cumulative presentation", () => {
  it("shows only completed per-asset prefixes and never sums NFT identities", () => {
    const rows = replayMovementSteps(fixture());
    expect(rows.filter((row) => row.assetId === A && row.role === "protocol")
      .map((row) => row.cumulativeNetObservedMovement)).toEqual(["-100", "-200", "-300"]);
    expect(rows.filter((row) => row.assetId === B).map((row) => row.cumulativeNetObservedMovement))
      .toEqual(["3", "6", "9"]);
    expect(rows.some((row) => row.assetId === NFT)).toBe(false);
  });
  it("does not sum independent runs or stopped iteration movement", () => {
    expect(replayMovementSteps({ ...fixture(), mode: "independent-replay" })).toEqual([]);
    const stopped = fixture();
    stopped.iterations[2] = { ...stopped.iterations[2]!, iteration: {
      ...stopped.iterations[2]!.iteration, status: "reverted", stopReason: "replay_transaction_outcome_changed" } };
    const consistent = { ...stopped, cumulativePositions: stopped.cumulativePositions.map((row) => ({
      ...row, netObservedMovement: row.assetId === B ? "6" : row.role === "protocol" ? "-200" : "200" })) };
    expect(replayMovementSteps(consistent).some((row) => row.iterationIndex === 3)).toBe(false);
  });
  it("refuses a presentation prefix that disagrees with F2A's authoritative total", () => {
    expect(() => replayMovementSteps({ ...fixture(), cumulativePositions: [{
      assetId: A, role: "protocol", netObservedMovement: "-999" } as ScenarioReplayResult["cumulativePositions"][number]] }))
      .toThrow("replay_view_cumulative_mismatch");
  });
});
