import type { ScenarioReplayResult } from "./impact-scenario-replay";
import type { ScenarioRole } from "./impact-scenario";

export type ReplayMovementStep = Readonly<{ iterationIndex: number; assetId: string; role: ScenarioRole;
  incoming: string; outgoing: string; netObservedMovement: string; cumulativeNetObservedMovement: string }>;

/** Server-owned display sequence. F2A's final cumulative positions remain authoritative. */
export function replayMovementSteps(result: ScenarioReplayResult): ReplayMovementStep[] {
  if (result.mode !== "cumulative-replay") return [];
  const totals = new Map<string, bigint>();
  const rows: ReplayMovementStep[] = [];
  for (const item of result.iterations) {
    const { iteration, accounting } = item;
    if (!accounting || !(iteration.status === "completed" ||
      iteration.status === "reverted" && iteration.stopReason === null)) continue;
    for (const position of accounting.rolePositions) {
      if (position.transactionOrdinal !== null || position.assetId.startsWith("erc721:")) continue;
      const key = `${position.assetId}|${position.role}`;
      const cumulative = (totals.get(key) ?? 0n) + BigInt(position.netObservedMovement);
      totals.set(key, cumulative);
      rows.push({ iterationIndex: iteration.index, assetId: position.assetId, role: position.role,
        incoming: position.incoming, outgoing: position.outgoing,
        netObservedMovement: position.netObservedMovement, cumulativeNetObservedMovement: cumulative.toString() });
    }
  }
  for (const position of result.cumulativePositions) {
    const key = `${position.assetId}|${position.role}`;
    if (totals.get(key)?.toString() !== position.netObservedMovement) throw Error("replay_view_cumulative_mismatch");
  }
  if (totals.size !== result.cumulativePositions.length) throw Error("replay_view_cumulative_mismatch");
  return rows;
}

