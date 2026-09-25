import type { InvariantReplayPlan } from "@contracthunter/core";

const record = (value: unknown): Record<string, unknown> | null => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
export function parseInvariantReplayForgeJson(output: string, replay: InvariantReplayPlan): "reproduced" | "not-reproduced" | null {
  if (Buffer.byteLength(output) > 1_048_576) return null; let raw: unknown;
  try { raw = JSON.parse(output); } catch { return null; }
  const suites = record(raw); if (!suites) return null;
  const found = Object.entries(suites).filter(([name]) => name.endsWith(":ContractHunterReplayTest")); if (found.length !== 1) return null;
  const results = record(record(found[0][1])?.test_results); if (!results || Object.keys(results).length !== 1) return null;
  const entries = Object.entries(results).filter(([name]) => name.split("(")[0] === `testReplay_${replay.propertyName}`); if (entries.length !== 1) return null;
  const result = record(entries[0][1]); if (!result) return null;
  if (result.counterexample !== null && result.counterexample !== undefined) return null;
  if (result.status === "Success") return result.reason === null || result.reason === undefined ? "reproduced" : null;
  return result.status === "Failure" && result.reason === "CH_REPLAY_NOT_REPRODUCED" ? "not-reproduced" : null;
}
export function parseTrustedInvariantReplayForgeResult(output: string, replay: InvariantReplayPlan, exitCode: number, outputTruncated: boolean): "reproduced" | "not-reproduced" | null {
  if (outputTruncated) return null;
  const outcome = parseInvariantReplayForgeJson(output, replay);
  return outcome === "reproduced" && exitCode === 0 ? outcome : outcome === "not-reproduced" && exitCode !== 0 ? outcome : null;
}
