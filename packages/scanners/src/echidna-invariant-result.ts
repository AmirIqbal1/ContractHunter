import { z } from "zod";
import { ECHIDNA_COMPAT_VERSION, ECHIDNA_COUNTEREXAMPLE_PARSER_VERSION, ECHIDNA_LIMITS, ECHIDNA_RESULT_SCHEMA, echidnaSeed, executableInvariantCounterexampleSchema, invariantPlanHash, type ExecutableInvariantCounterexample, type ExecutableInvariantEvidence, type ExecutableInvariantPlan } from "@contracthunter/core";

const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const hex = z.string().regex(/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/);
const tx = z.object({
  function: z.string().min(1).max(100), arguments: z.array(z.string().max(128)).max(8).nullable(), sender: address, destination: address,
  timeDelay: hex, blockDelay: hex, value: hex,
}).strict();
const stopReason = z.enum(["test-limit-reached", "symbolic-exploration-done", "symbolic-verification-done", "time-limit-reached", "fast-failed", "killed", "crashed", "missing-stop-reason"]);
const result = z.object({
  schema: z.literal(ECHIDNA_RESULT_SCHEMA), echidnaVersion: z.literal(ECHIDNA_COMPAT_VERSION), seed: z.number().int().nonnegative().max(281_474_976_710_655),
  configuredTestLimit: z.literal(ECHIDNA_LIMITS.testLimit), executedCalls: z.number().int().nonnegative().max(100_000), workerStopReasons: z.array(stopReason).length(1),
  tests: z.array(z.object({ name: z.string().regex(/^echidna_ch_[A-Za-z][A-Za-z0-9_]{0,63}$/), type: z.literal("property"), outcome: z.enum(["held-within-bounds", "counterexample-found", "execution-failed", "inconclusive"]), transactions: z.array(tx).min(1).max(ECHIDNA_LIMITS.seqLen).nullable() }).strict()).min(1).max(16),
  error: z.null(),
}).strict();
export type EchidnaPropertyFact = { propertyName: string; outcome: "held-within-bounds" | "counterexample-found" | "execution-failed" | "inconclusive"; counterexample: ExecutableInvariantCounterexample | null; replayAvailable: boolean };
export type ParsedEchidnaResult = { seed: number; executedCalls: number; campaignStopReason: string; tests: EchidnaPropertyFact[] };
const allowedSenders = new Set(["0000000000000000000000000000000000010000", "0000000000000000000000000000000000020000", "0000000000000000000000000000000000030000"]);
const harnessAddress = "00a329c0648769a73afac7f9381e08fb43dbea72";
function mapTransactions(transactions: z.infer<typeof tx>[], plan: Extract<ExecutableInvariantPlan, { mode: "stateful-invariant" }>): ExecutableInvariantCounterexample | null {
  const actions: Array<{ actionName: string; parameterValues: Array<{ name: string; type: "uint256"; value: string } | { name: string; type: "bool"; value: boolean }> }> = [];
  for (const transaction of transactions) {
    if (transaction.destination.slice(2).toLowerCase() !== harnessAddress || !allowedSenders.has(transaction.sender.slice(2).toLowerCase()) || transaction.value !== "0x0" || transaction.timeDelay !== "0x0" || transaction.blockDelay !== "0x0" || transaction.arguments === null) return null;
    const action = plan.handlerActions.find((candidate) => transaction.function === `action_${candidate.name}`);
    if (!action || transaction.arguments.length !== action.parameters.length) return null;
    const values = action.parameters.map((parameter, index) => {
      const raw = transaction.arguments![index];
      if (parameter.type === "bool") return raw === "true" || raw === "false" ? { name: parameter.name, type: "bool" as const, value: raw === "true" } : null;
      return /^(?:0|[1-9]\d{0,77})$/.test(raw) && BigInt(raw) < (1n << 256n) ? { name: parameter.name, type: "uint256" as const, value: raw } : null;
    });
    if (values.some((value) => value === null)) return null;
    actions.push({ actionName: action.name, parameterValues: values as typeof actions[number]["parameterValues"] });
  }
  const parsed = executableInvariantCounterexampleSchema.safeParse({ kind: "sequence", parserVersion: ECHIDNA_COUNTEREXAMPLE_PARSER_VERSION, actions, summary: "Echidna emitted a terminal bounded action sequence." });
  return parsed.success ? parsed.data : null;
}
export function parseTrustedEchidnaResult(stdout: string, plan: ExecutableInvariantPlan, exitCode: number | null, outputTruncated: boolean): ParsedEchidnaResult | null {
  if (outputTruncated || Buffer.byteLength(stdout) > ECHIDNA_LIMITS.maxOutputBytes || plan.mode !== "stateful-invariant") return null;
  let raw: unknown;
  try { raw = JSON.parse(stdout); } catch { return null; }
  const parsed = result.safeParse(raw);
  if (!parsed.success) return null;
  const campaign = parsed.data, expectedNames = plan.properties.map((property) => `echidna_ch_${property.name}`);
  if (campaign.seed !== echidnaSeed(invariantPlanHash(plan)) || campaign.tests.length !== expectedNames.length || new Set(campaign.tests.map((test) => test.name)).size !== expectedNames.length || campaign.tests.some((test) => !expectedNames.includes(test.name))) return null;
  const reason = campaign.workerStopReasons[0];
  if (campaign.tests.some((test) => test.outcome === "held-within-bounds" && (reason !== "test-limit-reached" || test.transactions !== null)) || campaign.tests.some((test) => test.outcome === "counterexample-found" && (!["test-limit-reached", "fast-failed"].includes(reason) || !test.transactions?.length)) || campaign.tests.some((test) => ["inconclusive", "execution-failed"].includes(test.outcome) && test.transactions !== null)) return null;
  const expectedExit = campaign.tests.some((test) => test.outcome === "inconclusive" || test.outcome === "execution-failed") ? 2 : campaign.tests.some((test) => test.outcome === "counterexample-found") ? 1 : 0;
  if (exitCode !== expectedExit) return null;
  return { seed: campaign.seed, executedCalls: campaign.executedCalls, campaignStopReason: reason,
    tests: campaign.tests.map((test) => {
      const counterexample = test.outcome === "counterexample-found" && test.transactions ? mapTransactions(test.transactions, plan) : null;
      return { propertyName: test.name.slice("echidna_ch_".length), outcome: test.outcome, counterexample, replayAvailable: counterexample !== null };
    }) };
}
export function interpretEchidnaFacts(plan: ExecutableInvariantPlan, parsed: ParsedEchidnaResult, isolationProvider: string): ExecutableInvariantEvidence[] {
  if (plan.mode !== "stateful-invariant" || parsed.tests.length !== plan.properties.length) throw new Error("echidna_result_unparseable");
  const completedRuns = parsed.campaignStopReason === "test-limit-reached" ? ECHIDNA_LIMITS.testLimit : 0;
  return parsed.tests.map((test) => ({ engine: "echidna", planHash: invariantPlanHash(plan), mode: plan.mode, propertyName: test.propertyName,
    configuredRuns: ECHIDNA_LIMITS.testLimit, configuredDepth: ECHIDNA_LIMITS.seqLen, runsExecuted: completedRuns, campaignCalls: parsed.executedCalls,
    propertyOutcome: test.outcome, hypothesisRelation: test.outcome === "counterexample-found" ? "unreviewed" : "neutral", compilerVersion: plan.compilerVersion, isolationProvider,
    counterexample: test.counterexample, replayAvailable: test.replayAvailable,
    summary: test.outcome === "held-within-bounds" ? "No counterexample found within Echidna's configured budget." : test.outcome === "counterexample-found" ? "Echidna found a bounded counterexample." : "Echidna campaign did not produce a decisive property result." }));
}
