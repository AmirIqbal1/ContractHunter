import { z } from "zod";
import { INVARIANT_COUNTEREXAMPLE_PARSER_VERSION, invariantPlanHash, executableInvariantCounterexampleSchema, type ExecutableInvariantPlan, type ExecutableInvariantCounterexample, type ExecutableInvariantEvidence } from "@contracthunter/core";

const boundedText = z.string().max(2048);
export const invariantCounterexampleSchema = executableInvariantCounterexampleSchema;
export const invariantTestFactSchema = z.object({ propertyName: z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/), testName: z.string().max(160), status: z.enum(["passed", "failed"]), runsExecuted: z.number().int().nonnegative().max(1_000), reason: boundedText.nullable(), counterexample: invariantCounterexampleSchema.nullable() }).strict();
export type InvariantTestFact = z.infer<typeof invariantTestFactSchema>;
export type InvariantCounterexample = ExecutableInvariantCounterexample;
export type ParsedInvariantForgeOutput = { testCount: number; passedCount: number; failedCount: number; runsExecuted: number; tests: InvariantTestFact[] };
const record = (value: unknown): Record<string, unknown> | null => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
const small = (value: unknown, maximum = 2048) => typeof value === "string" ? value.slice(0, maximum) : "";
function counterexample(raw: unknown, plan: ExecutableInvariantPlan): InvariantCounterexample | null {
  const value = record(raw);
  if (!value) return null;
  const parsedValue = (rawValue: unknown, parameter: { name: string; type: "uint256" | "bool" }) => {
    if (parameter.type === "bool") {
      const value = rawValue === true || rawValue === "true" ? true : rawValue === false || rawValue === "false" ? false : null;
      return value === null ? null : { name: parameter.name, type: parameter.type, value };
    }
    const text = typeof rawValue === "number" && Number.isSafeInteger(rawValue) ? String(rawValue) : typeof rawValue === "string" ? rawValue.trim() : "";
    return /^(?:0|[1-9]\d{0,77})$/.test(text) && BigInt(text) < (1n << 256n) ? { name: parameter.name, type: parameter.type, value: text } : null;
  };
  const values = (rawArgs: unknown, parameters: Array<{ name: string; type: "uint256" | "bool" }>) => {
    const items = Array.isArray(rawArgs) ? rawArgs : parameters.length === 0 && (rawArgs === "" || rawArgs === null || rawArgs === undefined) ? [] : parameters.length === 1 ? [rawArgs] : null;
    if (!items || items.length !== parameters.length) return null;
    const parsed = items.map((item, index) => parsedValue(item, parameters[index]));
    return parsed.every((item) => item !== null) ? parsed as Array<{ name: string; type: "uint256"; value: string } | { name: string; type: "bool"; value: boolean }> : null;
  };
  if (plan.mode === "fuzz-property" && "Single" in value) {
    const single = record(value.Single);
    const parameterValues = values(single?.raw_args ?? single?.args, plan.fuzzAction.parameters);
    if (!parameterValues) return null;
    return invariantCounterexampleSchema.parse({ kind: "single", parserVersion: INVARIANT_COUNTEREXAMPLE_PARSER_VERSION, parameterValues, summary: "Foundry reported a bounded final fuzz counterexample." });
  }
  if (plan.mode === "stateful-invariant" && "Sequence" in value) {
    const sequence = value.Sequence;
    const steps = Array.isArray(sequence) ? (Array.isArray(sequence[1]) ? sequence[1] : sequence) : [];
    if (!steps.length || steps.length > 32) return null;
    const expected = new Set(plan.handlerActions.map((action) => `action_${action.name}(${action.parameters.map((parameter) => parameter.type).join(",")})`));
    if (steps.some((item) => { const entry = record(item); return !entry || entry.contract_name !== "test/ContractHunterInvariant.t.sol:ContractHunterHandler" || !expected.has(String(entry.signature)); })) return null;
    const actions = steps.map((item) => {
      const entry = record(item);
      const signature = String(entry?.signature), action = plan.handlerActions.find((candidate) => signature === `action_${candidate.name}(${candidate.parameters.map((parameter) => parameter.type).join(",")})`);
      const parameterValues = action ? values(entry?.args, action.parameters) : null;
      return action && parameterValues ? { actionName: action.name, parameterValues } : null;
    });
    if (actions.some((action) => action === null)) return null;
    return invariantCounterexampleSchema.parse({ kind: "sequence", parserVersion: INVARIANT_COUNTEREXAMPLE_PARSER_VERSION, actions, summary: "Foundry reported a bounded final handler sequence." });
  }
  return null;
}
export function parseInvariantForgeJson(output: string, plan: ExecutableInvariantPlan): ParsedInvariantForgeOutput | null {
  if (Buffer.byteLength(output) > 2_097_152) return null;
  let raw: unknown;
  try { raw = JSON.parse(output); } catch { return null; }
  const suites = record(raw);
  if (!suites) return null;
  const contract = plan.mode === "fuzz-property" ? "ContractHunterFuzzTest" : "ContractHunterInvariantTest";
  const suitesFound = Object.entries(suites).filter(([name]) => name.endsWith(`:${contract}`));
  if (suitesFound.length !== 1) return null;
  const suite = record(suitesFound[0][1]);
  const results = record(suite?.test_results);
  if (!results) return null;
  const properties = plan.mode === "fuzz-property" ? [plan.property] : plan.properties;
  if (Object.keys(results).length !== properties.length) return null;
  const tests: InvariantTestFact[] = [];
  for (const property of properties) {
    const expectedName = `${plan.mode === "fuzz-property" ? "testFuzz" : "invariant"}_${property.name}`;
    const entries = Object.entries(results).filter(([name]) => name.split("(")[0] === expectedName);
    if (entries.length !== 1) return null;
    const [testName, rawResult] = entries[0], result = record(rawResult);
    if (!result || (result.status !== "Success" && result.status !== "Failure")) return null;
    const kind = record(result.kind);
    const detail = record(kind?.[plan.mode === "fuzz-property" ? "Fuzz" : "Invariant"]);
    const runsExecuted = detail?.runs;
    if (typeof runsExecuted !== "number" || !Number.isInteger(runsExecuted) || runsExecuted < 0 || runsExecuted > 1_000) return null;
    const fact = invariantTestFactSchema.safeParse({ propertyName: property.name, testName: small(testName, 160), status: result.status === "Success" ? "passed" : "failed", runsExecuted, reason: result.reason === null || result.reason === undefined ? null : small(result.reason), counterexample: counterexample(result.counterexample, plan) });
    if (!fact.success || (fact.data.status === "failed" && !fact.data.counterexample)) return null;
    tests.push(fact.data);
  }
  return { testCount: tests.length, passedCount: tests.filter((test) => test.status === "passed").length, failedCount: tests.filter((test) => test.status === "failed").length, runsExecuted: tests.reduce((sum, test) => sum + test.runsExecuted, 0), tests };
}
export type InvariantEvidence = ExecutableInvariantEvidence;
export function interpretInvariantFacts(plan: ExecutableInvariantPlan, facts: ParsedInvariantForgeOutput, isolationProvider: string): InvariantEvidence[] {
  const configuredRuns = plan.mode === "fuzz-property" ? 128 : 64;
  const names = plan.mode === "fuzz-property" ? [plan.property.name] : plan.properties.map((property) => property.name);
  if (facts.testCount !== names.length || facts.tests.length !== names.length || facts.passedCount + facts.failedCount !== names.length || facts.tests.some((test) => !names.includes(test.propertyName) || test.runsExecuted > configuredRuns || (test.status === "failed" && !test.counterexample)) || new Set(facts.tests.map((test) => test.propertyName)).size !== names.length) throw new Error("invariant_result_unparseable");
  return facts.tests.map((test) => ({ planHash: invariantPlanHash(plan), mode: plan.mode, propertyName: test.propertyName, configuredRuns, configuredDepth: plan.mode === "stateful-invariant" ? 32 : null,
    runsExecuted: test.runsExecuted, propertyOutcome: test.status === "passed" ? "held-within-bounds" : "counterexample-found", hypothesisRelation: test.status === "passed" ? "neutral" : "unreviewed",
    compilerVersion: plan.compilerVersion, isolationProvider, counterexample: test.counterexample,
    summary: test.status === "passed" ? "No counterexample found within configured runs." : "Foundry found a bounded counterexample to the property." }));
}
