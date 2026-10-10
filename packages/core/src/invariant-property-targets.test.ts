import { describe, expect, it } from "vitest";
import { executableInvariantPlanSchema } from "./executable-invariant";
import { buildInvariantPropertyTargets } from "./invariant-property-targets";

function plan(hypothesisId: string, propertyName = "accounting", assertionId = "equal") {
  return executableInvariantPlanSchema.parse({
    schemaVersion: "contracthunter-invariant-plan-v1", mode: "fuzz-property", scanId: "11111111-1111-4111-8111-111111111111", hypothesisId,
    resolvedCommit: "a".repeat(40), compilerVersion: "0.8.36", primaryContract: "VulnerableAccounting", primarySourcePath: "contracts/VulnerableAccounting.sol", sourceFiles: ["contracts/VulnerableAccounting.sol"], actors: ["deployer", "attacker"],
    setup: [{ kind: "deploy", contractName: "VulnerableAccounting", instanceName: "target" }],
    property: { name: propertyName, observations: [{ kind: "read-uint", instanceName: "target", functionName: "totalRecordedBalance", resultName: "recorded" }, { kind: "read-balance", target: { kind: "instance", name: "target" }, resultName: "balance" }], assertions: [{ id: assertionId, kind: "uint-eq", actual: "recorded", expected: { kind: "result", name: "balance" } }] },
    fuzzAction: { instanceName: "target", functionName: "record", caller: "attacker", parameters: [{ name: "amount", type: "uint256" }], args: [{ kind: "parameter", name: "amount" }] },
  });
}

describe("exact invariant property targets", () => {
  it("shares identity across hypotheses when action, observation and assertion semantics match", () => {
    const first = plan("22222222-2222-4222-8222-222222222222");
    const second = plan("33333333-3333-4333-8333-333333333333", "renamed", "another");
    const result = buildInvariantPropertyTargets([{ proposalId: "p2", plan: second }, { proposalId: "p1", plan: first }]);
    expect(result).toHaveLength(1);
    expect(result[0].members).toEqual([{ proposalId: "p1", hypothesisId: first.hypothesisId, propertyName: "accounting" }, { proposalId: "p2", hypothesisId: second.hypothesisId, propertyName: "renamed" }]);
    expect(buildInvariantPropertyTargets([{ proposalId: "p1", plan: first }, { proposalId: "p2", plan: second }])).toEqual(result);
  });
  it("keeps different action or observation semantics separate and ignores malformed plans", () => {
    const first = plan("22222222-2222-4222-8222-222222222222");
    if (first.mode !== "fuzz-property") throw new Error("Fixture mode changed.");
    const changedAction = { ...first, fuzzAction: { ...first.fuzzAction, functionName: "credit" } };
    const changedObservation = { ...first, property: { ...first.property, observations: first.property.observations.map((item) => item.kind === "read-uint" ? { ...item, functionName: "otherBalance" } : item) } };
    expect(buildInvariantPropertyTargets([{ proposalId: "p1", plan: first }, { proposalId: "p2", plan: changedAction }, { proposalId: "p3", plan: changedObservation }, { proposalId: "bad", plan: { source: "hostile" } }])).toHaveLength(3);
  });
});
