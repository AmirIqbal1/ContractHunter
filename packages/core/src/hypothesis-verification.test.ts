import { describe, expect, it } from "vitest";
import { dynamicEvidenceSchema, verificationCapabilityProfile, verificationHarnessPlanSchema, verificationOutcomeSchema, verificationRunStatusSchema } from "./hypothesis-verification";
import { verificationPlanProposalSchema } from "./verification-plan-generation";

const evidence = {
  assertionId: "share-conversion",
  assertionName: "second depositor receives proportional shares",
  expectedBehavior: "The second depositor receives shares at the pre-deposit exchange rate.",
  observedBehavior: "The second depositor received fewer shares than the pre-deposit exchange rate requires.",
  direction: "supports",
  contract: "Vault",
  functionName: "deposit",
  details: "A bounded local assertion compared the expected and actual share amounts.",
} as const;

describe("hypothesis verification domain", () => {
  it("accepts only verification run statuses", () => {
    for (const status of ["queued", "running", "completed", "failed"]) expect(verificationRunStatusSchema.parse(status)).toBe(status);
    expect(verificationRunStatusSchema.safeParse("confirmed").success).toBe(false);
  });

  it("keeps verification outcomes distinct from execution status", () => {
    for (const outcome of ["confirmed", "refuted", "inconclusive"]) expect(verificationOutcomeSchema.parse(outcome)).toBe(outcome);
    expect(verificationOutcomeSchema.safeParse("completed").success).toBe(false);
  });

  it("validates bounded structured dynamic evidence", () => {
    expect(dynamicEvidenceSchema.parse(evidence)).toEqual(evidence);
    expect(dynamicEvidenceSchema.safeParse({ ...evidence, direction: "reviewer-agrees" }).success).toBe(false);
    expect(dynamicEvidenceSchema.safeParse({ ...evidence, observedBehavior: "" }).success).toBe(false);
    expect(dynamicEvidenceSchema.safeParse({ ...evidence, shellCommand: "forge test" }).success).toBe(false);
  });
});

const plan = {
  scanId: "11111111-1111-4111-8111-111111111111", hypothesisId: "22222222-2222-4222-8222-222222222222", resolvedCommit: "a".repeat(40), compilerVersion: "0.8.24",
  primaryContract: "Counter", primarySourcePath: "contracts/Counter.sol", relevantFunctions: ["increment", "count"], sourceFiles: ["contracts/Counter.sol"],
  verificationGoal: "Confirm deterministic counter state changes.", expectedProperty: "Increment changes count from zero to one.", verificationSteps: ["Deploy Counter.", "Call increment.", "Read count."],
  operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "increment" }, { kind: "read-uint", instanceName: "target", functionName: "count", resultName: "observed" }],
  assertions: [{ id: "count-is-one", kind: "uint-eq", actual: "observed", expected: "1", expectedOutcome: "hypothesis-supported", description: "Count becomes one." }],
} as const;

describe("verification harness plan", () => {
  it("accepts a bounded structured plan", () => { expect(verificationHarnessPlanSchema.parse(plan)).toEqual(plan); });
  it("rejects arbitrary Solidity and unsafe source paths", () => {
    expect(verificationHarnessPlanSchema.safeParse({ ...plan, soliditySource: "contract Arbitrary {}" }).success).toBe(false);
    for (const primarySourcePath of ["../Counter.sol", "/tmp/Counter.sol", "https://example/Counter.sol", "contracts\\Counter.sol", "contracts/Evil\"; import \"Other.sol", "contracts/Evil\ncontract Injected.sol"]) {
      expect(verificationHarnessPlanSchema.safeParse({ ...plan, primarySourcePath, sourceFiles: [primarySourcePath] }).success).toBe(false);
    }
  });
  it("rejects oversized structured plans and unstable compilers", () => {
    expect(verificationHarnessPlanSchema.safeParse({ ...plan, verificationSteps: Array.from({ length: 31 }, () => "step") }).success).toBe(false);
    expect(verificationHarnessPlanSchema.safeParse({ ...plan, compilerVersion: "0.8.24-nightly" }).success).toBe(false);
  });

  it("accepts the bounded BrokenAccessControl actor and native-balance plan", () => {
    const accessPlan = {
      ...plan, primaryContract: "BrokenAccessControl", primarySourcePath: "contracts/BrokenAccessControl.sol", sourceFiles: ["contracts/BrokenAccessControl.sol"],
      relevantFunctions: ["setOwner", "owner", "withdraw"], actors: ["deployer", "attacker"],
      operations: [
        { kind: "deploy", contractName: "BrokenAccessControl", instanceName: "target" },
        { kind: "fund", target: { kind: "instance", name: "target" }, amountWei: "1000000000000000000" },
        { kind: "read-address", instanceName: "target", functionName: "owner", resultName: "initialOwner" },
        { kind: "call", instanceName: "target", functionName: "setOwner", caller: "attacker", args: [{ kind: "address", source: "actor", name: "attacker" }] },
        { kind: "read-address", instanceName: "target", functionName: "owner", resultName: "ownerAfter" },
        { kind: "call", instanceName: "target", functionName: "withdraw", caller: "attacker", args: [] },
        { kind: "read-balance", target: { kind: "instance", name: "target" }, resultName: "targetBalance" },
      ],
      assertions: [
        { id: "attacker-is-owner", kind: "address-eq", actual: "ownerAfter", expected: { kind: "address", source: "actor", name: "attacker" }, expectedOutcome: "hypothesis-supported", description: "The attacker becomes the observed owner." },
        { id: "target-drained", kind: "uint-eq", actual: "targetBalance", expected: "0", expectedOutcome: "hypothesis-supported", description: "The target native balance becomes zero." },
      ],
    } as const;
    expect(verificationHarnessPlanSchema.safeParse(accessPlan).success).toBe(true);
    expect(verificationHarnessPlanSchema.safeParse({ ...accessPlan, operations: [...accessPlan.operations, { kind: "call", instanceName: "target", functionName: "setOwner", args: [{ kind: "uint", value: "1" }, { kind: "bool", value: true }] }] }).success).toBe(true);
  });

  it("rejects unsafe actor, argument, funding, capability, and extension data", () => {
    const base = {
      ...plan, actors: ["attacker"], relevantFunctions: ["setOwner", "owner"],
      operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "setOwner", caller: "attacker", args: [{ kind: "address", source: "actor", name: "attacker" }] }, { kind: "read-address", instanceName: "target", functionName: "owner", resultName: "ownerAfter" }],
      assertions: [{ id: "owner", kind: "address-eq", actual: "ownerAfter", expected: { kind: "address", source: "actor", name: "attacker" }, expectedOutcome: "hypothesis-supported", description: "The attacker becomes owner." }],
    };
    const invalid = [
      { ...base, actors: ["attacker", "attacker"] },
      { ...base, operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "setOwner", caller: "unknown", args: [] }] },
      { ...base, operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "setOwner", args: [{ kind: "address", source: "actor", name: "attacker); vm.ffi" }] }] },
      { ...base, operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "setOwner", args: [{ kind: "address", source: "literal", name: "0x0000000000000000000000000000000000000001" }] }] },
      { ...base, operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "setOwner", args: [{ kind: "bytes", value: "0x00" }] }] },
      { ...base, operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "setOwner", args: Array.from({ length: 9 }, () => ({ kind: "bool", value: true })) }] },
      { ...base, operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "fund", target: { kind: "instance", name: "target" }, amountWei: "-1" }] },
      { ...base, operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "fund", target: { kind: "instance", name: "target" }, amountWei: "100000000000000000001" }] },
      { ...base, operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "ffi", command: "sh" }] },
      { ...base, operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "prank", args: [] }] },
      { ...base, operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, { kind: "call", instanceName: "target", functionName: "setOwner", args: [], calldata: "0x00" }] },
      { ...base, repositoryPath: "/tmp/attacker" },
    ];
    for (const candidate of invalid) expect(verificationHarnessPlanSchema.safeParse(candidate).success).toBe(false);
  });
});

describe("verification plan proposal", () => {
  it("keeps generated and not-plannable structured results distinct", () => {
    const generatedPlan: Record<string, unknown> = { ...plan, actors: ["deployer"], operations: plan.operations.map((operation) => operation.kind === "call" ? { ...operation, caller: null, args: [] } : operation) };
    for (const field of ["scanId", "hypothesisId", "resolvedCommit", "compilerVersion"]) delete generatedPlan[field];
    expect(verificationPlanProposalSchema.parse({ status: "generated", plan: generatedPlan, rationale: "The transition maps to bounded operations.", limitations: [], notPlannableReasons: [] }).status).toBe("generated");
    for (const identity of [{ scanId: plan.scanId }, { hypothesisId: plan.hypothesisId }, { resolvedCommit: plan.resolvedCommit }, { compilerVersion: plan.compilerVersion }]) {
      expect(verificationPlanProposalSchema.safeParse({ status: "generated", plan: { ...generatedPlan, ...identity }, rationale: "Identity injection attempt.", limitations: [], notPlannableReasons: [] }).success).toBe(false);
    }
    expect(verificationPlanProposalSchema.parse({ status: "not_plannable", plan: null, rationale: "Bytes arguments are required.", limitations: [], notPlannableReasons: ["unsupported_function_argument_type"] }).status).toBe("not_plannable");
    expect(verificationPlanProposalSchema.safeParse({ status: "generated", plan: null, rationale: "Forced", limitations: [], notPlannableReasons: [], command: "forge test" }).success).toBe(false);
  });

  it("keeps the canonical capability profile aligned with supported and rejected plan primitives", () => {
    expect(verificationCapabilityProfile).toMatchObject({ actors: true, maxActors: 8, callers: true, functionArguments: ["address", "uint256", "bool"], maxFunctionArguments: 8, observations: ["uint", "address", "native-balance"], maxFundingWei: "100000000000000000000", constructorArguments: false, rawCalldata: false, arrays: false, structs: false, bytes: false, timeManipulation: false, blockManipulation: false, attackerContractGeneration: false, erc20Helpers: false, rpc: false, forks: false, liveChain: false });
    for (const unsupported of [
      { kind: "call", instanceName: "target", functionName: "foo", caller: null, args: [{ kind: "bytes", value: "0x00" }] },
      { kind: "call", instanceName: "target", functionName: "foo", caller: null, args: [{ kind: "address[]", value: [] }] },
      { kind: "warp", timestamp: "1" }, { kind: "generate-attacker", contractName: "Attack" },
    ]) expect(verificationHarnessPlanSchema.safeParse({ ...plan, actors: ["deployer"], operations: [{ kind: "deploy", contractName: "Counter", instanceName: "target" }, unsupported] }).success).toBe(false);
    expect(verificationHarnessPlanSchema.safeParse({ ...plan, constructorArgs: [{ kind: "address", source: "actor", name: "deployer" }] }).success).toBe(false);
  });
});
