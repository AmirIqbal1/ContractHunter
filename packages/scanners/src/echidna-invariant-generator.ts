import { ECHIDNA_LIMITS, echidnaSeed, executableInvariantPlanSchema, invariantPlanHash, type ExecutableInvariantPlan, type InvariantCall } from "@contracthunter/core";
import { ExecutableInvariantGenerator } from "./executable-invariant-generator";
import { solidityStructure } from "./solidity-function-validation";
import { sha256Bytes } from "./verification-workspace-integrity";

export type EchidnaCompatibility = { compatible: true; reasons: [] } | { compatible: false; reasons: string[] };
const unsafeEnvironment = /\b(?:msg\s*\.|tx\s*\.|block\s*\.|blockhash\s*\(|gasleft\s*\(|address\s*\(\s*this\s*\)|delegatecall\s*\(|selfdestruct\s*\()/;
export function validateEchidnaPlanCompatibility(raw: ExecutableInvariantPlan, sources?: ReadonlyMap<string, string>): EchidnaCompatibility {
  const plan = executableInvariantPlanSchema.parse(raw), reasons: string[] = [];
  if (plan.mode !== "stateful-invariant") return { compatible: false, reasons: ["engine-not-supported-for-plan"] };
  if (plan.actors.length) reasons.push("symbolic-actors-unsupported");
  if (plan.setup.length !== 1 || plan.setup[0]?.kind !== "deploy") reasons.push("setup-semantics-unsupported");
  if (plan.handlerActions.some((action) => action.caller)) reasons.push("explicit-caller-unsupported");
  if (plan.handlerActions.some((action) => action.args.some((arg) => arg.kind === "address"))) reasons.push("symbolic-address-argument-unsupported");
  if (plan.properties.some((property) => property.observations.some((observation) => observation.kind === "read-address") || property.assertions.some((assertion) => assertion.kind.startsWith("address")))) reasons.push("address-property-unsupported");
  if (sources) {
    if (plan.sourceFiles.some((name) => !sources.has(name))) reasons.push("source-closure-incomplete");
    else if (plan.sourceFiles.some((name) => unsafeEnvironment.test(solidityStructure(sources.get(name)!)))) reasons.push("caller-or-environment-sensitive-source");
    if (reasons.length === 0) {
      try { new ExecutableInvariantGenerator().generate(plan, sources); }
      catch { reasons.push("source-signature-incompatible"); }
    }
  }
  return reasons.length ? { compatible: false, reasons: [...new Set(reasons)].slice(0, 8) } : { compatible: true, reasons: [] };
}

export type GeneratedEchidnaInvariant = { source: string; config: string; planHash: string; harnessHash: string; configHash: string; settings: { testMode: "property"; testLimit: 128; seqLen: 32; shrinkLimit: 128; workers: 1; timeout: 150; format: "json"; seed: number } };
const spaces = (lines: string[], count = 8) => lines.map((line) => `${" ".repeat(count)}${line}`).join("\n");
export class EchidnaInvariantGenerator {
  generate(raw: ExecutableInvariantPlan, sources: ReadonlyMap<string, string>): GeneratedEchidnaInvariant {
    const plan = executableInvariantPlanSchema.parse(raw);
    const compatibility = validateEchidnaPlanCompatibility(plan, sources);
    if (!compatibility.compatible) throw new Error(`echidna_incompatible:${compatibility.reasons.join(",")}`);
    if (plan.mode !== "stateful-invariant") throw new Error("engine-not-supported-for-plan");
    const deploy = plan.setup[0];
    if (deploy.kind !== "deploy") throw new Error("setup-semantics-unsupported");
    const fixed = (arg: Exclude<InvariantCall["args"][number], { kind: "parameter" }>) => arg.kind === "uint" ? arg.value : arg.kind === "bool" ? String(arg.value) : (() => { throw new Error("symbolic-address-argument-unsupported"); })();
    const actions = plan.handlerActions.map((action) => {
      const args = action.args.map((arg) => arg.kind === "parameter" ? arg.name : fixed(arg)).join(", ");
      return `    function action_${action.name}(${action.parameters.map((parameter) => `${parameter.type} ${parameter.name}`).join(", ")}) public {\n${spaces([`${action.instanceName}.${action.functionName}(${args});`])}\n    }`;
    }).join("\n\n");
    const properties = plan.properties.map((property) => {
      const observations = property.observations.map((observation) => observation.kind === "read-balance"
        ? `uint256 ${observation.resultName} = address(${observation.target.name}).balance;`
        : `uint256 ${observation.resultName} = ${observation.instanceName}.${observation.functionName}();`);
      const assertions = property.assertions.map((assertion) => `(${assertion.actual} ${assertion.kind === "uint-not-eq" ? "!=" : "=="} ${typeof assertion.expected === "string" ? assertion.expected : assertion.expected.name})`);
      return `    function echidna_ch_${property.name}() public view returns (bool) {\n${spaces([...observations, `return ${assertions.join(" && ")};`])}\n    }`;
    }).join("\n\n");
    const source = `// SPDX-License-Identifier: UNLICENSED\npragma solidity ${plan.compilerVersion};\n\nimport { ${plan.primaryContract} } from "./src/${plan.primarySourcePath}";\n\ncontract ContractHunterEchidnaHarness {\n    ${plan.primaryContract} internal ${deploy.instanceName};\n\n    constructor() {\n        ${deploy.instanceName} = new ${plan.primaryContract}();\n    }\n\n${actions}\n\n${properties}\n}\n`;
    const planHash = invariantPlanHash(plan), seed = echidnaSeed(planHash);
    const settings = { testMode: "property", testLimit: ECHIDNA_LIMITS.testLimit, seqLen: ECHIDNA_LIMITS.seqLen, shrinkLimit: ECHIDNA_LIMITS.shrinkLimit, workers: 1, timeout: ECHIDNA_LIMITS.timeoutSeconds, format: "json", seed } as const;
    const config = `testMode: property\ntestLimit: ${settings.testLimit}\nseqLen: ${settings.seqLen}\nshrinkLimit: ${settings.shrinkLimit}\nworkers: 1\ntimeout: ${settings.timeout}\nformat: json\nseed: ${seed}\ncoverage: false\nstopOnFail: false\nsymExec: false\nprefix: echidna_ch_\n`;
    return { source, config, planHash, harnessHash: sha256Bytes(source), configHash: sha256Bytes(config), settings };
  }
}
