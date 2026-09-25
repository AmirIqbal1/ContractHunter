import { executableInvariantPlanSchema, invariantReplayPlanHash, invariantReplayPlanSchema, validateReplayAgainstInvariant, type ExecutableInvariantPlan, type InvariantCall, type InvariantReplayPlan } from "@contracthunter/core";
import { createContractHunterFoundryConfig } from "./verification-foundry-config";
import { ExecutableInvariantGenerator } from "./executable-invariant-generator";
import { sha256Bytes } from "./verification-workspace-integrity";

const VM_ADDRESS = 'address(uint160(uint256(keccak256("hevm cheat code"))))';
const vmInterface = `interface ContractHunterVm {
    function prank(address caller) external;
    function deal(address target, uint256 newBalance) external;
}
abstract contract ContractHunterCheats {
    ContractHunterVm internal constant vm = ContractHunterVm(${VM_ADDRESS});
}`;
const indent = (lines: string[], spaces = 8) => lines.map((line) => `${" ".repeat(spaces)}${line}`).join("\n");
export type GeneratedInvariantReplay = { source: string; foundryConfig: string; replayPlanHash: string; harnessHash: string; configHash: string };

export class InvariantReplayGenerator {
  generate(rawReplay: InvariantReplayPlan, rawInvariant: ExecutableInvariantPlan, sources: ReadonlyMap<string, string>): GeneratedInvariantReplay {
    const replay = invariantReplayPlanSchema.parse(rawReplay), invariant = executableInvariantPlanSchema.parse(rawInvariant);
    validateReplayAgainstInvariant(replay, invariant);
    new ExecutableInvariantGenerator().generate(invariant, sources);
    const actors = new Set(invariant.actors), instances = new Set<string>();
    const address = (source: "actor" | "instance", name: string) => {
      if (source === "actor") { if (!actors.has(name)) throw new Error("Unknown actor."); return `actor_${name}`; }
      if (!instances.has(name)) throw new Error("Unknown instance."); return `address(${name})`;
    };
    const fixed = (arg: Exclude<InvariantCall["args"][number], { kind: "parameter" }>) => arg.kind === "address" ? address(arg.source, arg.name) : arg.kind === "uint" ? arg.value : String(arg.value);
    const setup: string[] = [];
    for (const operation of invariant.setup) {
      if (operation.kind === "deploy") { instances.add(operation.instanceName); setup.push(`${invariant.primaryContract} ${operation.instanceName} = new ${invariant.primaryContract}();`); }
      else if (operation.kind === "fund") setup.push(`vm.deal(${address(operation.target.kind, operation.target.name)}, ${operation.amountWei});`);
      else { if (operation.caller) setup.push(`vm.prank(actor_${operation.caller});`); setup.push(`${operation.instanceName}.${operation.functionName}(${operation.args.map(fixed).join(", ")});`); }
    }
    const value = (item: { type: "uint256"; value: string } | { type: "bool"; value: boolean }) => item.type === "uint256" ? item.value : String(item.value);
    const replayCall = (call: InvariantCall, parameterValues: Array<{ name: string; type: "uint256"; value: string } | { name: string; type: "bool"; value: boolean }>) => {
      const byName = new Map(parameterValues.map((item) => [item.name, item]));
      return [...(call.caller ? [`vm.prank(actor_${call.caller});`] : []), `${call.instanceName}.${call.functionName}(${call.args.map((arg) => arg.kind === "parameter" ? value(byName.get(arg.name)!) : fixed(arg)).join(", ")});`];
    };
    const properties = invariant.mode === "fuzz-property" ? [invariant.property] : invariant.properties;
    const property = properties.find((item) => item.name === replay.propertyName)!;
    const observations = property.observations.map((observation) => observation.kind === "read-balance" ? `uint256 ${observation.resultName} = ${address(observation.target.kind, observation.target.name)}.balance;` : `${observation.kind === "read-address" ? "address" : "uint256"} ${observation.resultName} = ${observation.instanceName}.${observation.functionName}();`);
    const condition = property.assertions.map((assertion) => {
      const expected = typeof assertion.expected === "string" ? assertion.expected : assertion.expected.kind === "result" ? assertion.expected.name : address(assertion.expected.source, assertion.expected.name);
      return `(${assertion.actual} ${assertion.kind.endsWith("not-eq") ? "!=" : "=="} ${expected})`;
    }).join(" && ");
    const calls = replay.counterexample.kind === "single" && invariant.mode === "fuzz-property" ? replayCall(invariant.fuzzAction, replay.counterexample.parameterValues)
      : replay.counterexample.kind === "sequence" && invariant.mode === "stateful-invariant" ? replay.counterexample.actions.flatMap((step) => replayCall(invariant.handlerActions.find((action) => action.name === step.actionName)!, step.parameterValues)) : [];
    const actorLines = invariant.actors.map((name, index) => `address actor_${name} = ${name === "deployer" ? "address(this)" : `address(uint160(${4097 + index}))`};`);
    const source = `// SPDX-License-Identifier: UNLICENSED
pragma solidity ${invariant.compilerVersion};

import { ${invariant.primaryContract} } from "../src/${invariant.primarySourcePath}";

${vmInterface}

contract ContractHunterReplayTest is ContractHunterCheats {
    function testReplay_${property.name}() public {
${indent([...actorLines, ...setup, ...calls, ...observations, `require(!(${condition}), "CH_REPLAY_NOT_REPRODUCED");`])}
    }
}
`;
    const foundryConfig = `${createContractHunterFoundryConfig(invariant.compilerVersion)}auto_detect_remappings = false\n`;
    return { source, foundryConfig, replayPlanHash: invariantReplayPlanHash(replay), harnessHash: sha256Bytes(source), configHash: sha256Bytes(foundryConfig) };
  }
}
