import { executableInvariantPlanSchema, invariantPlanHash, type ExecutableInvariantPlan, type InvariantCall, type InvariantProperty, type InvariantSetupOperation } from "@contracthunter/core";
import { createContractHunterInvariantFoundryConfig, invariantFoundrySettings } from "./verification-foundry-config";
import { sha256Bytes } from "./verification-workspace-integrity";
import { validateSolidityFunctionUses, type SourceFunctionUse, type SolidityArgumentKind } from "./solidity-function-validation";

const VM_ADDRESS = 'address(uint160(uint256(keccak256("hevm cheat code"))))';
const vmInterface = `interface ContractHunterVm {
    function prank(address caller) external;
    function deal(address target, uint256 newBalance) external;
}
abstract contract ContractHunterCheats {
    ContractHunterVm internal constant vm = ContractHunterVm(${VM_ADDRESS});
}`;
const targeting = `abstract contract ContractHunterTargeting {
    address[] private _targetedContracts;
    function targetContract(address target) internal { _targetedContracts.push(target); }
    function targetContracts() public view returns (address[] memory) { return _targetedContracts; }
}`;
export type GeneratedInvariantHarness = { source: string; foundryConfig: string; planHash: string; harnessHash: string; configHash: string; settings: typeof invariantFoundrySettings & { seed: string } };
function indent(lines: string[], spaces = 8): string { return lines.map((line) => `${" ".repeat(spaces)}${line}`).join("\n"); }
export class ExecutableInvariantGenerator {
  generate(input: ExecutableInvariantPlan, sourceFiles: ReadonlyMap<string, string>): GeneratedInvariantHarness {
    const plan = executableInvariantPlanSchema.parse(input);
    const primary = sourceFiles.get(plan.primarySourcePath);
    if (primary === undefined || plan.sourceFiles.some((file) => !sourceFiles.has(file))) throw new Error("Invariant source closure is incomplete.");
    const parameterKind = (call: InvariantCall, name: string): SolidityArgumentKind => {
      const parameter = call.parameters.find((item) => item.name === name);
      if (!parameter) throw new Error("Unknown fuzz parameter.");
      return parameter.type === "uint256" ? "uint" : "bool";
    };
    const calls = plan.mode === "fuzz-property" ? [plan.fuzzAction] : plan.handlerActions;
    const uses: SourceFunctionUse[] = [
      ...plan.setup.filter((op): op is Extract<InvariantSetupOperation, { kind: "call" }> => op.kind === "call").map((op) => ({ kind: "call" as const, functionName: op.functionName, argumentKinds: op.args.map((arg) => arg.kind) })),
      ...calls.map((call) => ({ kind: "call" as const, functionName: call.functionName, argumentKinds: call.args.map((arg) => arg.kind === "parameter" ? parameterKind(call, arg.name) : arg.kind) })),
      ...(plan.mode === "fuzz-property" ? [plan.property] : plan.properties).flatMap((property) => property.observations.filter((obs) => obs.kind !== "read-balance").map((obs) => ({ kind: obs.kind as "read-uint" | "read-address", functionName: obs.functionName, argumentKinds: [] }))),
    ];
    validateSolidityFunctionUses(primary, plan.sourceFiles.map((file) => sourceFiles.get(file)!), plan.primaryContract, uses, [], true);
    const actors = new Set(plan.actors), instances = new Set<string>();
    const address = (source: "actor" | "instance", name: string) => {
      if (source === "actor") { if (!actors.has(name)) throw new Error("Unknown actor."); return `actor_${name}`; }
      if (!instances.has(name)) throw new Error("Unknown instance.");
      return `address(${name})`;
    };
    const fixedArg = (arg: Exclude<InvariantCall["args"][number], { kind: "parameter" }>) => arg.kind === "address" ? address(arg.source, arg.name) : arg.kind === "uint" ? arg.value : String(arg.value);
    const setup: string[] = [];
    for (const op of plan.setup) {
      if (op.kind === "deploy") { instances.add(op.instanceName); setup.push(`${plan.mode === "fuzz-property" ? `${plan.primaryContract} ` : ""}${op.instanceName} = new ${plan.primaryContract}();`); }
      else if (op.kind === "fund") setup.push(`vm.deal(${address(op.target.kind, op.target.name)}, ${op.amountWei});`);
      else { if (op.caller) setup.push(`vm.prank(actor_${op.caller});`); setup.push(`${op.instanceName}.${op.functionName}(${op.args.map(fixedArg).join(", ")});`); }
    }
    const renderCall = (call: InvariantCall) => [
      ...(call.caller ? [`vm.prank(actor_${call.caller});`] : []),
      `${call.instanceName}.${call.functionName}(${call.args.map((arg) => arg.kind === "parameter" ? arg.name : fixedArg(arg)).join(", ")});`,
    ];
    const renderProperty = (property: InvariantProperty): string[] => {
      const reads = property.observations.map((obs) => obs.kind === "read-balance"
        ? `uint256 ${obs.resultName} = ${address(obs.target.kind, obs.target.name)}.balance;`
        : `${obs.kind === "read-address" ? "address" : "uint256"} ${obs.resultName} = ${obs.instanceName}.${obs.functionName}();`);
      const checks = property.assertions.map((assertion, index) => {
        const expected = typeof assertion.expected === "string" ? assertion.expected : assertion.expected.kind === "result" ? assertion.expected.name : address(assertion.expected.source, assertion.expected.name);
        return `require(${assertion.actual} ${assertion.kind.endsWith("not-eq") ? "!=" : "=="} ${expected}, "CH_ASSERT_${index}");`;
      });
      return [...reads, ...checks];
    };
    const importLine = `import { ${plan.primaryContract} } from "../src/${plan.primarySourcePath}";`;
    let source: string;
    if (plan.mode === "fuzz-property") {
      const actorLines = plan.actors.map((name, i) => `address actor_${name} = ${name === "deployer" ? "address(this)" : `address(uint160(${4097 + i}))`};`);
      const parameters = plan.fuzzAction.parameters.map((p) => `${p.type} ${p.name}`).join(", ");
      source = `// SPDX-License-Identifier: UNLICENSED\npragma solidity ${plan.compilerVersion};\n\n${importLine}\n\n${vmInterface}\n\ncontract ContractHunterFuzzTest is ContractHunterCheats {\n    function testFuzz_${plan.property.name}(${parameters}) public {\n${indent([...actorLines, ...setup, ...renderCall(plan.fuzzAction), ...renderProperty(plan.property)])}\n    }\n}\n`;
    } else {
      const instanceNames = plan.setup.filter((op): op is Extract<InvariantSetupOperation, { kind: "deploy" }> => op.kind === "deploy").map((op) => op.instanceName);
      const declarations = [...instanceNames.map((name) => `    ${plan.primaryContract} internal ${name};`), ...plan.actors.map((name) => `    address internal actor_${name};`)].join("\n");
      const constructorArgs = [...instanceNames.map((name) => `${plan.primaryContract} _${name}`), ...plan.actors.map((name) => `address _actor_${name}`)].join(", ");
      const assignments = [...instanceNames.map((name) => `${name} = _${name};`), ...plan.actors.map((name) => `actor_${name} = _actor_${name};`)];
      const actions = plan.handlerActions.map((action) => `    function action_${action.name}(${action.parameters.map((p) => `${p.type} ${p.name}`).join(", ")}) external {\n${indent(renderCall(action))}\n    }`).join("\n\n");
      const actorSetup = plan.actors.map((name, i) => `actor_${name} = ${name === "deployer" ? "address(this)" : `address(uint160(${4097 + i}))`};`);
      const properties = plan.properties.map((property) => `    function invariant_${property.name}() public view {\n${indent(renderProperty(property))}\n    }`).join("\n\n");
      source = `// SPDX-License-Identifier: UNLICENSED\npragma solidity ${plan.compilerVersion};\n\n${importLine}\n\n${vmInterface}\n\n${targeting}\n\ncontract ContractHunterHandler is ContractHunterCheats {\n${declarations}\n    constructor(${constructorArgs}) {\n${indent(assignments)}\n    }\n\n${actions}\n}\n\ncontract ContractHunterInvariantTest is ContractHunterCheats, ContractHunterTargeting {\n${declarations}\n    ContractHunterHandler internal handler;\n\n    function setUp() public {\n${indent([...actorSetup, ...setup, `handler = new ContractHunterHandler(${[...instanceNames, ...plan.actors.map((name) => `actor_${name}`)].join(", ")});`, "targetContract(address(handler));"])}\n    }\n\n${properties}\n}\n`;
    }
    const planHash = invariantPlanHash(plan), foundryConfig = createContractHunterInvariantFoundryConfig(plan.compilerVersion, planHash);
    return { source, foundryConfig, planHash, harnessHash: sha256Bytes(source), configHash: sha256Bytes(foundryConfig), settings: { ...invariantFoundrySettings, seed: `0x${planHash}` } };
  }
}
