import {
  verificationHarnessPlanSchema,
  type VerificationAddressReference,
  type VerificationHarnessPlan,
  type VerificationTypedValue,
} from "@contracthunter/core";

const MAX_UINT256 = (1n << 256n) - 1n;
const FORBIDDEN_OPERATION_NAMES = new Set(["ffi", "createFork", "selectFork", "rpc", "readFile", "writeFile", "readDir", "env", "broadcast", "startBroadcast", "deriveKey"]);

export class VerificationHarnessGenerationError extends Error {
  constructor(message: string) { super(message); this.name = "VerificationHarnessGenerationError"; }
}

export class VerificationHarnessGenerator {
  generate(input: VerificationHarnessPlan): string {
    const plan = verificationHarnessPlanSchema.parse(input);
    const actors = new Set(plan.actors ?? []); const instances = new Set<string>(); const results = new Map<string, "uint" | "address">(); const statements: string[] = [];
    const actor = (name: string) => {
      if (!actors.has(name)) throw new VerificationHarnessGenerationError("Operation references an undeclared actor.");
      return `actor_${name}`;
    };
    const addressReference = (reference: VerificationAddressReference | Extract<VerificationTypedValue, { kind: "address" }>) => {
      const source = "source" in reference ? reference.source : reference.kind;
      if (source === "actor") return actor(reference.name);
      if (!instances.has(reference.name)) throw new VerificationHarnessGenerationError("Operation references an undeclared instance.");
      return `address(${reference.name})`;
    };
    const typedValue = (value: VerificationTypedValue): string => {
      if (value.kind === "address") return addressReference(value);
      if (value.kind === "uint") {
        if (BigInt(value.value) > MAX_UINT256) throw new VerificationHarnessGenerationError("Typed uint value exceeds uint256.");
        return value.value;
      }
      return value.value ? "true" : "false";
    };

    for (const [index, name] of (plan.actors ?? []).entries()) statements.push(`address ${actor(name)} = ${name === "deployer" ? "address(this)" : `address(uint160(${4097 + index}))`};`);
    for (const operation of plan.operations) {
      if (operation.kind === "deploy") {
        if (operation.contractName !== plan.primaryContract || instances.has(operation.instanceName) || actors.has(operation.instanceName)) throw new VerificationHarnessGenerationError("Deployment operation is not valid for the primary contract.");
        instances.add(operation.instanceName); statements.push(`${plan.primaryContract} ${operation.instanceName} = new ${plan.primaryContract}();`); continue;
      }
      if (operation.kind === "fund") {
        statements.push(`vm.deal(${addressReference(operation.target)}, ${operation.amountWei});`); continue;
      }
      if (operation.kind === "read-balance") {
        if (results.has(operation.resultName) || instances.has(operation.resultName) || actors.has(operation.resultName)) throw new VerificationHarnessGenerationError("Read result name is duplicated or ambiguous.");
        results.set(operation.resultName, "uint"); statements.push(`uint256 ${operation.resultName} = ${addressReference(operation.target)}.balance;`); continue;
      }
      if (FORBIDDEN_OPERATION_NAMES.has(operation.functionName) || operation.functionName.startsWith("env")) throw new VerificationHarnessGenerationError("Operation uses a prohibited capability name.");
      if (!instances.has(operation.instanceName) || !plan.relevantFunctions.includes(operation.functionName)) throw new VerificationHarnessGenerationError("Operation references an undeclared instance or function.");
      if (operation.kind === "call") {
        if (operation.caller) statements.push(`vm.prank(${actor(operation.caller)});`);
        statements.push(`${operation.instanceName}.${operation.functionName}(${(operation.args ?? []).map(typedValue).join(", ")});`);
      } else {
        if (results.has(operation.resultName) || instances.has(operation.resultName) || actors.has(operation.resultName)) throw new VerificationHarnessGenerationError("Read result name is duplicated or ambiguous.");
        const resultType = operation.kind === "read-address" ? "address" : "uint";
        results.set(operation.resultName, resultType); statements.push(`${resultType === "address" ? "address" : "uint256"} ${operation.resultName} = ${operation.instanceName}.${operation.functionName}();`);
      }
    }
    if (!instances.size) throw new VerificationHarnessGenerationError("A controlled deployment operation is required.");
    const assertions = plan.assertions.map((assertion, index) => {
      const addressAssertion = assertion.kind === "address-eq" || assertion.kind === "address-not-eq";
      if (results.get(assertion.actual) !== (addressAssertion ? "address" : "uint")) throw new VerificationHarnessGenerationError("Assertion references an invalid or incompatible result.");
      const expected = addressAssertion ? addressReference(assertion.expected) : assertion.expected;
      const equality = assertion.kind === "uint-eq" || assertion.kind === "address-eq";
      return `require(${assertion.actual} ${equality ? "==" : "!="} ${expected}, "CH_ASSERT_${index}");`;
    });
    const importPath = `../src/${plan.primarySourcePath}`;
    const usesCheatcodes = plan.operations.some((operation) => operation.kind === "fund" || (operation.kind === "call" && Boolean(operation.caller)));
    return `// SPDX-License-Identifier: UNLICENSED
pragma solidity ${plan.compilerVersion};

import { ${plan.primaryContract} } from "${importPath}";

${usesCheatcodes ? `interface ContractHunterVm {
    function prank(address caller) external;
    function deal(address target, uint256 newBalance) external;
}

` : ""}contract ContractHunterVerification {
${usesCheatcodes ? `    ContractHunterVm private constant vm = ContractHunterVm(address(uint160(uint256(keccak256("hevm cheat code")))));

` : ""}    function testContractHunterVerification() public {
${[...statements, ...assertions].map((line) => `        ${line}`).join("\n")}
    }
}
`;
  }
}
