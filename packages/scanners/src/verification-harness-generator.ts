import { verificationHarnessPlanSchema, type VerificationHarnessPlan } from "@contracthunter/core";

const MAX_UINT256 = (1n << 256n) - 1n;
const FORBIDDEN_OPERATION_NAMES = new Set(["ffi", "createFork", "selectFork", "rpc", "readFile", "writeFile", "readDir", "env", "broadcast", "startBroadcast", "deriveKey"]);

export class VerificationHarnessGenerationError extends Error {
  constructor(message: string) { super(message); this.name = "VerificationHarnessGenerationError"; }
}

export class VerificationHarnessGenerator {
  generate(input: VerificationHarnessPlan): string {
    const plan = verificationHarnessPlanSchema.parse(input);
    const instances = new Set<string>(); const results = new Set<string>(); const statements: string[] = [];
    for (const operation of plan.operations) {
      if (operation.kind === "deploy") {
        if (operation.contractName !== plan.primaryContract || instances.has(operation.instanceName)) throw new VerificationHarnessGenerationError("Deployment operation is not valid for the primary contract.");
        instances.add(operation.instanceName); statements.push(`${plan.primaryContract} ${operation.instanceName} = new ${plan.primaryContract}();`); continue;
      }
      if (FORBIDDEN_OPERATION_NAMES.has(operation.functionName) || operation.functionName.startsWith("env")) throw new VerificationHarnessGenerationError("Operation uses a prohibited capability name.");
      if (!instances.has(operation.instanceName) || !plan.relevantFunctions.includes(operation.functionName)) throw new VerificationHarnessGenerationError("Operation references an undeclared instance or function.");
      if (operation.kind === "call") statements.push(`${operation.instanceName}.${operation.functionName}();`);
      else {
        if (results.has(operation.resultName) || instances.has(operation.resultName)) throw new VerificationHarnessGenerationError("Read result name is duplicated or ambiguous.");
        results.add(operation.resultName); statements.push(`uint256 ${operation.resultName} = ${operation.instanceName}.${operation.functionName}();`);
      }
    }
    if (!instances.size) throw new VerificationHarnessGenerationError("A controlled deployment operation is required.");
    const assertions = plan.assertions.map((assertion, index) => {
      if (!results.has(assertion.actual) || BigInt(assertion.expected) > MAX_UINT256) throw new VerificationHarnessGenerationError("Assertion references an invalid result or uint256 value.");
      return `require(${assertion.actual} ${assertion.kind === "uint-eq" ? "==" : "!="} ${assertion.expected}, "CH_ASSERT_${index}");`;
    });
    const importPath = `../src/${plan.primarySourcePath}`;
    return `// SPDX-License-Identifier: UNLICENSED
pragma solidity ${plan.compilerVersion};

import { ${plan.primaryContract} } from "${importPath}";

contract ContractHunterVerification {
    function testContractHunterVerification() public {
${[...statements, ...assertions].map((line) => `        ${line}`).join("\n")}
    }
}
`;
  }
}
