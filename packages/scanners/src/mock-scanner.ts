import type { NewFinding, Scanner, ScannerResult, ScanContext } from "@contracthunter/core";
import { createHash } from "node:crypto";

const mockFindings: NewFinding[] = [
  {
    title: "[MOCK] External call before state update",
    severity: "high",
    confidence: 82,
    source: "mock-scanner",
    detectorId: "mock-reentrancy",
    fingerprint: "pending",
    contract: "ExampleVault",
    functionName: "withdraw",
    filePath: "contracts/ExampleVault.sol",
    startLine: 41,
    endLine: 48,
    rootCause: "MOCK DATA: State is represented as being updated after an external value transfer.",
    attackScenario: "MOCK DATA: A receiver could re-enter the illustrated withdrawal path before its balance changes.",
    impact: "MOCK DATA: Repeated withdrawals could drain funds from the example contract.",
    evidence: "MOCK DATA ONLY — no Solidity source was parsed or executed by this scanner.",
    status: "candidate",
  },
  {
    title: "[MOCK] Privileged action lacks visible access control",
    severity: "medium",
    confidence: 68,
    source: "mock-scanner",
    detectorId: "mock-access-control",
    fingerprint: "pending",
    contract: "ExampleTreasury",
    functionName: "setRecipient",
    filePath: "contracts/ExampleTreasury.sol",
    startLine: 19,
    endLine: 23,
    rootCause: "MOCK DATA: A sensitive setter is represented without an authorization guard.",
    attackScenario: "MOCK DATA: An arbitrary caller could redirect a hypothetical recipient.",
    impact: "MOCK DATA: Protocol-controlled payments could be redirected.",
    evidence: "MOCK DATA ONLY — this finding exists to exercise the V0.1 review workflow.",
    status: "candidate",
  },
  {
    title: "[MOCK] Compiler pragma permits a broad version range",
    severity: "informational",
    confidence: 91,
    source: "mock-scanner",
    detectorId: "mock-pragma",
    fingerprint: "pending",
    contract: null,
    functionName: null,
    filePath: "contracts/ExampleToken.sol",
    startLine: 2,
    endLine: 2,
    rootCause: "MOCK DATA: The represented pragma is not pinned to a narrow compiler version.",
    attackScenario: "MOCK DATA: Builds could use compiler versions with different behavior.",
    impact: "MOCK DATA: Reproducibility and audit assumptions may be weakened.",
    evidence: "MOCK DATA ONLY — repository files were not examined for this result.",
    status: "candidate",
  },
];

export class MockScanner implements Scanner {
  readonly id = "mock-scanner";
  readonly name = "ContractHunter Mock Scanner";

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async scan(context: ScanContext): Promise<ScannerResult> {
    void context;
    return { scannerId: this.id, findings: mockFindings.map((finding) => ({ ...finding, fingerprint: createHash("sha256").update(`${context.scan.id}:${finding.detectorId}`).digest("hex") })), warnings: ["Mock scanner enabled: results are demonstration data only."] };
  }
}
