import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { validateEvidence } from "./evidence-validation";

const root = mkdtempSync(path.join(tmpdir(), "contracthunter-evidence-")); mkdirSync(path.join(root, "src")); writeFileSync(path.join(root, "src/Vault.sol"), "contract Vault {\n function withdraw() external {}\n}\n");
afterAll(() => rmSync(root, { recursive: true, force: true }));
const base = { filePath: "src/Vault.sol", contract: "Vault", functionName: "withdraw", startLine: 2, endLine: 2 };
describe("AI evidence validation", () => {
  it("validates real relative source evidence", () => expect(validateEvidence(root, base)).toMatchObject({ valid: true, validationError: null }));
  it.each([{ ...base, filePath: "missing.sol" }, { ...base, filePath: "../Vault.sol" }, { ...base, filePath: "/etc/passwd" }, { ...base, startLine: 99, endLine: 99 }])("marks invalid references without throwing", (evidence) => expect(validateEvidence(root, evidence)).toMatchObject({ valid: false }));
});
