import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { assessVerificationStrategies, verificationStrategies, type VerificationAssessmentInput } from "@contracthunter/core";
import { toPublicVerificationOptions } from "@/lib/verification/public-verification-options";
import { VerificationOptions } from "./verification-options";

function options(detectorId: string | null, source = "slither") {
  const input: VerificationAssessmentInput = {
    hypothesis: { scanId: "scan-1", relatedInvestigationIds: ["investigation-1"] },
    investigations: [{ id: "investigation-1", scanId: "scan-1", primaryContract: "Vault", primaryFilePath: "src/Vault.sol",
      findings: [{ scanId: "scan-1", source, detectorId, contract: "Vault", filePath: "src/Vault.sol" }] }],
  };
  return toPublicVerificationOptions(assessVerificationStrategies(input));
}

describe("public verification option mapping", () => {
  it("retains stable display order and separate engine and plan mode", () => {
    const result = options("protected-vars");
    expect(result.map((option) => option.strategy)).toEqual(verificationStrategies);
    expect(result.map((option) => [option.engine, option.planMode])).toEqual([
      [null, null], ["foundry", "fuzz-property"], ["foundry", "stateful-invariant"], ["echidna", "stateful-invariant"],
    ]);
    expect(result.map((option) => option.selectionAvailable)).toEqual([true, true, true, false]);
    expect(result[3]).toMatchObject({ compatibility: "incompatible", reasons: [{ code: "unsupported-requirement", requirement: "explicit-caller", message: "Explicit caller semantics are not supported by this strategy." }] });
  });

  it.each([
    ["reentrancy-eth", "reentrant-callback", "Reentrant callbacks"],
    ["tx-origin", "tx-origin", "tx.origin semantics"],
    ["unchecked-lowlevel", "external-return-value", "External return-value observation"],
    ["timestamp", "block-timestamp", "Block timestamp control"],
  ])("maps %s to bounded unsupported capability text", (rule, requirement, phrase) => {
    const result = options(rule);
    expect(result.every((option) => option.compatibility === "incompatible")).toBe(true);
    expect(result.every((option) => option.selectionAvailable === false)).toBe(true);
    expect(result[0].reasons.some((reason) => reason.requirement === requirement && reason.message.includes(phrase))).toBe(true);
  });

  it("keeps unknown distinct and exposes no scanner text or paths", () => {
    const result = options("unknown-rule");
    expect(result.every((option) => option.compatibility === "unknown" && !option.selectionAvailable)).toBe(true);
    expect(result[0].reasons).toEqual([{ code: "unmapped-scanner-rule", requirement: null, message: "The available scanner rule has no verified capability mapping yet." }]);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("unknown-rule");
    expect(serialized).not.toContain("src/Vault.sol");
    expect(serialized.length).toBeLessThan(5000);
  });
});

describe("verification options UI", () => {
  it("shows compatible choices as explicit page-local selection without generation or execution controls", () => {
    const html = renderToStaticMarkup(<VerificationOptions options={options("protected-vars")} />);
    expect(html).toContain("Verification options");
    expect(html).toContain("Structured verification");
    expect(html).toContain("Foundry fuzz property");
    expect(html).toContain("Echidna stateful invariant");
    expect(html).toContain("Explicit caller semantics are not supported by this strategy.");
    expect((html.match(/Select for planning/g) ?? [])).toHaveLength(3);
    expect(html).not.toContain("Generate verification plan");
    expect(html).not.toContain("Run with Echidna");
  });

  it("shows incompatible and unknown separately and offers neither a selection action", () => {
    const incompatible = renderToStaticMarkup(<VerificationOptions options={options("timestamp")} />);
    const unknown = renderToStaticMarkup(<VerificationOptions options={options("unknown-rule")} />);
    expect(incompatible).toContain("Not compatible");
    expect(incompatible).toContain("Block timestamp control is not supported");
    expect(incompatible).not.toContain("Select for planning");
    expect(unknown).toContain("Unknown");
    expect(unknown).toContain("Compatibility could not be determined from the available structured evidence.");
    expect(unknown).not.toContain("Select for planning");
  });
});
