import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { PublicHypothesisVerificationRun } from "@/lib/verification/public-verification";
import { LocalVerification } from "./local-verification";

const base: PublicHypothesisVerificationRun = {
  id: crypto.randomUUID(), hypothesisId: crypto.randomUUID(), status: "completed", outcome: "confirmed", verifier: "contracthunter-local-verification", compiler: "0.8.24", contentFingerprint: "a".repeat(64), createdAt: "2026-08-16T10:00:00.000Z", startedAt: "2026-08-16T10:00:00.001Z", completedAt: "2026-08-16T10:00:00.013Z", durationMs: 12, isolationBackend: "linux-bubblewrap", exitCode: 0, timedOut: false, testCounts: { total: 1, passed: 1, failed: 0 }, failureCode: null,
  dynamicEvidence: [{ assertionId: "balance", assertionName: "Balance property", expectedBehavior: "Balance remains conserved.", observedBehavior: "Balance decreased after the transition.", direction: "supports", contract: "Vault", functionName: "withdraw", details: "The generated balance assertion did not hold." }],
};
const render = (runs: PublicHypothesisVerificationRun[], status: "candidate" | "verified" = "candidate") => renderToStaticMarkup(<LocalVerification hypothesisId={base.hypothesisId} hypothesisStatus={status} initialRuns={runs} />);

describe("local verification UI", () => {
  it("keeps workflow status separate and shows no-run state with explicit plan controls", () => {
    const html = render([]); expect(html).toContain("Hypothesis status"); expect(html).toContain("Local verification"); expect(html).toContain("Not run"); expect(html).toContain("Open developer verification-plan input"); expect(html).toContain("Validate plan"); expect(html).toContain("Verify locally"); expect(html).not.toContain("Mark verified");
  });

  it.each([
    ["queued", null, "Queued"], ["running", null, "Running"], ["completed", "confirmed", "Confirmed"],
    ["completed", "refuted", "Refuted"], ["completed", "inconclusive", "Inconclusive"], ["failed", null, "Failed"],
  ] as const)("renders %s/%s as %s", (status, outcome, label) => {
    const run = { ...base, status, outcome, failureCode: status === "failed" ? "verification_failed" : null };
    const html = render([run]); expect(html).toContain(label);
    if (status === "queued" || status === "running") expect(html).toMatch(/<button[^>]+disabled[^>]*>VERIFYING…<\/button>/);
  });

  it("renders dynamic evidence, run history, and read-only verified status", () => {
    const older = { ...base, id: crypto.randomUUID(), outcome: "refuted" as const, createdAt: "2026-08-15T10:00:00.000Z" };
    const html = render([base, older], "verified"); expect(html).toContain("Dynamic evidence"); expect(html).toContain("Balance property"); expect(html).toContain("Expected property"); expect(html).toContain("Observed result"); expect(html).toContain("Vault.withdraw"); expect(html).toContain("Verification history"); expect(html).toContain("15 Aug 2026"); expect(html).not.toContain("Mark verified");
  });

  it("explains fail-closed isolation without suggesting unsafe workarounds", () => {
    const html = render([{ ...base, status: "failed", outcome: null, isolationBackend: null, failureCode: "network_isolation_unavailable" }]);
    expect(html).toContain("required isolation environment is unavailable"); expect(html).toContain("did not fall back to unsafe execution"); expect(html).not.toMatch(/sudo|host networking|privileged container/i);
  });
});
