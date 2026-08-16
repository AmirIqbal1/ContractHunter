import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("manual AI hunt-page workflow", () => {
  it("presents static completion and both AI stages as explicit optional actions", () => {
    const source = readFileSync(new URL("./[id]/page.tsx", import.meta.url), "utf8");
    expect(source).toContain("Static analysis is complete. Review the findings before spending API tokens on AI analysis.");
    expect(source).toContain("Optional AI stage. Run it manually after reviewing the static findings.");
    expect(source).toContain("Optional deeper AI review. Available after a successful current protocol analysis.");
    expect(source).toContain("RUN AI ANALYSIS");
    expect(source).toContain("RUN SECURITY REVIEW");
  });
});
