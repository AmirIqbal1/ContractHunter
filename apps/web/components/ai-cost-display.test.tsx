import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AIUsageSummary, RecordedAICost } from "./ai-cost-display";

describe("hunt AI cost display", () => {
  it("shows actual recorded stage cost and labels it as an estimate", () => {
    const html = renderToStaticMarkup(<RecordedAICost costUsd={0.01234} />);
    expect(html).toContain("Estimated API cost from recorded token usage");
    expect(html).toContain("$0.0123");
    expect(html).toContain("not an official invoice");
  });

  it("shows only recorded stages and their aggregate hunt total", () => {
    const html = renderToStaticMarkup(<AIUsageSummary protocolCostUsd={0.0012} reviewCostUsd={0.0034} />);
    expect(html).toContain("AI usage this hunt");
    expect(html).toContain("Protocol analysis");
    expect(html).toContain("Security review");
    expect(html).toContain("Recorded AI cost");
    expect(html).toContain("$0.0046");
  });

  it("omits stages without complete recorded token usage", () => {
    const html = renderToStaticMarkup(<AIUsageSummary protocolCostUsd={0.0012} reviewCostUsd={null} />);
    expect(html).toContain("Protocol analysis");
    expect(html).not.toContain("Security review");
  });
});
