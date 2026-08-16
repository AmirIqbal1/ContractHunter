import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ProtocolCostEstimate } from "./ai-analysis-control";
import { SecurityReviewCostEstimate } from "./security-review-control";

describe("manual AI estimate display", () => {
  it("shows the protocol estimate and clearly labels it non-exact", () => {
    const html = renderToStaticMarkup(<ProtocolCostEstimate estimate={{ approximateInputBytes: 10_240, estimatedCostDisplay: "$0.0086" }} />);
    expect(html).toContain("Estimated API cost: ~$0.0086");
    expect(html).toContain("Estimate only");
  });

  it("shows the concise security-review preview and estimate", () => {
    const html = renderToStaticMarkup(<SecurityReviewCostEstimate estimate={{ approximateSourceBytes: 20_480, approximateRequestCount: 3, selectedReviewers: [{}, {}, {}], estimatedCostDisplay: "$0.0193" }} />);
    expect(html).toContain("Selected reviewers: 3");
    expect(html).toContain("Estimated requests: 3");
    expect(html).toContain("Estimated context: ~20 KiB");
    expect(html).toContain("Estimated API cost: ~$0.0193");
    expect(html).toContain("Estimate only");
  });
});
