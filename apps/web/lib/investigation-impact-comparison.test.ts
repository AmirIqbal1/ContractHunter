import { describe, expect, it } from "vitest";
import type { ImpactOverlay, InvestigationPathResult } from "@contracthunter/core";
import { investigationImpactComparison } from "./investigation-impact-comparison";

describe("Investigation observed comparison", () => {
  it("compares only executions from an exact member finding and keeps other paths separate", () => {
    const path = { scanId: "scan", protocolGraphId: "graph", graphContentSha256: "hash",
      subject: { type: "investigation", id: "investigation", findingIds: ["finding"] },
      paths: [{ id: "path-a", steps: [{ nodeId: "A", nodeKind: "function" },
        { nodeId: "B", nodeKind: "function", relationship: "calls" }], edgeIds: ["AB"] },
        { id: "path-b", steps: [{ nodeId: "B", nodeKind: "function" },
          { nodeId: "C", nodeKind: "function", relationship: "calls" }], edgeIds: ["BC"] }] } as InvestigationPathResult;
    const overlay = { scanId: "scan", protocolGraphId: "graph", provenance: { graphContentSha256: "hash" },
      subject: { type: "finding", id: "finding" }, capabilities: { traceAvailable: true },
      observedCalls: [{ id: "call", callType: "CALL", mapping: { functionNodeId: "B", contractNodeId: null },
        staticEdgeId: "AB", relationshipStatus: "observed-static-edge" }] } as ImpactOverlay;
    const result = investigationImpactComparison(path, overlay);
    expect(result.map((item) => item.pathId)).toEqual(["path-a", "path-b"]);
    expect(result[0]?.edges[0]?.status).toBe("observed-in-this-local-execution");
    expect(result[1]?.edges[0]?.status).toBe("not-observed-in-this-execution");
    expect(investigationImpactComparison(path, { ...overlay, subject: { type: "finding", id: "foreign" } })).toEqual([]);
  });
});
