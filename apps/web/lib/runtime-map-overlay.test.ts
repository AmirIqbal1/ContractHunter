import { describe, expect, it } from "vitest";
import type { ImpactOverlay, StaticProtocolGraphArtifact } from "@contracthunter/core";
import type { MapView } from "./protocol-map";
import { runtimeMapOverlay } from "./runtime-map-overlay";

describe("Protocol Map observed layer", () => {
  it("adds only ephemeral runtime IDs and leaves the static graph and view unchanged", () => {
    const artifact = { graph: { nodes: [], edges: [] } } as unknown as StaticProtocolGraphArtifact;
    const view: MapView = { nodes: [], edges: [], totalNodes: 0, totalEdges: 0, clipped: false, hiddenFunctionNodes: 0 };
    const call = { id: "trace:1", transactionOrdinal: 0, parentCallId: null, from: "0x1111111111111111111111111111111111111111",
      to: "0x2222222222222222222222222222222222222222", callType: "CALL",
      relationshipStatus: "unmapped-runtime-call", mapping: { functionNodeId: null, contractNodeId: null } };
    const overlay = { executionId: "execution", observedCalls: [call, { ...call, id: "trace:2", transactionOrdinal: 1 }] } as unknown as ImpactOverlay;
    const original = structuredClone(artifact), result = runtimeMapOverlay(artifact, view, overlay);
    expect(result.nodes).toHaveLength(2); expect(result.edges).toHaveLength(1);
    expect(result.nodes.every((node) => node.id.startsWith("io:execution:"))).toBe(true);
    expect(result.edges[0]?.label).toBe("OBSERVED CALL");
    expect(runtimeMapOverlay(artifact, view, overlay, 1).edges.map((edge) => edge.id)).toEqual(["io:execution:trace:2:edge"]);
    expect(artifact).toEqual(original); expect(view.nodes).toHaveLength(0);
  });
});
